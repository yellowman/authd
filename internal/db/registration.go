package db

import (
	"context"
	"crypto/hmac"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/yellowman/authd/internal/identity"
	"github.com/yellowman/authd/internal/oidc"
)

func IssueInitialRegistrationToken(ctx context.Context, pool *sql.DB, hash []byte, prefix string, expires time.Time) error {
	if len(hash) != 32 || !oidc.ValidRegistrationPrefix(prefix) || expires.Before(time.Now().Add(time.Minute)) || expires.After(time.Now().Add(time.Hour)) {
		return identity.Invalid("invalid registration token policy")
	}
	_, err := pool.ExecContext(ctx, `INSERT INTO initial_registration_tokens(token_hash,scope_prefix,expires_at) VALUES($1,$2,$3)`, hash, prefix, expires)
	return err
}

func (s *OIDCStore) RegisterDynamicClient(ctx context.Context, tokenHash []byte, edit oidc.ClientEdit, secretHash, managementHash []byte, scopes []string, roles []oidc.RoleTemplate, groups []oidc.GroupTemplate, a identity.Audit) (out oidc.Client, err error) {
	err = (&IdentityStore{DB: s.DB}).write(ctx, func(tx *sql.Tx) error {
		var tokenID, prefix string
		if err := tx.QueryRowContext(ctx, `SELECT id::text,scope_prefix FROM initial_registration_tokens WHERE token_hash=$1 AND used_at IS NULL AND expires_at>clock_timestamp() FOR UPDATE`, tokenHash).Scan(&tokenID, &prefix); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return oidc.ErrRegistrationTokenUsed
			}
			return err
		}
		if len(scopes) == 0 || len(scopes) > 64 {
			return identity.Invalid("invalid application scope count")
		}
		for _, scope := range scopes {
			if !strings.HasPrefix(scope, prefix) || scope == prefix || scope == "system.admin" {
				return identity.Invalid("application scope is outside registration token namespace")
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO permissions(name,description) VALUES($1,$2) ON CONFLICT(name) DO NOTHING`, scope, "Dynamically registered application scope"); err != nil {
				return err
			}
			var permissionID string
			if err := tx.QueryRowContext(ctx, `SELECT id::text FROM permissions WHERE name=$1`, scope).Scan(&permissionID); err != nil {
				return err
			}
			edit.PermissionIDs = append(edit.PermissionIDs, permissionID)
		}
		if len(secretHash) != 32 || len(tokenHash) != 32 || len(managementHash) != 32 || hmac.Equal(secretHash, tokenHash) || hmac.Equal(managementHash, tokenHash) || hmac.Equal(managementHash, secretHash) {
			return identity.Invalid("invalid registration credentials")
		}
		if err := tx.QueryRowContext(ctx, `INSERT INTO clients(client_id,name,client_type,client_secret_hash,enabled,require_mfa,refresh_tokens_enabled,dynamic_registration,access_token_ttl_seconds)
 VALUES($1,$2,'confidential',$3,true,false,false,true,$4) RETURNING id::text`, edit.ClientID, edit.Name, secretHash, int64(edit.AccessTokenTTL.Seconds())).Scan(&edit.ID); err != nil {
			return err
		}
		if err := replaceClientSets(ctx, tx, edit.ID, edit); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO client_registration_credentials(client_id,scope_prefix,token_hash) VALUES($1::uuid,$2,$3)`, edit.ID, prefix, managementHash); err != nil {
			return err
		}
		roleIDs := map[string]string{}
		for _, role := range roles {
			if !strings.HasPrefix(role.Name, prefix) || role.Name == prefix {
				return identity.Invalid("role template is outside registration namespace")
			}
			var id string
			e := tx.QueryRowContext(ctx, `INSERT INTO roles(name,description) VALUES($1,$2) ON CONFLICT(name) DO NOTHING RETURNING id::text`, role.Name, role.Description).Scan(&id)
			if errors.Is(e, sql.ErrNoRows) {
				return identity.ErrConflict
			}
			if e != nil {
				return e
			}
			roleIDs[role.Name] = id
			if _, e = tx.ExecContext(ctx, `INSERT INTO client_role_templates(client_id,role_id) VALUES($1::uuid,$2::uuid)`, edit.ID, id); e != nil {
				return e
			}
			for _, scope := range role.Scopes {
				var result sql.Result
				result, e = tx.ExecContext(ctx, `INSERT INTO role_permissions(role_id,permission_id) SELECT $1::uuid,id FROM permissions WHERE name=$2 AND left(name,length($3))=$3`, id, scope, prefix)
				if e != nil {
					return e
				}
				if n, _ := result.RowsAffected(); n != 1 {
					return identity.Invalid("role template references an unknown scope")
				}
			}
		}
		for _, group := range groups {
			if !strings.HasPrefix(group.Name, prefix) || group.Name == prefix {
				return identity.Invalid("group template is outside registration namespace")
			}
			var id string
			e := tx.QueryRowContext(ctx, `INSERT INTO groups(name,description) VALUES($1,$2) ON CONFLICT(name) DO NOTHING RETURNING id::text`, group.Name, group.Description).Scan(&id)
			if errors.Is(e, sql.ErrNoRows) {
				return identity.ErrConflict
			}
			if e != nil {
				return e
			}
			if _, e = tx.ExecContext(ctx, `INSERT INTO client_group_templates(client_id,group_id) VALUES($1::uuid,$2::uuid)`, edit.ID, id); e != nil {
				return e
			}
			for _, name := range group.Roles {
				idOfRole, ok := roleIDs[name]
				if !ok {
					return identity.Invalid("group template references unknown role")
				}
				if _, e = tx.ExecContext(ctx, `INSERT INTO group_roles(group_id,role_id) VALUES($1::uuid,$2::uuid)`, id, idOfRole); e != nil {
					return e
				}
			}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE initial_registration_tokens SET used_at=clock_timestamp() WHERE id=$1::uuid`, tokenID); err != nil {
			return err
		}
		if err := audit(ctx, tx, "client.dynamically_registered", "", "client", edit.ID, a); err != nil {
			return err
		}
		out, err = clientByDBID(ctx, tx, edit.ID)
		return err
	})
	return
}

// IssueClientRegistrationToken rotates the management credential for an
// existing dynamic client. The operator supplies the namespace on adoption;
// every currently allowed application scope must already be inside it.
func IssueClientRegistrationToken(ctx context.Context, pool *sql.DB, clientID, prefix string, hash []byte) error {
	if len(hash) != 32 || !oidc.ValidRegistrationPrefix(prefix) {
		return identity.Invalid("invalid client registration management credential")
	}
	tx, err := pool.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var id string
	if err = tx.QueryRowContext(ctx, `SELECT id::text FROM clients WHERE client_id=$1 AND dynamic_registration AND enabled FOR UPDATE`, clientID).Scan(&id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return oidc.ErrInvalidClient
		}
		return err
	}
	var outside bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM client_permissions cp JOIN permissions p ON p.id=cp.permission_id WHERE cp.client_id=$1::uuid AND (left(p.name,length($2))<>$2 OR p.name=$2))`, id, prefix).Scan(&outside); err != nil {
		return err
	}
	if outside {
		return identity.Invalid("existing client scopes are outside the requested namespace")
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO client_registration_credentials(client_id,scope_prefix,token_hash) VALUES($1::uuid,$2,$3)
ON CONFLICT(client_id) DO UPDATE SET scope_prefix=excluded.scope_prefix,token_hash=excluded.token_hash,issued_at=clock_timestamp()`, id, prefix, hash); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *OIDCStore) ManagedClient(ctx context.Context, clientID string, tokenHash []byte) (oidc.Client, string, error) {
	if len(tokenHash) != 32 {
		return oidc.Client{}, "", oidc.ErrInvalidClient
	}
	var prefix string
	err := s.DB.QueryRowContext(ctx, `SELECT m.scope_prefix FROM client_registration_credentials m JOIN clients c ON c.id=m.client_id
WHERE c.client_id=$1 AND c.dynamic_registration AND c.enabled AND m.token_hash=$2`, clientID, tokenHash).Scan(&prefix)
	if errors.Is(err, sql.ErrNoRows) {
		return oidc.Client{}, "", oidc.ErrInvalidClient
	}
	if err != nil {
		return oidc.Client{}, "", err
	}
	client, err := s.Client(ctx, clientID)
	return client, prefix, err
}

func (s *OIDCStore) UpdateManagedClientScopes(ctx context.Context, clientID string, tokenHash, secretHash []byte, scopes []string, a identity.Audit) (out oidc.Client, err error) {
	if len(tokenHash) != 32 || len(secretHash) != 32 {
		return out, oidc.ErrInvalidClient
	}
	err = (&IdentityStore{DB: s.DB}).write(ctx, func(tx *sql.Tx) error {
		var id, prefix string
		var savedSecret []byte
		e := tx.QueryRowContext(ctx, `SELECT c.id::text,m.scope_prefix,c.client_secret_hash FROM clients c
JOIN client_registration_credentials m ON m.client_id=c.id WHERE c.client_id=$1 AND c.dynamic_registration AND c.enabled AND m.token_hash=$2 FOR UPDATE OF c,m`, clientID, tokenHash).Scan(&id, &prefix, &savedSecret)
		if errors.Is(e, sql.ErrNoRows) {
			return oidc.ErrInvalidClient
		}
		if e != nil {
			return e
		}
		if !hmac.Equal(savedSecret, secretHash) {
			return oidc.ErrInvalidClient
		}
		if len(scopes) == 0 || len(scopes) > 64 {
			return identity.Invalid("invalid application scope count")
		}
		for _, scope := range scopes {
			if !strings.HasPrefix(scope, prefix) || scope == prefix || scope == "system.admin" {
				return identity.Invalid("application scope is outside registration namespace")
			}
			if _, e = tx.ExecContext(ctx, `INSERT INTO permissions(name,description) VALUES($1,$2) ON CONFLICT(name) DO NOTHING`, scope, "Dynamically registered application scope"); e != nil {
				return e
			}
		}
		if _, e = tx.ExecContext(ctx, `DELETE FROM client_permissions WHERE client_id=$1::uuid`, id); e != nil {
			return e
		}
		for _, scope := range scopes {
			if _, e = tx.ExecContext(ctx, `INSERT INTO client_permissions(client_id,permission_id) SELECT $1::uuid,id FROM permissions WHERE name=$2`, id, scope); e != nil {
				return e
			}
		}
		if _, e = tx.ExecContext(ctx, `UPDATE clients SET updated_at=clock_timestamp() WHERE id=$1::uuid`, id); e != nil {
			return e
		}
		if e = audit(ctx, tx, "client.registration_scopes_updated", "", "client", id, a); e != nil {
			return e
		}
		out, e = clientByDBID(ctx, tx, id)
		return e
	})
	return
}
