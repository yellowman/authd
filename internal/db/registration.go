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

func (s *OIDCStore) RegisterDynamicClient(ctx context.Context, tokenHash []byte, edit oidc.ClientEdit, secretHash []byte, scopes []string, a identity.Audit) (out oidc.Client, err error) {
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
		if len(secretHash) != 32 || len(tokenHash) != 32 || hmac.Equal(secretHash, tokenHash) {
			return identity.Invalid("invalid registration credentials")
		}
		if err := tx.QueryRowContext(ctx, `INSERT INTO clients(client_id,name,client_type,client_secret_hash,enabled,require_mfa,refresh_tokens_enabled,dynamic_registration,access_token_ttl_seconds)
 VALUES($1,$2,'confidential',$3,true,false,false,true,$4) RETURNING id::text`, edit.ClientID, edit.Name, secretHash, int64(edit.AccessTokenTTL.Seconds())).Scan(&edit.ID); err != nil {
			return err
		}
		if err := replaceClientSets(ctx, tx, edit.ID, edit); err != nil {
			return err
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
