package db

import (
	"context"
	"crypto/hmac"
	"database/sql"
	"encoding/json"
	"errors"
	"net/url"
	"time"

	"github.com/yellowman/authd/internal/identity"
	"github.com/yellowman/authd/internal/oidc"
)

type OIDCStore struct{ DB *sql.DB }

var _ oidc.Store = (*OIDCStore)(nil)

func scanClient(row scanner) (oidc.Client, error) {
	var c oidc.Client
	var ttl int64
	var redirects, logouts, identityScopes, permissionIDs, permissions string
	err := row.Scan(&c.ID, &c.ClientID, &c.Name, &c.Type, &c.SecretHash, &c.Enabled, &c.RequireMFA, &c.RefreshTokensEnabled, &c.DynamicRegistration, &c.TokenEndpointAuthMethod, &ttl, &c.UpdatedAt, &redirects, &logouts, &identityScopes, &permissionIDs, &permissions)
	if err != nil {
		return c, err
	}
	c.AccessTokenTTL = time.Duration(ttl) * time.Second
	if c.RedirectURIs, err = decodeList(redirects); err != nil {
		return c, err
	}
	if c.LogoutURIs, err = decodeList(logouts); err != nil {
		return c, err
	}
	if c.IdentityScopes, err = decodeList(identityScopes); err != nil {
		return c, err
	}
	if c.PermissionIDs, err = decodeList(permissionIDs); err != nil {
		return c, err
	}
	if c.Permissions, err = decodeList(permissions); err != nil {
		return c, err
	}
	return c, nil
}

const clientColumns = `c.id::text,c.client_id,c.name,c.client_type,c.client_secret_hash,c.enabled,c.require_mfa,c.refresh_tokens_enabled,c.dynamic_registration,COALESCE(c.token_endpoint_auth_method,''),c.access_token_ttl_seconds,c.updated_at,
 COALESCE((SELECT json_agg(x.uri ORDER BY x.uri) FROM client_redirect_uris x WHERE x.client_id=c.id),'[]'::json)::text,
 COALESCE((SELECT json_agg(x.uri ORDER BY x.uri) FROM client_logout_uris x WHERE x.client_id=c.id),'[]'::json)::text,
 COALESCE((SELECT json_agg(x.scope ORDER BY x.scope) FROM client_identity_scopes x WHERE x.client_id=c.id),'[]'::json)::text,
 COALESCE((SELECT json_agg(cp.permission_id::text ORDER BY cp.permission_id) FROM client_permissions cp WHERE cp.client_id=c.id),'[]'::json)::text,
 COALESCE((SELECT json_agg(p.name ORDER BY p.name) FROM client_permissions cp JOIN permissions p ON p.id=cp.permission_id WHERE cp.client_id=c.id),'[]'::json)::text`

func (s *OIDCStore) Client(ctx context.Context, clientID string) (oidc.Client, error) {
	c, err := scanClient(s.DB.QueryRowContext(ctx, `SELECT `+clientColumns+` FROM clients c WHERE c.client_id=$1`, clientID))
	if errors.Is(err, sql.ErrNoRows) {
		return c, oidc.ErrInvalidClient
	}
	return c, err
}

// Match the same canonical authority used by the HTTP CORS gate. A scalar
// indexed existence query replaces a truncated full-client-catalog transfer.
func (s *OIDCStore) PublicOriginAllowed(ctx context.Context, origin string) (bool, error) {
	u, err := url.Parse(origin)
	if err != nil {
		return false, err
	}
	alternate := origin
	if u.Port() == "" {
		if u.Scheme == "https" {
			alternate = origin + ":443"
		} else if u.Scheme == "http" {
			alternate = origin + ":80"
		}
	}
	var allowed bool
	err = s.DB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM client_redirect_uris r JOIN clients c ON c.id=r.client_id WHERE c.enabled AND c.client_type='public' AND lower(substring(r.uri from '^(https?://[^/?#]+)')) IN ($1,$2))`, origin, alternate).Scan(&allowed)
	return allowed, err
}

func clientByDBID(ctx context.Context, tx *sql.Tx, id string) (oidc.Client, error) {
	c, err := scanClient(tx.QueryRowContext(ctx, `SELECT `+clientColumns+` FROM clients c WHERE c.id=$1::uuid`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return c, oidc.ErrInvalidClient
	}
	return c, err
}

const authorizationColumns = `ar.client_id::text,c.client_id,ar.redirect_uri,array_to_json(ar.scopes)::text,ar.required_acr,COALESCE(ar.state,''),COALESCE(ar.nonce,''),ar.code_challenge,COALESCE(ar.login_hint,''),ar.prompt,ar.created_at,ar.expires_at,ar.browser_hash,COALESCE(ar.consent_session_id::text,''),ar.preferred_acr,array_to_json(ar.expected_subjects)::text,ar.max_age_seconds,ar.claims::text`

func (s *OIDCStore) CreateAuthorizationRequest(ctx context.Context, hash []byte, req oidc.AuthorizationRequest) error {
	res, err := s.DB.ExecContext(ctx, `INSERT INTO authorization_requests(request_hash,client_id,redirect_uri,scopes,required_acr,state,nonce,code_challenge,login_hint,prompt,created_at,expires_at,browser_hash,preferred_acr,expected_subjects,max_age_seconds,claims)
 SELECT $1,c.id,$3,ARRAY(SELECT jsonb_array_elements_text($4::jsonb)),$5,NULLIF($6,''),NULLIF($7,''),$8,NULLIF($9,''),$10,$11,$12,$13,$14,ARRAY(SELECT jsonb_array_elements_text($15::jsonb)),$16,$17::jsonb FROM clients c WHERE c.client_id=$2 AND c.enabled`, hash, req.ClientID, req.RedirectURI, listJSON(req.Scopes), req.RequiredACR, req.State, req.Nonce, req.CodeChallenge, req.LoginHint, req.Prompt, req.CreatedAt, req.ExpiresAt, req.BrowserHash, req.PreferredACR, listJSON(req.ExpectedSubjects), req.MaxAgeSeconds, claimsJSON(req.Claims))
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return oidc.ErrInvalidClient
	}
	return nil
}
func scanAuthorization(row scanner) (req oidc.AuthorizationRequest, clientDBID string, err error) {
	var scopes, claims, subjects string
	err = row.Scan(&clientDBID, &req.ClientID, &req.RedirectURI, &scopes, &req.RequiredACR, &req.State, &req.Nonce, &req.CodeChallenge, &req.LoginHint, &req.Prompt, &req.CreatedAt, &req.ExpiresAt, &req.BrowserHash, &req.ConsentSessionID, &req.PreferredACR, &subjects, &req.MaxAgeSeconds, &claims)
	if err != nil {
		return
	}
	req.Scopes, err = decodeList(scopes)
	if err == nil {
		req.ExpectedSubjects, err = decodeList(subjects)
	}
	if err == nil {
		err = json.Unmarshal([]byte(claims), &req.Claims)
	}
	return
}
func authorizationTx(ctx context.Context, tx *sql.Tx, hash []byte) (oidc.AuthorizationRequest, string, error) {
	req, cid, err := scanAuthorization(tx.QueryRowContext(ctx, `SELECT `+authorizationColumns+` FROM authorization_requests ar JOIN clients c ON c.id=ar.client_id WHERE ar.request_hash=$1 AND ar.expires_at>clock_timestamp() FOR UPDATE OF ar`, hash))
	if errors.Is(err, sql.ErrNoRows) {
		err = oidc.ErrInvalidRequest
	}
	return req, cid, err
}
func (s *OIDCStore) AuthorizationRequest(ctx context.Context, hash []byte) (oidc.AuthorizationRequest, oidc.Client, error) {
	req, _, err := scanAuthorization(s.DB.QueryRowContext(ctx, `SELECT `+authorizationColumns+` FROM authorization_requests ar JOIN clients c ON c.id=ar.client_id WHERE ar.request_hash=$1`, hash))
	if errors.Is(err, sql.ErrNoRows) {
		err = oidc.ErrInvalidRequest
	}
	if err != nil {
		return req, oidc.Client{}, err
	}
	client, err := s.Client(ctx, req.ClientID)
	return req, client, err
}

func (s *OIDCStore) ConsentAuthorizationRequest(ctx context.Context, rh, bh, sh []byte, allow bool, a identity.Audit) error {
	return s.grantWrite(ctx, func(tx *sql.Tx) error {
		req, cid, err := authorizationTx(ctx, tx, rh)
		if err != nil {
			return err
		}
		if !hmac.Equal(req.BrowserHash, bh) {
			return oidc.ErrInvalidRequest
		}
		session, err := requireSession(ctx, tx, sh, false, false, false)
		if errors.Is(err, identity.ErrSession) || errors.Is(err, identity.ErrForbidden) {
			return oidc.ErrLoginRequired
		}
		if err != nil {
			return err
		}
		if !oidc.SubjectMatches(req, session.User.ID) {
			return oidc.ErrAccessDenied
		}
		if allow {
			_, err = tx.ExecContext(ctx, `UPDATE authorization_requests SET consent_session_id=$2::uuid WHERE request_hash=$1`, rh, session.ID)
		} else {
			_, err = tx.ExecContext(ctx, `DELETE FROM authorization_requests WHERE request_hash=$1`, rh)
		}
		if err != nil {
			return err
		}
		event := "authorization.consent_denied"
		if allow {
			event = "authorization.consent_granted"
		}
		return audit(ctx, tx, event, session.User.ID, "client", cid, a)
	})
}

func permissionSet(values []string) map[string]bool {
	m := make(map[string]bool, len(values))
	for _, v := range values {
		m[v] = true
	}
	return m
}
func hasMFA(values []string) bool { m := permissionSet(values); return m["otp"] || m["recovery"] }
func meetsACRDB(values []string, required string) bool {
	switch required {
	case "":
		return true
	case oidc.ACRPassword:
		return permissionSet(values)["pwd"]
	case oidc.ACRMFA:
		return permissionSet(values)["pwd"] && hasMFA(values)
	default:
		return false
	}
}
func knownIdentityScope(v string) bool {
	switch v {
	case "openid", "profile", "email", "groups", "roles", "offline_access":
		return true
	}
	return false
}
func clientAllows(c oidc.Client, scopes []string) bool {
	ids, perms := permissionSet(c.IdentityScopes), permissionSet(c.Permissions)
	for _, v := range scopes {
		if knownIdentityScope(v) {
			if !ids[v] {
				return false
			}
		} else if !perms[v] {
			return false
		}
	}
	return true
}
func subjectAllows(subject oidc.Subject, scopes []string) bool {
	perms := permissionSet(subject.Permissions)
	for _, v := range scopes {
		if !knownIdentityScope(v) && !perms[v] {
			return false
		}
	}
	return true
}

func grantedScopes(subject oidc.Subject, requested []string) []string {
	perms := permissionSet(subject.Permissions)
	granted := make([]string, 0, len(requested))
	for _, scope := range requested {
		if knownIdentityScope(scope) || perms[scope] {
			granted = append(granted, scope)
		}
	}
	return granted
}

func subjectByUserID(ctx context.Context, tx *sql.Tx, userID string) (oidc.Subject, error) {
	var out oidc.Subject
	var roles, permissions string
	err := tx.QueryRowContext(ctx, `SELECT u.id::text,u.username,u.display_name,COALESCE(u.email,''),u.email_verified,u.enabled,
 COALESCE((SELECT json_agg(r.name ORDER BY r.name) FROM roles r WHERE r.id IN
   (SELECT ur.role_id FROM user_roles ur WHERE ur.user_id=u.id UNION SELECT gr.role_id FROM user_groups ug JOIN group_roles gr ON gr.group_id=ug.group_id WHERE ug.user_id=u.id)),'[]'::json)::text,
 COALESCE((SELECT json_agg(x.name ORDER BY x.name) FROM (SELECT DISTINCT p.name FROM roles r JOIN role_permissions rp ON rp.role_id=r.id JOIN permissions p ON p.id=rp.permission_id
   WHERE r.id IN (SELECT ur.role_id FROM user_roles ur WHERE ur.user_id=u.id UNION SELECT gr.role_id FROM user_groups ug JOIN group_roles gr ON gr.group_id=ug.group_id WHERE ug.user_id=u.id)) x),'[]'::json)::text
 FROM users u WHERE u.id=$1::uuid AND u.enabled AND NOT u.force_password_change AND u.deleted_at IS NULL`, userID).Scan(&out.ID, &out.Username, &out.DisplayName, &out.Email, &out.EmailVerified, &out.Enabled, &roles, &permissions)
	if errors.Is(err, sql.ErrNoRows) {
		return out, oidc.ErrAccessDenied
	}
	if err != nil {
		return out, err
	}
	if out.Roles, err = decodeList(roles); err != nil {
		return out, err
	}
	out.Permissions, err = decodeList(permissions)
	return out, err
}

func subjectFromSession(sess identity.Session) oidc.Subject {
	return oidc.Subject{ID: sess.User.ID, SessionID: sess.ID, Username: sess.User.Username, DisplayName: sess.User.DisplayName, Email: sess.User.Email, EmailVerified: sess.User.EmailVerified, Enabled: sess.User.Enabled, Roles: append([]string(nil), sess.Roles...), Permissions: append([]string(nil), sess.Permissions...), AuthTime: sess.AuthTime, AuthMethods: append([]string(nil), sess.AuthMethods...)}
}

func (s *OIDCStore) IssueAuthorizationCode(ctx context.Context, requestHash, browserHash, sessionHash, codeHash []byte, expires time.Time) (out oidc.CodeGrant, err error) {
	err = s.grantWrite(ctx, func(tx *sql.Tx) error {
		req, cid, e := authorizationTx(ctx, tx, requestHash)
		if e != nil {
			return e
		}
		if !hmac.Equal(req.BrowserHash, browserHash) {
			return oidc.ErrInvalidRequest
		}
		client, e := clientByDBID(ctx, tx, cid)
		if e != nil {
			return e
		}
		if !client.Enabled || !containsString(client.RedirectURIs, req.RedirectURI) {
			return oidc.ErrInvalidRequest
		}
		sess, e := requireSession(ctx, tx, sessionHash, false, false, false)
		if errors.Is(e, identity.ErrSession) || errors.Is(e, identity.ErrForbidden) {
			return oidc.ErrLoginRequired
		}
		if e != nil {
			return e
		}
		now := time.Now().UTC()
		if !oidc.AuthenticationFresh(req, sess.AuthTime, now) || !oidc.SubjectMatches(req, sess.User.ID) {
			return oidc.ErrLoginRequired
		}
		if !meetsACRDB(sess.AuthMethods, req.RequiredACR) || (client.RequireMFA && !meetsACRDB(sess.AuthMethods, oidc.ACRMFA)) {
			return oidc.ErrUnmetAuthn
		}
		if oidc.ConsentNeeded(req, sess.ID) {
			return oidc.ErrConsentRequired
		}
		subject := subjectFromSession(sess)
		subject.ACR = oidc.ResultACR(req, sess.AuthMethods)
		if !clientAllows(client, req.Scopes) || (!client.DynamicRegistration && !subjectAllows(subject, req.Scopes)) || !oidc.ClientAllowsClaims(client, req.Claims) {
			return oidc.ErrAccessDenied
		}
		issuedScopes := req.Scopes
		if client.DynamicRegistration {
			issuedScopes = grantedScopes(subject, req.Scopes)
		}
		if !expires.After(now) || expires.After(now.Add(time.Minute)) {
			return oidc.ErrInvalidRequest
		}
		_, e = tx.ExecContext(ctx, `INSERT INTO authorization_codes(code_hash,client_id,user_id,redirect_uri,scopes,nonce,code_challenge,auth_time,auth_methods,expires_at,session_id,acr,claims)
 VALUES($1,$2::uuid,$3::uuid,$4,ARRAY(SELECT jsonb_array_elements_text($5::jsonb)),NULLIF($6,''),$7,$8,ARRAY(SELECT jsonb_array_elements_text($9::jsonb)),$10,$11::uuid,$12,$13::jsonb)`, codeHash, client.ID, subject.ID, req.RedirectURI, listJSON(issuedScopes), req.Nonce, req.CodeChallenge, sess.AuthTime, listJSON(sess.AuthMethods), expires, sess.ID, subject.ACR, claimsJSON(req.Claims))
		if e != nil {
			return e
		}
		if req.ConsentSessionID == sess.ID {
			if e = saveConsentApprovalTx(ctx, tx, subject.ID, client.ID, req); e != nil {
				return e
			}
		}
		if _, e = tx.ExecContext(ctx, `DELETE FROM authorization_requests WHERE request_hash=$1`, requestHash); e != nil {
			return e
		}
		out = oidc.CodeGrant{Claims: req.Claims, Client: client, Subject: subject, RedirectURI: req.RedirectURI, Scopes: issuedScopes, Nonce: req.Nonce}
		return nil
	})
	return
}
func containsString(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

func subsetStrings(a, b []string) bool {
	set := permissionSet(b)
	for _, v := range a {
		if !set[v] {
			return false
		}
	}
	return true
}

func (s *OIDCStore) RevokeRefreshToken(ctx context.Context, tokenHash []byte, proof oidc.Client, a identity.Audit) error {
	return s.grantWrite(ctx, func(tx *sql.Tx) error {
		client, err := authenticatedClient(ctx, tx, proof.ID, proof)
		if err != nil {
			return err
		}
		var family, user string
		var revoked *time.Time
		err = tx.QueryRowContext(ctx, `SELECT f.id::text,f.user_id::text,f.revoked_at FROM refresh_token_families f JOIN refresh_tokens t ON t.family_id=f.id WHERE t.token_hash=$1 AND f.client_id=$2::uuid FOR UPDATE OF f`, tokenHash, client.ID).Scan(&family, &user, &revoked)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if revoked != nil {
			return nil
		}
		if _, err = tx.ExecContext(ctx, `UPDATE refresh_token_families SET revoked_at=clock_timestamp(),revoke_reason='revoked' WHERE id=$1::uuid`, family); err != nil {
			return err
		}
		return audit(ctx, tx, "token.revoked", user, "refresh_family", family, a)
	})
}

func (s *OIDCStore) SigningKeys(ctx context.Context) (out []oidc.SigningKey, err error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT id::text,kid,algorithm,''::bytea,public_jwk::text,active,created_at,retired_at FROM signing_keys ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var k oidc.SigningKey
		var jwkText string
		if err = rows.Scan(&k.ID, &k.KID, &k.Algorithm, &k.Ciphertext, &jwkText, &k.Active, &k.CreatedAt, &k.RetiredAt); err != nil {
			return nil, err
		}
		k.PublicJWK = []byte(jwkText)
		out = append(out, k)
	}
	return out, rows.Err()
}
func (s *OIDCStore) ActiveSigningKey(ctx context.Context) (oidc.SigningKey, error) {
	var k oidc.SigningKey
	var jwkText string
	err := s.DB.QueryRowContext(ctx, `SELECT id::text,kid,algorithm,private_key_ciphertext,public_jwk::text,active,created_at,retired_at FROM signing_keys WHERE active`).Scan(&k.ID, &k.KID, &k.Algorithm, &k.Ciphertext, &jwkText, &k.Active, &k.CreatedAt, &k.RetiredAt)
	if errors.Is(err, sql.ErrNoRows) {
		return k, oidc.ErrSigningKeyNotFound
	}
	k.PublicJWK = []byte(jwkText)
	return k, err
}
func (s *OIDCStore) SigningKey(ctx context.Context, kid string) (oidc.SigningKey, error) {
	var k oidc.SigningKey
	var jwkText string
	err := s.DB.QueryRowContext(ctx, `SELECT id::text,kid,algorithm,''::bytea,public_jwk::text,active,created_at,retired_at FROM signing_keys WHERE kid=$1`, kid).Scan(&k.ID, &k.KID, &k.Algorithm, &k.Ciphertext, &jwkText, &k.Active, &k.CreatedAt, &k.RetiredAt)
	if errors.Is(err, sql.ErrNoRows) {
		return k, oidc.ErrSigningKeyNotFound
	}
	k.PublicJWK = []byte(jwkText)
	return k, err
}
func installSigningKeyTx(ctx context.Context, tx *sql.Tx, key oidc.SigningKey, rotate bool, actor string, a identity.Audit) (oidc.SigningKey, error) {
	existing, existingErr := scanSigningText(tx.QueryRowContext(ctx, `SELECT id::text,kid,algorithm,private_key_ciphertext,public_jwk::text,active,created_at,retired_at FROM signing_keys WHERE active`))
	if existingErr == nil && !rotate {
		return existing, nil
	}
	if existingErr != nil && !errors.Is(existingErr, sql.ErrNoRows) {
		return oidc.SigningKey{}, existingErr
	}
	hadActive := existingErr == nil
	if rotate && hadActive {
		if _, e := tx.ExecContext(ctx, `UPDATE signing_keys SET active=false,retired_at=COALESCE(retired_at,now()),private_key_ciphertext=''::bytea WHERE id=$1::uuid AND active`, existing.ID); e != nil {
			return oidc.SigningKey{}, e
		}
		if e := audit(ctx, tx, "signing_key.retired", actor, "signing_key", existing.ID, a); e != nil {
			return oidc.SigningKey{}, e
		}
	}
	var jwk any
	if e := json.Unmarshal(key.PublicJWK, &jwk); e != nil {
		return oidc.SigningKey{}, e
	}
	raw, _ := json.Marshal(jwk)
	if e := tx.QueryRowContext(ctx, `INSERT INTO signing_keys(kid,algorithm,private_key_ciphertext,public_jwk,active) VALUES($1,'RS256',$2,$3::jsonb,true) RETURNING id::text,created_at`, key.KID, key.Ciphertext, string(raw)).Scan(&key.ID, &key.CreatedAt); e != nil {
		return oidc.SigningKey{}, e
	}
	key.Active = true
	event := "signing_key.created"
	if rotate && hadActive {
		event = "signing_key.rotated"
	}
	if e := audit(ctx, tx, event, actor, "signing_key", key.ID, a); e != nil {
		return oidc.SigningKey{}, e
	}
	return key, nil
}

func (s *OIDCStore) InstallSigningKey(ctx context.Context, key oidc.SigningKey, rotate bool) (out oidc.SigningKey, err error) {
	err = (&IdentityStore{DB: s.DB}).write(ctx, func(tx *sql.Tx) error {
		var e error
		out, e = installSigningKeyTx(ctx, tx, key, rotate, "", identity.Audit{})
		return e
	})
	return
}

func (s *OIDCStore) AdminSigningKeys(ctx context.Context, actorHash []byte) (out []oidc.SigningKey, err error) {
	err = (&IdentityStore{DB: s.DB}).read(ctx, func(tx *sql.Tx) error {
		if _, e := requireSession(ctx, tx, actorHash, true, false, false); e != nil {
			return e
		}
		rows, e := tx.QueryContext(ctx, `SELECT id::text,kid,algorithm,private_key_ciphertext,public_jwk::text,active,created_at,retired_at FROM signing_keys ORDER BY active DESC,created_at DESC LIMIT 64`)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			key, e := scanSigningText(rows)
			if e != nil {
				return e
			}
			// Never expose private-key ciphertext to the administration layer.
			key.Ciphertext = nil
			out = append(out, key)
		}
		return rows.Err()
	})
	return
}

func (s *OIDCStore) RotateSigningKey(ctx context.Context, actorHash []byte, key oidc.SigningKey, a identity.Audit) (out oidc.SigningKey, err error) {
	err = (&IdentityStore{DB: s.DB}).write(ctx, func(tx *sql.Tx) error {
		actor, e := requireSession(ctx, tx, actorHash, true, true, false)
		if e != nil {
			return e
		}
		out, e = installSigningKeyTx(ctx, tx, key, true, actor.User.ID, a)
		return e
	})
	return
}

func scanSigningText(row scanner) (oidc.SigningKey, error) {
	var k oidc.SigningKey
	var text string
	err := row.Scan(&k.ID, &k.KID, &k.Algorithm, &k.Ciphertext, &text, &k.Active, &k.CreatedAt, &k.RetiredAt)
	k.PublicJWK = []byte(text)
	return k, err
}

func (s *OIDCStore) AdminClients(ctx context.Context, actorHash []byte) (out []oidc.Client, err error) {
	err = (&IdentityStore{DB: s.DB}).read(ctx, func(tx *sql.Tx) error {
		if _, e := requireSession(ctx, tx, actorHash, true, false, false); e != nil {
			return e
		}
		rows, e := tx.QueryContext(ctx, `SELECT `+clientColumns+` FROM clients c ORDER BY lower(c.name),c.client_id LIMIT 200`)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			c, e := scanClient(rows)
			if e != nil {
				return e
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return
}

func replaceClientSets(ctx context.Context, tx *sql.Tx, id string, edit oidc.ClientEdit) error {
	for _, table := range []string{"client_redirect_uris", "client_logout_uris", "client_identity_scopes", "client_permissions"} {
		if _, e := tx.ExecContext(ctx, `DELETE FROM `+table+` WHERE client_id=$1::uuid`, id); e != nil {
			return e
		}
	}
	for _, v := range edit.RedirectURIs {
		if _, e := tx.ExecContext(ctx, `INSERT INTO client_redirect_uris(client_id,uri) VALUES($1::uuid,$2)`, id, v); e != nil {
			return e
		}
	}
	for _, v := range edit.LogoutURIs {
		if _, e := tx.ExecContext(ctx, `INSERT INTO client_logout_uris(client_id,uri) VALUES($1::uuid,$2)`, id, v); e != nil {
			return e
		}
	}
	for _, v := range edit.IdentityScopes {
		if _, e := tx.ExecContext(ctx, `INSERT INTO client_identity_scopes(client_id,scope) VALUES($1::uuid,$2)`, id, v); e != nil {
			return e
		}
	}
	if len(edit.PermissionIDs) > 0 {
		res, e := tx.ExecContext(ctx, `INSERT INTO client_permissions(client_id,permission_id)
 SELECT $1::uuid,p.id FROM jsonb_array_elements_text($2::jsonb) j(value)
 JOIN permissions p ON p.id=j.value::uuid WHERE p.name<>'system.admin'`, id, listJSON(edit.PermissionIDs))
		if e != nil {
			return e
		}
		if n, e := res.RowsAffected(); e != nil || n != int64(len(edit.PermissionIDs)) {
			if e != nil {
				return e
			}
			return identity.ErrConflict
		}
	}
	return nil
}

func (s *OIDCStore) CreateClient(ctx context.Context, actorHash []byte, edit oidc.ClientEdit, secretHash []byte, a identity.Audit) (out oidc.Client, err error) {
	err = (&IdentityStore{DB: s.DB}).write(ctx, func(tx *sql.Tx) error {
		actor, e := requireSession(ctx, tx, actorHash, true, true, false)
		if e != nil {
			return e
		}
		if edit.Type == "public" {
			secretHash = nil
		}
		if e = tx.QueryRowContext(ctx, `INSERT INTO clients(client_id,name,client_type,client_secret_hash,enabled,require_mfa,refresh_tokens_enabled,access_token_ttl_seconds)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id::text`, edit.ClientID, edit.Name, edit.Type, secretHash, edit.Enabled, edit.RequireMFA, edit.RefreshTokensEnabled, int64(edit.AccessTokenTTL.Seconds())).Scan(&edit.ID); e != nil {
			return e
		}
		if e = replaceClientSets(ctx, tx, edit.ID, edit); e != nil {
			return e
		}
		if e = audit(ctx, tx, "client.created", actor.User.ID, "client", edit.ID, a); e != nil {
			return e
		}
		out, e = clientByDBID(ctx, tx, edit.ID)
		return e
	})
	return
}

func (s *OIDCStore) UpdateClient(ctx context.Context, actorHash []byte, edit oidc.ClientEdit, a identity.Audit) error {
	return (&IdentityStore{DB: s.DB}).write(ctx, func(tx *sql.Tx) error {
		actor, e := requireSession(ctx, tx, actorHash, true, true, false)
		if e != nil {
			return e
		}
		before, e := clientByDBID(ctx, tx, edit.ID)
		if e != nil {
			return e
		}
		if edit.ExpectedUpdatedAt.IsZero() || !before.UpdatedAt.Equal(edit.ExpectedUpdatedAt) {
			return identity.ErrConflict
		}
		if before.ClientID != edit.ClientID || before.Type != edit.Type {
			return identity.ErrConflict
		}
		res, e := tx.ExecContext(ctx, `UPDATE clients SET name=$2,enabled=$3,require_mfa=$4,refresh_tokens_enabled=$5,access_token_ttl_seconds=$6,updated_at=now() WHERE id=$1::uuid`, edit.ID, edit.Name, edit.Enabled, edit.RequireMFA, edit.RefreshTokensEnabled, int64(edit.AccessTokenTTL.Seconds()))
		if e != nil {
			return e
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return identity.ErrConflict
		}
		if e = replaceClientSets(ctx, tx, edit.ID, edit); e != nil {
			return e
		}
		if before.Enabled && !edit.Enabled || before.RefreshTokensEnabled && !edit.RefreshTokensEnabled {
			if _, e = tx.ExecContext(ctx, `UPDATE refresh_token_families SET revoked_at=COALESCE(revoked_at,now()),revoke_reason=COALESCE(revoke_reason,'client_policy_changed') WHERE client_id=$1::uuid AND revoked_at IS NULL`, edit.ID); e != nil {
				return e
			}
		} else if !before.RequireMFA && edit.RequireMFA {
			if _, e = tx.ExecContext(ctx, `UPDATE refresh_token_families SET revoked_at=COALESCE(revoked_at,now()),revoke_reason=COALESCE(revoke_reason,'client_mfa_required') WHERE client_id=$1::uuid AND revoked_at IS NULL AND NOT ('otp'=ANY(auth_methods) OR 'recovery'=ANY(auth_methods))`, edit.ID); e != nil {
				return e
			}
		}
		return audit(ctx, tx, "client.updated", actor.User.ID, "client", edit.ID, a)
	})
}

func (s *OIDCStore) RotateClientSecret(ctx context.Context, actorHash []byte, clientID string, secretHash []byte, a identity.Audit) error {
	return (&IdentityStore{DB: s.DB}).write(ctx, func(tx *sql.Tx) error {
		actor, e := requireSession(ctx, tx, actorHash, true, true, false)
		if e != nil {
			return e
		}
		res, e := tx.ExecContext(ctx, `UPDATE clients SET client_secret_hash=$2,updated_at=now() WHERE id=$1::uuid AND client_type='confidential'`, clientID, secretHash)
		if e != nil {
			return e
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return identity.ErrConflict
		}
		return audit(ctx, tx, "client.secret_rotated", actor.User.ID, "client", clientID, a)
	})
}

func (s *OIDCStore) DeleteClient(ctx context.Context, actorHash []byte, clientID string, a identity.Audit) error {
	return (&IdentityStore{DB: s.DB}).write(ctx, func(tx *sql.Tx) error {
		actor, e := requireSession(ctx, tx, actorHash, true, true, false)
		if e != nil {
			return e
		}
		var exists string
		if e = tx.QueryRowContext(ctx, `SELECT client_id FROM clients WHERE id=$1::uuid FOR UPDATE`, clientID).Scan(&exists); e != nil {
			if errors.Is(e, sql.ErrNoRows) {
				return identity.ErrConflict
			}
			return e
		}
		// The clients row owns every durable authorization continuation, code,
		// refresh family, redirect/scopes set, and secret through foreign keys.
		// Deleting it therefore makes all future grants impossible atomically.
		res, e := tx.ExecContext(ctx, `DELETE FROM clients WHERE id=$1::uuid`, clientID)
		if e != nil {
			return e
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return identity.ErrConflict
		}
		return audit(ctx, tx, "client.deleted", actor.User.ID, "client", clientID, a)
	})
}

func claimsJSON(v oidc.ClaimSelection) string { b, _ := json.Marshal(v); return string(b) }
