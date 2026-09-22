package db

import (
	"context"
	"crypto/hmac"
	"database/sql"
	"encoding/json"
	"errors"
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
	err := row.Scan(&c.ID, &c.ClientID, &c.Name, &c.Type, &c.SecretHash, &c.Enabled, &c.RequireMFA, &c.RefreshTokensEnabled, &ttl, &redirects, &logouts, &identityScopes, &permissionIDs, &permissions)
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

const clientColumns = `c.id::text,c.client_id,c.name,c.client_type,c.client_secret_hash,c.enabled,c.require_mfa,c.refresh_tokens_enabled,c.access_token_ttl_seconds,
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

func (s *OIDCStore) PublicClientRedirectURIs(ctx context.Context) ([]string, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT r.uri FROM client_redirect_uris r JOIN clients c ON c.id=r.client_id WHERE c.enabled AND c.client_type='public' ORDER BY r.uri LIMIT 4096`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var uri string
		if err = rows.Scan(&uri); err != nil {
			return nil, err
		}
		out = append(out, uri)
	}
	return out, rows.Err()
}

func clientByDBID(ctx context.Context, tx *sql.Tx, id string) (oidc.Client, error) {
	c, err := scanClient(tx.QueryRowContext(ctx, `SELECT `+clientColumns+` FROM clients c WHERE c.id=$1::uuid`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return c, oidc.ErrInvalidClient
	}
	return c, err
}

func (s *OIDCStore) CreateAuthorizationRequest(ctx context.Context, hash []byte, req oidc.AuthorizationRequest) error {
	res, err := s.DB.ExecContext(ctx, `INSERT INTO authorization_requests(request_hash,client_id,redirect_uri,scopes,state,nonce,code_challenge,login_hint,prompt,min_auth_time,created_at,expires_at)
 SELECT $1,c.id,$3,ARRAY(SELECT jsonb_array_elements_text($4::jsonb)),NULLIF($5,''),NULLIF($6,''),$7,NULLIF($8,''),$9,$10,$11,$12
 FROM clients c WHERE c.client_id=$2 AND c.enabled`, hash, req.ClientID, req.RedirectURI, listJSON(req.Scopes), req.State, req.Nonce, req.CodeChallenge, req.LoginHint, req.Prompt, req.MinAuthTime, req.CreatedAt, req.ExpiresAt)
	if err != nil {
		return dbError(err)
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

func scanAuthorization(row scanner) (oidc.AuthorizationRequest, string, error) {
	var req oidc.AuthorizationRequest
	var clientDBID, scopes string
	err := row.Scan(&clientDBID, &req.ClientID, &req.RedirectURI, &scopes, &req.State, &req.Nonce, &req.CodeChallenge, &req.LoginHint, &req.Prompt, &req.MinAuthTime, &req.CreatedAt, &req.ExpiresAt)
	if err != nil {
		return req, "", err
	}
	req.Scopes, err = decodeList(scopes)
	return req, clientDBID, err
}

func (s *OIDCStore) AuthorizationRequest(ctx context.Context, hash []byte) (oidc.AuthorizationRequest, oidc.Client, error) {
	req, dbid, err := scanAuthorization(s.DB.QueryRowContext(ctx, `SELECT ar.client_id::text,c.client_id,ar.redirect_uri,array_to_json(ar.scopes)::text,COALESCE(ar.state,''),COALESCE(ar.nonce,''),ar.code_challenge,COALESCE(ar.login_hint,''),ar.prompt,ar.min_auth_time,ar.created_at,ar.expires_at
 FROM authorization_requests ar JOIN clients c ON c.id=ar.client_id WHERE ar.request_hash=$1`, hash))
	if errors.Is(err, sql.ErrNoRows) {
		return req, oidc.Client{}, oidc.ErrInvalidRequest
	}
	if err != nil {
		return req, oidc.Client{}, err
	}
	// Avoid a large join in the request lookup; the client row is separately authoritative.
	client, err := s.Client(ctx, req.ClientID)
	_ = dbid
	return req, client, err
}

func permissionSet(values []string) map[string]bool {
	m := make(map[string]bool, len(values))
	for _, v := range values {
		m[v] = true
	}
	return m
}
func hasMFA(values []string) bool { m := permissionSet(values); return m["otp"] || m["recovery"] }
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

func subjectByUserID(ctx context.Context, tx *sql.Tx, userID string) (oidc.Subject, error) {
	var out oidc.Subject
	var roles, permissions string
	err := tx.QueryRowContext(ctx, `SELECT u.id::text,u.username,u.display_name,COALESCE(u.email,''),u.email_verified,u.enabled,
 COALESCE((SELECT json_agg(r.name ORDER BY r.name) FROM user_roles ur JOIN roles r ON r.id=ur.role_id WHERE ur.user_id=u.id),'[]'::json)::text,
 COALESCE((SELECT json_agg(x.name ORDER BY x.name) FROM (SELECT DISTINCT p.name FROM user_roles ur JOIN role_permissions rp ON rp.role_id=ur.role_id JOIN permissions p ON p.id=rp.permission_id WHERE ur.user_id=u.id) x),'[]'::json)::text
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
	return oidc.Subject{ID: sess.User.ID, Username: sess.User.Username, DisplayName: sess.User.DisplayName, Email: sess.User.Email, EmailVerified: sess.User.EmailVerified, Enabled: sess.User.Enabled, Roles: append([]string(nil), sess.Roles...), Permissions: append([]string(nil), sess.Permissions...), AuthTime: sess.AuthTime, AuthMethods: append([]string(nil), sess.AuthMethods...)}
}

func (s *OIDCStore) IssueAuthorizationCode(ctx context.Context, requestHash, sessionHash, codeHash []byte, expires time.Time) (out oidc.CodeGrant, err error) {
	err = (&IdentityStore{DB: s.DB}).write(ctx, func(tx *sql.Tx) error {
		req, clientDBID, e := scanAuthorization(tx.QueryRowContext(ctx, `SELECT ar.client_id::text,c.client_id,ar.redirect_uri,array_to_json(ar.scopes)::text,COALESCE(ar.state,''),COALESCE(ar.nonce,''),ar.code_challenge,COALESCE(ar.login_hint,''),ar.prompt,ar.min_auth_time,ar.created_at,ar.expires_at
 FROM authorization_requests ar JOIN clients c ON c.id=ar.client_id WHERE ar.request_hash=$1 AND ar.expires_at>now() FOR UPDATE OF ar`, requestHash))
		if errors.Is(e, sql.ErrNoRows) {
			return oidc.ErrInvalidRequest
		}
		if e != nil {
			return e
		}
		client, e := clientByDBID(ctx, tx, clientDBID)
		if e != nil || !client.Enabled {
			return oidc.ErrInvalidClient
		}
		sess, e := requireSession(ctx, tx, sessionHash, false, false, false)
		if e != nil {
			return oidc.ErrLoginRequired
		}
		if req.MinAuthTime != nil && sess.AuthTime.Before(*req.MinAuthTime) {
			return oidc.ErrLoginRequired
		}
		if client.RequireMFA && !hasMFA(sess.AuthMethods) {
			return oidc.ErrAccessDenied
		}
		subject := subjectFromSession(sess)
		if !clientAllows(client, req.Scopes) || !subjectAllows(subject, req.Scopes) {
			return oidc.ErrAccessDenied
		}
		_, e = tx.ExecContext(ctx, `INSERT INTO authorization_codes(code_hash,client_id,user_id,redirect_uri,scopes,nonce,code_challenge,auth_time,auth_methods,expires_at)
 VALUES($1,$2::uuid,$3::uuid,$4,ARRAY(SELECT jsonb_array_elements_text($5::jsonb)),NULLIF($6,''),$7,$8,ARRAY(SELECT jsonb_array_elements_text($9::jsonb)),$10)`, codeHash, client.ID, subject.ID, req.RedirectURI, listJSON(req.Scopes), req.Nonce, req.CodeChallenge, sess.AuthTime, listJSON(sess.AuthMethods), expires)
		if e != nil {
			return e
		}
		if _, e = tx.ExecContext(ctx, `DELETE FROM authorization_requests WHERE request_hash=$1`, requestHash); e != nil {
			return e
		}
		out = oidc.CodeGrant{Client: client, Subject: subject, RedirectURI: req.RedirectURI, Scopes: req.Scopes, Nonce: req.Nonce}
		return nil
	})
	return
}

func (s *OIDCStore) ConsumeAuthorizationCode(ctx context.Context, codeHash []byte, clientID, redirectURI, challenge string, now time.Time) (out oidc.CodeGrant, err error) {
	err = (&IdentityStore{DB: s.DB}).write(ctx, func(tx *sql.Tx) error {
		var clientDBID, userID, redirect, scopes, nonce, storedChallenge, methods string
		var authTime, expires time.Time
		var consumed *time.Time
		e := tx.QueryRowContext(ctx, `SELECT client_id::text,user_id::text,redirect_uri,array_to_json(scopes)::text,COALESCE(nonce,''),code_challenge,auth_time,array_to_json(auth_methods)::text,expires_at,consumed_at
 FROM authorization_codes WHERE code_hash=$1 FOR UPDATE`, codeHash).Scan(&clientDBID, &userID, &redirect, &scopes, &nonce, &storedChallenge, &authTime, &methods, &expires, &consumed)
		if errors.Is(e, sql.ErrNoRows) {
			return oidc.ErrInvalidGrant
		}
		if e != nil {
			return e
		}
		client, e := clientByDBID(ctx, tx, clientDBID)
		if e != nil || !client.Enabled || client.ClientID != clientID {
			return oidc.ErrInvalidGrant
		}
		if consumed != nil || !now.Before(expires) || redirect != redirectURI || !hmac.Equal([]byte(storedChallenge), []byte(challenge)) {
			return oidc.ErrInvalidGrant
		}
		var scopeList, methodList []string
		if scopeList, e = decodeList(scopes); e != nil {
			return e
		}
		if methodList, e = decodeList(methods); e != nil {
			return e
		}
		subject, e := subjectByUserID(ctx, tx, userID)
		if e != nil {
			return oidc.ErrInvalidGrant
		}
		subject.AuthTime = authTime
		subject.AuthMethods = methodList
		if client.RequireMFA && !hasMFA(methodList) {
			return oidc.ErrInvalidGrant
		}
		if !clientAllows(client, scopeList) || !subjectAllows(subject, scopeList) {
			return oidc.ErrInvalidGrant
		}
		res, e := tx.ExecContext(ctx, `UPDATE authorization_codes SET consumed_at=$2 WHERE code_hash=$1 AND consumed_at IS NULL`, codeHash, now)
		if e != nil {
			return e
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return oidc.ErrInvalidGrant
		}
		out = oidc.CodeGrant{Client: client, Subject: subject, RedirectURI: redirect, Scopes: scopeList, Nonce: nonce}
		return nil
	})
	return
}

func (s *OIDCStore) CreateRefreshFamily(ctx context.Context, userID, clientDBID string, scopes []string, authTime time.Time, authMethods []string, tokenHash []byte, idleExpires, absoluteExpires time.Time) error {
	return (&IdentityStore{DB: s.DB}).write(ctx, func(tx *sql.Tx) error {
		var family string
		if e := tx.QueryRowContext(ctx, `INSERT INTO refresh_token_families(user_id,client_id,scopes,absolute_expires_at,auth_time,auth_methods)
 VALUES($1::uuid,$2::uuid,ARRAY(SELECT jsonb_array_elements_text($3::jsonb)),$4,$5,ARRAY(SELECT jsonb_array_elements_text($6::jsonb))) RETURNING id::text`, userID, clientDBID, listJSON(scopes), absoluteExpires, authTime, listJSON(authMethods)).Scan(&family); e != nil {
			return e
		}
		_, e := tx.ExecContext(ctx, `INSERT INTO refresh_tokens(token_hash,family_id,idle_expires_at,scopes) VALUES($1,$2::uuid,LEAST($3,$4),ARRAY(SELECT jsonb_array_elements_text($5::jsonb)))`, tokenHash, family, idleExpires, absoluteExpires, listJSON(scopes))
		return e
	})
}

func (s *OIDCStore) RotateRefreshToken(ctx context.Context, tokenHash, replacementHash []byte, clientID string, requested []string, now, idleExpires time.Time, a identity.Audit) (out oidc.RefreshGrant, retErr error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, identityLock); err != nil {
		return out, err
	}
	var familyID, userID, clientDBID, familyScopes, tokenScopes, authMethods string
	var absExpires, tokenIdle, authTime time.Time
	var familyRevoked, consumed *time.Time
	err = tx.QueryRowContext(ctx, `SELECT f.id::text,f.user_id::text,f.client_id::text,array_to_json(f.scopes)::text,array_to_json(rt.scopes)::text,f.absolute_expires_at,f.revoked_at,rt.idle_expires_at,rt.consumed_at,f.auth_time,array_to_json(f.auth_methods)::text
 FROM refresh_tokens rt JOIN refresh_token_families f ON f.id=rt.family_id WHERE rt.token_hash=$1 FOR UPDATE OF rt,f`, tokenHash).Scan(&familyID, &userID, &clientDBID, &familyScopes, &tokenScopes, &absExpires, &familyRevoked, &tokenIdle, &consumed, &authTime, &authMethods)
	if errors.Is(err, sql.ErrNoRows) {
		return out, oidc.ErrInvalidGrant
	}
	if err != nil {
		return out, err
	}
	if consumed != nil {
		if familyRevoked == nil {
			if _, err = tx.ExecContext(ctx, `UPDATE refresh_token_families SET revoked_at=$2,revoke_reason='reuse' WHERE id=$1::uuid AND revoked_at IS NULL`, familyID, now); err != nil {
				return out, err
			}
			if err = audit(ctx, tx, "token.refresh_reuse_detected", userID, "refresh_family", familyID, a); err != nil {
				return out, err
			}
		}
		if err = tx.Commit(); err != nil {
			return out, err
		}
		return out, oidc.ErrRefreshReuse
	}
	if familyRevoked != nil || !now.Before(absExpires) || !now.Before(tokenIdle) {
		return out, oidc.ErrInvalidGrant
	}
	client, err := clientByDBID(ctx, tx, clientDBID)
	if err != nil || !client.Enabled || client.ClientID != clientID || !client.RefreshTokensEnabled {
		return out, oidc.ErrInvalidGrant
	}
	var scopes, original, methods []string
	if scopes, err = decodeList(tokenScopes); err != nil {
		return out, err
	}
	if original, err = decodeList(familyScopes); err != nil {
		return out, err
	}
	_ = original
	if methods, err = decodeList(authMethods); err != nil {
		return out, err
	}
	if len(requested) > 0 {
		if !subsetStrings(requested, scopes) {
			return out, oidc.ErrInvalidScope
		}
		scopes = requested
	}
	subject, err := subjectByUserID(ctx, tx, userID)
	if err != nil {
		return out, oidc.ErrInvalidGrant
	}
	subject.AuthTime = authTime
	subject.AuthMethods = methods
	if client.RequireMFA && !hasMFA(methods) {
		return out, oidc.ErrInvalidGrant
	}
	if !clientAllows(client, scopes) || !subjectAllows(subject, scopes) {
		return out, oidc.ErrInvalidGrant
	}
	res, err := tx.ExecContext(ctx, `UPDATE refresh_tokens SET consumed_at=$2,replacement_hash=$3 WHERE token_hash=$1 AND consumed_at IS NULL`, tokenHash, now, replacementHash)
	if err != nil {
		return out, err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return out, oidc.ErrInvalidGrant
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO refresh_tokens(token_hash,family_id,idle_expires_at,scopes) VALUES($1,$2::uuid,LEAST($3,$4),ARRAY(SELECT jsonb_array_elements_text($5::jsonb)))`, replacementHash, familyID, idleExpires, absExpires, listJSON(scopes)); err != nil {
		return out, err
	}
	if err = audit(ctx, tx, "token.refresh", userID, "refresh_family", familyID, a); err != nil {
		return out, err
	}
	if err = tx.Commit(); err != nil {
		return out, err
	}
	out = oidc.RefreshGrant{FamilyID: familyID, Client: client, Subject: subject, Scopes: scopes}
	return out, nil
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

func (s *OIDCStore) RevokeRefreshToken(ctx context.Context, tokenHash []byte, clientID string, a identity.Audit) error {
	return (&IdentityStore{DB: s.DB}).write(ctx, func(tx *sql.Tx) error {
		var familyID, userID string
		err := tx.QueryRowContext(ctx, `UPDATE refresh_token_families f
 SET revoked_at=now(),revoke_reason='revoked'
 FROM refresh_tokens rt, clients c
 WHERE rt.family_id=f.id AND c.id=f.client_id AND rt.token_hash=$1 AND c.client_id=$2 AND f.revoked_at IS NULL
 RETURNING f.id::text,f.user_id::text`, tokenHash, clientID).Scan(&familyID, &userID)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		return audit(ctx, tx, "token.revoked", userID, "refresh_family", familyID, a)
	})
}

func (s *OIDCStore) SigningKeys(ctx context.Context) (out []oidc.SigningKey, err error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT id::text,kid,algorithm,private_key_ciphertext,public_jwk::text,active,created_at,retired_at FROM signing_keys ORDER BY created_at DESC`)
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
	err := s.DB.QueryRowContext(ctx, `SELECT id::text,kid,algorithm,private_key_ciphertext,public_jwk::text,active,created_at,retired_at FROM signing_keys WHERE kid=$1`, kid).Scan(&k.ID, &k.KID, &k.Algorithm, &k.Ciphertext, &jwkText, &k.Active, &k.CreatedAt, &k.RetiredAt)
	if errors.Is(err, sql.ErrNoRows) {
		return k, oidc.ErrSigningKeyNotFound
	}
	k.PublicJWK = []byte(jwkText)
	return k, err
}
func (s *OIDCStore) InstallSigningKey(ctx context.Context, key oidc.SigningKey, rotate bool) (out oidc.SigningKey, err error) {
	err = (&IdentityStore{DB: s.DB}).write(ctx, func(tx *sql.Tx) error {
		existing, existingErr := scanSigningText(tx.QueryRowContext(ctx, `SELECT id::text,kid,algorithm,private_key_ciphertext,public_jwk::text,active,created_at,retired_at FROM signing_keys WHERE active`))
		if existingErr == nil && !rotate {
			out = existing
			return nil
		}
		if existingErr != nil && !errors.Is(existingErr, sql.ErrNoRows) {
			return existingErr
		}
		hadActive := existingErr == nil
		if rotate && hadActive {
			if _, e := tx.ExecContext(ctx, `UPDATE signing_keys SET active=false,retired_at=COALESCE(retired_at,now()),private_key_ciphertext=''::bytea WHERE id=$1::uuid AND active`, existing.ID); e != nil {
				return e
			}
			if e := audit(ctx, tx, "signing_key.retired", "", "signing_key", existing.ID, identity.Audit{}); e != nil {
				return e
			}
		}
		var jwk any
		if e := json.Unmarshal(key.PublicJWK, &jwk); e != nil {
			return e
		}
		raw, _ := json.Marshal(jwk)
		if e := tx.QueryRowContext(ctx, `INSERT INTO signing_keys(kid,algorithm,private_key_ciphertext,public_jwk,active) VALUES($1,'RS256',$2,$3::jsonb,true) RETURNING id::text,created_at`, key.KID, key.Ciphertext, string(raw)).Scan(&key.ID, &key.CreatedAt); e != nil {
			return e
		}
		key.Active = true
		out = key
		event := "signing_key.created"
		if rotate && hadActive {
			event = "signing_key.rotated"
		}
		return audit(ctx, tx, event, "", "signing_key", key.ID, identity.Audit{})
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
	err = (&IdentityStore{DB: s.DB}).write(ctx, func(tx *sql.Tx) error {
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
