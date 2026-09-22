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

// grantWrite admits unrelated grants concurrently. Identity/client/key mutations
// take the EXCLUSIVE form of this lock; grants take the SHARED form, then lock
// their own code or token family. No KDF or network call belongs in this transaction.
// Lock order: identity gate -> request/code/family -> member token.
func (s *OIDCStore) grantWrite(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock_shared($1)`, identityLock); err != nil {
		return err
	}
	outcome := fn(tx)
	if outcome != nil && !errors.Is(outcome, oidc.ErrRefreshReuse) && !errors.Is(outcome, oidc.ErrCodeReuse) {
		return outcome
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	return outcome
}

// Client authentication outside the transaction is not sufficient: a secret can
// be rotated between that read and redemption. Compare the authenticated proof
// to current state while identity/client administration is excluded.
func authenticatedClient(ctx context.Context, tx *sql.Tx, id string, proof oidc.Client) (oidc.Client, error) {
	c, err := clientByDBID(ctx, tx, id)
	if err != nil {
		return c, err
	}
	if c.ID != proof.ID || c.ClientID != proof.ClientID {
		return c, oidc.ErrInvalidGrant
	}
	if !c.Enabled || c.Type != proof.Type ||
		(c.Type == "confidential" && !hmac.Equal(c.SecretHash, proof.SecretHash)) {
		return c, oidc.ErrInvalidClient
	}
	return c, nil
}
func activeKeyTx(ctx context.Context, tx *sql.Tx) (oidc.SigningKey, error) {
	key, err := scanSigningText(tx.QueryRowContext(ctx, `SELECT id::text,kid,algorithm,private_key_ciphertext,public_jwk::text,active,created_at,retired_at FROM signing_keys WHERE active`))
	if errors.Is(err, sql.ErrNoRows) {
		return key, oidc.ErrSigningKeyNotFound
	}
	return key, err
}
func rejectMissingSubject(err error) error {
	if errors.Is(err, oidc.ErrAccessDenied) {
		return oidc.ErrInvalidGrant
	}
	return err
}
func createRefreshFamilyTx(ctx context.Context, tx *sql.Tx, grant oidc.CodeGrant, material oidc.TokenMaterial) (string, error) {
	var family string
	err := tx.QueryRowContext(ctx, `INSERT INTO refresh_token_families(user_id,client_id,session_id,scopes,absolute_expires_at,auth_time,auth_methods,acr,claims)
 VALUES($1::uuid,$2::uuid,NULLIF($3,'')::uuid,ARRAY(SELECT jsonb_array_elements_text($4::jsonb)),$5,$6,ARRAY(SELECT jsonb_array_elements_text($7::jsonb)),$8,$9::jsonb) RETURNING id::text`,
		grant.Subject.ID, grant.Client.ID, grant.Subject.SessionID, listJSON(grant.Scopes), material.AbsoluteExpiresAt, grant.Subject.AuthTime, listJSON(grant.Subject.AuthMethods), grant.Subject.ACR, claimsJSON(grant.Claims)).Scan(&family)
	if err != nil {
		return "", err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO refresh_tokens(token_hash,family_id,idle_expires_at,scopes) VALUES($1,$2::uuid,LEAST($3::timestamptz,$4::timestamptz),ARRAY(SELECT jsonb_array_elements_text($5::jsonb)))`, material.RefreshHash, family, material.IdleExpiresAt, material.AbsoluteExpiresAt, listJSON(grant.Scopes))
	return family, err
}

func (s *OIDCStore) RedeemCode(ctx context.Context, proof oidc.Client, hash []byte, redirectURI, challenge string, now time.Time, a identity.Audit, issue oidc.TokenIssuer) (response oidc.TokenResponse, err error) {
	err = s.grantWrite(ctx, func(tx *sql.Tx) error {
		var cid, uid, redirect, scopeJSON, nonce, storedChallenge, methodJSON, sid, family, acr, claims string
		var authTime, expires time.Time
		var consumed *time.Time
		e := tx.QueryRowContext(ctx, `SELECT client_id::text,user_id::text,redirect_uri,array_to_json(scopes)::text,COALESCE(nonce,''),code_challenge,auth_time,array_to_json(auth_methods)::text,expires_at,consumed_at,COALESCE(session_id::text,''),COALESCE(refresh_family_id::text,''),acr,claims::text
 FROM authorization_codes WHERE code_hash=$1 FOR UPDATE`, hash).Scan(&cid, &uid, &redirect, &scopeJSON, &nonce, &storedChallenge, &authTime, &methodJSON, &expires, &consumed, &sid, &family, &acr, &claims)
		if errors.Is(e, sql.ErrNoRows) {
			return oidc.ErrInvalidGrant
		}
		if e != nil {
			return e
		}
		client, e := authenticatedClient(ctx, tx, cid, proof)
		if e != nil {
			return e
		}
		// A different client/verifier cannot trigger revocation of the legitimate grant.
		if redirect != redirectURI || !hmac.Equal([]byte(challenge), []byte(storedChallenge)) {
			return oidc.ErrInvalidGrant
		}
		if consumed != nil {
			if family != "" {
				if _, e = tx.ExecContext(ctx, `UPDATE refresh_token_families SET revoked_at=COALESCE(revoked_at,clock_timestamp()),revoke_reason=COALESCE(revoke_reason,'code_reuse') WHERE id=$1::uuid`, family); e != nil {
					return e
				}
			}
			if e = audit(ctx, tx, "token.code_reuse_detected", uid, "client", cid, a); e != nil {
				return e
			}
			return oidc.ErrCodeReuse
		}
		if time.Now().After(now) {
			now = time.Now().UTC()
		}
		if !now.Before(expires) {
			return oidc.ErrInvalidGrant
		}
		var selection oidc.ClaimSelection
		if e = json.Unmarshal([]byte(claims), &selection); e != nil {
			return e
		}
		if !oidc.ClientAllowsClaims(client, selection) {
			return oidc.ErrInvalidGrant
		}
		scopes, e := decodeList(scopeJSON)
		if e != nil {
			return e
		}
		methods, e := decodeList(methodJSON)
		if e != nil {
			return e
		}
		subject, e := subjectByUserID(ctx, tx, uid)
		if e != nil {
			return rejectMissingSubject(e)
		}
		var live bool
		if e = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM sessions WHERE id=NULLIF($1,'')::uuid AND user_id=$2::uuid AND idle_expires_at>clock_timestamp() AND absolute_expires_at>clock_timestamp())`, sid, uid).Scan(&live); e != nil {
			return e
		}
		if !live || (client.RequireMFA && !meetsACRDB(methods, oidc.ACRMFA)) || !clientAllows(client, scopes) || !subjectAllows(subject, scopes) {
			return oidc.ErrInvalidGrant
		}
		subject.AuthTime = authTime
		subject.AuthMethods = methods
		subject.SessionID = sid
		subject.ACR = acr
		grant := oidc.CodeGrant{Claims: selection, Client: client, Subject: subject, RedirectURI: redirect, Scopes: scopes, Nonce: nonce}
		key, e := activeKeyTx(ctx, tx)
		if e != nil {
			return e
		}
		material, e := issue(grant, key, time.Now().UTC())
		if e != nil {
			return e
		}
		if len(material.RefreshHash) > 0 {
			if family, e = createRefreshFamilyTx(ctx, tx, grant, material); e != nil {
				return e
			}
		}
		if _, e = tx.ExecContext(ctx, `UPDATE authorization_codes SET consumed_at=clock_timestamp(),refresh_family_id=NULLIF($2,'')::uuid WHERE code_hash=$1`, hash, family); e != nil {
			return e
		}
		if e = audit(ctx, tx, "token.code_exchanged", uid, "client", cid, a); e != nil {
			return e
		}
		response = material.Response
		return nil
	})
	if err != nil {
		return oidc.TokenResponse{}, err
	}
	return response, nil
}

func (s *OIDCStore) RedeemRefresh(ctx context.Context, proof oidc.Client, hash []byte, requested []string, now time.Time, a identity.Audit, issue oidc.TokenIssuer) (response oidc.TokenResponse, err error) {
	err = s.grantWrite(ctx, func(tx *sql.Tx) error {
		var family string
		// Discover the family without locking the token first; all rotations within
		// that family take the same row lock, including replay and revocation.
		e := tx.QueryRowContext(ctx, `SELECT family_id::text FROM refresh_tokens WHERE token_hash=$1`, hash).Scan(&family)
		if errors.Is(e, sql.ErrNoRows) {
			return oidc.ErrInvalidGrant
		}
		if e != nil {
			return e
		}
		var uid, cid, sid, originalJSON, methodJSON, acr, claims string
		var absolute, authTime time.Time
		var revoked *time.Time
		e = tx.QueryRowContext(ctx, `SELECT user_id::text,client_id::text,COALESCE(session_id::text,''),array_to_json(scopes)::text,absolute_expires_at,revoked_at,auth_time,array_to_json(auth_methods)::text,acr,claims::text FROM refresh_token_families WHERE id=$1::uuid FOR UPDATE`, family).Scan(&uid, &cid, &sid, &originalJSON, &absolute, &revoked, &authTime, &methodJSON, &acr, &claims)
		if errors.Is(e, sql.ErrNoRows) {
			return oidc.ErrInvalidGrant
		}
		if e != nil {
			return e
		}
		client, e := authenticatedClient(ctx, tx, cid, proof)
		if e != nil {
			return e
		}
		var tokenScopes string
		var idle time.Time
		var consumed *time.Time
		e = tx.QueryRowContext(ctx, `SELECT array_to_json(scopes)::text,idle_expires_at,consumed_at FROM refresh_tokens WHERE token_hash=$1 AND family_id=$2::uuid FOR UPDATE`, hash, family).Scan(&tokenScopes, &idle, &consumed)
		if errors.Is(e, sql.ErrNoRows) {
			return oidc.ErrInvalidGrant
		}
		if e != nil {
			return e
		}
		if consumed != nil {
			if revoked == nil {
				if _, e = tx.ExecContext(ctx, `UPDATE refresh_token_families SET revoked_at=clock_timestamp(),revoke_reason='reuse' WHERE id=$1::uuid`, family); e != nil {
					return e
				}
				if e = audit(ctx, tx, "token.refresh_reuse_detected", uid, "refresh_family", family, a); e != nil {
					return e
				}
			}
			return oidc.ErrRefreshReuse
		}
		if time.Now().After(now) {
			now = time.Now().UTC()
		}
		if revoked != nil || !now.Before(absolute) || !now.Before(idle) || !client.RefreshTokensEnabled {
			return oidc.ErrInvalidGrant
		}
		var selection oidc.ClaimSelection
		if e = json.Unmarshal([]byte(claims), &selection); e != nil {
			return e
		}
		if !oidc.ClientAllowsClaims(client, selection) {
			return oidc.ErrInvalidGrant
		}
		scopes, e := decodeList(tokenScopes)
		if e != nil {
			return e
		}
		original, e := decodeList(originalJSON)
		if e != nil {
			return e
		}
		methods, e := decodeList(methodJSON)
		if e != nil {
			return e
		}
		if !subsetStrings(scopes, original) {
			return oidc.ErrInvalidGrant
		}
		if len(requested) > 0 {
			if !subsetStrings(requested, scopes) {
				return oidc.ErrInvalidScope
			}
			scopes = requested
		}
		subject, e := subjectByUserID(ctx, tx, uid)
		if e != nil {
			return rejectMissingSubject(e)
		}
		if (client.RequireMFA && !meetsACRDB(methods, oidc.ACRMFA)) || !clientAllows(client, scopes) || !subjectAllows(subject, scopes) {
			return oidc.ErrInvalidGrant
		}
		subject.AuthTime = authTime
		subject.AuthMethods = methods
		subject.SessionID = sid
		subject.ACR = acr
		key, e := activeKeyTx(ctx, tx)
		if e != nil {
			return e
		}
		material, e := issue(oidc.CodeGrant{Claims: selection, Client: client, Subject: subject, Scopes: scopes}, key, time.Now().UTC())
		if e != nil {
			return e
		}
		if len(material.RefreshHash) != 32 {
			return errors.New("refresh issuer did not provide a replacement")
		}
		if _, e = tx.ExecContext(ctx, `UPDATE refresh_tokens SET consumed_at=clock_timestamp(),replacement_hash=$2,scopes=ARRAY[]::text[] WHERE token_hash=$1`, hash, material.RefreshHash); e != nil {
			return e
		}
		if _, e = tx.ExecContext(ctx, `INSERT INTO refresh_tokens(token_hash,family_id,idle_expires_at,scopes) VALUES($1,$2::uuid,LEAST($3::timestamptz,$4::timestamptz),ARRAY(SELECT jsonb_array_elements_text($5::jsonb)))`, material.RefreshHash, family, material.IdleExpiresAt, absolute, listJSON(scopes)); e != nil {
			return e
		}
		if e = audit(ctx, tx, "token.refresh", uid, "refresh_family", family, a); e != nil {
			return e
		}
		response = material.Response
		return nil
	})
	if err != nil {
		return oidc.TokenResponse{}, err
	}
	return response, nil
}
