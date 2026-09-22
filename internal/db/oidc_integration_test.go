//go:build integration

package db_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/yellowman/authd/internal/db"
	"github.com/yellowman/authd/internal/identity"
	"github.com/yellowman/authd/internal/oidc"
)

func TestPostgresOIDCLifecycle(t *testing.T) {
	identityStore, ctx := postgres(t)
	_, actor := bootstrap(t, ctx, identityStore)
	require(t, identityStore.CreatePermission(ctx, actor.TokenHash, "bdcmaps.read", "Read BDC maps", auditFixture))
	adminData, err := identityStore.AdminData(ctx, actor.TokenHash)
	require(t, err)
	perm := findPermission(t, adminData, "bdcmaps.read")
	systemAdminPermission := findPermission(t, adminData, "system.admin")
	adminRole := findRole(t, adminData, "system-admin")
	adminRole.PermissionIDs = append(adminRole.PermissionIDs, perm.ID)
	require(t, identityStore.SaveRole(ctx, actor.TokenHash, identity.RoleEdit{ID: adminRole.ID, Name: adminRole.Name, Description: adminRole.Description, PermissionIDs: adminRole.PermissionIDs, ExpectedUpdatedAt: adminRole.UpdatedAt}, auditFixture))
	actor, err = identityStore.Session(ctx, actor.TokenHash, time.Hour)
	require(t, err)

	store := &db.OIDCStore{DB: identityStore.DB}
	secretHash := identity.Hash(token(t))
	client, err := store.CreateClient(ctx, actor.TokenHash, oidc.ClientEdit{
		ClientID: "bdcmaps", Name: "BDC Maps", Type: "confidential", Enabled: true,
		RefreshTokensEnabled: true, AccessTokenTTL: 5 * time.Minute,
		RedirectURIs: []string{"https://bdc.example.test/auth/callback"}, LogoutURIs: []string{"https://bdc.example.test/"},
		IdentityScopes: []string{"openid", "profile", "email", "groups", "offline_access"}, PermissionIDs: []string{perm.ID},
	}, secretHash, auditFixture)
	require(t, err)
	if client.ClientID != "bdcmaps" || len(client.PermissionIDs) != 1 || client.Permissions[0] != "bdcmaps.read" {
		t.Fatalf("unexpected client %#v", client)
	}
	clientEdit := oidc.ClientEdit{
		ID: client.ID, ClientID: client.ClientID, Name: "BDC Maps Updated", Type: client.Type, Enabled: client.Enabled,
		RefreshTokensEnabled: client.RefreshTokensEnabled, RequireMFA: client.RequireMFA, AccessTokenTTL: client.AccessTokenTTL,
		RedirectURIs: client.RedirectURIs, LogoutURIs: client.LogoutURIs, IdentityScopes: client.IdentityScopes, PermissionIDs: client.PermissionIDs,
		ExpectedUpdatedAt: client.UpdatedAt,
	}
	require(t, store.UpdateClient(ctx, actor.TokenHash, clientEdit, auditFixture))
	if err = store.UpdateClient(ctx, actor.TokenHash, clientEdit, auditFixture); !errors.Is(err, identity.ErrConflict) {
		t.Fatalf("stale client edit accepted: %v", err)
	}
	_, err = store.CreateClient(ctx, actor.TokenHash, oidc.ClientEdit{
		ClientID: "bad-admin-scope", Name: "Bad", Type: "public", Enabled: true, AccessTokenTTL: time.Minute,
		RedirectURIs: []string{"https://bad.example.test/callback"}, IdentityScopes: []string{"openid"}, PermissionIDs: []string{systemAdminPermission.ID},
	}, nil, auditFixture)
	if !errors.Is(err, identity.ErrConflict) {
		t.Fatalf("system.admin became an application scope: %v", err)
	}

	key := oidc.SigningKey{KID: "integration-key", Algorithm: "RS256", Ciphertext: []byte("encrypted-fixture"), PublicJWK: []byte(`{"kty":"RSA","kid":"integration-key"}`)}
	installed, err := store.InstallSigningKey(ctx, key, false)
	require(t, err)
	client, err = store.Client(ctx, client.ClientID)
	require(t, err)
	now := time.Now().UTC()
	codeRaw := databaseCode(t, ctx, store, actor, client, []string{"openid", "bdcmaps.read", "offline_access"})
	refresh1 := token(t)
	material := databaseIssuer(refresh1)
	response, err := store.RedeemCode(ctx, client, identity.Hash(codeRaw), client.RedirectURIs[0], "challenge", now, auditFixture, material)
	require(t, err)
	if response.RefreshToken != refresh1 {
		t.Fatal("grant did not return committed token material")
	}
	refresh2 := token(t)
	_, err = store.RedeemRefresh(ctx, client, identity.Hash(refresh1), nil, now, auditFixture, databaseIssuer(refresh2))
	require(t, err)
	if _, err = store.RedeemRefresh(ctx, client, identity.Hash(refresh1), nil, now, auditFixture, material); !errors.Is(err, oidc.ErrRefreshReuse) {
		t.Fatalf("refresh reuse not detected: %v", err)
	}
	if _, err = store.RedeemRefresh(ctx, client, identity.Hash(refresh2), nil, now, auditFixture, material); !errors.Is(err, oidc.ErrInvalidGrant) {
		t.Fatalf("compromised family remained usable: %v", err)
	}
	if _, err = store.RedeemCode(ctx, client, identity.Hash(codeRaw), client.RedirectURIs[0], "challenge", now, auditFixture, material); !errors.Is(err, oidc.ErrCodeReuse) {
		t.Fatalf("authorization code replay: %v", err)
	}
	refresh3 := token(t)
	code3 := databaseCode(t, ctx, store, actor, client, []string{"openid", "offline_access"})
	_, err = store.RedeemCode(ctx, client, identity.Hash(code3), client.RedirectURIs[0], "challenge", now, auditFixture, databaseIssuer(refresh3))
	require(t, err)
	require(t, store.RevokeRefreshToken(ctx, identity.Hash(refresh3), client, auditFixture))
	var refreshAudits, reuseAudits, revokeAudits int
	require(t, identityStore.DB.QueryRowContext(ctx, `SELECT
	 count(*) FILTER (WHERE event_type='token.refresh'),
	 count(*) FILTER (WHERE event_type='token.refresh_reuse_detected'),
	 count(*) FILTER (WHERE event_type='token.revoked') FROM audit_events`).Scan(&refreshAudits, &reuseAudits, &revokeAudits))
	if refreshAudits != 1 || reuseAudits != 1 || revokeAudits != 1 {
		t.Fatalf("OIDC audit counts refresh=%d reuse=%d revoke=%d", refreshAudits, reuseAudits, revokeAudits)
	}
	second := oidc.SigningKey{KID: "integration-key-2", Algorithm: "RS256", Ciphertext: []byte("encrypted-fixture-2"), PublicJWK: []byte(`{"kty":"RSA","use":"sig","alg":"RS256","kid":"integration-key-2","n":"AQ","e":"AQAB"}`)}
	rotatedKey, err := store.RotateSigningKey(ctx, actor.TokenHash, second, auditFixture)
	require(t, err)
	if rotatedKey.KID == installed.KID {
		t.Fatal("signing rotation did not replace active key")
	}
	adminKeys, err := store.AdminSigningKeys(ctx, actor.TokenHash)
	require(t, err)
	if len(adminKeys) != 2 {
		t.Fatalf("admin signing key list=%d want=2", len(adminKeys))
	}
	for _, listed := range adminKeys {
		if len(listed.Ciphertext) != 0 {
			t.Fatal("admin key listing exposed private-key ciphertext")
		}
	}
	old, err := store.SigningKey(ctx, installed.KID)
	require(t, err)
	if len(old.Ciphertext) != 0 || len(old.PublicJWK) == 0 || old.Active {
		t.Fatalf("retired key retained private material or lost JWKS data: %#v", old)
	}
	var keyCreated, keyRotated, keyRetired int
	require(t, identityStore.DB.QueryRowContext(ctx, `SELECT
	 count(*) FILTER (WHERE event_type='signing_key.created'),
	 count(*) FILTER (WHERE event_type='signing_key.rotated'),
	 count(*) FILTER (WHERE event_type='signing_key.retired')
	 FROM audit_events`).Scan(&keyCreated, &keyRotated, &keyRetired))
	if keyCreated != 1 || keyRotated != 1 || keyRetired != 1 {
		t.Fatalf("signing key audit counts created=%d rotated=%d retired=%d", keyCreated, keyRotated, keyRetired)
	}

	// Client deletion is a destructive revocation boundary. All durable grant
	// state owned by the client is removed by foreign-key cascades, while
	// already-issued short-lived JWTs are left to expire normally.
	deleteCode := databaseCode(t, ctx, store, actor, client, []string{"openid", "offline_access"})
	_, err = store.RedeemCode(ctx, client, identity.Hash(deleteCode), client.RedirectURIs[0], "challenge", now, auditFixture, databaseIssuer(token(t)))
	require(t, err)
	deleteRequest := token(t)
	require(t, store.CreateAuthorizationRequest(ctx, identity.Hash(deleteRequest), oidc.AuthorizationRequest{
		ClientID: client.ClientID, RedirectURI: client.RedirectURIs[0], Scopes: []string{"openid"}, BrowserHash: identity.Hash(token(t)), CodeChallenge: "delete-challenge", CreatedAt: now, ExpiresAt: now.Add(time.Minute),
	}))
	require(t, store.DeleteClient(ctx, actor.TokenHash, client.ID, auditFixture))
	if _, err = store.Client(ctx, client.ClientID); !errors.Is(err, oidc.ErrInvalidClient) {
		t.Fatalf("deleted client remained addressable: %v", err)
	}
	var ownedRows int
	require(t, identityStore.DB.QueryRowContext(ctx, `SELECT
		(SELECT count(*) FROM refresh_token_families WHERE client_id=$1::uuid) +
		(SELECT count(*) FROM authorization_requests WHERE client_id=$1::uuid) +
		(SELECT count(*) FROM authorization_codes WHERE client_id=$1::uuid)`, client.ID).Scan(&ownedRows))
	if ownedRows != 0 {
		t.Fatalf("deleted client retained grant state: %d rows", ownedRows)
	}
	var deleteAudits int
	require(t, identityStore.DB.QueryRowContext(ctx, `SELECT count(*) FROM audit_events WHERE event_type='client.deleted' AND target_id=$1`, client.ID).Scan(&deleteAudits))
	if deleteAudits != 1 {
		t.Fatalf("client deletion audit count=%d", deleteAudits)
	}
}

// This callback is deliberately a transaction witness, not a JWT implementation.
// Actual RSA/JWT encoding is exercised in internal/oidc. These tests prove SQL
// commit/rollback, lock ordering and lifecycle using real PostgreSQL, never mocks.
func databaseIssuer(refresh string) oidc.TokenIssuer {
	return func(g oidc.CodeGrant, key oidc.SigningKey, at time.Time) (oidc.TokenMaterial, error) {
		if key.KID == "" || g.Subject.SessionID == "" {
			return oidc.TokenMaterial{}, errors.New("missing signing/session context")
		}
		m := oidc.TokenMaterial{Response: oidc.TokenResponse{AccessToken: "transaction-witness", TokenType: "Bearer"}}
		if refresh != "" {
			m.Response.RefreshToken = refresh
			m.RefreshHash = identity.Hash(refresh)
			m.IdleExpiresAt = at.Add(time.Hour)
			m.AbsoluteExpiresAt = at.Add(2 * time.Hour)
		}
		return m, nil
	}
}
func databaseCode(t *testing.T, ctx context.Context, store *db.OIDCStore, actor identity.Session, client oidc.Client, scopes []string) string {
	t.Helper()
	rh, bh, ch := identity.Hash(token(t)), identity.Hash(token(t)), token(t)
	now := time.Now().UTC()
	req := oidc.AuthorizationRequest{ClientID: client.ClientID, RedirectURI: client.RedirectURIs[0], Scopes: scopes, RequiredACR: oidc.ACRPassword, Nonce: "nonce", CodeChallenge: "challenge", BrowserHash: bh, Prompt: "consent", CreatedAt: now, ExpiresAt: now.Add(time.Minute)}
	require(t, store.CreateAuthorizationRequest(ctx, rh, req))
	require(t, store.ConsentAuthorizationRequest(ctx, rh, bh, actor.TokenHash, true, auditFixture))
	g, err := store.IssueAuthorizationCode(ctx, rh, bh, actor.TokenHash, identity.Hash(ch), time.Now().Add(50*time.Second))
	require(t, err)
	if g.Subject.ID != actor.User.ID || g.Subject.SessionID != actor.ID || g.Nonce != "nonce" {
		t.Fatal("code lost subject/session/nonce binding")
	}
	return ch
}
func databaseOIDC(t *testing.T) (*db.IdentityStore, *db.OIDCStore, context.Context, identity.Session, oidc.Client) {
	t.Helper()
	ids, ctx := postgres(t)
	_, actor := bootstrap(t, ctx, ids)
	os := &db.OIDCStore{DB: ids.DB}
	c, err := os.CreateClient(ctx, actor.TokenHash, oidc.ClientEdit{ClientID: "test-rp", Name: "Test RP", Type: "confidential", Enabled: true, RefreshTokensEnabled: true, AccessTokenTTL: time.Minute, RedirectURIs: []string{"https://rp.example.test/callback"}, IdentityScopes: []string{"openid", "profile", "email", "offline_access"}}, identity.Hash(token(t)), auditFixture)
	require(t, err)
	_, err = os.InstallSigningKey(ctx, oidc.SigningKey{KID: "db-key", Algorithm: "RS256", Ciphertext: []byte("SQL-transaction-fixture"), PublicJWK: []byte(`{"kty":"RSA","kid":"db-key"}`)}, false)
	require(t, err)
	return ids, os, ctx, actor, c
}
func TestPostgresGrantSigningFailureRollsBack(t *testing.T) {
	ids, s, ctx, actor, c := databaseOIDC(t)
	code := databaseCode(t, ctx, s, actor, c, []string{"openid", "offline_access"})
	failure := errors.New("signing unavailable")
	bad := func(oidc.CodeGrant, oidc.SigningKey, time.Time) (oidc.TokenMaterial, error) {
		return oidc.TokenMaterial{}, failure
	}
	if _, err := s.RedeemCode(ctx, c, identity.Hash(code), c.RedirectURIs[0], "challenge", time.Now(), auditFixture, bad); !errors.Is(err, failure) {
		t.Fatal(err)
	}
	var consumed bool
	var families int
	require(t, ids.DB.QueryRowContext(ctx, `SELECT consumed_at IS NOT NULL FROM authorization_codes WHERE code_hash=$1`, identity.Hash(code)).Scan(&consumed))
	require(t, ids.DB.QueryRowContext(ctx, `SELECT count(*) FROM refresh_token_families`).Scan(&families))
	if consumed || families != 0 {
		t.Fatal("failed signing consumed code or created a family")
	}
	rt := token(t)
	_, err := s.RedeemCode(ctx, c, identity.Hash(code), c.RedirectURIs[0], "challenge", time.Now(), auditFixture, databaseIssuer(rt))
	require(t, err)
	if _, err = s.RedeemRefresh(ctx, c, identity.Hash(rt), nil, time.Now(), auditFixture, bad); !errors.Is(err, failure) {
		t.Fatal(err)
	}
	require(t, ids.DB.QueryRowContext(ctx, `SELECT consumed_at IS NOT NULL FROM refresh_tokens WHERE token_hash=$1`, identity.Hash(rt)).Scan(&consumed))
	if consumed {
		t.Fatal("failed signing burned the refresh token")
	}
	_, err = s.RedeemRefresh(ctx, c, identity.Hash(rt), nil, time.Now(), auditFixture, databaseIssuer(token(t)))
	require(t, err)
}
func TestPostgresGrantReplayAndCredentialBoundaries(t *testing.T) {
	_, s, ctx, actor, c := databaseOIDC(t)
	code := databaseCode(t, ctx, s, actor, c, []string{"openid", "offline_access"})
	rt1, rt2 := token(t), token(t)
	_, err := s.RedeemCode(ctx, c, identity.Hash(code), c.RedirectURIs[0], "challenge", time.Now(), auditFixture, databaseIssuer(rt1))
	require(t, err)
	_, err = s.RedeemRefresh(ctx, c, identity.Hash(rt1), nil, time.Now(), auditFixture, databaseIssuer(rt2))
	require(t, err)
	other := c
	other.ClientID = "different-rp"
	if _, err = s.RedeemRefresh(ctx, other, identity.Hash(rt1), nil, time.Now(), auditFixture, databaseIssuer(token(t))); !errors.Is(err, oidc.ErrInvalidGrant) {
		t.Fatalf("wrong-client replay: %v", err)
	}
	// Wrong-client replay has NOT revoked the family.
	rt3 := token(t)
	_, err = s.RedeemRefresh(ctx, c, identity.Hash(rt2), nil, time.Now(), auditFixture, databaseIssuer(rt3))
	require(t, err)
	if _, err = s.RedeemCode(ctx, c, identity.Hash(code), c.RedirectURIs[0], "wrong-pkce", time.Now(), auditFixture, databaseIssuer(token(t))); !errors.Is(err, oidc.ErrInvalidGrant) {
		t.Fatal(err)
	}
	if _, err = s.RedeemCode(ctx, c, identity.Hash(code), c.RedirectURIs[0], "challenge", time.Now(), auditFixture, databaseIssuer(token(t))); !errors.Is(err, oidc.ErrCodeReuse) {
		t.Fatal(err)
	}
	if _, err = s.RedeemRefresh(ctx, c, identity.Hash(rt3), nil, time.Now(), auditFixture, databaseIssuer(token(t))); !errors.Is(err, oidc.ErrInvalidGrant) {
		t.Fatalf("code replay failed to revoke descendants: %v", err)
	}
	code = databaseCode(t, ctx, s, actor, c, []string{"openid"})
	stale := c
	stale.SecretHash = identity.Hash("stale-authentication-proof")
	if _, err = s.RedeemCode(ctx, stale, identity.Hash(code), c.RedirectURIs[0], "challenge", time.Now(), auditFixture, databaseIssuer("")); !errors.Is(err, oidc.ErrInvalidClient) {
		t.Fatalf("stale secret proof accepted: %v", err)
	}
	_, err = s.RedeemCode(ctx, c, identity.Hash(code), c.RedirectURIs[0], "challenge", time.Now(), auditFixture, databaseIssuer(""))
	require(t, err)
}
func TestPostgresUnrelatedGrantsAreConcurrent(t *testing.T) {
	_, s, ctx, actor, c := databaseOIDC(t)
	code1 := databaseCode(t, ctx, s, actor, c, []string{"openid"})
	code2 := databaseCode(t, ctx, s, actor, c, []string{"openid"})
	// Each callback must enter BEFORE either transaction is released. A global
	// exclusive token lock makes this deterministic witness time out.
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	issue := func(g oidc.CodeGrant, k oidc.SigningKey, at time.Time) (oidc.TokenMaterial, error) {
		entered <- struct{}{}
		select {
		case <-release:
			return databaseIssuer("")(g, k, at)
		case <-ctx.Done():
			return oidc.TokenMaterial{}, ctx.Err()
		}
	}
	done := make(chan error, 2)
	for _, code := range []string{code1, code2} {
		go func(code string) {
			_, err := s.RedeemCode(ctx, c, identity.Hash(code), c.RedirectURIs[0], "challenge", time.Now(), auditFixture, issue)
			done <- err
		}(code)
	}
	for i := 0; i < 2; i++ {
		select {
		case <-entered:
		case err := <-done:
			t.Fatalf("grant exited early: %v", err)
		case <-time.After(5 * time.Second):
			t.Fatal("unrelated token grants serialize")
		}
	}
	unblock()
	for i := 0; i < 2; i++ {
		require(t, <-done)
	}
}
func TestPostgresOneCodeHasOneWinner(t *testing.T) {
	_, s, ctx, actor, c := databaseOIDC(t)
	code := databaseCode(t, ctx, s, actor, c, []string{"openid"})
	done := make(chan error, 8)
	for i := 0; i < 8; i++ {
		go func() {
			_, err := s.RedeemCode(ctx, c, identity.Hash(code), c.RedirectURIs[0], "challenge", time.Now(), auditFixture, databaseIssuer(""))
			done <- err
		}()
	}
	winners := 0
	for i := 0; i < 8; i++ {
		err := <-done
		if err == nil {
			winners++
		} else if !errors.Is(err, oidc.ErrCodeReuse) {
			t.Fatal(err)
		}
	}
	if winners != 1 {
		t.Fatalf("code winners=%d", winners)
	}
}
func TestPostgresSessionRetirementAndOfflineLifetime(t *testing.T) {
	ids, s, ctx, actor, c := databaseOIDC(t)
	code := databaseCode(t, ctx, s, actor, c, []string{"openid", "offline_access"})
	rt := token(t)
	_, err := s.RedeemCode(ctx, c, identity.Hash(code), c.RedirectURIs[0], "challenge", time.Now(), auditFixture, databaseIssuer(rt))
	require(t, err)
	pending := databaseCode(t, ctx, s, actor, c, []string{"openid"})
	// Natural expiry does not invalidate an explicit offline grant.
	_, err = ids.DB.ExecContext(ctx, `UPDATE sessions SET idle_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1::uuid`, actor.ID)
	require(t, err)
	rt2 := token(t)
	_, err = s.RedeemRefresh(ctx, c, identity.Hash(rt), nil, time.Now(), auditFixture, databaseIssuer(rt2))
	require(t, err)
	if _, err = s.RedeemCode(ctx, c, identity.Hash(pending), c.RedirectURIs[0], "challenge", time.Now(), auditFixture, databaseIssuer("")); !errors.Is(err, oidc.ErrInvalidGrant) {
		t.Fatalf("dead session authorized an unused code: %v", err)
	}
	// Restore the fixture session so it can explicitly revoke itself.
	_, err = ids.DB.ExecContext(ctx, `UPDATE sessions SET idle_expires_at=clock_timestamp()+interval '1 hour' WHERE id=$1::uuid`, actor.ID)
	require(t, err)
	require(t, ids.RevokeSession(ctx, actor.TokenHash, actor.ID, false, auditFixture))
	if _, err = s.RedeemRefresh(ctx, c, identity.Hash(rt2), nil, time.Now(), auditFixture, databaseIssuer(token(t))); !errors.Is(err, oidc.ErrInvalidGrant) {
		t.Fatalf("explicit logout retained offline authority: %v", err)
	}
}
func TestPostgresRefreshNarrowingAndAbsoluteExpiry(t *testing.T) {
	ids, s, ctx, actor, c := databaseOIDC(t)
	code := databaseCode(t, ctx, s, actor, c, []string{"openid", "profile", "offline_access"})
	rt := token(t)
	_, err := s.RedeemCode(ctx, c, identity.Hash(code), c.RedirectURIs[0], "challenge", time.Now(), auditFixture, databaseIssuer(rt))
	require(t, err)
	_, err = ids.DB.ExecContext(ctx, `UPDATE refresh_token_families SET absolute_expires_at=clock_timestamp()+interval '10 minutes'`)
	require(t, err)
	rt2 := token(t)
	_, err = s.RedeemRefresh(ctx, c, identity.Hash(rt), []string{"openid"}, time.Now(), auditFixture, databaseIssuer(rt2))
	require(t, err)
	var capped bool
	require(t, ids.DB.QueryRowContext(ctx, `SELECT t.idle_expires_at<=f.absolute_expires_at FROM refresh_tokens t JOIN refresh_token_families f ON f.id=t.family_id WHERE token_hash=$1`, identity.Hash(rt2)).Scan(&capped))
	if !capped {
		t.Fatal("rotation reset the absolute lifetime")
	}
	if _, err = s.RedeemRefresh(ctx, c, identity.Hash(rt2), []string{"openid", "profile"}, time.Now(), auditFixture, databaseIssuer(token(t))); !errors.Is(err, oidc.ErrInvalidScope) {
		t.Fatalf("narrowed grant re-expanded: %v", err)
	}
	_, err = s.RedeemRefresh(ctx, c, identity.Hash(rt2), nil, time.Now(), auditFixture, databaseIssuer(token(t)))
	require(t, err)
}
func TestPostgresBrowserConsentBinding(t *testing.T) {
	_, s, ctx, actor, c := databaseOIDC(t)
	rh, bh := identity.Hash(token(t)), identity.Hash(token(t))
	now := time.Now()
	req := oidc.AuthorizationRequest{ClientID: c.ClientID, RedirectURI: c.RedirectURIs[0], Scopes: []string{"openid", "offline_access"}, BrowserHash: bh, CodeChallenge: "challenge", Prompt: "consent", CreatedAt: now, ExpiresAt: now.Add(time.Minute)}
	require(t, s.CreateAuthorizationRequest(ctx, rh, req))
	if _, err := s.IssueAuthorizationCode(ctx, rh, identity.Hash(token(t)), actor.TokenHash, identity.Hash(token(t)), now.Add(50*time.Second)); !errors.Is(err, oidc.ErrInvalidRequest) {
		t.Fatalf("cross-browser resume: %v", err)
	}
	if _, err := s.IssueAuthorizationCode(ctx, rh, bh, actor.TokenHash, identity.Hash(token(t)), now.Add(50*time.Second)); !errors.Is(err, oidc.ErrConsentRequired) {
		t.Fatalf("missing consent: %v", err)
	}
	require(t, s.ConsentAuthorizationRequest(ctx, rh, bh, actor.TokenHash, true, auditFixture))
	_, err := s.IssueAuthorizationCode(ctx, rh, bh, actor.TokenHash, identity.Hash(token(t)), now.Add(50*time.Second))
	require(t, err)
}
func TestPostgresCleanupRetainsCodeReplayWitness(t *testing.T) {
	ids, s, ctx, actor, c := databaseOIDC(t)
	code := databaseCode(t, ctx, s, actor, c, []string{"openid", "offline_access"})
	rt := token(t)
	_, err := s.RedeemCode(ctx, c, identity.Hash(code), c.RedirectURIs[0], "challenge", time.Now(), auditFixture, databaseIssuer(rt))
	require(t, err)
	_, err = ids.DB.ExecContext(ctx, `UPDATE authorization_codes SET consumed_at=clock_timestamp()-interval '2 days',expires_at=clock_timestamp()-interval '2 days' WHERE code_hash=$1`, identity.Hash(code))
	require(t, err)
	_, err = db.CleanupExpired(ctx, ids.DB, time.Now(), 90*24*time.Hour)
	require(t, err)
	var count int
	require(t, ids.DB.QueryRowContext(ctx, `SELECT count(*) FROM authorization_codes WHERE code_hash=$1`, identity.Hash(code)).Scan(&count))
	if count != 1 {
		t.Fatal("cleanup erased live-family replay witness")
	}
	if _, err = s.RedeemCode(ctx, c, identity.Hash(code), c.RedirectURIs[0], "challenge", time.Now(), auditFixture, databaseIssuer(token(t))); !errors.Is(err, oidc.ErrCodeReuse) {
		t.Fatal(err)
	}
}

func TestPostgresReservedPermissionConstraint(t *testing.T) {
	store, ctx := postgres(t)
	for _, name := range []string{"openid", "profile", "email", "groups", "roles", "offline_access"} {
		if _, err := store.DB.ExecContext(ctx, `INSERT INTO permissions(name,description) VALUES($1,'must reject')`, name); err == nil {
			t.Fatalf("OIDC control scope became a permission: %s", name)
		}
	}
}

// Revocation must wait for a grant's commit and then revoke its descendants;
// it must not interleave between consuming the code and creating its family.
func TestPostgresRevocationSerializesWithGrantCommit(t *testing.T) {
	ids, s, ctx, actor, c := databaseOIDC(t)
	code := databaseCode(t, ctx, s, actor, c, []string{"openid", "offline_access"})
	rt := token(t)
	entered, release := make(chan struct{}), make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	granted := make(chan error, 1)
	go func() {
		_, err := s.RedeemCode(ctx, c, identity.Hash(code), c.RedirectURIs[0], "challenge", time.Now(), auditFixture, func(g oidc.CodeGrant, k oidc.SigningKey, n time.Time) (oidc.TokenMaterial, error) {
			close(entered)
			select {
			case <-release:
				return databaseIssuer(rt)(g, k, n)
			case <-ctx.Done():
				return oidc.TokenMaterial{}, ctx.Err()
			}
		})
		granted <- err
	}()
	select {
	case <-entered:
	case err := <-granted:
		t.Fatalf("grant did not enter signing: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("grant did not enter signing")
	}
	revoked := make(chan error, 1)
	go func() { revoked <- ids.RevokeSession(ctx, actor.TokenHash, actor.ID, false, auditFixture) }()
	select {
	case err := <-revoked:
		t.Fatalf("revocation crossed the uncommitted grant: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	select {
	case err := <-granted:
		require(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("grant stalled")
	}
	select {
	case err := <-revoked:
		require(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("revocation stalled")
	}
	_, err := s.RedeemRefresh(ctx, c, identity.Hash(rt), nil, time.Now(), auditFixture, databaseIssuer(token(t)))
	if !errors.Is(err, oidc.ErrInvalidGrant) {
		t.Fatalf("family survived revocation after its creation: %v", err)
	}
}

func TestPostgresSessionReadsThrottleActivityWrites(t *testing.T) {
	ids, _, ctx, actor, _ := databaseOIDC(t)
	var before, after time.Time
	require(t, ids.DB.QueryRowContext(ctx, `SELECT last_seen_at FROM sessions WHERE id=$1::uuid`, actor.ID).Scan(&before))
	for i := 0; i < 5; i++ {
		_, err := ids.Session(ctx, actor.TokenHash, time.Hour)
		require(t, err)
	}
	require(t, ids.DB.QueryRowContext(ctx, `SELECT last_seen_at FROM sessions WHERE id=$1::uuid`, actor.ID).Scan(&after))
	if !before.Equal(after) {
		t.Fatal("hot session read wrote last_seen_at")
	}
	_, err := ids.DB.ExecContext(ctx, `UPDATE sessions SET last_seen_at=clock_timestamp()-interval '2 minutes' WHERE id=$1::uuid`, actor.ID)
	require(t, err)
	_, err = ids.Session(ctx, actor.TokenHash, time.Hour)
	require(t, err)
	var touched bool
	require(t, ids.DB.QueryRowContext(ctx, `SELECT last_seen_at>clock_timestamp()-interval '10 seconds' FROM sessions WHERE id=$1::uuid`, actor.ID).Scan(&touched))
	if !touched {
		t.Fatal("throttled session was not eventually touched")
	}
}
