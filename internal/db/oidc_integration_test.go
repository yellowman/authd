//go:build integration

package db_test

import (
	"errors"
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

	requestRaw := token(t)
	now := time.Now().UTC()
	req := oidc.AuthorizationRequest{ClientID: "bdcmaps", RedirectURI: "https://bdc.example.test/auth/callback", Scopes: []string{"bdcmaps.read", "openid"}, State: "state", Nonce: "nonce", CodeChallenge: "challenge", CreatedAt: now, ExpiresAt: now.Add(10 * time.Minute)}
	require(t, store.CreateAuthorizationRequest(ctx, identity.Hash(requestRaw), req))
	codeRaw := token(t)
	grant, err := store.IssueAuthorizationCode(ctx, identity.Hash(requestRaw), actor.TokenHash, identity.Hash(codeRaw), now.Add(time.Minute))
	require(t, err)
	if grant.Subject.ID != actor.User.ID || grant.Nonce != "nonce" {
		t.Fatal("authorization grant lost identity binding")
	}
	grant, err = store.ConsumeAuthorizationCode(ctx, identity.Hash(codeRaw), "bdcmaps", req.RedirectURI, "challenge", now)
	require(t, err)
	if grant.Client.ID != client.ID {
		t.Fatal("code client binding changed")
	}
	if _, err = store.ConsumeAuthorizationCode(ctx, identity.Hash(codeRaw), "bdcmaps", req.RedirectURI, "challenge", now); !errors.Is(err, oidc.ErrInvalidGrant) {
		t.Fatalf("authorization code replay: %v", err)
	}

	refresh1 := token(t)
	require(t, store.CreateRefreshFamily(ctx, actor.User.ID, client.ID, req.Scopes, actor.AuthTime, actor.AuthMethods, identity.Hash(refresh1), now.Add(time.Hour), now.Add(2*time.Hour)))
	refresh2 := token(t)
	rotated, err := store.RotateRefreshToken(ctx, identity.Hash(refresh1), identity.Hash(refresh2), "bdcmaps", nil, now, now.Add(time.Hour), identity.Audit{})
	require(t, err)
	if rotated.Client.ClientID != "bdcmaps" {
		t.Fatal("refresh client binding changed")
	}
	if _, err = store.RotateRefreshToken(ctx, identity.Hash(refresh1), identity.Hash(token(t)), "bdcmaps", nil, now, now.Add(time.Hour), identity.Audit{}); !errors.Is(err, oidc.ErrRefreshReuse) {
		t.Fatalf("refresh reuse not detected: %v", err)
	}
	if _, err = store.RotateRefreshToken(ctx, identity.Hash(refresh2), identity.Hash(token(t)), "bdcmaps", nil, now, now.Add(time.Hour), identity.Audit{}); !errors.Is(err, oidc.ErrInvalidGrant) {
		t.Fatalf("compromised family remained usable: %v", err)
	}
	refresh3 := token(t)
	require(t, store.CreateRefreshFamily(ctx, actor.User.ID, client.ID, req.Scopes, actor.AuthTime, actor.AuthMethods, identity.Hash(refresh3), now.Add(time.Hour), now.Add(2*time.Hour)))
	require(t, store.RevokeRefreshToken(ctx, identity.Hash(refresh3), "bdcmaps", auditFixture))
	var refreshAudits, reuseAudits, revokeAudits int
	require(t, identityStore.DB.QueryRowContext(ctx, `SELECT
	 count(*) FILTER (WHERE event_type='token.refresh'),
	 count(*) FILTER (WHERE event_type='token.refresh_reuse_detected'),
	 count(*) FILTER (WHERE event_type='token.revoked')
	 FROM audit_events`).Scan(&refreshAudits, &reuseAudits, &revokeAudits))
	if refreshAudits != 1 || reuseAudits != 1 || revokeAudits != 1 {
		t.Fatalf("OIDC token audit counts refresh=%d reuse=%d revoke=%d", refreshAudits, reuseAudits, revokeAudits)
	}

	key := oidc.SigningKey{KID: "integration-key", Algorithm: "RS256", Ciphertext: []byte("encrypted-fixture"), PublicJWK: []byte(`{"kty":"RSA","use":"sig","alg":"RS256","kid":"integration-key","n":"AQ","e":"AQAB"}`)}
	installed, err := store.InstallSigningKey(ctx, key, false)
	require(t, err)
	active, err := store.ActiveSigningKey(ctx)
	require(t, err)
	if active.KID != installed.KID {
		t.Fatal("active signing key mismatch")
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
	deleteRefresh := token(t)
	require(t, store.CreateRefreshFamily(ctx, actor.User.ID, client.ID, []string{"openid"}, actor.AuthTime, actor.AuthMethods, identity.Hash(deleteRefresh), now.Add(time.Hour), now.Add(2*time.Hour)))
	deleteRequest := token(t)
	require(t, store.CreateAuthorizationRequest(ctx, identity.Hash(deleteRequest), oidc.AuthorizationRequest{
		ClientID: client.ClientID, RedirectURI: client.RedirectURIs[0], Scopes: []string{"openid"}, CodeChallenge: "delete-challenge", CreatedAt: now, ExpiresAt: now.Add(time.Minute),
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
