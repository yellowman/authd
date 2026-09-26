//go:build integration

package db_test

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/yellowman/authd/internal/db"
	"github.com/yellowman/authd/internal/identity"
	"github.com/yellowman/authd/internal/oidc"
)

func TestPostgresDynamicRefreshLifecycle(t *testing.T) {
	ids, ctx := postgres(t)
	_, actor := bootstrap(t, ctx, ids)
	s := &db.OIDCStore{DB: ids.DB}
	initial, secret, management := token(t), token(t), token(t)
	require(t, db.IssueInitialRegistrationToken(ctx, ids.DB, identity.Hash(initial), "inventory.", time.Now().Add(15*time.Minute)))
	c, err := s.RegisterDynamicClient(ctx, identity.Hash(initial), oidc.ClientEdit{
		ClientID: "dcr-inventory", Name: "Inventory", Type: "confidential", Enabled: true,
		RefreshTokensEnabled: true, AccessTokenTTL: 5 * time.Minute,
		RedirectURIs: []string{"https://inventory.example.test/callback"}, IdentityScopes: []string{"openid", "offline_access"},
	}, identity.Hash(secret), identity.Hash(management), []string{"inventory.read"}, nil, nil, auditFixture)
	require(t, err)
	if !c.RefreshTokensEnabled || !slices.Contains(c.IdentityScopes, "offline_access") {
		t.Fatal("refresh opt-in was not persisted")
	}
	_, err = s.InstallSigningKey(ctx, oidc.SigningKey{KID: "integration-key", Algorithm: "RS256", Ciphertext: []byte("encrypted-fixture"), PublicJWK: []byte(`{"kty":"RSA","kid":"integration-key"}`)}, false)
	require(t, err)
	code := databaseCode(t, ctx, s, actor, c, []string{"openid", "offline_access"})
	first, second := token(t), token(t)
	_, err = s.RedeemCode(ctx, c, identity.Hash(code), c.RedirectURIs[0], "challenge", time.Now(), auditFixture, databaseIssuer(first))
	require(t, err)
	_, err = s.RedeemRefresh(ctx, c, identity.Hash(first), nil, time.Now(), auditFixture, databaseIssuer(second))
	require(t, err)
	if _, err = s.RedeemRefresh(ctx, c, identity.Hash(first), nil, time.Now(), auditFixture, databaseIssuer(token(t))); !errors.Is(err, oidc.ErrRefreshReuse) {
		t.Fatalf("reuse: %v", err)
	}
	if _, err = s.RedeemRefresh(ctx, c, identity.Hash(second), nil, time.Now(), auditFixture, databaseIssuer(token(t))); !errors.Is(err, oidc.ErrInvalidGrant) {
		t.Fatalf("family survived reuse: %v", err)
	}
	code = databaseCode(t, ctx, s, actor, c, []string{"openid", "offline_access"})
	third := token(t)
	_, err = s.RedeemCode(ctx, c, identity.Hash(code), c.RedirectURIs[0], "challenge", time.Now(), auditFixture, databaseIssuer(third))
	require(t, err)
	stale := c.UpdatedAt
	c, err = s.UpdateManagedClientScopes(ctx, c.ClientID, identity.Hash(management), identity.Hash(secret), oidc.ManagedClientUpdate{Scopes: c.Permissions, ExpectedUpdatedAt: c.UpdatedAt}, auditFixture)
	require(t, err)
	if c.RefreshTokensEnabled || slices.Contains(c.IdentityScopes, "offline_access") {
		t.Fatal("refresh opt-out was not persisted")
	}
	var active int
	require(t, ids.DB.QueryRowContext(ctx, `SELECT count(*) FROM refresh_token_families WHERE client_id=$1 AND revoked_at IS NULL`, c.ID).Scan(&active))
	if active != 0 {
		t.Fatal("opt-out left refresh families active")
	}
	_, err = s.UpdateManagedClientScopes(ctx, c.ClientID, identity.Hash(management), identity.Hash(secret), oidc.ManagedClientUpdate{Scopes: c.Permissions, RefreshTokensEnabled: true, ExpectedUpdatedAt: stale}, auditFixture)
	if !errors.Is(err, identity.ErrConflict) {
		t.Fatalf("stale update overwrote client policy: %v", err)
	}
	c, err = s.UpdateManagedClientScopes(ctx, c.ClientID, identity.Hash(management), identity.Hash(secret), oidc.ManagedClientUpdate{Scopes: c.Permissions, RefreshTokensEnabled: true, ExpectedUpdatedAt: c.UpdatedAt}, auditFixture)
	require(t, err)
	if !c.RefreshTokensEnabled {
		t.Fatal("existing code-only client could not opt in")
	}
	if _, err = s.RedeemRefresh(ctx, c, identity.Hash(third), nil, time.Now(), auditFixture, databaseIssuer(token(t))); !errors.Is(err, oidc.ErrInvalidGrant) {
		t.Fatalf("opt-in resurrected revoked family: %v", err)
	}
}
