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

func TestPostgresConsentApprovalHistory(t *testing.T) {
	ids, store, ctx, actor, client := databaseOIDC(t)
	create := func(scopes []string, claims oidc.ClaimSelection, prompt string) ([]byte, []byte) {
		t.Helper()
		rh, bh := identity.Hash(token(t)), identity.Hash(token(t))
		now := time.Now()
		require(t, store.CreateAuthorizationRequest(ctx, rh, oidc.AuthorizationRequest{ClientID: client.ClientID, RedirectURI: client.RedirectURIs[0], Scopes: scopes, Claims: claims, Prompt: prompt, BrowserHash: bh, CodeChallenge: "challenge", CreatedAt: now, ExpiresAt: now.Add(time.Minute)}))
		return rh, bh
	}
	read := func() oidc.ConsentApproval {
		t.Helper()
		prior, err := store.ConsentApproval(ctx, actor.TokenHash, client.ID)
		require(t, err)
		return prior
	}
	if !read().ApprovedAt.IsZero() {
		t.Fatal("old session inferred consent history")
	}
	scopes := []string{"openid", "profile", "email", "offline_access"}
	claims := oidc.ClaimSelection{IDToken: []string{"name"}, UserInfo: []string{"email"}}
	rh, bh := create(scopes, claims, "consent")
	require(t, store.ConsentAuthorizationRequest(ctx, rh, bh, actor.TokenHash, true, auditFixture))
	if !read().ApprovedAt.IsZero() {
		t.Fatal("unfinished approval became the saved baseline")
	}
	_, err := store.IssueAuthorizationCode(ctx, rh, bh, actor.TokenHash, identity.Hash(token(t)), time.Now().Add(50*time.Second))
	require(t, err)
	first := read()
	if first.ApprovedAt.IsZero() || !slices.Equal(first.Scopes, scopes) || !slices.Equal(first.IDTokenClaims, claims.IDToken) || !slices.Equal(first.UserInfoClaims, claims.UserInfo) {
		t.Fatal("completed consent not persisted", first)
	}
	for _, decision := range []string{"deny", "failed-code", "no-consent"} {
		prompt := "consent"
		if decision == "no-consent" {
			prompt = ""
		}
		rh, bh = create([]string{"openid"}, oidc.ClaimSelection{}, prompt)
		switch decision {
		case "deny":
			require(t, store.ConsentAuthorizationRequest(ctx, rh, bh, actor.TokenHash, false, auditFixture))
		case "failed-code":
			require(t, store.ConsentAuthorizationRequest(ctx, rh, bh, actor.TokenHash, true, auditFixture))
			if _, err = store.IssueAuthorizationCode(ctx, rh, bh, actor.TokenHash, identity.Hash(token(t)), time.Now().Add(2*time.Minute)); !errors.Is(err, oidc.ErrInvalidRequest) {
				t.Fatal("invalid code expiry accepted", err)
			}
		case "no-consent":
			_, err = store.IssueAuthorizationCode(ctx, rh, bh, actor.TokenHash, identity.Hash(token(t)), time.Now().Add(50*time.Second))
			require(t, err)
		}
		if prior := read(); !prior.ApprovedAt.Equal(first.ApprovedAt) || !slices.Equal(prior.Scopes, first.Scopes) {
			t.Fatal("non-completed explicit consent changed history", decision, prior)
		}
	}
	rh, bh = create([]string{"openid"}, oidc.ClaimSelection{}, "consent")
	require(t, store.ConsentAuthorizationRequest(ctx, rh, bh, actor.TokenHash, true, auditFixture))
	_, err = store.IssueAuthorizationCode(ctx, rh, bh, actor.TokenHash, identity.Hash(token(t)), time.Now().Add(50*time.Second))
	require(t, err)
	latest := read()
	if !slices.Equal(latest.Scopes, []string{"openid"}) || len(latest.IDTokenClaims)+len(latest.UserInfoClaims) != 0 {
		t.Fatal("new approval unioned old scopes or identity fields", latest)
	}
	persisted, err := (&db.OIDCStore{DB: ids.DB}).ConsentApproval(ctx, actor.TokenHash, client.ID)
	require(t, err)
	if !persisted.ApprovedAt.Equal(latest.ApprovedAt) || !slices.Equal(persisted.Scopes, latest.Scopes) {
		t.Fatal("approval depended on one process's memory")
	}
	other, err := store.CreateClient(ctx, actor.TokenHash, oidc.ClientEdit{ClientID: "other-app", Name: "Other app", Type: "public", Enabled: true, AccessTokenTTL: time.Minute, RedirectURIs: []string{"https://other.example.test/callback"}, IdentityScopes: []string{"openid"}}, nil, auditFixture)
	require(t, err)
	prior, err := store.ConsentApproval(ctx, actor.TokenHash, other.ID)
	require(t, err)
	if !prior.ApprovedAt.IsZero() {
		t.Fatal("approval crossed applications")
	}
	require(t, ids.CreateUser(ctx, actor.TokenHash, identity.NewUser{Profile: identity.Profile{Username: "other-person"}, PasswordHash: "repository-test-other-hash"}, auditFixture))
	rec, err := ids.LoginRecord(ctx, "other-person")
	require(t, err)
	otherSession := sessionFixture(t, rec, "pwd")
	require(t, ids.CreateSession(ctx, rec, otherSession, nil, "", auditFixture))
	prior, err = store.ConsentApproval(ctx, otherSession.TokenHash, client.ID)
	require(t, err)
	if !prior.ApprovedAt.IsZero() {
		t.Fatal("approval crossed people")
	}
	require(t, store.DeleteClient(ctx, actor.TokenHash, client.ID, auditFixture))
	var remaining int
	require(t, ids.DB.QueryRowContext(ctx, `SELECT count(*) FROM client_consent_approvals WHERE client_id=$1::uuid`, client.ID).Scan(&remaining))
	if remaining != 0 {
		t.Fatal("deleted application left approval history")
	}
	_, err = ids.DB.ExecContext(ctx, `UPDATE sessions SET idle_expires_at=clock_timestamp()-interval '1 second' WHERE token_hash=$1`, actor.TokenHash)
	require(t, err)
	if _, err = store.ConsentApproval(ctx, actor.TokenHash, other.ID); !errors.Is(err, oidc.ErrLoginRequired) {
		t.Fatal("expired session read consent history", err)
	}
}

func TestPostgresConsentApprovalFailureRollsBackCode(t *testing.T) {
	ids, store, ctx, actor, client := databaseOIDC(t)
	rh, bh, code := identity.Hash(token(t)), identity.Hash(token(t)), identity.Hash(token(t))
	now := time.Now()
	require(t, store.CreateAuthorizationRequest(ctx, rh, oidc.AuthorizationRequest{ClientID: client.ClientID, RedirectURI: client.RedirectURIs[0], Scopes: []string{"openid"}, Prompt: "consent", BrowserHash: bh, CodeChallenge: "challenge", CreatedAt: now, ExpiresAt: now.Add(time.Minute)}))
	require(t, store.ConsentAuthorizationRequest(ctx, rh, bh, actor.TokenHash, true, auditFixture))
	_, err := ids.DB.ExecContext(ctx, `CREATE FUNCTION reject_consent_approval() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'approval failure fixture'; END $$;
 CREATE TRIGGER reject_consent_approval BEFORE INSERT OR UPDATE ON client_consent_approvals FOR EACH ROW EXECUTE FUNCTION reject_consent_approval()`)
	require(t, err)
	if _, err = store.IssueAuthorizationCode(ctx, rh, bh, actor.TokenHash, code, time.Now().Add(50*time.Second)); err == nil {
		t.Fatal("failed approval storage published a code")
	}
	var codes, requests, approvals int
	require(t, ids.DB.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM authorization_codes),(SELECT count(*) FROM authorization_requests),(SELECT count(*) FROM client_consent_approvals)`).Scan(&codes, &requests, &approvals))
	if codes != 0 || requests != 1 || approvals != 0 {
		t.Fatal("approval failure was not atomic", codes, requests, approvals)
	}
	_, err = ids.DB.ExecContext(ctx, `DROP TRIGGER reject_consent_approval ON client_consent_approvals`)
	require(t, err)
	_, err = store.IssueAuthorizationCode(ctx, rh, bh, actor.TokenHash, code, time.Now().Add(50*time.Second))
	require(t, err)
}

func TestPostgresConsentHistoryIsNotAuthorization(t *testing.T) {
	ids, store, ctx, actor, client := databaseOIDC(t)
	require(t, ids.CreatePermission(ctx, actor.TokenHash, "inventory.write", "Edit inventory", auditFixture))
	data, err := ids.AdminData(ctx, actor.TokenHash)
	require(t, err)
	permission := findPermission(t, data, "inventory.write")
	_, err = ids.DB.ExecContext(ctx, `INSERT INTO client_permissions(client_id,permission_id) VALUES($1::uuid,$2::uuid)`, client.ID, permission.ID)
	require(t, err)
	_, err = ids.DB.ExecContext(ctx, `UPDATE clients SET dynamic_registration=true WHERE id=$1::uuid`, client.ID)
	require(t, err)
	for i := 0; i < 2; i++ {
		rh, bh := identity.Hash(token(t)), identity.Hash(token(t))
		now := time.Now()
		require(t, store.CreateAuthorizationRequest(ctx, rh, oidc.AuthorizationRequest{ClientID: client.ClientID, RedirectURI: client.RedirectURIs[0], Scopes: []string{"openid", "inventory.write"}, Prompt: "consent", BrowserHash: bh, CodeChallenge: "challenge", CreatedAt: now, ExpiresAt: now.Add(time.Minute)}))
		if _, err = store.IssueAuthorizationCode(ctx, rh, bh, actor.TokenHash, identity.Hash(token(t)), now.Add(50*time.Second)); !errors.Is(err, oidc.ErrConsentRequired) {
			t.Fatal("saved approval bypassed prompt=consent", i, err)
		}
		require(t, store.ConsentAuthorizationRequest(ctx, rh, bh, actor.TokenHash, true, auditFixture))
		grant, err := store.IssueAuthorizationCode(ctx, rh, bh, actor.TokenHash, identity.Hash(token(t)), time.Now().Add(50*time.Second))
		require(t, err)
		if !slices.Equal(grant.Scopes, []string{"openid"}) {
			t.Fatal("consent granted an unheld application permission", grant.Scopes)
		}
	}
	prior, err := store.ConsentApproval(ctx, actor.TokenHash, client.ID)
	require(t, err)
	if !slices.Equal(prior.Scopes, []string{"openid", "inventory.write"}) {
		t.Fatal("history lost the request actually reviewed", prior)
	}
}
