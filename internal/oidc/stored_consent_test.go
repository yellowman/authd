package oidc

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/yellowman/authd/internal/cryptoutil"
	"github.com/yellowman/authd/internal/identity"
)

func TestStoredOfflineConsentReuse(t *testing.T) {
	_, svc, store, _, sessionRaw, _ := providerFixture(t)
	browser, _ := cryptoutil.RandomToken(32)
	_, challenge := verifierAndChallenge()
	q := auditRequest()
	q.Set("scope", "openid offline_access")
	q.Set("code_challenge", challenge)
	begin := func() string {
		t.Helper()
		flow, _, _, err := svc.BeginAuthorization(context.Background(), q, browser, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return flow
	}
	flow := begin()
	if _, _, err := svc.ContinueAuthorization(context.Background(), flow, browser, sessionRaw, time.Now()); !errors.Is(err, ErrConsentRequired) {
		t.Fatal("first offline request bypassed consent", err)
	}
	if err := store.ConsentAuthorizationRequest(context.Background(), identity.Hash(flow), identity.Hash(browser), identity.Hash(sessionRaw), true, identity.Audit{}); err != nil {
		t.Fatal(err)
	}
	if location, _, err := svc.ContinueAuthorization(context.Background(), flow, browser, sessionRaw, time.Now()); err != nil || !strings.Contains(location, "code=") {
		t.Fatal("explicit approval did not complete", err)
	}
	if location, _, err := svc.ContinueAuthorization(context.Background(), begin(), browser, sessionRaw, time.Now()); err != nil || !strings.Contains(location, "code=") {
		t.Fatal("unchanged request repeated consent", err)
	}
	q.Set("prompt", "consent")
	if _, _, err := svc.ContinueAuthorization(context.Background(), begin(), browser, sessionRaw, time.Now()); !errors.Is(err, ErrConsentRequired) {
		t.Fatal("explicit prompt ignored", err)
	}
	q.Del("prompt")
	q.Set("scope", "openid offline_access email")
	if _, _, err := svc.ContinueAuthorization(context.Background(), begin(), browser, sessionRaw, time.Now()); !errors.Is(err, ErrConsentRequired) {
		t.Fatal("new scope inherited old approval", err)
	}
	q.Set("scope", "openid offline_access")
	q.Set("claims", `{"userinfo":{"name":null}}`)
	if _, _, err := svc.ContinueAuthorization(context.Background(), begin(), browser, sessionRaw, time.Now()); !errors.Is(err, ErrConsentRequired) {
		t.Fatal("new claim target inherited approval", err)
	}
	q.Del("claims")
	q.Set("scope", "openid offline_access email")
	q.Set("prompt", "none")
	location, interaction, err := svc.ContinueAuthorization(context.Background(), begin(), browser, sessionRaw, time.Now())
	u, _ := url.Parse(location)
	if !errors.Is(err, ErrConsentRequired) || interaction || u.Query().Get("error") != "consent_required" {
		t.Fatal("silent request must deny uncovered consent", err)
	}
	q.Del("prompt")
	q.Set("scope", "openid offline_access")
	svc.Store = failedConsentHistoryStore{store}
	if _, _, err := svc.ContinueAuthorization(context.Background(), begin(), browser, sessionRaw, time.Now()); err == nil {
		t.Fatal("failed history read silently issued a code")
	}
}

func TestConsentApprovalTargetsAndEmptyBaseline(t *testing.T) {
	req := AuthorizationRequest{Scopes: []string{"openid", "offline_access"}, Claims: ClaimSelection{IDToken: []string{"name"}}}
	prior := ConsentApproval{Scopes: req.Scopes, IDTokenClaims: []string{"name"}, ApprovedAt: time.Now()}
	if ConsentNeeded(req, "session", prior) {
		t.Fatal("matching stored approval not recognized")
	}
	prior.ApprovedAt = time.Time{}
	if !ConsentNeeded(req, "session", prior) {
		t.Fatal("undated baseline counted as consent")
	}
	prior.ApprovedAt = time.Now()
	prior.IDTokenClaims = nil
	prior.UserInfoClaims = []string{"name"}
	if !ConsentNeeded(req, "session", prior) {
		t.Fatal("UserInfo approval released an ID token claim")
	}
}

func TestFormRedirectEndsNativeSubmission(t *testing.T) {
	for _, target := range []string{"/authorize/resume?flow=example", "https://app.example.test/callback?error=access_denied&state=example"} {
		w := httptest.NewRecorder()
		RedirectFromForm(w, httptest.NewRequest(http.MethodPost, "https://auth.example.test/authorize/consent", nil), target)
		if w.Code != http.StatusOK || w.Header().Get("Location") != "" || formRedirectTarget(t, w.Body.String()) != target {
			t.Fatal("form remained in HTTP redirect chain")
		}
		if w.Header().Get("Cache-Control") != "no-store" || !strings.Contains(w.Header().Get("Content-Security-Policy"), "form-action 'self'") {
			t.Fatal("handoff cached or relaxed form policy")
		}
	}
}

func TestSilentUnapprovedOfflineRequestRedirectsWithoutForm(t *testing.T) {
	h, svc, _, _, session, _ := providerFixture(t)
	q := auditRequest()
	q.Set("scope", "openid offline_access")
	q.Set("prompt", "none")
	req := httptest.NewRequest(http.MethodGet, svc.issuer+"/authorize?"+q.Encode(), nil)
	req.AddCookie(&http.Cookie{Name: h.cookieName("session"), Value: session})
	w := httptest.NewRecorder()
	muxFor(h).ServeHTTP(w, req)
	target, _ := url.Parse(w.Header().Get("Location"))
	if w.Code != http.StatusFound || target.Query().Get("error") != "consent_required" || strings.Contains(w.Body.String(), "/authorize/consent") {
		t.Fatal("prompt none caused interaction instead of a consent-required error", w.Code)
	}
}
