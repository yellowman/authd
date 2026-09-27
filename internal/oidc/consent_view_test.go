package oidc

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/yellowman/authd/internal/identity"
)

func TestConsentComparisonTracksChanges(t *testing.T) {
	prior := ConsentApproval{Scopes: []string{"openid", "inventory.assets.read", "email"}, IDTokenClaims: []string{"name"}, ApprovedAt: time.Now()}
	view := compareConsent([]string{"offline_access", "inventory.assets.read", "openid", "openid"}, []string{"UserInfo: name"}, prior)
	if !view.HasPrior || !view.HasChanges || view.NewCount != 2 || view.ApprovedCount != 2 || view.NotRequestedCount != 2 {
		t.Fatal("incorrect change counts", view)
	}
	if view.NewScopes[0].Scope != "offline_access" || view.NewScopes[0].Description == "" || !slices.Equal(view.NewClaims, []string{"UserInfo: name"}) || !slices.Equal(view.NotRequestedClaims, []string{"ID token: name"}) {
		t.Fatal("scope or claim target change lost", view)
	}
	unchanged := compareConsent(prior.Scopes, []string{"ID token: name"}, prior)
	if unchanged.HasChanges || unchanged.NewCount != 0 || unchanged.NotRequestedCount != 0 || unchanged.ApprovedCount != 4 {
		t.Fatal("unchanged access is reported as new", unchanged)
	}
	first := compareConsent([]string{"openid"}, nil, ConsentApproval{Scopes: []string{"openid"}})
	if first.HasPrior || first.NewCount != 1 || first.ApprovedCount != 0 {
		t.Fatal("unrecorded history inferred approval", first)
	}
}

func TestConsentScopeHierarchyKeepsExactScopes(t *testing.T) {
	added, _, _ := consentDiff([]string{"inventory", "inventory.assets.read", "inventory.assets.write", "profile"}, nil)
	nodes := groupConsentScopes(added, true)
	if len(nodes) != 2 || nodes[0].Label != "inventory" || nodes[0].Count != 3 || nodes[0].Scope != "inventory" || !nodes[0].Open {
		t.Fatal("root scope or hierarchy lost", nodes)
	}
	assets := nodes[0].Children[0]
	if assets.Label != "assets" || assets.Scope != "" || len(assets.Children) != 2 || assets.Children[0].Scope != "inventory.assets.read" {
		t.Fatal("group treated as a grant or leaf lost", assets)
	}
	if assets.Children[0].Description != "" || nodes[1].Description != ScopeDescription("profile") {
		t.Fatal("generic scope help repeated or identity scope help omitted")
	}
}

func TestConsentPresentationIsWideGroupedAndEscaped(t *testing.T) {
	h, _, _, _, _, _ := providerFixture(t)
	view := interactionView{Title: "Authorize application", Action: "/authorize/consent", ClientName: `<img src=x onerror=alert(1)>`, Username: `<script>bad</script>`, Scopes: []string{"openid", "offline_access", "inventory.assets.read"}, Offline: true, PreviousApproval: ConsentApproval{Scopes: []string{"openid", "inventory.assets.read", "email"}, ApprovedAt: time.Now()}}
	w := httptest.NewRecorder()
	h.interaction(w, httptest.NewRequest("GET", "/authorize/resume", nil), view)
	body := w.Body.String()
	for _, want := range []string{`class="consent-frame"`, "New access", "Previously approved", "Not requested this time", "Existing tokens are not revoked", "Offline access allows", "&lt;img", "&lt;script&gt;"} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(body, `<img`) || strings.Contains(body, `<script>`) || strings.Contains(body, `class="auth-frame"`) || strings.Contains(body, "Application-defined permission;") {
		t.Fatal("unsafe markup, narrow frame or repeated generic scope help retained")
	}
	if strings.Count(body, "Application permissions are limited by your roles.") != 1 || strings.Count(body, `name="decision" value="allow"`) != 1 {
		t.Fatal("duplicated guidance or consent controls")
	}
	if strings.Index(body, "New access") > strings.Index(body, "Previously approved") || strings.Contains(body, `class="consent-section consent-history" open`) {
		t.Fatal("changes not prominent or history expanded by default")
	}
	view.PreviousApproval.Scopes = view.Scopes
	w = httptest.NewRecorder()
	h.interaction(w, httptest.NewRequest("GET", "/authorize/resume", nil), view)
	if !strings.Contains(w.Body.String(), "No access changes.") || !strings.Contains(w.Body.String(), "Allow and continue") {
		t.Fatal("unchanged explicit consent lost its decision")
	}
}

type failedConsentHistoryStore struct{ *fakeOIDCStore }

func (f failedConsentHistoryStore) ConsentApproval(context.Context, []byte, string) (ConsentApproval, error) {
	return ConsentApproval{}, errors.New("history unavailable")
}

func TestConsentHistoryDoesNotBypassPromptOrHideReadFailure(t *testing.T) {
	h, svc, store, _, raw, _ := providerFixture(t)
	session := store.sessions[hashKey(identity.Hash(raw))]
	store.approvals[session.User.ID+"\x00"+store.client.ID] = ConsentApproval{Scopes: []string{"openid", "offline_access"}, ApprovedAt: time.Now()}
	_, challenge := verifierAndChallenge()
	q := url.Values{"response_type": {"code"}, "client_id": {store.client.ClientID}, "redirect_uri": {store.client.RedirectURIs[0]}, "scope": {"openid offline_access"}, "prompt": {"consent"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}}
	for _, failure := range []bool{false, true} {
		if failure {
			svc.Store = failedConsentHistoryStore{store}
		}
		r := httptest.NewRequest("GET", svc.issuer+"/authorize?"+q.Encode(), nil)
		r.AddCookie(&http.Cookie{Name: "__Host-authd_session", Value: raw})
		w := httptest.NewRecorder()
		muxFor(h).ServeHTTP(w, r)
		if !failure {
			if w.Code != 200 || !strings.Contains(w.Body.String(), "No access changes.") || !strings.Contains(w.Body.String(), "/authorize/consent") {
				t.Fatal("saved approval bypassed explicit consent", w.Code, w.Body.String())
			}
		} else if w.Code < 500 || strings.Contains(w.Body.String(), "Allow and continue") {
			t.Fatal("failed history read presented an invented baseline", w.Code)
		}
	}
}
