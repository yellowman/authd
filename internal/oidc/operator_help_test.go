package oidc

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestInteractionFormsPreserveBrowserOrigin(t *testing.T) {
	h, _, _, _, _, _ := providerFixture(t)
	for _, action := range []string{"/authorize/consent", "/logout"} {
		w := httptest.NewRecorder()
		h.interaction(w, httptest.NewRequest("GET", "https://auth.example.test/authorize/resume?flow=private", nil), interactionView{Title: "Review", Action: action, Scopes: []string{"openid", "groups", "offline_access", "app.read"}, ClientName: `<img src=x onerror=alert(1)>`})
		if w.Header().Get("Referrer-Policy") != "origin" {
			t.Errorf("%s: bad referrer policy %q", action, w.Header().Get("Referrer-Policy"))
		}
		if !strings.Contains(w.Body.String(), "Share your assigned authd role names.") || !strings.Contains(w.Body.String(), "Application-defined permission") {
			t.Error("missing scope explanation")
		}
		if strings.Contains(w.Body.String(), "<img") {
			t.Fatal("unsafe client markup")
		}
	}
}
func TestScopeDescriptionsDoNotInventPermissions(t *testing.T) {
	if ScopeDescription("system.admin") != ScopeDescription("unknown.scope") {
		t.Fatal("description inferred authority from unregistered name")
	}
	if ScopeDescription("roles") != ScopeDescription("groups") {
		t.Fatal("aliases described as different role models")
	}
}
