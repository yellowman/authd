package web

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/yellowman/authd/internal/identity"
	"github.com/yellowman/authd/internal/oidc"
)

// Text is not authorization. Exercise the real admin entry point so the new
// default view cannot accidentally become a public operational information page.
func TestOperatorGuideUsesAdminAuthorization(t *testing.T) {
	for _, admin := range []bool{false, true} {
		s, h, m := fixture(t, admin)
		for _, path := range []string{"/admin/", "/admin/?view=guide"} {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, request(s, m, "GET", path, nil, true))
			if !admin {
				if w.Code != http.StatusForbidden {
					t.Fatalf("unprivileged guide: %d", w.Code)
				}
				continue
			}
			if w.Code != 200 {
				t.Fatalf("guide: %d", w.Code)
			}
			if m.adminCalls != 0 {
				t.Error("static guide scanned the full admin catalog")
			}
			for _, text := range []string{"Start here", "Adding an app to authd", "Decide how the app will use access information", "When something fails", "no separate per-client allowed-users list", "system-admin"} {
				if !strings.Contains(w.Body.String(), text) {
					t.Errorf("guide missing %q", text)
				}
			}
			if strings.Contains(w.Body.String(), `action="/admin/users/create"`) {
				t.Error("default guide is not a user-creation form")
			}
		}
	}
}

func TestOperatorHelpRendersAcrossSections(t *testing.T) {
	s, h, m := fixture(t, true)
	for view, text := range map[string]string{
		"users":       "Users are people, not applications.",
		"roles":       "A role is a bundle you assign to people.",
		"groups":      "A group grants its roles to its members.",
		"permissions": "A permission names an operation the app understands.",
		"sessions":    "These are sign-ins at authd, not every app’s session.",
		"audit":       "Audit records show what authd did.",
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, request(s, m, "GET", "/admin/?view="+view, nil, true))
		if w.Code != 200 || !strings.Contains(w.Body.String(), text) {
			t.Errorf("%s help failed: %d", view, w.Code)
		}
	}
	m.snapshot.Users[0].Username = `<script>alert("user")</script>`
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request(s, m, "GET", "/admin/?user="+userID, nil, true))
	if w.Code != 200 || strings.Contains(w.Body.String(), "<script>") || !strings.Contains(w.Body.String(), "Subject (<code>sub</code>)") {
		t.Fatal("subject/help must render without trusting profile HTML")
	}
}

func TestGroupAccessPresentation(t *testing.T) {
	s, h, m := fixture(t, true)
	m.snapshot.Users[0].Groups = []string{"network.operations"}
	m.snapshot.Users[0].EffectiveRoles = []string{"network.operator"}
	m.snapshot.Groups = []identity.Group{{ID: "00000000-0000-4000-8000-000000000002", Name: "network.operations", RoleIDs: []string{userID}, UserIDs: []string{userID}, Roles: []string{"network.operator"}}}
	for _, tc := range []struct {
		path string
		want []string
	}{
		{"/admin/?view=users", []string{"Effective roles: network.operator", "Direct: None", "Groups: network.operations"}},
		{"/admin/?view=groups", []string{"Roles granted", "network.operator", "A group grants its roles to its members."}},
		{"/admin/?group=00000000-0000-4000-8000-000000000002", []string{"Deleting this group removes its membership and group-derived role grants", "Already-issued access tokens remain valid until expiry"}},
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, request(s, m, "GET", tc.path, nil, true))
		if w.Code != 200 {
			t.Fatalf("%s: %d: %s", tc.path, w.Code, w.Body.String())
		}
		for _, want := range tc.want {
			if !strings.Contains(w.Body.String(), want) {
				t.Errorf("%s missing %q", tc.path, want)
			}
		}
	}
}

type helpClientStore struct {
	oidc.Store
	client oidc.Client
}

func (m *helpClientStore) AdminClients(context.Context, []byte) ([]oidc.Client, error) {
	return []oidc.Client{m.client}, nil
}
func (m *helpClientStore) CreateClient(_ context.Context, _ []byte, e oidc.ClientEdit, secret []byte, _ identity.Audit) (oidc.Client, error) {
	m.client = oidc.Client{ID: userID, ClientID: e.ClientID, Name: e.Name, Type: e.Type, Enabled: e.Enabled, SecretHash: secret, IdentityScopes: e.IdentityScopes, RedirectURIs: e.RedirectURIs, AccessTokenTTL: e.AccessTokenTTL}
	return m.client, nil
}
func (m *helpClientStore) AdminSigningKeys(context.Context, []byte) ([]oidc.SigningKey, error) {
	return nil, nil
}
func helpProvider(t *testing.T, s *Server) *helpClientStore {
	t.Helper()
	m := &helpClientStore{client: oidc.Client{ID: userID, ClientID: "inventory", Name: "Inventory", Type: "confidential", Enabled: true, RedirectURIs: []string{"https://inventory.example.test/auth/callback"}, IdentityScopes: []string{"openid", "profile", "email", "groups"}, AccessTokenTTL: 5 * time.Minute}}
	svc, err := oidc.NewService(m, s.auth, s.cfg.Issuer, []byte("0123456789abcdef0123456789abcdef"), time.Minute, 24*time.Hour, 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	s.oidc = oidc.NewHTTP(svc, s.cfg.Issuer, false)
	return m
}
func TestClientConnectionDetailsAreSavedValuesNotHostInput(t *testing.T) {
	s, _, m := fixture(t, true)
	store := helpProvider(t, s)
	h, _ := s.Handler()
	store.client.Name = `<script>alert("client")</script>`
	w := httptest.NewRecorder()
	req := request(s, m, "GET", "/admin/?client="+userID, nil, true)
	req.Host = "attacker.invalid"
	h.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	for _, text := range []string{"Copy into", s.cfg.Issuer, "https://inventory.example.test/auth/callback", "openid profile email groups", "client_secret_post", "client_secret_basic"} {
		if !strings.Contains(w.Body.String(), text) {
			t.Errorf("missing %s", text)
		}
	}
	if strings.Contains(w.Body.String(), "attacker.invalid") || strings.Contains(w.Body.String(), "<script>") {
		t.Fatal("untrusted authority or HTML in instructions")
	}
	for _, view := range []string{"clients", "keys"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, request(s, m, "GET", "/admin/?view="+view, nil, true))
		if w.Code != 200 {
			t.Errorf("%s: %d", view, w.Code)
		}
	}
}
func TestCreatedSecretPageIncludesConnectionInstructions(t *testing.T) {
	s, _, m := fixture(t, true)
	helpProvider(t, s)
	h, _ := s.Handler()
	values := url.Values{"csrf_token": {s.auth.CSRF(m.raw, "session")}, "client_id": {"inventory"}, "name": {"Inventory"}, "client_type": {"confidential"}, "enabled": {"on"}, "access_token_ttl": {"300"}, "redirect_uris": {"https://inventory.example.test/auth/callback"}, "identity_scopes": {"openid", "profile", "email", "groups"}}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request(s, m, "POST", "/admin/clients/create", values, true))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Copy into Inventory") || !strings.Contains(w.Body.String(), "protected runtime configuration") {
		t.Fatal(w.Code, w.Body.String())
	}
}
func TestFormResponsesPreserveOriginForNativePosts(t *testing.T) {
	s, h, m := fixture(t, true)
	for _, path := range []string{"/setup", "/login", "/account", "/admin/"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, request(s, m, "GET", path, nil, true))
		if w.Code != 200 || w.Header().Get("Referrer-Policy") != "origin" {
			t.Errorf("%s: status=%d policy=%q", path, w.Code, w.Header().Get("Referrer-Policy"))
		}
	}
}
func TestOpaqueOrForeignOriginStillRefusedWithValidCSRF(t *testing.T) {
	for _, origin := range []string{"null", "https://elsewhere.example.test"} {
		s, h, m := fixture(t, true)
		v := url.Values{"name": {"app.read"}, "csrf_token": {s.auth.CSRF(m.raw, "session")}}
		req := request(s, m, "POST", "/admin/permissions/create", v, true)
		req.Header.Set("Origin", origin)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != 403 || m.mutationCalls != 0 {
			t.Errorf("accepted origin %q", origin)
		}
	}
}
func TestGuideLinksPointToRealSections(t *testing.T) {
	s, _, m := fixture(t, true)
	d := s.data("Guide")
	d.View = "guide"
	d.Session = m.session
	d.Admin = m.snapshot
	s.startDocument(&d)
	var b bytes.Buffer
	if err := s.templates.ExecuteTemplate(&b, "admin.html", d); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"doc-1-decide-how-the-app-will-use-access-information", "doc-4-register-the-application", "doc-when-something-fails"} {
		if !strings.Contains(b.String(), `id="`+id+`"`) {
			t.Errorf("missing guide anchor %s", id)
		}
	}
}

func TestFormFailuresOfferDifferentRecoveryWithoutWeakeningGuards(t *testing.T) {
	s, h, m := fixture(t, true)
	for _, tc := range []struct{ origin, csrf, want string }{
		{"null", s.auth.CSRF(m.raw, "session"), "Referrer-Policy"},
		{s.cfg.Issuer, "", "Reload the page"},
	} {
		v := url.Values{"name": {"app.read"}, "csrf_token": {tc.csrf}}
		req := request(s, m, "POST", "/admin/permissions/create", v, true)
		req.Header.Set("Origin", tc.origin)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != 403 || m.mutationCalls != 0 || !strings.Contains(w.Body.String(), tc.want) {
			t.Errorf("wrong refusal/recovery: %d %s", w.Code, w.Body.String())
		}
	}
}

// A client's ID is data, not a dispatch key for application-specific UI help.
func TestClientHelpDoesNotSpecialCaseAnApplication(t *testing.T) {
	s, _, m := fixture(t, true)
	store := helpProvider(t, s)
	store.client.Name = "Example application"
	h, err := s.Handler()
	if err != nil {
		t.Fatal(err)
	}
	render := func(id string) string {
		store.client.ClientID = id
		w := httptest.NewRecorder()
		h.ServeHTTP(w, request(s, m, "GET", "/admin/?client="+userID, nil, true))
		if w.Code != 200 {
			t.Fatalf("client page: %d", w.Code)
		}
		return strings.ReplaceAll(w.Body.String(), id, "CLIENT-ID")
	}
	if render("bdcmaps") != render("ordinary-app") {
		t.Fatal("application ID changes help, links, or UI beyond the saved identifier")
	}
}
