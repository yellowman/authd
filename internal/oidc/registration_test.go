package oidc

import (
	"context"
	"strings"
	"testing"

	"github.com/yellowman/authd/internal/identity"
)

type registrationFixture struct {
	Store
	scopes []string
	called bool
}

func (f *registrationFixture) RegisterDynamicClient(_ context.Context, _ []byte, edit ClientEdit, _ []byte, scopes []string, _ identity.Audit) (Client, error) {
	f.called = true
	f.scopes = append([]string(nil), scopes...)
	return Client{ClientID: edit.ClientID, Name: edit.Name, RedirectURIs: edit.RedirectURIs}, nil
}

func TestProtectedRegistrationMetadata(t *testing.T) {
	f := &registrationFixture{}
	s := &Service{Store: f}
	token := strings.Repeat("A", 43)
	req := RegistrationRequest{ClientName: "BDC Maps", RedirectURIs: []string{"https://maps.example.test/auth/callback"}, Scope: "openid profile email bdcmaps.site.read bdcmaps.site.write"}
	response, err := s.RegisterDynamicClient(context.Background(), token, req, identity.Audit{})
	if err != nil {
		t.Fatal(err)
	}
	if !f.called || len(f.scopes) != 2 || !strings.HasPrefix(response.ClientID, "dcr-") || response.ClientSecret == "" || response.Scope != "bdcmaps.site.read bdcmaps.site.write email openid profile" {
		t.Fatalf("registration did not retain client-only scopes: %#v, %v", response, f.scopes)
	}
	f.called = false
	req.Scope += " system.admin"
	if _, err := s.RegisterDynamicClient(context.Background(), token, req, identity.Audit{}); err == nil || f.called {
		t.Fatal("registered system.admin as an application scope")
	}
	f.called = false
	req.Scope = "openid offline_access bdcmaps.site.read"
	if _, err := s.RegisterDynamicClient(context.Background(), token, req, identity.Audit{}); err == nil || f.called {
		t.Fatal("registered unsupported offline access")
	}
	f.called = false
	req.Scope = "openid bdcmaps.site.read"
	req.RedirectURIs = []string{"https://evil.example.test/cb#fragment"}
	if _, err := s.RegisterDynamicClient(context.Background(), token, req, identity.Audit{}); err == nil || f.called {
		t.Fatal("registered invalid redirect URI")
	}
}

func TestDynamicAuthorizationDoesNotRequireEveryRequestedPermission(t *testing.T) {
	session := identity.Session{Permissions: []string{"bdcmaps.site.read"}}
	requested := []string{"openid", "bdcmaps.site.read", "bdcmaps.site.write"}
	if !subjectCanGrant(session, Client{DynamicRegistration: true}, requested) {
		t.Fatal("dynamic client could not downscope")
	}
	if subjectCanGrant(session, Client{}, requested) {
		t.Fatal("manual client silently changed to partial grant")
	}
}
