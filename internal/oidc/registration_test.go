package oidc

import (
	"context"
	"strings"
	"testing"

	"github.com/yellowman/authd/internal/cryptoutil"
	"github.com/yellowman/authd/internal/identity"
)

type registrationFixture struct {
	Store
	scopes []string
	roles  []RoleTemplate
	groups []GroupTemplate
	called bool
}

func (f *registrationFixture) RegisterDynamicClient(_ context.Context, _ []byte, edit ClientEdit, _, _ []byte, scopes []string, roles []RoleTemplate, groups []GroupTemplate, _ identity.Audit) (Client, error) {
	f.called = true
	f.scopes = append([]string(nil), scopes...)
	f.roles = append([]RoleTemplate(nil), roles...)
	f.groups = append([]GroupTemplate(nil), groups...)
	return Client{ClientID: edit.ClientID, Name: edit.Name, RedirectURIs: edit.RedirectURIs}, nil
}

func TestProtectedRegistrationMetadata(t *testing.T) {
	f := &registrationFixture{}
	s := &Service{Store: f, issuer: "https://auth.example.test"}
	token := strings.Repeat("A", 43)
	req := RegistrationRequest{ClientName: "Network Map", RedirectURIs: []string{"https://maps.example.test/auth/callback"}, Scope: "openid profile email bdcmaps.site.read bdcmaps.site.write",
		AuthdRoleTemplates:  []RoleTemplate{{Name: "bdcmaps.viewer", Scopes: []string{"bdcmaps.site.read"}}},
		AuthdGroupTemplates: []GroupTemplate{{Name: "bdcmaps.readers", Roles: []string{"bdcmaps.viewer"}}}}
	response, err := s.RegisterDynamicClient(context.Background(), token, req, identity.Audit{})
	if err != nil {
		t.Fatal(err)
	}
	if !f.called || len(f.scopes) != 2 || len(f.roles) != 1 || len(f.groups) != 1 || !strings.HasPrefix(response.ClientID, "dcr-") || response.ClientSecret == "" || response.RegistrationAccessToken == "" || response.RegistrationClientURI == "" || response.Scope != "bdcmaps.site.read bdcmaps.site.write email openid profile" {
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

func TestAuthdRoleAndGroupTemplateBoundaries(t *testing.T) {
	scopes := []string{"networkmap.site.read", "networkmap.coverage.run"}
	roles := []RoleTemplate{{Name: "networkmap.viewer", Scopes: []string{"networkmap.site.read"}}}
	groups := []GroupTemplate{{Name: "networkmap.engineering", Roles: []string{"networkmap.viewer"}}}
	if err := validateTemplates(roles, groups, scopes); err != nil {
		t.Fatal(err)
	}
	roles[0].Scopes = []string{"system.admin"}
	if err := validateTemplates(roles, groups, scopes); err == nil {
		t.Fatal("role template accepted an unregistered privilege")
	}
	roles[0].Scopes = []string{"networkmap.site.read"}
	groups[0].Roles = []string{"system.admin"}
	if err := validateTemplates(roles, groups, scopes); err == nil {
		t.Fatal("group template accepted an unrelated role")
	}
}

type managedRegistrationFixture struct {
	Store
	client  Client
	updated []string
}

func (f *managedRegistrationFixture) ManagedClient(_ context.Context, clientID string, _ []byte) (Client, string, error) {
	if clientID != f.client.ClientID {
		return Client{}, "", ErrInvalidClient
	}
	return f.client, "networkmap.", nil
}
func (f *managedRegistrationFixture) UpdateManagedClientScopes(_ context.Context, _ string, _, _ []byte, scopes []string, _ identity.Audit) (Client, error) {
	f.updated = append([]string(nil), scopes...)
	f.client.Permissions = f.updated
	return f.client, nil
}
func TestManagedRegistrationScopeReplacement(t *testing.T) {
	f := &managedRegistrationFixture{client: Client{ClientID: "dcr-test", Name: "Network Map", RedirectURIs: []string{"https://map.example.test/callback"}, IdentityScopes: []string{"email", "openid", "profile"}, Permissions: []string{"networkmap.site.read"}}}
	s := &Service{Store: f, issuer: "https://auth.example.test"}
	management, err := cryptoutil.RandomToken(32)
	if err != nil {
		t.Fatal(err)
	}
	req := RegistrationRequest{ClientID: "dcr-test", ClientSecret: strings.Repeat("A", 43), ClientName: "Network Map", RedirectURIs: f.client.RedirectURIs, GrantTypes: []string{"authorization_code"}, ResponseTypes: []string{"code"}, TokenEndpointAuthMethod: "client_secret_basic", Scope: "openid email profile networkmap.site.read networkmap.coverage.run"}
	out, err := s.UpdateManagedRegistration(context.Background(), "dcr-test", management, req, identity.Audit{})
	if err != nil || len(f.updated) != 2 || out.ClientID != "dcr-test" || out.ClientSecret != req.ClientSecret {
		t.Fatalf("managed update: %#v %v", out, err)
	}
	f.updated = nil
	req.Scope += " otherapp.admin"
	if _, err = s.UpdateManagedRegistration(context.Background(), "dcr-test", management, req, identity.Audit{}); err == nil || f.updated != nil {
		t.Fatal("cross-namespace update succeeded")
	}
}
