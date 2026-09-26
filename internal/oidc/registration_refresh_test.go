package oidc

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/yellowman/authd/internal/identity"
)

func TestDynamicRefreshOptIn(t *testing.T) {
	for _, tc := range []struct {
		name                    string
		grants                  []string
		offline, valid, refresh bool
	}{
		{"default", nil, false, true, false},
		{"code only", []string{"authorization_code"}, false, true, false},
		{"opt in", []string{"authorization_code", "refresh_token"}, true, true, true},
		{"unordered", []string{"refresh_token", "authorization_code"}, true, true, true},
		{"offline alone", nil, true, false, false},
		{"grant alone", []string{"authorization_code", "refresh_token"}, false, false, false},
		{"no code", []string{"refresh_token"}, true, false, false},
		{"duplicate", []string{"authorization_code", "refresh_token", "refresh_token"}, true, false, false},
		{"unknown", []string{"authorization_code", "client_credentials"}, false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &registrationFixture{}
			s := &Service{Store: f, issuer: "https://auth.example.test"}
			req := RegistrationRequest{ClientName: "Inventory", RedirectURIs: []string{"https://inventory.example.test/callback"}, Scope: "openid inventory.read", GrantTypes: tc.grants}
			if tc.offline {
				req.Scope += " offline_access"
			}
			out, err := s.RegisterDynamicClient(context.Background(), strings.Repeat("A", 43), req, identity.Audit{})
			if (err == nil) != tc.valid || f.called != tc.valid {
				t.Fatalf("valid=%v called=%v err=%v", tc.valid, f.called, err)
			}
			if !tc.valid {
				return
			}
			if f.edit.RefreshTokensEnabled != tc.refresh || slices.Contains(out.GrantTypes, "refresh_token") != tc.refresh || f.edit.AccessTokenTTL != 5*time.Minute {
				t.Fatal("refresh policy or access-token default did not round trip")
			}
		})
	}
}

func TestManagedRefreshOptInAndOut(t *testing.T) {
	f := &managedRegistrationFixture{client: Client{ClientID: "dcr-test", Name: "Inventory", RedirectURIs: []string{"https://inventory.example.test/callback"}, IdentityScopes: []string{"email", "openid"}, Permissions: []string{"networkmap.read"}, TokenEndpointAuthMethod: "client_secret_basic"}}
	s := &Service{Store: f, issuer: "https://auth.example.test"}
	secret := strings.Repeat("A", 43)
	req := RegistrationRequest{ClientID: f.client.ClientID, ClientName: f.client.Name, ClientSecret: secret, RedirectURIs: f.client.RedirectURIs, GrantTypes: []string{"authorization_code", "refresh_token"}, ResponseTypes: []string{"code"}, TokenEndpointAuthMethod: "client_secret_basic", Scope: "openid email offline_access networkmap.read"}
	for _, enabled := range []bool{true, false} {
		if !enabled {
			req.GrantTypes = []string{"authorization_code"}
			req.Scope = "openid email networkmap.read"
		}
		out, err := s.UpdateManagedRegistration(context.Background(), req.ClientID, secret, req, identity.Audit{})
		if err != nil {
			t.Fatal(err)
		}
		get, err := s.ManagedRegistration(context.Background(), req.ClientID, secret)
		if err != nil || slices.Contains(out.GrantTypes, "refresh_token") != enabled || slices.Contains(strings.Fields(get.Scope), "offline_access") != enabled || f.client.RefreshTokensEnabled != enabled {
			t.Fatalf("refresh update/read mismatch: %v", err)
		}
	}
	req.Scope = "openid networkmap.read"
	if _, err := s.UpdateManagedRegistration(context.Background(), req.ClientID, secret, req, identity.Audit{}); err == nil {
		t.Fatal("changed a non-offline identity scope")
	}
}
