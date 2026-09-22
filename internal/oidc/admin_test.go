package oidc

import (
	"testing"
	"time"
)

func validClientEditFixture() ClientEdit {
	return ClientEdit{
		ClientID: "bdcmaps", Name: "BDC Maps", Type: "confidential", Enabled: true,
		AccessTokenTTL: 5 * time.Minute,
		RedirectURIs:   []string{"https://bdc.example.test/auth/callback"},
		LogoutURIs:     []string{"https://bdc.example.test/"},
		IdentityScopes: []string{"openid", "profile", "email", "groups"},
	}
}

func TestClientRegistrationURIValidation(t *testing.T) {
	good := validClientEditFixture()
	if _, err := validateClientEdit(good); err != nil {
		t.Fatalf("valid client rejected: %v", err)
	}
	loopback := good
	loopback.RedirectURIs = []string{"http://127.0.0.1:8080/callback", "http://localhost:8081/callback"}
	if _, err := validateClientEdit(loopback); err != nil {
		t.Fatalf("loopback development redirects rejected: %v", err)
	}

	cases := []struct {
		name string
		edit ClientEdit
	}{
		{"external-http", func() ClientEdit { e := good; e.RedirectURIs = []string{"http://bdc.example.test/callback"}; return e }()},
		{"fragment", func() ClientEdit {
			e := good
			e.RedirectURIs = []string{"https://bdc.example.test/callback#fragment"}
			return e
		}()},
		{"duplicate", func() ClientEdit {
			e := good
			e.RedirectURIs = []string{good.RedirectURIs[0], good.RedirectURIs[0]}
			return e
		}()},
		{"unknown-scope", func() ClientEdit { e := good; e.IdentityScopes = append(e.IdentityScopes, "mystery"); return e }()},
		{"refresh-without-offline", func() ClientEdit { e := good; e.RefreshTokensEnabled = true; return e }()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := validateClientEdit(tc.edit); err == nil {
				t.Fatal("invalid client registration accepted")
			}
		})
	}
}

func TestRefreshClientRequiresOfflineAccess(t *testing.T) {
	e := validClientEditFixture()
	e.RefreshTokensEnabled = true
	e.IdentityScopes = append(e.IdentityScopes, "offline_access")
	if _, err := validateClientEdit(e); err != nil {
		t.Fatalf("refresh-capable client rejected: %v", err)
	}
}
