package oidc

import (
	"errors"
	"slices"
	"testing"
)

func TestMetadataBDCMapsCompatibility(t *testing.T) {
	m := NewMetadata("https://auth.example.test/")
	if m.Issuer != "https://auth.example.test" {
		t.Fatalf("issuer %q", m.Issuer)
	}
	for _, scope := range []string{"openid", "profile", "email", "groups"} {
		if !slices.Contains(m.ScopesSupported, scope) {
			t.Fatalf("missing bdcmaps scope %q", scope)
		}
	}
	if !slices.Contains(m.CodeChallengeMethodsSupported, "S256") {
		t.Fatal("S256 PKCE missing")
	}
	if !slices.Contains(m.TokenEndpointAuthMethodsSupported, "client_secret_post") {
		t.Fatal("bdcmaps requires client_secret_post compatibility")
	}
}

func TestClientMFAPolicyOverridesPasswordACRPreference(t *testing.T) {
	client := Client{RequireMFA: true}
	got, err := parseACRValues(ACRPassword, client, []string{"openid"})
	if err != nil {
		t.Fatal(err)
	}
	if got != ACRMFA {
		t.Fatalf("required ACR=%q want %q", got, ACRMFA)
	}
}

func TestACRValuesRequireOpenIDScope(t *testing.T) {
	if _, err := parseACRValues(ACRMFA, Client{}, []string{"profile"}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("acr_values without openid accepted: %v", err)
	}
}
