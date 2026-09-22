package oidc

import (
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
