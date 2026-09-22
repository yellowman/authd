package config

import (
	"encoding/base64"
	"testing"
)

func TestLoadDevelopmentConfig(t *testing.T) {
	t.Setenv("AUTHD_ISSUER", "http://127.0.0.1:8080/")
	t.Setenv("AUTHD_DEVELOPMENT", "true")
	t.Setenv("DATABASE_URL", "postgres://authd:authd@127.0.0.1/authd")
	t.Setenv("AUTHD_MASTER_KEY", base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")))
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Issuer != "http://127.0.0.1:8080" {
		t.Fatalf("issuer %q", cfg.Issuer)
	}
}

func TestLoadRequiresHTTPSOutsideDevelopment(t *testing.T) {
	t.Setenv("AUTHD_ISSUER", "http://auth.example.test")
	t.Setenv("AUTHD_DEVELOPMENT", "false")
	t.Setenv("DATABASE_URL", "postgres://example")
	t.Setenv("AUTHD_MASTER_KEY", base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")))
	if _, err := Load(); err == nil {
		t.Fatal("insecure production issuer was accepted")
	}
}
