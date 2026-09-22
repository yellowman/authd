package config

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// An operator may run tests from a shell with the installed service environment
// loaded. Fixtures must not accidentally consume that listener, secret file or
// duration policy, or a negative case can pass for the wrong reason.
func clearConfigurationEnv(t *testing.T) {
	t.Helper()
	for _, field := range os.Environ() {
		name, _, _ := strings.Cut(field, "=")
		if name == "DATABASE_URL" || strings.HasPrefix(name, "AUTHD_") {
			t.Setenv(name, "")
		}
	}
}

func TestLoadDevelopmentConfig(t *testing.T) {
	clearConfigurationEnv(t)
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
	clearConfigurationEnv(t)
	t.Setenv("AUTHD_ISSUER", "http://auth.example.test")
	t.Setenv("AUTHD_DEVELOPMENT", "false")
	t.Setenv("DATABASE_URL", "postgres://example")
	t.Setenv("AUTHD_MASTER_KEY", base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")))
	if _, err := Load(); err == nil {
		t.Fatal("insecure production issuer was accepted")
	}
}

func TestConfigurationFailsClosed(t *testing.T) {
	clearConfigurationEnv(t)
	for _, c := range []struct{ name, key, value string }{
		{"invalid_boolean", "AUTHD_DEVELOPMENT", "maybe"},
		{"malformed_duration", "AUTHD_SESSION_IDLE_TTL", "twelve hours"},
		{"zero_duration", "AUTHD_SESSION_IDLE_TTL", "0"},
		{"subsecond_cookie", "AUTHD_SESSION_IDLE_TTL", "10ms"},
		{"long_code", "AUTHD_AUTH_CODE_TTL", "61s"},
		{"unsafe_scheme", "AUTHD_ISSUER", "ftp://127.0.0.1"},
		{"userinfo", "AUTHD_ISSUER", "http://name:password@127.0.0.1:8080"},
		{"path", "AUTHD_ISSUER", "http://127.0.0.1:8080/path"},
		{"extra_slash", "AUTHD_ISSUER", "http://127.0.0.1:8080//"},
		{"fragment", "AUTHD_ISSUER", "http://127.0.0.1:8080/#"},
		{"empty_query", "AUTHD_ISSUER", "http://127.0.0.1:8080?"},
		{"remote_dev_origin", "AUTHD_ISSUER", "http://example.test"},
		{"public_dev_bind", "AUTHD_LISTEN", "0.0.0.0:8080"},
		{"bad_port", "AUTHD_LISTEN", "127.0.0.1:99999"},
		{"short_cleanup", "AUTHD_CLEANUP_INTERVAL", "30s"},
		{"short_audit_retention", "AUTHD_AUDIT_RETENTION", "1h"},
		{"ambiguous_key", "AUTHD_MASTER_KEY_FILE", "/unused"},
	} {
		t.Run(c.name, func(t *testing.T) {
			for _, name := range []string{"AUTHD_MASTER_KEY_FILE", "AUTHD_ACCESS_TOKEN_TTL", "AUTHD_AUTH_CODE_TTL", "AUTHD_SESSION_IDLE_TTL", "AUTHD_SESSION_ABSOLUTE_TTL", "AUTHD_REFRESH_IDLE_TTL", "AUTHD_REFRESH_ABSOLUTE_TTL", "AUTHD_CLEANUP_INTERVAL", "AUTHD_AUDIT_RETENTION", "AUTHD_TRUSTED_PROXIES"} {
				t.Setenv(name, "")
			}
			t.Setenv("AUTHD_ISSUER", "http://127.0.0.1:8080")
			t.Setenv("AUTHD_LISTEN", "127.0.0.1:8080")
			t.Setenv("AUTHD_DEVELOPMENT", "true")
			t.Setenv("DATABASE_URL", "postgres://localhost/test")
			t.Setenv("AUTHD_MASTER_KEY", base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")))
			t.Setenv(c.key, c.value)
			if _, err := Load(); err == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
}

func TestTrustedProxyConfiguration(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want int
		ok   bool
	}{
		{"", 0, true},
		{"127.0.0.1/32, 10.0.0.0/8, ::1/128", 3, true},
		{"127.0.0.1/32,127.0.0.1/32", 0, false},
		{"0.0.0.0/0", 0, false},
		{"not-a-prefix", 0, false},
	} {
		got, err := trustedProxies(tc.raw)
		if (err == nil) != tc.ok || (err == nil && len(got) != tc.want) {
			t.Fatalf("trustedProxies(%q) len=%d err=%v", tc.raw, len(got), err)
		}
	}
}

func TestMasterKeyFilePermissions(t *testing.T) {
	clearConfigurationEnv(t)
	path := filepath.Join(t.TempDir(), "master.key")
	t.Setenv("AUTHD_MASTER_KEY", "")
	t.Setenv("AUTHD_MASTER_KEY_FILE", path)
	if err := os.WriteFile(path, []byte("0123456789abcdef0123456789abcdef"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := masterKeyFromEnv(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := masterKeyFromEnv(); err == nil {
		t.Fatal("world-readable master key accepted")
	}
}
