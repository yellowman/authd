package config

import (
	"encoding/base64"
	"testing"
)

func TestLoadUnixSocketAddress(t *testing.T) {
	clearConfigurationEnv(t)
	for _, addr := range []string{"unix:/run/authd/authd.sock", "/run/authd/authd.sock"} {
		t.Run(addr, func(t *testing.T) {
			t.Setenv("AUTHD_ISSUER", "https://auth.example.test")
			t.Setenv("AUTHD_DEVELOPMENT", "false")
			t.Setenv("AUTHD_LISTEN", addr)
			t.Setenv("DATABASE_URL", "postgres://example")
			t.Setenv("AUTHD_MASTER_KEY_FILE", "")
			t.Setenv("AUTHD_MASTER_KEY", base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")))
			if _, err := Load(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestUnixListenerOptionsFailClosed(t *testing.T) {
	clearConfigurationEnv(t)
	for _, tc := range []struct {
		name, address, mode, group, trust, issuer, development string
		ok                                                     bool
	}{
		{"unix_defaults", "unix:/run/authd/authd.sock", "", "", "", "https://auth.example.test", "false", true},
		{"explicit_group", "/run/authd/authd.sock", "0660", "authd_proxy", "true", "https://auth.example.test", "false", true},
		{"dev_unix", "unix:/tmp/authd.sock", "0600", "", "", "http://localhost:8080", "true", true},
		{"remote_dev", "unix:/tmp/authd.sock", "0600", "", "", "http://outside.test", "true", false},
		{"relative", "unix:authd.sock", "", "", "", "https://auth.example.test", "false", false},
		{"abstract", "unix:@authd", "", "", "", "https://auth.example.test", "false", false},
		{"url", "unix:///run/authd/authd.sock", "", "", "", "https://auth.example.test", "false", false},
		{"traversal", "unix:/run/authd/../other.sock", "", "", "", "https://auth.example.test", "false", false},
		{"world_mode", "unix:/run/authd/authd.sock", "0666", "", "", "https://auth.example.test", "false", false},
		{"exec_mode", "unix:/run/authd/authd.sock", "0770", "", "", "https://auth.example.test", "false", false},
		{"bad_boolean", "unix:/run/authd/authd.sock", "", "", "yesplease", "https://auth.example.test", "false", false},
		{"tcp_unix_trust", "127.0.0.1:8080", "", "", "true", "https://auth.example.test", "false", false},
		{"tcp_unix_mode", "127.0.0.1:8080", "0660", "", "", "https://auth.example.test", "false", false},
		{"tcp_unix_group", "127.0.0.1:8080", "", "authd_proxy", "", "https://auth.example.test", "false", false},
		{"tcp_unchanged", "127.0.0.1:8080", "", "", "", "https://auth.example.test", "false", true},
		{"tcp_zero_port", "127.0.0.1:0", "", "", "", "https://auth.example.test", "false", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("AUTHD_ISSUER", tc.issuer)
			t.Setenv("AUTHD_DEVELOPMENT", tc.development)
			t.Setenv("AUTHD_LISTEN", tc.address)
			t.Setenv("AUTHD_UNIX_MODE", tc.mode)
			t.Setenv("AUTHD_UNIX_GROUP", tc.group)
			t.Setenv("AUTHD_TRUST_UNIX_PROXY", tc.trust)
			t.Setenv("DATABASE_URL", "postgres://example")
			t.Setenv("AUTHD_MASTER_KEY_FILE", "")
			t.Setenv("AUTHD_MASTER_KEY", base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")))
			cfg, err := Load()
			if (err == nil) != tc.ok {
				t.Fatalf("accepted=%v err=%v", tc.ok, err)
			}
			if tc.ok && tc.mode == "" && cfg.UnixSocketMode != 0600 {
				t.Fatal("unsafe default mode")
			}
		})
	}
}
