package web

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/yellowman/authd/internal/requestid"
)

func TestUnixPeerNameIsNotAClientIP(t *testing.T) {
	s, _, _ := fixture(t, false)
	r := httptest.NewRequest("GET", "http://auth.example.test/", nil)
	// A Unix client can bind a filename which looks like an IP. Its name is
	// not a network address, even if ParseAddr accepts the string.
	r.RemoteAddr = "192.0.2.77"
	r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, &net.UnixAddr{Name: "/run/authd/authd.sock", Net: "unix"}))
	h := s.clientAddress(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := requestid.ClientIP(r.Context()); got != "" {
			t.Fatalf("Unix peer name became client IP: %q", got)
		}
	}))
	h.ServeHTTP(httptest.NewRecorder(), r)
}

func TestUnixProxyTrustAndForwarding(t *testing.T) {
	for _, tc := range []struct {
		name        string
		unix, trust bool
		peer        string
		forwarded   []string
		want        string
	}{
		{"untrusted_unix", true, false, "@", []string{"198.51.100.22"}, ""},
		{"trusted_unix", true, true, "@", []string{"198.51.100.22"}, "198.51.100.22"},
		{"ipv6", true, true, "", []string{"2001:db8::22"}, "2001:db8::22"},
		{"mapped_ip", true, true, "", []string{"::ffff:198.51.100.22"}, "198.51.100.22"},
		{"missing", true, true, "@", nil, ""},
		{"malformed", true, true, "@", []string{"secret-not-an-ip"}, ""},
		{"malformed_chain", true, true, "@", []string{"bad, 198.51.100.22"}, ""},
		{"duplicate", true, true, "@", []string{"192.0.2.1", "198.51.100.22"}, ""},
		{"rightmost_only", true, true, "@", []string{"192.0.2.1, 198.51.100.22"}, "198.51.100.22"},
		{"zone_rejected", true, true, "@", []string{"fe80::1%eth0"}, ""},
		{"unix_does_not_trust_tcp", false, true, "192.0.2.10:1234", []string{"198.51.100.22"}, "192.0.2.10"},
		{"name_not_identity", true, false, "127.0.0.1:54321", []string{"198.51.100.22"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "http://auth.example.test/", nil)
			r.RemoteAddr = tc.peer
			if tc.unix {
				r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, &net.UnixAddr{Name: "/run/authd/authd.sock", Net: "unix"}))
			}
			for _, val := range tc.forwarded {
				r.Header.Add("X-Forwarded-For", val)
			}
			if got := resolvedClientIP(r, nil, tc.trust); got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

func TestUnixForwardedChainBoundsAndExtraProxyHops(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	for _, tc := range []struct {
		name, header string
		trust        bool
		want         string
	}{
		{"extra_proxy", "198.51.100.9, 127.0.0.1", true, "198.51.100.9"},
		{"cidr_not_unix_trust", "198.51.100.9, 127.0.0.1", false, ""},
		{"too_many_hops", strings.Repeat("127.0.0.1,", 32) + "127.0.0.1", true, ""},
		{"too_many_bytes", strings.Repeat(" ", 2049) + "198.51.100.9", true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "http://auth.example.test/", nil)
			r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, &net.UnixAddr{Name: "/run/authd/s", Net: "unix"}))
			r.Header.Set("X-Forwarded-For", tc.header)
			if got := resolvedClientIP(r, trusted, tc.trust); got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}
