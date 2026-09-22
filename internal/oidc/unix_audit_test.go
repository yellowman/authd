package oidc

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yellowman/authd/internal/requestid"
)

func TestUnixAuditNeverFallsBackToPeerName(t *testing.T) {
	r := httptest.NewRequest("GET", "http://auth.example.test/", nil)
	r.RemoteAddr = "192.0.2.99"
	r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, &net.UnixAddr{Name: "/run/authd/s", Net: "unix"}))
	if audit := auditFromRequest(r); audit.IP != "" {
		t.Fatal("Unix filename entered audit", audit.IP)
	}
	r = r.WithContext(requestid.WithClientIP(r.Context(), ""))
	if audit := auditFromRequest(r); audit.IP != "" {
		t.Fatal("intentional unknown address was overwritten", audit.IP)
	}
	r = r.WithContext(requestid.WithClientIP(r.Context(), "198.51.100.5"))
	if audit := auditFromRequest(r); audit.IP != "198.51.100.5" {
		t.Fatal("trusted middleware address lost", audit.IP)
	}
}
