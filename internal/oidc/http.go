package oidc

import (
	"encoding/json"
	"net/http"
)

type HTTP struct {
	metadata Metadata
}

func NewHTTP(issuer string) *HTTP {
	return &HTTP{metadata: NewMetadata(issuer)}
}

func (h *HTTP) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /.well-known/openid-configuration", h.discovery)
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", h.discovery)
	mux.HandleFunc("GET /jwks.json", h.jwks)
	mux.HandleFunc("GET /authorize", notImplemented("authorization endpoint"))
	mux.HandleFunc("POST /token", notImplementedOAuth("token endpoint"))
	mux.HandleFunc("GET /userinfo", notImplementedOAuth("userinfo endpoint"))
	mux.HandleFunc("POST /userinfo", notImplementedOAuth("userinfo endpoint"))
	mux.HandleFunc("POST /revoke", notImplementedOAuth("revocation endpoint"))
	mux.HandleFunc("GET /logout", notImplemented("logout endpoint"))
	mux.HandleFunc("POST /logout", notImplemented("logout endpoint"))
}

func (h *HTTP) discovery(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_ = json.NewEncoder(w).Encode(h.metadata)
}

func (h *HTTP) jwks(w http.ResponseWriter, _ *http.Request) {
	// Empty until the signing-key store is implemented. Keeping the endpoint
	// present lets client discovery and deployment plumbing be exercised without
	// pretending token issuance is ready.
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=60")
	_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{}})
}

func notImplemented(component string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		http.Error(w, component+" is not implemented in the initial scaffold", http.StatusNotImplemented)
	}
}

func notImplementedOAuth(component string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusNotImplemented)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":             "temporarily_unavailable",
			"error_description": component + " is not implemented in the initial scaffold",
		})
	}
}
