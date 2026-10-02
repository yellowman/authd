package oidc

import (
	"bytes"
	"html/template"
	"net/http"
)

var formRedirectTemplate = template.Must(template.New("form-redirect").Parse(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="refresh" content="0;url={{.}}"><title>Continue sign-in · authd</title><link rel="stylesheet" href="/static/app.css"></head><body class="auth-page"><main class="auth-frame"><section class="auth-panel"><h2>Continue sign-in</h2><p>Continuing to the application.</p><a class="button button-primary" href="{{.}}">Continue</a></section></main></body></html>`))

// RedirectFromForm ends a native form submission at a same-origin document.
// Chrome applies form-action to subsequent HTTP redirects, including a later
// application's callback. Document navigation starts a fresh redirect chain.
// Callers supply a validated local path or registered application redirect.
func RedirectFromForm(w http.ResponseWriter, r *http.Request, target string) {
	var body bytes.Buffer
	if err := formRedirectTemplate.Execute(&body, target); err != nil {
		http.Error(w, "Unable to continue sign-in", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	_, _ = w.Write(body.Bytes())
}
