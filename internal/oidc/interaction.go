package oidc

import (
	"bytes"
	"crypto/hmac"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"strings"

	"github.com/yellowman/authd/internal/cryptoutil"
	"github.com/yellowman/authd/internal/identity"
)

type interactionView struct {
	Title, Description, ClientName, Username, Action, CSRF, Flow string
	Scopes                                                       []string
	Claims                                                       []string
	Fields                                                       map[string]string
	Offline                                                      bool
}

var interactionTemplate = template.Must(template.New("interaction").Funcs(template.FuncMap{"scopeHelp": ScopeDescription}).Parse(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{{.Title}} · authd</title><link rel="stylesheet" href="/static/app.css"></head><body class="auth-page"><main class="auth-frame"><section class="auth-brand"><div class="mark" aria-hidden="true">A</div><div><div class="eyebrow">IDENTITY SERVICE</div><h1>authd</h1></div></section><section class="auth-panel"><div class="section-rule"></div><h2>{{.Title}}</h2><p>{{.Description}}</p><p><strong>{{.ClientName}}</strong>{{if .Username}} · {{.Username}}{{end}}</p>{{if .Scopes}}<h3>Requested access</h3><ul>{{range .Scopes}}<li><code>{{.}}</code><span class="block muted">{{scopeHelp .}}</span></li>{{end}}</ul>{{end}}{{if .Claims}}<h3>Additional identity claims</h3><ul>{{range .Claims}}<li><code>{{.}}</code></li>{{end}}</ul>{{end}}{{if .Offline}}<p class="message">This application requests access while you are not signed in. Revoking the associated provider session also revokes its refresh grants.</p>{{end}}<form method="post" action="{{.Action}}" class="stack-lg"><input type="hidden" name="csrf_token" value="{{.CSRF}}">{{if .Flow}}<input type="hidden" name="flow" value="{{.Flow}}">{{end}}{{range $name,$value := .Fields}}<input type="hidden" name="{{$name}}" value="{{$value}}">{{end}}<button name="decision" value="allow" class="button button-primary">{{if eq .Action "/authorize/consent"}}Allow and continue{{else}}Sign out of authd{{end}}</button><button name="decision" value="deny" class="button">Cancel</button></form></section></main></body></html>`))

func (h *HTTP) interaction(w http.ResponseWriter, r *http.Request, view interactionView) {
	var buf bytes.Buffer
	if err := interactionTemplate.Execute(&buf, view); err != nil {
		h.transient(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	// Native consent-form submissions must retain a usable Origin header.
	w.Header().Set("Referrer-Policy", "origin")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	_, _ = w.Write(buf.Bytes())
}
func (h *HTTP) consentCSRF(flow, browser, session string) string {
	return cryptoutil.CSRF(h.service.masterKey, "oidc-consent:"+flow, browser+"\x00"+session)
}
func (h *HTTP) renderConsent(w http.ResponseWriter, r *http.Request, flow, browser string) {
	req, client, err := h.service.Store.AuthorizationRequest(r.Context(), identity.Hash(flow))
	if err != nil {
		h.transient(w, r)
		return
	}
	raw := h.readCookie(r, "session")
	session, err := h.service.Sessions.Session(r.Context(), raw)
	if err != nil {
		h.transient(w, r)
		return
	}
	h.interaction(w, r, interactionView{Title: "Authorize application", Description: "You are signed in to authd. Review what this application is asking to receive. Continuing sends a sign-in result, never your password. Cancel if you did not start this sign-in.", ClientName: client.Name, Username: session.User.Username, Action: "/authorize/consent", Flow: flow, CSRF: h.consentCSRF(flow, browser, raw), Scopes: req.Scopes, Claims: consentClaimNames(req.Claims), Offline: contains(req.Scopes, "offline_access")})
}
func (h *HTTP) consent(w http.ResponseWriter, r *http.Request) {
	if h.service == nil {
		h.transient(w, r)
		return
	}
	form, err := h.parseProtocolForm(w, r)
	if err != nil {
		h.oauthError(w, 400, "invalid_request", "invalid consent form")
		return
	}
	flow, browser, session := form.Get("flow"), h.readCookie(r, "oidc_browser"), h.readCookie(r, "session")
	csrf := form.Get("csrf_token")
	if !cryptoutil.ValidToken(flow) || browser == "" || session == "" || !cryptoutil.ValidToken(csrf) || !hmac.Equal([]byte(csrf), []byte(h.consentCSRF(flow, browser, session))) {
		h.oauthError(w, 403, "invalid_request", "consent is not bound to this browser and session")
		return
	}
	if form.Get("decision") != "allow" && form.Get("decision") != "deny" {
		h.oauthError(w, 400, "invalid_request", "a consent decision is required")
		return
	}
	req, client, err := h.service.Store.AuthorizationRequest(r.Context(), identity.Hash(flow))
	if err != nil && !errors.Is(err, ErrInvalidRequest) && !errors.Is(err, ErrInvalidClient) {
		h.transient(w, r)
		return
	}
	if err != nil || !client.Enabled || !contains(client.RedirectURIs, req.RedirectURI) {
		h.oauthError(w, 400, "invalid_request", "authorization request is unavailable")
		return
	}
	allow := form.Get("decision") == "allow"
	if err = h.service.Store.ConsentAuthorizationRequest(r.Context(), identity.Hash(flow), identity.Hash(browser), identity.Hash(session), allow, auditFromRequest(r)); err != nil {
		if authorizationError(err) == "server_error" {
			h.transient(w, r)
		} else {
			h.oauthError(w, 400, authorizationError(err), "consent was rejected")
		}
		return
	}
	if !allow {
		http.Redirect(w, r, h.service.authRedirect(req, "", "access_denied"), http.StatusFound)
		return
	}
	http.Redirect(w, r, "/authorize/resume?flow="+url.QueryEscape(flow), http.StatusSeeOther)
}

func (h *HTTP) logoutCSRF(values url.Values, session string) string {
	return cryptoutil.CSRF(h.service.masterKey, "oidc-logout:"+values.Encode(), session)
}
func promptFields(v url.Values) map[string]string {
	out := map[string]string{}
	for key, values := range v {
		out[key] = strings.Join(values, "")
	}
	return out
}
func validLogoutFields(v url.Values) (url.Values, error) {
	out := url.Values{}
	for name, limit := range map[string]int{"id_token_hint": maxJWTBytes, "client_id": 256, "post_logout_redirect_uri": 4096, "state": 2048} {
		value, err := single(v, name, false, limit)
		if err != nil {
			return nil, err
		}
		if value != "" {
			out.Set(name, value)
		}
	}
	return out, nil
}

func consentClaimNames(v ClaimSelection) []string {
	out := []string{}
	for _, name := range v.IDToken {
		out = append(out, "ID token: "+name)
	}
	for _, name := range v.UserInfo {
		out = append(out, "UserInfo: "+name)
	}
	return out
}
