package oidc

import (
	"bytes"
	"crypto/hmac"
	"errors"
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
	PreviousApproval                                             ConsentApproval
	Consent                                                      *consentComparison
}

func (h *HTTP) interaction(w http.ResponseWriter, r *http.Request, view interactionView) {
	if view.Action == "/authorize/consent" {
		view.Consent = compareConsent(view.Scopes, view.Claims, view.PreviousApproval)
	}
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
	previous, err := h.service.Store.ConsentApproval(r.Context(), identity.Hash(raw), client.ID)
	if err != nil {
		h.transient(w, r)
		return
	}
	h.interaction(w, r, interactionView{Title: "Authorize application", Description: "Review the access requested by this application.", ClientName: client.Name, Username: session.User.Username, Action: "/authorize/consent", Flow: flow, CSRF: h.consentCSRF(flow, browser, raw), Scopes: req.Scopes, Claims: consentClaimNames(req.Claims), Offline: contains(req.Scopes, "offline_access"), PreviousApproval: previous})
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
