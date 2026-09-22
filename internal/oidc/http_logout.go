package oidc

import (
	"crypto/hmac"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/yellowman/authd/internal/identity"
)

// GET without a session-matching hint is a confirmation, never a logout-CSRF
// endpoint. Bind the confirmed target as well as the browser session to the form.
func (h *HTTP) logout(w http.ResponseWriter, r *http.Request) {
	if h.service == nil {
		h.transient(w, r)
		return
	}
	values, err := h.authorizationValues(w, r)
	if err != nil {
		h.oauthError(w, 400, "invalid_request", "invalid logout request")
		return
	}
	params, err := validLogoutFields(values)
	if err != nil {
		h.oauthError(w, 400, "invalid_request", "invalid logout parameters")
		return
	}
	now := time.Now()
	var client Client
	var subject, sid string
	trustedHint := params.Get("id_token_hint") != ""
	if trustedHint {
		client, subject, sid, err = h.service.LogoutClient(r.Context(), params.Get("id_token_hint"), now)
		if err != nil {
			if errors.Is(err, ErrInvalidGrant) {
				h.oauthError(w, 400, "invalid_request", "invalid ID token hint")
			} else {
				h.transient(w, r)
			}
			return
		}
		if id := params.Get("client_id"); id != "" && id != client.ClientID {
			h.oauthError(w, 400, "invalid_request", "client and ID token hint disagree")
			return
		}
	} else if id := params.Get("client_id"); id != "" {
		client, err = h.service.Store.Client(r.Context(), id)
		if err != nil {
			if errors.Is(err, ErrInvalidClient) {
				h.oauthError(w, 400, "invalid_request", "invalid client")
			} else {
				h.transient(w, r)
			}
			return
		}
		if !client.Enabled {
			h.oauthError(w, 400, "invalid_request", "invalid client")
			return
		}
	}
	target := params.Get("post_logout_redirect_uri")
	if target != "" && (client.ClientID == "" || !contains(client.LogoutURIs, target)) {
		h.oauthError(w, 400, "invalid_request", "logout redirect is not registered")
		return
	}
	sessionRaw := h.readCookie(r, "session")
	session, sessionErr := h.service.Sessions.Session(r.Context(), sessionRaw)
	if sessionErr != nil && !errors.Is(sessionErr, identity.ErrSession) {
		h.transient(w, r)
		return
	}
	active := sessionErr == nil
	// A signed hint for another browser session cannot terminate this one. The
	// caller must explicitly confirm the desired logout with its current cookie.
	matches := active && trustedHint && session.User.ID == subject && (sid == "" || sid == session.ID)
	confirmed := false
	if r.Method == http.MethodPost && values.Get("decision") != "" {
		expected := h.logoutCSRF(params, sessionRaw)
		if !active || !hmac.Equal([]byte(values.Get("csrf_token")), []byte(expected)) {
			h.oauthError(w, 403, "invalid_request", "invalid logout confirmation")
			return
		}
		switch values.Get("decision") {
		case "deny":
			http.Redirect(w, r, "/account", http.StatusSeeOther)
			return
		case "allow":
			confirmed = true
		default:
			h.oauthError(w, 400, "invalid_request", "a logout decision is required")
			return
		}
	}
	if active && !matches && !confirmed {
		h.interaction(w, r, interactionView{Title: "Sign out", Description: "Confirm signing out of this authd browser session. Other applications may retain their own sessions.", Username: session.User.Username, ClientName: client.Name, Action: "/logout", Fields: promptFields(params), CSRF: h.logoutCSRF(params, sessionRaw)})
		return
	}
	if active {
		if err = h.service.Sessions.EndSession(r.Context(), sessionRaw, auditFromRequest(r)); err != nil {
			h.transient(w, r)
			return
		}
	}
	h.setCookie(w, "session", "", 0)
	// Without proof/confirmation a public client_id is not sufficient to send
	// the browser to a supplied destination. A valid signed hint is sufficient
	// for idempotent logout after the local session has expired.
	if target != "" && (trustedHint || confirmed) {
		u, _ := url.Parse(target)
		q := u.Query()
		if state := params.Get("state"); state != "" {
			q.Set("state", state)
		}
		u.RawQuery = q.Encode()
		http.Redirect(w, r, u.String(), http.StatusFound)
		return
	}
	http.Redirect(w, r, "/login", http.StatusFound)
}
