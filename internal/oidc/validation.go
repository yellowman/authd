package oidc

import (
	"encoding/base64"
	"errors"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

var identityScopes = map[string]bool{
	"openid": true, "profile": true, "email": true, "groups": true, "roles": true, "offline_access": true,
}

func single(values map[string][]string, name string, required bool, max int) (string, error) {
	items := values[name]
	if len(items) == 0 {
		if required {
			return "", ErrInvalidRequest
		}
		return "", nil
	}
	if len(items) != 1 || len(items[0]) > max {
		return "", ErrInvalidRequest
	}
	return items[0], nil
}

func parseScopes(raw string) ([]string, error) {
	if len(raw) > 4096 {
		return nil, ErrInvalidScope
	}
	fields := strings.Fields(raw)
	if len(fields) == 0 || len(fields) > 64 {
		return nil, ErrInvalidScope
	}
	seen := map[string]bool{}
	for _, scope := range fields {
		if len(scope) > 256 || seen[scope] {
			return nil, ErrInvalidScope
		}
		seen[scope] = true
	}
	sort.Strings(fields)
	return fields, nil
}

func validPKCEChallenge(value string) bool {
	if len(value) != 43 {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32
}

func validVerifier(value string) bool {
	if len(value) < 43 || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || strings.ContainsRune("-._~", r) {
			continue
		}
		return false
	}
	return true
}

func scopeAllowed(client Client, requested []string) error {
	ids := make(map[string]bool, len(client.IdentityScopes))
	for _, v := range client.IdentityScopes {
		ids[v] = true
	}
	perms := make(map[string]bool, len(client.Permissions))
	for _, v := range client.Permissions {
		perms[v] = true
	}
	for _, scope := range requested {
		if identityScopes[scope] {
			if !ids[scope] {
				return ErrInvalidScope
			}
			continue
		}
		if !perms[scope] {
			return ErrInvalidScope
		}
	}
	return nil
}

func parseMaxAge(raw string, now time.Time) (*time.Time, error) {
	if raw == "" {
		return nil, nil
	}
	if len(raw) > 10 {
		return nil, ErrInvalidRequest
	}
	seconds, err := strconv.ParseUint(raw, 10, 31)
	if err != nil {
		return nil, ErrInvalidRequest
	}
	t := now.Add(-time.Duration(seconds) * time.Second)
	return &t, nil
}

func contains(items []string, wanted string) bool {
	for _, item := range items {
		if item == wanted {
			return true
		}
	}
	return false
}

func authorizationError(err error) string {
	switch {
	case errors.Is(err, ErrInvalidScope):
		return "invalid_scope"
	case errors.Is(err, ErrLoginRequired):
		return "login_required"
	case errors.Is(err, ErrAccessDenied):
		return "access_denied"
	default:
		return "invalid_request"
	}
}

func canonicalOrigin(raw string) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", false
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" && scheme != "http" {
		return "", false
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "", false
	}
	port := u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		return scheme + "://" + net.JoinHostPort(host, port), true
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return scheme + "://" + host, true
}

func clientOriginAllowed(client Client, origin string) bool {
	if client.Type != "public" || !client.Enabled {
		return false
	}
	want, ok := canonicalOrigin(origin)
	if !ok {
		return false
	}
	for _, redirect := range client.RedirectURIs {
		u, err := url.Parse(redirect)
		if err != nil {
			continue
		}
		candidate, ok := canonicalOrigin(u.Scheme + "://" + u.Host)
		if ok && candidate == want {
			return true
		}
	}
	return false
}
