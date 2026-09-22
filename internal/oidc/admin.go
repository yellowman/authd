package oidc

import (
	"context"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/yellowman/authd/internal/cryptoutil"
	"github.com/yellowman/authd/internal/identity"
)

var clientIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

func normalizeUnique(values []string, maxItems int) ([]string, error) {
	if len(values) > maxItems {
		return nil, identity.Invalid("too many values")
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, raw := range values {
		v := strings.TrimSpace(raw)
		if v == "" || len(v) > 4096 {
			return nil, identity.Invalid("invalid empty or oversized value")
		}
		if seen[v] {
			return nil, identity.Invalid("duplicate value")
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Strings(out)
	return out, nil
}
func validClientURI(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil || u.Fragment != "" {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	if u.Scheme != "http" {
		return false
	}
	host := u.Hostname()
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
func validateClientEdit(edit ClientEdit) (ClientEdit, error) {
	edit.ClientID = strings.TrimSpace(edit.ClientID)
	edit.Name = strings.TrimSpace(edit.Name)
	if !clientIDPattern.MatchString(edit.ClientID) {
		return edit, identity.Invalid("client ID must use letters, digits, dot, underscore, colon, or hyphen")
	}
	if edit.Name == "" || len(edit.Name) > 200 {
		return edit, identity.Invalid("client name is required and must be at most 200 characters")
	}
	if edit.Type != "public" && edit.Type != "confidential" {
		return edit, identity.Invalid("client type must be public or confidential")
	}
	if edit.AccessTokenTTL < 30*time.Second || edit.AccessTokenTTL > time.Hour {
		return edit, identity.Invalid("access token lifetime must be between 30 seconds and one hour")
	}
	var err error
	if edit.RedirectURIs, err = normalizeUnique(edit.RedirectURIs, 32); err != nil || len(edit.RedirectURIs) == 0 {
		return edit, identity.Invalid("at least one valid redirect URI is required")
	}
	for _, v := range edit.RedirectURIs {
		if !validClientURI(v) {
			return edit, identity.Invalid("redirect URIs must be absolute HTTPS URLs, except loopback HTTP for local development")
		}
	}
	if edit.LogoutURIs, err = normalizeUnique(edit.LogoutURIs, 32); err != nil {
		return edit, err
	}
	for _, v := range edit.LogoutURIs {
		if !validClientURI(v) {
			return edit, identity.Invalid("logout URIs must be absolute HTTPS URLs, except loopback HTTP for local development")
		}
	}
	if edit.IdentityScopes, err = normalizeUnique(edit.IdentityScopes, 16); err != nil {
		return edit, err
	}
	for _, v := range edit.IdentityScopes {
		if !identityScopes[v] {
			return edit, identity.Invalid("unknown identity scope")
		}
	}
	if edit.RefreshTokensEnabled && !contains(edit.IdentityScopes, "offline_access") {
		return edit, identity.Invalid("refresh-token clients must allow offline_access")
	}
	if err = identity.ValidateIDs(edit.PermissionIDs); err != nil {
		return edit, err
	}
	return edit, nil
}

func (s *Service) AdminClients(ctx context.Context, actorRaw string) ([]Client, error) {
	if !cryptoutil.ValidToken(actorRaw) {
		return nil, identity.ErrSession
	}
	return s.Store.AdminClients(ctx, identity.Hash(actorRaw))
}
func (s *Service) CreateClient(ctx context.Context, actorRaw string, edit ClientEdit, a identity.Audit) (Client, string, error) {
	var err error
	if edit, err = validateClientEdit(edit); err != nil {
		return Client{}, "", err
	}
	if !cryptoutil.ValidToken(actorRaw) {
		return Client{}, "", identity.ErrSession
	}
	var secret string
	var hash []byte
	if edit.Type == "confidential" {
		secret, err = cryptoutil.RandomToken(32)
		if err != nil {
			return Client{}, "", err
		}
		hash = identity.Hash(secret)
	}
	client, err := s.Store.CreateClient(ctx, identity.Hash(actorRaw), edit, hash, a)
	if err != nil {
		return Client{}, "", err
	}
	return client, secret, nil
}
func (s *Service) UpdateClient(ctx context.Context, actorRaw string, edit ClientEdit, a identity.Audit) error {
	var err error
	if edit, err = validateClientEdit(edit); err != nil {
		return err
	}
	if !identity.ValidID(edit.ID) || !cryptoutil.ValidToken(actorRaw) {
		return identity.ErrSession
	}
	return s.Store.UpdateClient(ctx, identity.Hash(actorRaw), edit, a)
}
func (s *Service) RotateClientSecret(ctx context.Context, actorRaw, clientID string, a identity.Audit) (string, error) {
	if !cryptoutil.ValidToken(actorRaw) || !identity.ValidID(clientID) {
		return "", identity.ErrSession
	}
	secret, err := cryptoutil.RandomToken(32)
	if err != nil {
		return "", err
	}
	if err = s.Store.RotateClientSecret(ctx, identity.Hash(actorRaw), clientID, identity.Hash(secret), a); err != nil {
		return "", err
	}
	return secret, nil
}

func (s *Service) RotateSigningKey(ctx context.Context) (SigningKey, error) {
	generated, err := generateSigningKey(s.masterKey)
	if err != nil {
		return SigningKey{}, err
	}
	return s.Store.InstallSigningKey(ctx, generated, true)
}
