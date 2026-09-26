package oidc

import (
	"context"
	"errors"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/yellowman/authd/internal/cryptoutil"
	"github.com/yellowman/authd/internal/identity"
)

var registrationPrefix = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]*\.$`)
var applicationScope = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]*$`)

func ValidRegistrationPrefix(prefix string) bool {
	return len(prefix) <= 128 && registrationPrefix.MatchString(prefix)
}

// RegistrationRequest uses the standard RFC 7591 client metadata names.
// Other metadata is ignored; this server supports only confidential code+PKCE.
type RegistrationRequest struct {
	ClientID                string          `json:"client_id,omitempty"`
	ClientSecret            string          `json:"client_secret,omitempty"`
	ClientName              string          `json:"client_name"`
	RedirectURIs            []string        `json:"redirect_uris"`
	GrantTypes              []string        `json:"grant_types"`
	ResponseTypes           []string        `json:"response_types"`
	Scope                   string          `json:"scope"`
	TokenEndpointAuthMethod string          `json:"token_endpoint_auth_method"`
	AuthdRoleTemplates      []RoleTemplate  `json:"authd_role_templates,omitempty"`
	AuthdGroupTemplates     []GroupTemplate `json:"authd_group_templates,omitempty"`
}

// These fields are authd-specific client metadata, not OIDC/OAuth standard
// metadata. They define optional defaults; user membership is never supplied.
type RoleTemplate struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Scopes      []string `json:"scopes"`
}
type GroupTemplate struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Roles       []string `json:"roles"`
}

type RegistrationResponse struct {
	ClientID                string          `json:"client_id"`
	ClientSecret            string          `json:"client_secret"`
	ClientIDIssuedAt        int64           `json:"client_id_issued_at"`
	ClientSecretExpiresAt   int64           `json:"client_secret_expires_at"`
	ClientName              string          `json:"client_name"`
	RedirectURIs            []string        `json:"redirect_uris"`
	GrantTypes              []string        `json:"grant_types"`
	ResponseTypes           []string        `json:"response_types"`
	Scope                   string          `json:"scope"`
	TokenEndpointAuthMethod string          `json:"token_endpoint_auth_method,omitempty"`
	RegistrationAccessToken string          `json:"registration_access_token,omitempty"`
	RegistrationClientURI   string          `json:"registration_client_uri,omitempty"`
	AuthdRoleTemplates      []RoleTemplate  `json:"authd_role_templates,omitempty"`
	AuthdGroupTemplates     []GroupTemplate `json:"authd_group_templates,omitempty"`
}

type dynamicRegistrar interface {
	RegisterDynamicClient(context.Context, []byte, ClientEdit, []byte, []byte, []string, []RoleTemplate, []GroupTemplate, identity.Audit) (Client, error)
}

type managedRegistrar interface {
	ManagedClient(context.Context, string, []byte) (Client, string, error)
	UpdateManagedClientScopes(context.Context, string, []byte, []byte, ManagedClientUpdate, identity.Audit) (Client, error)
}

// ManagedClientUpdate is checked against the client's version under its row
// lock so a concurrent administrative policy change cannot be overwritten.
type ManagedClientUpdate struct {
	Scopes               []string
	RefreshTokensEnabled bool
	ExpectedUpdatedAt    time.Time
}

func registrationGrants(grants []string) (bool, error) {
	seen := map[string]bool{}
	for _, grant := range grants {
		if seen[grant] || (grant != "authorization_code" && grant != "refresh_token") {
			return false, identity.Invalid("only authorization_code and optional refresh_token are supported")
		}
		seen[grant] = true
	}
	if !seen["authorization_code"] {
		return false, identity.Invalid("authorization_code is required")
	}
	return seen["refresh_token"], nil
}

func clientGrantTypes(c Client) []string {
	grants := []string{"authorization_code"}
	if c.RefreshTokensEnabled {
		grants = append(grants, "refresh_token")
	}
	return grants
}

func withoutOfflineAccess(scopes []string) []string {
	return slices.DeleteFunc(slices.Clone(scopes), func(scope string) bool { return scope == "offline_access" })
}

func (s *Service) RegisterDynamicClient(ctx context.Context, token string, req RegistrationRequest, a identity.Audit) (RegistrationResponse, error) {
	if !cryptoutil.ValidToken(token) {
		return RegistrationResponse{}, ErrInvalidClient
	}
	store, ok := s.Store.(dynamicRegistrar)
	if !ok {
		return RegistrationResponse{}, ErrRegistrationNotSupported
	}
	if len(req.GrantTypes) == 0 {
		req.GrantTypes = []string{"authorization_code"}
	}
	if len(req.ResponseTypes) == 0 {
		req.ResponseTypes = []string{"code"}
	}
	refresh, err := registrationGrants(req.GrantTypes)
	if err != nil {
		return RegistrationResponse{}, err
	}
	if len(req.ResponseTypes) != 1 || req.ResponseTypes[0] != "code" {
		return RegistrationResponse{}, identity.Invalid("only the code response is supported")
	}
	if req.TokenEndpointAuthMethod == "" {
		req.TokenEndpointAuthMethod = "client_secret_basic"
	}
	if req.TokenEndpointAuthMethod != "client_secret_basic" && req.TokenEndpointAuthMethod != "client_secret_post" {
		return RegistrationResponse{}, identity.Invalid("only confidential client secret authentication is supported")
	}
	scopes, err := parseScopes(req.Scope)
	if err != nil || !contains(scopes, "openid") {
		return RegistrationResponse{}, identity.Invalid("scope must include openid and valid space-separated scope tokens")
	}
	if refresh != contains(scopes, "offline_access") {
		return RegistrationResponse{}, identity.Invalid("refresh_token and offline_access must be requested together")
	}
	appScopes := make([]string, 0, len(scopes))
	identityScopeList := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		if identityScopes[scope] {
			identityScopeList = append(identityScopeList, scope)
		} else if len(scope) <= 128 && applicationScope.MatchString(scope) && scope != "system.admin" {
			appScopes = append(appScopes, scope)
		} else {
			return RegistrationResponse{}, identity.Invalid("invalid application permission scope")
		}
	}
	if len(appScopes) == 0 {
		return RegistrationResponse{}, identity.Invalid("at least one application permission scope is required")
	}
	if err := validateTemplates(req.AuthdRoleTemplates, req.AuthdGroupTemplates, appScopes); err != nil {
		return RegistrationResponse{}, err
	}
	clientID, err := cryptoutil.RandomToken(16)
	if err != nil {
		return RegistrationResponse{}, err
	}
	secret, err := cryptoutil.RandomToken(32)
	if err != nil {
		return RegistrationResponse{}, err
	}
	managementToken, err := cryptoutil.RandomToken(32)
	if err != nil {
		return RegistrationResponse{}, err
	}
	edit, err := validateClientEdit(ClientEdit{ClientID: "dcr-" + clientID, Name: req.ClientName, Type: "confidential", Enabled: true, RefreshTokensEnabled: refresh, TokenEndpointAuthMethod: req.TokenEndpointAuthMethod, AccessTokenTTL: 5 * time.Minute, RedirectURIs: req.RedirectURIs, IdentityScopes: identityScopeList})
	if err != nil {
		return RegistrationResponse{}, err
	}
	client, err := store.RegisterDynamicClient(ctx, identity.Hash(token), edit, identity.Hash(secret), identity.Hash(managementToken), appScopes, req.AuthdRoleTemplates, req.AuthdGroupTemplates, a)
	if err != nil {
		return RegistrationResponse{}, err
	}
	return RegistrationResponse{ClientID: client.ClientID, ClientSecret: secret, ClientIDIssuedAt: time.Now().Unix(), ClientSecretExpiresAt: 0,
		ClientName: client.Name, RedirectURIs: client.RedirectURIs, GrantTypes: clientGrantTypes(client), ResponseTypes: []string{"code"}, Scope: strings.Join(scopes, " "), TokenEndpointAuthMethod: client.TokenEndpointAuthMethod,
		RegistrationAccessToken: managementToken, RegistrationClientURI: s.registrationURI(client.ClientID), AuthdRoleTemplates: req.AuthdRoleTemplates, AuthdGroupTemplates: req.AuthdGroupTemplates}, nil
}

func validateTemplates(roles []RoleTemplate, groups []GroupTemplate, appScopes []string) error {
	if len(roles) > 16 || len(groups) > 16 {
		return identity.Invalid("too many role or group templates")
	}
	allowed := make(map[string]bool, len(appScopes))
	for _, v := range appScopes {
		allowed[v] = true
	}
	roleNames := map[string]bool{}
	for _, r := range roles {
		if !applicationScope.MatchString(r.Name) || len(r.Name) > 128 || len(r.Description) > 500 || roleNames[r.Name] || len(r.Scopes) == 0 || len(r.Scopes) > 64 {
			return identity.Invalid("invalid role template")
		}
		roleNames[r.Name] = true
		seen := map[string]bool{}
		for _, v := range r.Scopes {
			if !allowed[v] || seen[v] {
				return identity.Invalid("role template contains an unknown or duplicate scope")
			}
			seen[v] = true
		}
	}
	groupNames := map[string]bool{}
	for _, g := range groups {
		if !applicationScope.MatchString(g.Name) || len(g.Name) > 128 || len(g.Description) > 500 || groupNames[g.Name] || len(g.Roles) == 0 || len(g.Roles) > 16 {
			return identity.Invalid("invalid group template")
		}
		groupNames[g.Name] = true
		seen := map[string]bool{}
		for _, v := range g.Roles {
			if !roleNames[v] || seen[v] {
				return identity.Invalid("group template references unknown or duplicate role")
			}
			seen[v] = true
		}
	}
	return nil
}

func (s *Service) registrationURI(clientID string) string { return s.issuer + "/register/" + clientID }

func managedResponse(s *Service, c Client) RegistrationResponse {
	scopes := append(append([]string(nil), c.IdentityScopes...), c.Permissions...)
	slices.Sort(scopes)
	return RegistrationResponse{ClientID: c.ClientID, ClientName: c.Name, RedirectURIs: c.RedirectURIs,
		GrantTypes: clientGrantTypes(c), ResponseTypes: []string{"code"}, Scope: strings.Join(scopes, " "),
		TokenEndpointAuthMethod: c.TokenEndpointAuthMethod, RegistrationClientURI: s.registrationURI(c.ClientID)}
}

func (s *Service) ManagedRegistration(ctx context.Context, clientID, token string) (RegistrationResponse, error) {
	store, ok := s.Store.(managedRegistrar)
	if !ok {
		return RegistrationResponse{}, ErrRegistrationNotSupported
	}
	if !cryptoutil.ValidToken(token) {
		return RegistrationResponse{}, ErrInvalidClient
	}
	c, _, err := store.ManagedClient(ctx, clientID, identity.Hash(token))
	if err != nil {
		return RegistrationResponse{}, err
	}
	return managedResponse(s, c), nil
}

// UpdateManagedRegistration supports a full scope replacement while preserving
// the client's identifier, login secret, redirect URIs, and other metadata.
func (s *Service) UpdateManagedRegistration(ctx context.Context, clientID, token string, req RegistrationRequest, a identity.Audit) (RegistrationResponse, error) {
	store, ok := s.Store.(managedRegistrar)
	if !ok {
		return RegistrationResponse{}, ErrRegistrationNotSupported
	}
	if !cryptoutil.ValidToken(token) {
		return RegistrationResponse{}, ErrInvalidClient
	}
	c, prefix, err := store.ManagedClient(ctx, clientID, identity.Hash(token))
	if err != nil {
		return RegistrationResponse{}, err
	}
	if req.ClientID != clientID || req.ClientName != c.Name || !slices.Equal(req.RedirectURIs, c.RedirectURIs) ||
		!slices.Equal(req.ResponseTypes, []string{"code"}) ||
		(req.TokenEndpointAuthMethod != "client_secret_basic" && req.TokenEndpointAuthMethod != "client_secret_post") ||
		(c.TokenEndpointAuthMethod != "" && req.TokenEndpointAuthMethod != c.TokenEndpointAuthMethod) ||
		!cryptoutil.ValidToken(req.ClientSecret) {
		return RegistrationResponse{}, identity.Invalid("registration metadata or client secret is invalid")
	}
	refresh, err := registrationGrants(req.GrantTypes)
	if err != nil {
		return RegistrationResponse{}, err
	}
	scopes, err := parseScopes(req.Scope)
	if err != nil || !contains(scopes, "openid") {
		return RegistrationResponse{}, identity.Invalid("invalid registration scope")
	}
	if refresh != contains(scopes, "offline_access") {
		return RegistrationResponse{}, identity.Invalid("refresh_token and offline_access must be requested together")
	}
	appScopes := make([]string, 0, len(scopes))
	ident := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		if identityScopes[scope] {
			ident = append(ident, scope)
		} else if len(scope) <= 128 && applicationScope.MatchString(scope) && strings.HasPrefix(scope, prefix) && scope != prefix {
			appScopes = append(appScopes, scope)
		} else {
			return RegistrationResponse{}, identity.Invalid("scope is outside registration namespace")
		}
	}
	if len(appScopes) == 0 || !slices.Equal(withoutOfflineAccess(ident), withoutOfflineAccess(c.IdentityScopes)) {
		return RegistrationResponse{}, identity.Invalid("identity scopes or application scopes are invalid")
	}
	c, err = store.UpdateManagedClientScopes(ctx, clientID, identity.Hash(token), identity.Hash(req.ClientSecret), ManagedClientUpdate{Scopes: appScopes, RefreshTokensEnabled: refresh, ExpectedUpdatedAt: c.UpdatedAt}, a)
	if err != nil {
		return RegistrationResponse{}, err
	}
	out := managedResponse(s, c)
	out.ClientSecret = req.ClientSecret
	return out, nil
}

var ErrRegistrationTokenUsed = errors.New("initial registration token is invalid, expired, or already used")
