package oidc

import (
	"context"
	"errors"
	"regexp"
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
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	Scope                   string   `json:"scope"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}

type RegistrationResponse struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
	ClientSecretExpiresAt   int64    `json:"client_secret_expires_at"`
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	Scope                   string   `json:"scope"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}

type dynamicRegistrar interface {
	RegisterDynamicClient(context.Context, []byte, ClientEdit, []byte, []string, identity.Audit) (Client, error)
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
	if len(req.GrantTypes) != 1 || req.GrantTypes[0] != "authorization_code" || len(req.ResponseTypes) != 1 || req.ResponseTypes[0] != "code" {
		return RegistrationResponse{}, identity.Invalid("only authorization_code with code response is supported")
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
	appScopes := make([]string, 0, len(scopes))
	identityScopeList := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		if scope == "offline_access" {
			return RegistrationResponse{}, identity.Invalid("offline_access is not supported for dynamically registered clients")
		}
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
	clientID, err := cryptoutil.RandomToken(16)
	if err != nil {
		return RegistrationResponse{}, err
	}
	secret, err := cryptoutil.RandomToken(32)
	if err != nil {
		return RegistrationResponse{}, err
	}
	edit, err := validateClientEdit(ClientEdit{ClientID: "dcr-" + clientID, Name: req.ClientName, Type: "confidential", Enabled: true, AccessTokenTTL: time.Hour, RedirectURIs: req.RedirectURIs, IdentityScopes: identityScopeList})
	if err != nil {
		return RegistrationResponse{}, err
	}
	client, err := store.RegisterDynamicClient(ctx, identity.Hash(token), edit, identity.Hash(secret), appScopes, a)
	if err != nil {
		return RegistrationResponse{}, err
	}
	return RegistrationResponse{ClientID: client.ClientID, ClientSecret: secret, ClientIDIssuedAt: time.Now().Unix(), ClientSecretExpiresAt: 0,
		ClientName: client.Name, RedirectURIs: client.RedirectURIs, GrantTypes: []string{"authorization_code"}, ResponseTypes: []string{"code"}, Scope: strings.Join(scopes, " "), TokenEndpointAuthMethod: req.TokenEndpointAuthMethod}, nil
}

var ErrRegistrationTokenUsed = errors.New("initial registration token is invalid, expired, or already used")
