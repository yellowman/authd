package oidc

import (
	"encoding/json"
	"time"
)

type Client struct {
	ID                      string
	ClientID                string
	Name                    string
	Type                    string
	SecretHash              []byte
	Enabled                 bool
	RequireMFA              bool
	RefreshTokensEnabled    bool
	DynamicRegistration     bool
	TokenEndpointAuthMethod string
	AccessTokenTTL          time.Duration
	RedirectURIs            []string
	LogoutURIs              []string
	IdentityScopes          []string
	PermissionIDs           []string
	Permissions             []string
	UpdatedAt               time.Time
}

// ClaimSelection records explicit normal identity-claim requests. It never grants
// application permissions and is revalidated against the current client allow-list.
type ClaimSelection struct {
	IDTokenValues  map[string][]json.RawMessage `json:"id_token_values,omitempty"`
	UserInfoValues map[string][]json.RawMessage `json:"userinfo_values,omitempty"`
	IDToken        []string                     `json:"id_token,omitempty"`
	UserInfo       []string                     `json:"userinfo,omitempty"`
}

type AuthorizationRequest struct {
	Claims ClaimSelection

	BrowserHash      []byte
	ConsentSessionID string
	PreferredACR     string
	ExpectedSubjects []string
	MaxAgeSeconds    *int64

	ClientID      string
	RedirectURI   string
	Scopes        []string
	RequiredACR   string
	State         string
	Nonce         string
	CodeChallenge string
	LoginHint     string
	Prompt        string
	CreatedAt     time.Time
	ExpiresAt     time.Time
}

// ConsentApproval remembers the last explicitly reviewed request. It can
// satisfy an unchanged offline request; live policy still determines scopes,
// and prompt=consent still requires a fresh decision for the current request.
type ConsentApproval struct {
	Scopes         []string
	IDTokenClaims  []string
	UserInfoClaims []string
	ApprovedAt     time.Time
}

type Subject struct {
	ACR           string
	ID            string
	SessionID     string
	Username      string
	DisplayName   string
	Email         string
	EmailVerified bool
	Enabled       bool
	Roles         []string
	Permissions   []string
	AuthTime      time.Time
	AuthMethods   []string
}

type CodeGrant struct {
	Claims      ClaimSelection
	Client      Client
	Subject     Subject
	RedirectURI string
	Scopes      []string
	Nonce       string
}

type RefreshGrant struct {
	Claims   ClaimSelection
	FamilyID string
	Client   Client
	Subject  Subject
	Scopes   []string
}

type SigningKey struct {
	ID         string
	KID        string
	Algorithm  string
	Ciphertext []byte
	PublicJWK  []byte
	Active     bool
	CreatedAt  time.Time
	RetiredAt  *time.Time
}

type ClientEdit struct {
	ID                      string
	ClientID                string
	Name                    string
	Type                    string
	Enabled                 bool
	RequireMFA              bool
	RefreshTokensEnabled    bool
	TokenEndpointAuthMethod string
	AccessTokenTTL          time.Duration
	RedirectURIs            []string
	LogoutURIs              []string
	IdentityScopes          []string
	PermissionIDs           []string
	ExpectedUpdatedAt       time.Time
}
