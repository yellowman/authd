package oidc

import "time"

type Client struct {
	ID                   string
	ClientID             string
	Name                 string
	Type                 string
	SecretHash           []byte
	Enabled              bool
	RequireMFA           bool
	RefreshTokensEnabled bool
	AccessTokenTTL       time.Duration
	RedirectURIs         []string
	LogoutURIs           []string
	IdentityScopes       []string
	PermissionIDs        []string
	Permissions          []string
	UpdatedAt            time.Time
}

type AuthorizationRequest struct {
	ClientID      string
	RedirectURI   string
	Scopes        []string
	State         string
	Nonce         string
	CodeChallenge string
	LoginHint     string
	Prompt        string
	MinAuthTime   *time.Time
	CreatedAt     time.Time
	ExpiresAt     time.Time
}

type Subject struct {
	ID            string
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
	Client      Client
	Subject     Subject
	RedirectURI string
	Scopes      []string
	Nonce       string
}

type RefreshGrant struct {
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
	ID                   string
	ClientID             string
	Name                 string
	Type                 string
	Enabled              bool
	RequireMFA           bool
	RefreshTokensEnabled bool
	AccessTokenTTL       time.Duration
	RedirectURIs         []string
	LogoutURIs           []string
	IdentityScopes       []string
	PermissionIDs        []string
	ExpectedUpdatedAt    time.Time
}
