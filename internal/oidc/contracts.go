package oidc

import (
	"context"
	"errors"
	"time"

	"github.com/yellowman/authd/internal/identity"
)

var (
	ErrCodeReuse                = errors.New("authorization code reuse detected")
	ErrConsentRequired          = errors.New("consent required")
	ErrInsufficientScope        = errors.New("insufficient scope")
	ErrUnsupportedResponse      = errors.New("unsupported response type")
	ErrRequestNotSupported      = errors.New("request objects are unsupported")
	ErrRequestURINotSupported   = errors.New("request URI is unsupported")
	ErrRegistrationNotSupported = errors.New("dynamic registration is unsupported")
	ErrInvalidRequest           = errors.New("invalid authorization request")
	ErrInvalidClient            = errors.New("invalid client")
	ErrInvalidGrant             = errors.New("invalid grant")
	ErrInvalidScope             = errors.New("invalid scope")
	ErrLoginRequired            = errors.New("login required")
	ErrAccessDenied             = errors.New("access denied")
	ErrUnmetAuthn               = errors.New("unmet authentication requirements")
	ErrRefreshReuse             = errors.New("refresh token reuse detected")
	ErrSigningKeyNotFound       = errors.New("signing key not found")
)

type Sessions interface {
	Session(context.Context, string) (identity.Session, error)
	EndSession(context.Context, string, identity.Audit) error
}

type Store interface {
	Client(context.Context, string) (Client, error)
	PublicOriginAllowed(context.Context, string) (bool, error)
	CreateAuthorizationRequest(context.Context, []byte, AuthorizationRequest) error
	AuthorizationRequest(context.Context, []byte) (AuthorizationRequest, Client, error)
	ConsentApproval(context.Context, []byte, string) (ConsentApproval, error)
	ConsentAuthorizationRequest(context.Context, []byte, []byte, []byte, bool, identity.Audit) error
	IssueAuthorizationCode(context.Context, []byte, []byte, []byte, []byte, time.Time) (CodeGrant, error)
	// The issuer runs inside the grant transaction and MUST NOT perform database I/O.
	// No code/family state may commit if token construction fails. Responses are
	// returned only after commit; replay revocation is the sole commit-on-deny path.
	RedeemCode(context.Context, Client, []byte, string, string, time.Time, identity.Audit, TokenIssuer) (TokenResponse, error)
	RedeemRefresh(context.Context, Client, []byte, []string, time.Time, identity.Audit, TokenIssuer) (TokenResponse, error)
	RevokeRefreshToken(context.Context, []byte, Client, identity.Audit) error
	SigningKeys(context.Context) ([]SigningKey, error)
	ActiveSigningKey(context.Context) (SigningKey, error)
	SigningKey(context.Context, string) (SigningKey, error)
	InstallSigningKey(context.Context, SigningKey, bool) (SigningKey, error)
	AdminSigningKeys(context.Context, []byte) ([]SigningKey, error)
	RotateSigningKey(context.Context, []byte, SigningKey, identity.Audit) (SigningKey, error)
	AdminClients(context.Context, []byte) ([]Client, error)
	CreateClient(context.Context, []byte, ClientEdit, []byte, identity.Audit) (Client, error)
	UpdateClient(context.Context, []byte, ClientEdit, identity.Audit) error
	RotateClientSecret(context.Context, []byte, string, []byte, identity.Audit) error
	DeleteClient(context.Context, []byte, string, identity.Audit) error
}

// TokenMaterial separates client-visible credentials from their durable hashes.
// The plaintext response exists only in request memory; it is never serialized to SQL.
type TokenMaterial struct {
	Response          TokenResponse
	RefreshHash       []byte
	IdleExpiresAt     time.Time
	AbsoluteExpiresAt time.Time
}
type TokenIssuer func(CodeGrant, SigningKey, time.Time) (TokenMaterial, error)
