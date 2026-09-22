package oidc

import (
	"context"
	"errors"
	"time"

	"github.com/yellowman/authd/internal/identity"
)

var (
	ErrInvalidRequest     = errors.New("invalid authorization request")
	ErrInvalidClient      = errors.New("invalid client")
	ErrInvalidGrant       = errors.New("invalid grant")
	ErrInvalidScope       = errors.New("invalid scope")
	ErrLoginRequired      = errors.New("login required")
	ErrAccessDenied       = errors.New("access denied")
	ErrRefreshReuse       = errors.New("refresh token reuse detected")
	ErrSigningKeyNotFound = errors.New("signing key not found")
)

type Sessions interface {
	Session(context.Context, string) (identity.Session, error)
	EndSession(context.Context, string, identity.Audit) error
}

type Store interface {
	Client(context.Context, string) (Client, error)
	PublicClientRedirectURIs(context.Context) ([]string, error)
	CreateAuthorizationRequest(context.Context, []byte, AuthorizationRequest) error
	AuthorizationRequest(context.Context, []byte) (AuthorizationRequest, Client, error)
	IssueAuthorizationCode(context.Context, []byte, []byte, []byte, time.Time) (CodeGrant, error)
	ConsumeAuthorizationCode(context.Context, []byte, string, string, string, time.Time) (CodeGrant, error)
	CreateRefreshFamily(context.Context, string, string, []string, time.Time, []string, []byte, time.Time, time.Time) error
	RotateRefreshToken(context.Context, []byte, []byte, string, []string, time.Time, time.Time, identity.Audit) (RefreshGrant, error)
	RevokeRefreshToken(context.Context, []byte, string, identity.Audit) error
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
