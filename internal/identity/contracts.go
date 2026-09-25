package identity

import (
	"context"
	"errors"
	"time"
)

var (
	ErrCredentials     = errors.New("invalid credentials")
	ErrForbidden       = errors.New("not authorized")
	ErrSession         = errors.New("session expired or revoked")
	ErrConflict        = errors.New("record changed or already exists")
	ErrBootstrapClosed = errors.New("initial setup is closed")
	ErrLastAdmin       = errors.New("at least one enabled administrator must remain")
	ErrRateLimited     = errors.New("too many attempts; try again later")
	ErrUnavailable     = errors.New("authentication service is unavailable")
)

type Audit struct{ IP, RequestID string }
type Profile struct{ Username, DisplayName, Email string }
type NewUser struct {
	Profile
	PasswordHash        string
	ForcePasswordChange bool
	RoleIDs             []string
}
type UserEdit struct {
	ID string
	Profile
	Enabled, ForcePasswordChange, VerifyEmail bool
	RoleIDs                                   []string
	ExpectedUpdatedAt                         time.Time
}
type Factor struct {
	Ciphertext  []byte
	LastCounter *int64
}
type LoginRecord struct {
	User         User
	PasswordHash string
	Factor       *Factor
}

// FactorUse is evidence computed by the service, then atomically committed with
// the new session. No OTP or recovery plaintext crosses the storage boundary.
type FactorUse struct {
	Ciphertext   []byte
	Counter      *int64
	RecoveryHash []byte
}
type Session struct {
	// Creation-only replacement proof, never returned as session identity.
	ReplacesTokenHash                                                 []byte `json:"-"`
	ID, UserAgent, IP                                                 string
	TokenHash, CSRFHash                                               []byte
	User                                                              User
	Roles, Permissions, AuthMethods                                   []string
	CreatedAt, AuthTime, LastSeenAt, IdleExpiresAt, AbsoluteExpiresAt time.Time
}

func (s Session) Has(permission string) bool {
	for _, p := range s.Permissions {
		if p == permission {
			return true
		}
	}
	return false
}

type PendingTOTP struct {
	Ciphertext []byte
	ExpiresAt  time.Time
}
type AuditEvent struct {
	ID                       int64
	At                       time.Time
	Event, Actor, Target, IP string
}
type AdminData struct {
	Users       []User
	Roles       []Role
	Groups      []Group
	Permissions []Permission
	Sessions    []Session
	Events      []AuditEvent
}
type GroupEdit struct {
	ID, Name, Description string
	RoleIDs, UserIDs      []string
	ExpectedUpdatedAt     time.Time
}
type RoleEdit struct {
	ID, Name, Description string
	PermissionIDs         []string
	ExpectedUpdatedAt     time.Time
}
type PermissionEdit struct {
	ID, Name, Description string
	ExpectedUpdatedAt     time.Time
}

// Passwords has a single real production implementation in internal/password.
// Test implementations are used only to test orchestration, never as crypto proof.
type Passwords interface {
	Hash(string) (string, error)
	Verify(encoded, password string) (match, needsRehash bool, err error)
}

// Store operations are use-case transactions, not generic CRUD. Any mutation
// involving an actor must recheck the actor's live session and authorization
// inside the transaction. See internal/db/identity.go for the sole backend.
type Store interface {
	BootstrapOpen(context.Context) (bool, error)
	IssueBootstrap(context.Context, []byte, time.Time) error
	Bootstrap(context.Context, []byte, NewUser, Audit) error
	LoginRecord(context.Context, string) (LoginRecord, error)
	CreateSession(context.Context, LoginRecord, Session, *FactorUse, string, Audit) error
	Session(context.Context, []byte, time.Duration) (Session, error)
	Sessions(context.Context, []byte) ([]Session, error)
	RevokeSession(context.Context, []byte, string, bool, Audit) error
	EditOwnProfile(context.Context, []byte, Profile, Audit) error
	ChangePassword(context.Context, []byte, string, string, Audit) error
	AdminData(context.Context, []byte) (AdminData, error)
	CreateUser(context.Context, []byte, NewUser, Audit) error
	EditUser(context.Context, []byte, UserEdit, Audit) error
	DeleteUser(context.Context, []byte, string, Audit) error
	ResetPassword(context.Context, []byte, string, string, bool, Audit) error
	ResetMFA(context.Context, []byte, string, Audit) error
	SaveRole(context.Context, []byte, RoleEdit, Audit) error
	DeleteRole(context.Context, []byte, string, Audit) error
	SaveGroup(context.Context, []byte, GroupEdit, Audit) error
	DeleteGroup(context.Context, []byte, string, Audit) error
	CreatePermission(context.Context, []byte, string, string, Audit) error
	SavePermission(context.Context, []byte, PermissionEdit, Audit) error
	DeletePermission(context.Context, []byte, string, Audit) error
	BeginTOTP(context.Context, []byte, string, []byte, Audit) error
	PendingTOTP(context.Context, []byte) (PendingTOTP, error)
	ConfirmTOTP(context.Context, []byte, []byte, int64, [][]byte, Audit) error
	ReplaceRecoveryCodes(context.Context, []byte, [][]byte, Audit) error
	RemoveTOTP(context.Context, []byte, string, Audit) error
	AuditFailure(context.Context, string, Audit) error
}
