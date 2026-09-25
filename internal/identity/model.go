package identity

import "time"

type User struct {
	ID                  string
	Username            string
	DisplayName         string
	Email               string
	EmailVerified       bool
	Enabled             bool
	ForcePasswordChange bool
	CreatedAt           time.Time
	UpdatedAt           time.Time
	LastLoginAt         *time.Time
	MFAEnabled          bool
	RoleIDs             []string
	Roles               []string
}

type Role struct {
	ID            string
	Name          string
	Description   string
	BuiltIn       bool
	UpdatedAt     time.Time
	PermissionIDs []string
	Permissions   []string
}

type Group struct {
	ID, Name, Description string
	UpdatedAt             time.Time
	RoleIDs, UserIDs      []string
}

type Permission struct {
	ID          string
	Name        string
	Description string
	UpdatedAt   time.Time
}
