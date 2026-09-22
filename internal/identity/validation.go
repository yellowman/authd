package identity

import (
	"net/mail"
	"regexp"
	"strings"
	"unicode/utf8"
)

var namePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{0,127}$`)
var usernamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@+-]{0,127}$`)
var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func ValidID(s string) bool { return uuidPattern.MatchString(s) }
func NormalizeProfile(p Profile) (Profile, error) {
	p.Username = strings.TrimSpace(p.Username)
	p.DisplayName = strings.TrimSpace(p.DisplayName)
	p.Email = strings.ToLower(strings.TrimSpace(p.Email))
	if !usernamePattern.MatchString(p.Username) {
		return p, Invalid("username must be 1–128 ASCII letters, digits, or . _ @ + -")
	}
	if !utf8.ValidString(p.DisplayName) || len(p.DisplayName) > 256 || strings.ContainsAny(p.DisplayName, "\r\n\x00") {
		return p, Invalid("invalid display name")
	}
	if p.Email != "" {
		a, e := mail.ParseAddress(p.Email)
		if e != nil || a.Address != p.Email || len(p.Email) > 254 {
			return p, Invalid("invalid email address")
		}
	}
	return p, nil
}
func ValidateName(name, description string) error {
	if !namePattern.MatchString(name) {
		return Invalid("name must be 1–128 lowercase letters, digits, or . _ : -")
	}
	if !utf8.ValidString(description) || len(description) > 1024 {
		return Invalid("description is too long or invalid")
	}
	return nil
}
func ValidateIDs(ids []string) error {
	if len(ids) > 128 {
		return Invalid("too many assignments")
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if !ValidID(id) || seen[id] {
			return Invalid("invalid or repeated assignment")
		}
		seen[id] = true
	}
	return nil
}

// InputError contains only an authored validation message, never a driver error.
type InputError struct{ Message string }

func (e *InputError) Error() string { return e.Message }
func Invalid(message string) error  { return &InputError{Message: message} }
