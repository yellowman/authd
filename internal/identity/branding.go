package identity

import (
	"context"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Branding is presentation only. It never changes issuer, token claims or roles.
type Branding struct {
	Name      string
	Logo      []byte
	UpdatedAt time.Time
}

type BrandingStore interface {
	Branding(context.Context) (Branding, error)
	SaveBranding(context.Context, []byte, Branding, bool, bool, Audit) error
}

func ValidateBrandName(name string) error {
	if strings.TrimSpace(name) == "" || !utf8.ValidString(name) || utf8.RuneCountInString(name) > 100 || strings.IndexFunc(name, unicode.IsControl) >= 0 {
		return Invalid("Enter a display name of 1–100 characters without control characters.")
	}
	return nil
}
