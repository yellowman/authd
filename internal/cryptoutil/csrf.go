package cryptoutil

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
)

// CSRF binds a token to a high-entropy browser/session cookie and a distinct
// purpose. The HMAC key is deployment-secret; a sibling origin cannot mint it.
func CSRF(key []byte, purpose, browserToken string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("authd/csrf/v1\x00" + purpose + "\x00" + browserToken))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
func ValidToken(raw string) bool {
	if len(raw) != 43 {
		return false
	}
	b, e := base64.RawURLEncoding.Strict().DecodeString(raw)
	return e == nil && len(b) == 32
}
