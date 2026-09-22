package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" // RFC 6238 default and broad authenticator compatibility.
	"encoding/base32"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultPeriod = 30 * time.Second
	DefaultDigits = 6
)

func NewSecret() ([]byte, error) {
	secret := make([]byte, 20)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	return secret, nil
}

func SecretString(secret []byte) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
}

func ProvisioningURI(issuer, account string, secret []byte) string {
	label := url.PathEscape(strings.TrimSpace(issuer) + ":" + strings.TrimSpace(account))
	values := url.Values{}
	values.Set("secret", SecretString(secret))
	values.Set("issuer", strings.TrimSpace(issuer))
	values.Set("algorithm", "SHA1")
	values.Set("digits", strconv.Itoa(DefaultDigits))
	values.Set("period", strconv.Itoa(int(DefaultPeriod/time.Second)))
	return "otpauth://totp/" + label + "?" + values.Encode()
}

func Verify(secret []byte, code string, now time.Time, window int) (int64, bool) {
	code = strings.TrimSpace(code)
	if len(code) != DefaultDigits || window < 0 {
		return 0, false
	}
	counter := now.Unix() / int64(DefaultPeriod/time.Second)
	for offset := -window; offset <= window; offset++ {
		candidateCounter := counter + int64(offset)
		candidate, err := Code(secret, candidateCounter, DefaultDigits)
		if err == nil && hmac.Equal([]byte(candidate), []byte(code)) {
			return candidateCounter, true
		}
	}
	return 0, false
}

func Code(secret []byte, counter int64, digits int) (string, error) {
	if len(secret) < 10 {
		return "", errors.New("TOTP secret is too short")
	}
	if digits < 6 || digits > 8 || counter < 0 {
		return "", errors.New("invalid TOTP parameters")
	}
	var message [8]byte
	value := uint64(counter)
	for i := 7; i >= 0; i-- {
		message[i] = byte(value)
		value >>= 8
	}
	mac := hmac.New(sha1.New, secret)
	_, _ = mac.Write(message[:])
	digest := mac.Sum(nil)
	offset := digest[len(digest)-1] & 0x0f
	binary := (uint32(digest[offset])&0x7f)<<24 |
		uint32(digest[offset+1])<<16 |
		uint32(digest[offset+2])<<8 |
		uint32(digest[offset+3])
	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, binary%mod), nil
}
