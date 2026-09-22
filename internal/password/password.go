package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

var DefaultArgon2Params = Argon2Params{Memory: 64 * 1024, Iterations: 3, Parallelism: 2, SaltLength: 16, KeyLength: 32}

type Hasher struct{ Params Argon2Params }

func (h Hasher) Hash(p string) (string, error)          { return HashPassword(p, h.Params) }
func (h Hasher) Verify(e, p string) (bool, bool, error) { return VerifyPassword(e, p, h.Params) }
func HashPassword(password string, p Argon2Params) (string, error) {
	if !utf8.ValidString(password) || utf8.RuneCountInString(password) < 12 || len(password) > 1024 {
		return "", errors.New("invalid password length or encoding")
	}
	if e := validateArgon2Params(p); e != nil {
		return "", e
	}
	salt := make([]byte, p.SaltLength)
	if _, e := rand.Read(salt); e != nil {
		return "", e
	}
	hash := argon2.IDKey([]byte(password), salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, p.Memory, p.Iterations, p.Parallelism, base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(hash)), nil
}
func VerifyPassword(encoded, password string, desired Argon2Params) (bool, bool, error) {
	if len(password) > 1024 || !utf8.ValidString(password) {
		return false, false, errors.New("invalid password input")
	}
	if e := validateArgon2Params(desired); e != nil {
		return false, false, e
	}
	p, salt, expected, e := parseArgon2id(encoded)
	if e != nil {
		return false, false, e
	}
	actual := argon2.IDKey([]byte(password), salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)
	if subtle.ConstantTimeCompare(actual, expected) != 1 {
		return false, false, nil
	}
	// Do not downgrade a stronger stored memory/time/length setting merely because
	// defaults changed. Parallelism alone is not a reason to replace a verifier.
	rehash := desired.Memory >= p.Memory && desired.Iterations >= p.Iterations && desired.SaltLength >= p.SaltLength && desired.KeyLength >= p.KeyLength &&
		(desired.Memory > p.Memory || desired.Iterations > p.Iterations || desired.SaltLength > p.SaltLength || desired.KeyLength > p.KeyLength)
	return true, rehash, nil
}
