package cryptoutil

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

type Argon2Params struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

var DefaultArgon2Params = Argon2Params{
	Memory:      64 * 1024,
	Iterations:  3,
	Parallelism: 2,
	SaltLength:  16,
	KeyLength:   32,
}

func HashPassword(password string, params Argon2Params) (string, error) {
	if len(password) < 12 {
		return "", errors.New("password must be at least 12 characters")
	}
	if len(password) > 1024 {
		return "", errors.New("password is too long")
	}
	if err := validateArgon2Params(params); err != nil {
		return "", err
	}
	salt := make([]byte, params.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}
	hash := argon2.IDKey([]byte(password), salt, params.Iterations, params.Memory, params.Parallelism, params.KeyLength)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		params.Memory,
		params.Iterations,
		params.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

func VerifyPassword(encoded, password string, desired Argon2Params) (match bool, needsRehash bool, err error) {
	params, salt, expected, err := parseArgon2id(encoded)
	if err != nil {
		return false, false, err
	}
	actual := argon2.IDKey([]byte(password), salt, params.Iterations, params.Memory, params.Parallelism, uint32(len(expected)))
	match = subtle.ConstantTimeCompare(actual, expected) == 1
	if !match {
		return false, false, nil
	}
	needsRehash = params.Memory != desired.Memory ||
		params.Iterations != desired.Iterations ||
		params.Parallelism != desired.Parallelism ||
		uint32(len(salt)) != desired.SaltLength ||
		uint32(len(expected)) != desired.KeyLength
	return true, needsRehash, nil
}

func parseArgon2id(encoded string) (Argon2Params, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return Argon2Params{}, nil, nil, errors.New("invalid argon2id encoding")
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return Argon2Params{}, nil, nil, errors.New("unsupported argon2 version")
	}
	params := Argon2Params{}
	for _, item := range strings.Split(parts[3], ",") {
		kv := strings.SplitN(item, "=", 2)
		if len(kv) != 2 {
			return Argon2Params{}, nil, nil, errors.New("invalid argon2 parameters")
		}
		n, err := strconv.ParseUint(kv[1], 10, 32)
		if err != nil {
			return Argon2Params{}, nil, nil, errors.New("invalid argon2 parameters")
		}
		switch kv[0] {
		case "m":
			params.Memory = uint32(n)
		case "t":
			params.Iterations = uint32(n)
		case "p":
			if n > 255 {
				return Argon2Params{}, nil, nil, errors.New("invalid argon2 parallelism")
			}
			params.Parallelism = uint8(n)
		default:
			return Argon2Params{}, nil, nil, errors.New("unknown argon2 parameter")
		}
	}
	if params.Memory == 0 || params.Iterations == 0 || params.Parallelism == 0 {
		return Argon2Params{}, nil, nil, errors.New("incomplete argon2 parameters")
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) < 8 {
		return Argon2Params{}, nil, nil, errors.New("invalid argon2 salt")
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(expected) < 16 {
		return Argon2Params{}, nil, nil, errors.New("invalid argon2 hash")
	}
	params.SaltLength = uint32(len(salt))
	params.KeyLength = uint32(len(expected))
	return params, salt, expected, nil
}

func validateArgon2Params(params Argon2Params) error {
	if params.Memory < 8*1024 || params.Iterations == 0 || params.Parallelism == 0 || params.SaltLength < 16 || params.KeyLength < 16 {
		return errors.New("unsafe argon2 parameters")
	}
	return nil
}
