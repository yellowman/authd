package password

import (
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
)

type Argon2Params struct {
	Memory, Iterations    uint32
	Parallelism           uint8
	SaltLength, KeyLength uint32
}

func parseArgon2id(encoded string) (Argon2Params, []byte, []byte, error) {
	fail := func() (Argon2Params, []byte, []byte, error) {
		return Argon2Params{}, nil, nil, errors.New("invalid or unsafe Argon2id verifier")
	}
	if len(encoded) > 512 {
		return fail()
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" {
		return fail()
	}
	settings := strings.Split(parts[3], ",")
	if len(settings) != 3 {
		return fail()
	}
	n := make([]uint64, 3)
	for i, key := range []string{"m=", "t=", "p="} {
		if !strings.HasPrefix(settings[i], key) {
			return fail()
		}
		value := strings.TrimPrefix(settings[i], key)
		var e error
		n[i], e = strconv.ParseUint(value, 10, 32)
		if e != nil || strconv.FormatUint(n[i], 10) != value {
			return fail()
		}
	}
	if n[2] > 255 {
		return fail()
	}
	salt, e := base64.RawStdEncoding.Strict().DecodeString(parts[4])
	if e != nil {
		return fail()
	}
	hash, e := base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if e != nil {
		return fail()
	}
	p := Argon2Params{Memory: uint32(n[0]), Iterations: uint32(n[1]), Parallelism: uint8(n[2]), SaltLength: uint32(len(salt)), KeyLength: uint32(len(hash))}
	if base64.RawStdEncoding.EncodeToString(salt) != parts[4] || base64.RawStdEncoding.EncodeToString(hash) != parts[5] {
		return fail()
	}
	if validateArgon2Params(p) != nil {
		return fail()
	}
	return p, salt, hash, nil
}
func validateArgon2Params(p Argon2Params) error {
	// Memory/time ceilings protect the process even if a stored verifier is corrupt.
	if p.Memory < 8*1024 || p.Memory > 256*1024 || p.Iterations < 1 || p.Iterations > 10 || p.Parallelism < 1 || p.Parallelism > 8 || p.SaltLength < 16 || p.SaltLength > 64 || p.KeyLength < 16 || p.KeyLength > 64 {
		return errors.New("unsafe Argon2id parameters")
	}
	return nil
}
