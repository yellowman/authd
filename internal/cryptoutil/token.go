package cryptoutil

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

func RandomToken(bytes int) (string, error) {
	if bytes < 16 {
		return "", errors.New("security token must contain at least 128 bits")
	}
	buf := make([]byte, bytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func HashOpaque(raw string) [sha256.Size]byte {
	return sha256.Sum256([]byte(raw))
}
