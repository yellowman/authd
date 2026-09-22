package oidc

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"errors"

	"github.com/yellowman/authd/internal/cryptoutil"
)

type cachedPublicKey struct {
	digest [32]byte
	key    *rsa.PublicKey
}

// Cache parsed crypto objects, NOT authorization state. Every live exchange
// still selects the active database key inside its transaction. Rotation and
// policy revocation therefore have no stale-cache grace period.
func (s *Service) cachedPrivateKey(record SigningKey) (*rsa.PrivateKey, error) {
	if !record.Active || record.Algorithm != "RS256" || record.KID == "" || len(record.Ciphertext) == 0 {
		return nil, errors.New("invalid active signing key")
	}
	digest := sha256.New()
	digest.Write([]byte(record.KID))
	digest.Write(record.Ciphertext)
	digest.Write(record.PublicJWK)
	var fingerprint [32]byte
	copy(fingerprint[:], digest.Sum(nil))
	s.keyMu.Lock()
	defer s.keyMu.Unlock()
	if s.cachedPrivate != nil && s.cachedPrivateDigest == fingerprint {
		return s.cachedPrivate, nil
	}
	plain, err := cryptoutil.Open(s.masterKey, record.Ciphertext, []byte("oidc-signing-key:"+record.KID))
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	key, err := parsePrivateKey(plain)
	if err != nil {
		return nil, err
	}
	pub, err := recordPublicKey(record)
	if err != nil || key.N.Cmp(pub.N) != 0 || key.E != pub.E {
		return nil, errors.New("signing key does not match JWKS")
	}
	s.cachedPrivate = key
	s.cachedPrivateDigest = fingerprint
	return key, nil
}
func (s *Service) cachedPublic(record SigningKey) (*rsa.PublicKey, error) {
	if record.Algorithm != "RS256" || record.KID == "" {
		return nil, errors.New("invalid signing key metadata")
	}
	digest := sha256.Sum256(record.PublicJWK)
	s.keyMu.Lock()
	defer s.keyMu.Unlock()
	if entry, ok := s.publicKeys[record.KID]; ok && entry.digest == digest {
		return entry.key, nil
	}
	key, err := recordPublicKey(record)
	if err != nil {
		return nil, err
	}
	if len(s.publicKeys) >= 32 {
		s.publicKeys = nil
	} // bounded, and a miss never changes authority
	if s.publicKeys == nil {
		s.publicKeys = map[string]cachedPublicKey{}
	}
	s.publicKeys[record.KID] = cachedPublicKey{digest: digest, key: key}
	return key, nil
}

func recordPublicKey(record SigningKey) (*rsa.PublicKey, error) {
	var v jwk
	if record.Algorithm != "RS256" || json.Unmarshal(record.PublicJWK, &v) != nil || record.KID != v.KID {
		return nil, errors.New("signing key metadata mismatch")
	}
	return parsePublicJWK(record.PublicJWK)
}
