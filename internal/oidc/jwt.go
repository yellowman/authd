package oidc

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"time"
)

type jwk struct {
	KTY string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	KID string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type tokenClaims struct {
	Issuer        string   `json:"iss"`
	Subject       string   `json:"sub"`
	Audience      string   `json:"aud"`
	ClientID      string   `json:"client_id,omitempty"`
	IssuedAt      int64    `json:"iat"`
	ExpiresAt     int64    `json:"exp"`
	JWTID         string   `json:"jti,omitempty"`
	Scope         string   `json:"scope,omitempty"`
	AuthTime      int64    `json:"auth_time,omitempty"`
	Nonce         string   `json:"nonce,omitempty"`
	AMR           []string `json:"amr,omitempty"`
	Username      string   `json:"preferred_username,omitempty"`
	Name          string   `json:"name,omitempty"`
	Email         string   `json:"email,omitempty"`
	EmailVerified *bool    `json:"email_verified,omitempty"`
	Groups        []string `json:"groups,omitempty"`
	Roles         []string `json:"roles,omitempty"`
}

func publicJWK(kid string, key *rsa.PublicKey) ([]byte, error) {
	e := big.NewInt(int64(key.E)).Bytes()
	return json.Marshal(jwk{
		KTY: "RSA", Use: "sig", Alg: "RS256", KID: kid,
		N: base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		E: base64.RawURLEncoding.EncodeToString(e),
	})
}

func parsePublicJWK(raw []byte) (*rsa.PublicKey, error) {
	var value jwk
	if err := json.Unmarshal(raw, &value); err != nil || value.KTY != "RSA" || value.Alg != "RS256" || value.KID == "" {
		return nil, errors.New("invalid signing JWK")
	}
	n, err := base64.RawURLEncoding.DecodeString(value.N)
	if err != nil || len(n) < 256 {
		return nil, errors.New("invalid RSA modulus")
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(value.E)
	if err != nil || len(eBytes) == 0 || len(eBytes) > 4 {
		return nil, errors.New("invalid RSA exponent")
	}
	e := 0
	for _, b := range eBytes {
		e = (e << 8) | int(b)
	}
	if e < 3 {
		return nil, errors.New("invalid RSA exponent")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: e}, nil
}

func marshalPrivateKey(key *rsa.PrivateKey) ([]byte, error) {
	return x509.MarshalPKCS8PrivateKey(key)
}

func parsePrivateKey(raw []byte) (*rsa.PrivateKey, error) {
	value, err := x509.ParsePKCS8PrivateKey(raw)
	if err != nil {
		return nil, errors.New("invalid encrypted signing key")
	}
	key, ok := value.(*rsa.PrivateKey)
	if !ok || key.N.BitLen() < 2048 {
		return nil, errors.New("invalid RSA signing key")
	}
	if err := key.Validate(); err != nil {
		return nil, errors.New("invalid RSA signing key")
	}
	return key, nil
}

func signJWT(kid string, key *rsa.PrivateKey, claims tokenClaims) (string, error) {
	headerBytes, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": kid, "typ": "JWT"})
	claimBytes, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	header := base64.RawURLEncoding.EncodeToString(headerBytes)
	payload := base64.RawURLEncoding.EncodeToString(claimBytes)
	input := header + "." + payload
	digest := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func tokenHeader(raw string) (string, error) {
	if len(raw) == 0 || len(raw) > 16<<10 {
		return "", ErrInvalidGrant
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return "", ErrInvalidGrant
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", ErrInvalidGrant
	}
	var header struct {
		Alg string `json:"alg"`
		KID string `json:"kid"`
		Typ string `json:"typ"`
	}
	if json.Unmarshal(body, &header) != nil || header.Alg != "RS256" || header.KID == "" {
		return "", ErrInvalidGrant
	}
	return header.KID, nil
}

func verifyJWT(raw string, public *rsa.PublicKey, issuer string, now time.Time, checkExpiry bool) (tokenClaims, error) {
	if len(raw) == 0 || len(raw) > 16<<10 {
		return tokenClaims{}, ErrInvalidGrant
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return tokenClaims{}, ErrInvalidGrant
	}
	headerBody, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return tokenClaims{}, ErrInvalidGrant
	}
	var header struct {
		Alg string `json:"alg"`
		KID string `json:"kid"`
	}
	if json.Unmarshal(headerBody, &header) != nil || header.Alg != "RS256" || header.KID == "" {
		return tokenClaims{}, ErrInvalidGrant
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return tokenClaims{}, ErrInvalidGrant
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(public, crypto.SHA256, digest[:], sig) != nil {
		return tokenClaims{}, ErrInvalidGrant
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return tokenClaims{}, ErrInvalidGrant
	}
	var claims tokenClaims
	if json.Unmarshal(payload, &claims) != nil || claims.Issuer != issuer || claims.Subject == "" || claims.Audience == "" || claims.IssuedAt == 0 {
		return tokenClaims{}, ErrInvalidGrant
	}
	if checkExpiry && (claims.ExpiresAt == 0 || now.Unix() >= claims.ExpiresAt) {
		return tokenClaims{}, ErrInvalidGrant
	}
	if claims.IssuedAt > now.Add(2*time.Minute).Unix() {
		return tokenClaims{}, ErrInvalidGrant
	}
	return claims, nil
}
