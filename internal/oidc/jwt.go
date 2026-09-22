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

const maxJWTBytes = 16 << 10

type jwk struct {
	KTY string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	KID string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type tokenClaims struct {
	Issuer          string    `json:"iss"`
	Subject         string    `json:"sub"`
	Audience        string    `json:"aud"`
	ClientID        string    `json:"client_id,omitempty"`
	IssuedAt        int64     `json:"iat"`
	ExpiresAt       int64     `json:"exp"`
	JWTID           string    `json:"jti,omitempty"`
	Scope           string    `json:"scope,omitempty"`
	AuthTime        int64     `json:"auth_time,omitempty"`
	ACR             string    `json:"acr,omitempty"`
	AccessTokenHash string    `json:"at_hash,omitempty"`
	Nonce           string    `json:"nonce,omitempty"`
	AMR             []string  `json:"amr,omitempty"`
	SID             string    `json:"sid,omitempty"`
	Username        string    `json:"preferred_username,omitempty"`
	Name            string    `json:"name,omitempty"`
	Email           string    `json:"email,omitempty"`
	EmailVerified   *bool     `json:"email_verified,omitempty"`
	Groups          *[]string `json:"groups,omitempty"`
	Roles           *[]string `json:"roles,omitempty"`
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
	if len(raw) > 8192 || uniqueJSONObject(raw) != nil {
		return nil, errors.New("invalid signing JWK")
	}
	if err := json.Unmarshal(raw, &value); err != nil || value.KTY != "RSA" || value.Use != "sig" || value.Alg != "RS256" || value.KID == "" || len(value.KID) > 256 {
		return nil, errors.New("invalid signing JWK")
	}
	n, err := base64.RawURLEncoding.Strict().DecodeString(value.N)
	if err != nil || len(n) < 256 || len(n) > 1024 || n[0] == 0 || n[len(n)-1]&1 == 0 {
		return nil, errors.New("invalid RSA modulus")
	}
	eBytes, err := base64.RawURLEncoding.Strict().DecodeString(value.E)
	if err != nil || len(eBytes) == 0 || len(eBytes) > 4 {
		return nil, errors.New("invalid RSA exponent")
	}
	e := 0
	for _, b := range eBytes {
		e = (e << 8) | int(b)
	}
	if e < 3 || e%2 == 0 {
		return nil, errors.New("invalid RSA exponent")
	}
	modulus := new(big.Int).SetBytes(n)
	if modulus.BitLen() < 2048 {
		return nil, errors.New("invalid RSA modulus")
	}
	return &rsa.PublicKey{N: modulus, E: e}, nil
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
	typ := "JWT"
	if claims.ClientID != "" {
		typ = "at+jwt"
	}
	headerBytes, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": kid, "typ": typ})
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
	raw := input + "." + base64.RawURLEncoding.EncodeToString(sig)
	if len(raw) > maxJWTBytes {
		return "", errors.New("token exceeds supported size limit")
	}
	return raw, nil
}

type jwtHeader struct {
	Alg string `json:"alg"`
	KID string `json:"kid"`
	Typ string `json:"typ"`
}

func readJWTHeader(raw string) (jwtHeader, error) {
	if len(raw) == 0 || len(raw) > maxJWTBytes {
		return jwtHeader{}, ErrInvalidGrant
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return jwtHeader{}, ErrInvalidGrant
	}
	body, err := base64.RawURLEncoding.Strict().DecodeString(parts[0])
	if err != nil || uniqueJSONObject(body) != nil {
		return jwtHeader{}, ErrInvalidGrant
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) != nil {
		return jwtHeader{}, ErrInvalidGrant
	}
	// authd publishes ordinary, unencoded-payload RS256 JWTs, not arbitrary JOSE.
	if _, ok := fields["crit"]; ok {
		return jwtHeader{}, ErrInvalidGrant
	}
	if _, ok := fields["b64"]; ok {
		return jwtHeader{}, ErrInvalidGrant
	}
	var header jwtHeader
	if json.Unmarshal(body, &header) != nil || header.Alg != "RS256" || header.KID == "" || len(header.KID) > 256 || (header.Typ != "JWT" && header.Typ != "at+jwt") {
		return jwtHeader{}, ErrInvalidGrant
	}
	return header, nil
}
func tokenHeader(raw string) (string, error) {
	header, err := readJWTHeader(raw)
	return header.KID, err
}

func verifyJWT(raw string, public *rsa.PublicKey, issuer string, now time.Time, checkExpiry bool) (tokenClaims, error) {
	header, err := readJWTHeader(raw)
	if err != nil {
		return tokenClaims{}, err
	}
	parts := strings.Split(raw, ".")
	sig, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil {
		return tokenClaims{}, ErrInvalidGrant
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(public, crypto.SHA256, digest[:], sig) != nil {
		return tokenClaims{}, ErrInvalidGrant
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil {
		return tokenClaims{}, ErrInvalidGrant
	}
	if uniqueJSONObject(payload) != nil {
		return tokenClaims{}, ErrInvalidGrant
	}
	var claims tokenClaims
	if json.Unmarshal(payload, &claims) != nil || claims.Issuer != issuer || claims.Subject == "" || claims.Audience == "" || claims.IssuedAt == 0 {
		return tokenClaims{}, ErrInvalidGrant
	}
	if claims.ExpiresAt <= claims.IssuedAt || (claims.ClientID != "" && header.Typ != "at+jwt") || (claims.ClientID == "" && header.Typ != "JWT") {
		return tokenClaims{}, ErrInvalidGrant
	}
	if checkExpiry && now.Unix() >= claims.ExpiresAt {
		return tokenClaims{}, ErrInvalidGrant
	}
	if claims.IssuedAt > now.Add(2*time.Minute).Unix() {
		return tokenClaims{}, ErrInvalidGrant
	}
	return claims, nil
}
