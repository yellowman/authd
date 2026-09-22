package identity

import (
	"context"
	"crypto/hmac"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/yellowman/authd/internal/cryptoutil"
	"github.com/yellowman/authd/internal/totp"
)

type Service struct {
	Store          Store
	passwords      Passwords
	key            []byte
	dummy          string
	slots          chan struct{}
	limiter        *Limiter
	idle, absolute time.Duration
}

func NewService(store Store, passwords Passwords, key []byte, idle, absolute time.Duration) (*Service, error) {
	if store == nil || passwords == nil || len(key) != 32 || idle <= 0 || absolute < idle {
		return nil, errors.New("invalid identity service configuration")
	}
	dummyPassword, err := cryptoutil.RandomToken(32)
	if err != nil {
		return nil, err
	}
	dummy, err := passwords.Hash(dummyPassword)
	if err != nil {
		return nil, err
	}
	return &Service{Store: store, passwords: passwords, key: append([]byte(nil), key...), dummy: dummy, slots: make(chan struct{}, 4), limiter: NewLimiter(10000), idle: idle, absolute: absolute}, nil
}
func (s *Service) withHash(ctx context.Context, fn func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
		return fn()
	case <-ctx.Done():
		return ctx.Err()
	default:
		return ErrRateLimited
	}
}
func (s *Service) hash(ctx context.Context, password string) (out string, err error) {
	if !utf8.ValidString(password) || utf8.RuneCountInString(password) < 12 || len(password) > 1024 {
		return "", Invalid("password must contain at least 12 Unicode characters and at most 1024 bytes")
	}
	err = s.withHash(ctx, func() error { var e error; out, e = s.passwords.Hash(password); return e })
	return
}
func (s *Service) verify(ctx context.Context, encoded, password string) (match, rehash bool, err error) {
	if len(password) > 1024 {
		return false, false, ErrCredentials
	}
	err = s.withHash(ctx, func() error { var e error; match, rehash, e = s.passwords.Verify(encoded, password); return e })
	return
}
func Hash(raw string) []byte                       { v := cryptoutil.HashOpaque(raw); return v[:] }
func (s *Service) CSRF(raw, purpose string) string { return cryptoutil.CSRF(s.key, purpose, raw) }
func (s *Service) IssueBootstrap(ctx context.Context) (string, error) {
	raw, e := cryptoutil.RandomToken(32)
	if e != nil {
		return "", e
	}
	if e = s.Store.IssueBootstrap(ctx, Hash(raw), time.Now().Add(30*time.Minute)); e != nil {
		return "", e
	}
	return raw, nil
}
func (s *Service) Bootstrap(ctx context.Context, token string, p Profile, password string, a Audit) error {
	if !s.limiter.Allow("setup:"+a.IP, 5, time.Minute) {
		return ErrRateLimited
	}
	if !cryptoutil.ValidToken(token) {
		return ErrCredentials
	}
	open, err := s.Store.BootstrapOpen(ctx)
	if err != nil {
		return ErrUnavailable
	}
	if !open {
		return ErrBootstrapClosed
	}

	p, err = NormalizeProfile(p)
	if err != nil {
		return err
	}
	encoded, err := s.hash(ctx, password)
	if err != nil {
		return err
	}
	return s.Store.Bootstrap(ctx, Hash(token), NewUser{Profile: p, PasswordHash: encoded}, a)
}

// Authenticate never creates a password-only session for an MFA-enrolled user.
// Consumption of an OTP/recovery code and the session insertion are one commit.
func (s *Service) Authenticate(ctx context.Context, username, password, factor, userAgent string, a Audit) (string, error) {
	if !s.limiter.Allow("login-ip:"+a.IP, 30, 2*time.Second) {
		return "", ErrRateLimited
	}
	// Bound attacker-controlled keys before inserting them in the limiter.
	if len(username) > 256 || len(password) > 1024 || len(factor) > 128 {
		return "", s.failure(ctx, a)
	}
	username = strings.ToLower(strings.TrimSpace(username))
	if len(username) > 128 {
		return "", s.failure(ctx, a)
	}
	if !s.limiter.Allow("login-user:"+username, 8, 15*time.Second) {
		return "", ErrRateLimited
	}
	rec, err := s.Store.LoginRecord(ctx, username)
	if err != nil && !errors.Is(err, ErrCredentials) {
		return "", ErrUnavailable
	}
	encoded := rec.PasswordHash
	if encoded == "" {
		encoded = s.dummy
	}
	match, rehash, verifyErr := s.verify(ctx, encoded, password)
	if errors.Is(verifyErr, ErrRateLimited) {
		return "", verifyErr
	}
	if verifyErr != nil || !match || err != nil || rec.PasswordHash == "" || !rec.User.Enabled {
		return "", s.failure(ctx, a)
	}
	methods := []string{"pwd"}
	var use *FactorUse
	if rec.Factor != nil {
		use = &FactorUse{Ciphertext: rec.Factor.Ciphertext}
		code := strings.TrimSpace(factor)
		if len(code) == 6 {
			secret, e := cryptoutil.Open(s.key, rec.Factor.Ciphertext, []byte("totp:"+rec.User.ID))
			if e != nil {
				return "", ErrUnavailable
			}
			counter, ok := totp.Verify(secret, code, time.Now(), 1)
			if !ok || (rec.Factor.LastCounter != nil && counter <= *rec.Factor.LastCounter) {
				return "", s.failure(ctx, a)
			}
			use.Counter = &counter
			methods = append(methods, "otp")
		} else {
			if !cryptoutil.ValidToken(code) {
				return "", s.failure(ctx, a)
			}
			use.RecoveryHash = Hash(code)
			methods = append(methods, "recovery")
		}
	}
	replacement := ""
	if rehash {
		replacement, err = s.hash(ctx, password)
		if err != nil {
			return "", err
		}
	}
	raw, err := cryptoutil.RandomToken(32)
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	session := Session{TokenHash: Hash(raw), CSRFHash: Hash(s.CSRF(raw, "session")), User: rec.User, UserAgent: userAgent, IP: a.IP, AuthTime: now, AuthMethods: methods, IdleExpiresAt: now.Add(s.idle), AbsoluteExpiresAt: now.Add(s.absolute)}
	if len(session.UserAgent) > 512 {
		session.UserAgent = session.UserAgent[:512]
	}
	if err = s.Store.CreateSession(ctx, rec, session, use, replacement, a); err != nil {
		if errors.Is(err, ErrCredentials) || errors.Is(err, ErrConflict) {
			return "", s.failure(ctx, a)
		}
		return "", ErrUnavailable
	}
	return raw, nil
}
func (s *Service) failure(ctx context.Context, a Audit) error {
	if err := s.Store.AuditFailure(ctx, "login.failure", a); err != nil {
		return ErrUnavailable
	}
	return ErrCredentials
}
func (s *Service) Session(ctx context.Context, raw string) (Session, error) {
	if !cryptoutil.ValidToken(raw) {
		return Session{}, ErrSession
	}
	return s.Store.Session(ctx, Hash(raw), s.idle)
}
func (s *Service) ValidCSRF(session Session, raw, form string) bool {
	return cryptoutil.ValidToken(form) && hmac.Equal(Hash(form), session.CSRFHash) && hmac.Equal([]byte(s.CSRF(raw, "session")), []byte(form))
}
func (s *Service) CreateUser(ctx context.Context, actor string, p Profile, password string, roles []string, force bool, a Audit) error {
	p, err := NormalizeProfile(p)
	if err != nil {
		return err
	}
	if err = ValidateIDs(roles); err != nil {
		return err
	}
	hash, err := s.hash(ctx, password)
	if err != nil {
		return err
	}
	return s.Store.CreateUser(ctx, Hash(actor), NewUser{Profile: p, PasswordHash: hash, ForcePasswordChange: force, RoleIDs: roles}, a)
}
func (s *Service) EditUser(ctx context.Context, actor string, edit UserEdit, a Audit) error {
	var err error
	edit.Profile, err = NormalizeProfile(edit.Profile)
	if err != nil {
		return err
	}
	if !ValidID(edit.ID) {
		return Invalid("invalid user ID")
	}
	if err = ValidateIDs(edit.RoleIDs); err != nil {
		return err
	}
	return s.Store.EditUser(ctx, Hash(actor), edit, a)
}
func (s *Service) SaveRole(ctx context.Context, actor string, edit RoleEdit, a Audit) error {
	if edit.ID != "" && !ValidID(edit.ID) {
		return Invalid("invalid role ID")
	}
	if err := ValidateName(edit.Name, edit.Description); err != nil {
		return err
	}
	if err := ValidateIDs(edit.PermissionIDs); err != nil {
		return err
	}
	return s.Store.SaveRole(ctx, Hash(actor), edit, a)
}
func (s *Service) CreatePermission(ctx context.Context, actor, name, description string, a Audit) error {
	if err := ValidateName(name, description); err != nil {
		return err
	}
	switch name {
	case "openid", "profile", "email", "groups", "roles", "offline_access":
		return Invalid("permission name is reserved for an identity scope")
	}
	return s.Store.CreatePermission(ctx, Hash(actor), name, description, a)
}
func (s *Service) ChangePassword(ctx context.Context, raw, current, next string, a Audit) error {
	session, err := s.Session(ctx, raw)
	if err != nil {
		return err
	}
	rec, err := s.Store.LoginRecord(ctx, session.User.Username)
	if err != nil {
		return err
	}
	if !s.limiter.Allow("password:"+session.User.ID, 8, 15*time.Second) {
		return ErrRateLimited
	}
	match, _, err := s.verify(ctx, rec.PasswordHash, current)
	if err != nil {
		return err
	}
	if !match {
		return ErrCredentials
	}
	if current == next {
		return Invalid("new password must differ from the current password")
	}
	hash, err := s.hash(ctx, next)
	if err != nil {
		return err
	}
	return s.Store.ChangePassword(ctx, Hash(raw), rec.PasswordHash, hash, a)
}
func (s *Service) ResetPassword(ctx context.Context, actor, userID, password string, force bool, a Audit) error {
	if !ValidID(userID) {
		return Invalid("invalid user ID")
	}
	hash, err := s.hash(ctx, password)
	if err != nil {
		return err
	}
	return s.Store.ResetPassword(ctx, Hash(actor), userID, hash, force, a)
}
func (s *Service) checkPassword(ctx context.Context, raw, password string) (Session, LoginRecord, error) {
	sess, err := s.Session(ctx, raw)
	if err != nil {
		return sess, LoginRecord{}, err
	}
	if sess.User.ForcePasswordChange || time.Since(sess.AuthTime) > 10*time.Minute {
		return sess, LoginRecord{}, ErrForbidden
	}
	if !s.limiter.Allow("credential:"+sess.User.ID, 8, 15*time.Second) {
		return sess, LoginRecord{}, ErrRateLimited
	}
	rec, err := s.Store.LoginRecord(ctx, sess.User.Username)
	if err != nil {
		return sess, rec, err
	}
	match, _, err := s.verify(ctx, rec.PasswordHash, password)
	if err != nil {
		return sess, rec, err
	}
	if !match {
		return sess, rec, ErrCredentials
	}
	return sess, rec, nil
}
func (s *Service) BeginTOTP(ctx context.Context, raw, password string, a Audit) (string, string, error) {
	sess, rec, err := s.checkPassword(ctx, raw, password)
	if err != nil {
		return "", "", err
	}
	if rec.Factor != nil {
		return "", "", Invalid("remove the existing authenticator before enrolling another")
	}
	secret, err := totp.NewSecret()
	if err != nil {
		return "", "", err
	}
	cipher, err := cryptoutil.Seal(s.key, secret, []byte("totp:"+sess.User.ID))
	if err != nil {
		return "", "", err
	}
	if err = s.Store.BeginTOTP(ctx, Hash(raw), rec.PasswordHash, cipher, a); err != nil {
		return "", "", err
	}
	return totp.SecretString(secret), totp.ProvisioningURI("authd", sess.User.Username, secret), nil
}
func (s *Service) ConfirmTOTP(ctx context.Context, raw, code string, a Audit) ([]string, error) {
	sess, err := s.Session(ctx, raw)
	if err != nil {
		return nil, err
	}
	if !s.limiter.Allow("enroll:"+sess.User.ID, 8, 15*time.Second) {
		return nil, ErrRateLimited
	}
	pending, err := s.Store.PendingTOTP(ctx, Hash(raw))
	if err != nil {
		return nil, err
	}
	if !time.Now().Before(pending.ExpiresAt) {
		return nil, ErrConflict
	}
	secret, err := cryptoutil.Open(s.key, pending.Ciphertext, []byte("totp:"+sess.User.ID))
	if err != nil {
		return nil, ErrUnavailable
	}
	counter, ok := totp.Verify(secret, code, time.Now(), 1)
	if !ok {
		return nil, ErrCredentials
	}
	codes := make([]string, 8)
	hashes := make([][]byte, len(codes))
	for i := range codes {
		codes[i], err = cryptoutil.RandomToken(32)
		if err != nil {
			return nil, err
		}
		hashes[i] = Hash(codes[i])
	}
	if err = s.Store.ConfirmTOTP(ctx, Hash(raw), pending.Ciphertext, counter, hashes, a); err != nil {
		return nil, err
	}
	return codes, nil
}
func (s *Service) RemoveTOTP(ctx context.Context, raw, password string, a Audit) error {
	sess, rec, err := s.checkPassword(ctx, raw, password)
	if err != nil {
		return err
	}
	if !contains(sess.AuthMethods, "otp") && !contains(sess.AuthMethods, "recovery") {
		return fmt.Errorf("%w: sign in with MFA first", ErrForbidden)
	}
	return s.Store.RemoveTOTP(ctx, Hash(raw), rec.PasswordHash, a)
}
func contains(items []string, want string) bool {
	for _, v := range items {
		if v == want {
			return true
		}
	}
	return false
}
