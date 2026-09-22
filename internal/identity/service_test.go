package identity

import (
	"context"
	"errors"
	"github.com/yellowman/authd/internal/cryptoutil"
	"github.com/yellowman/authd/internal/totp"
	"strings"
	"testing"
	"time"
)

// Deterministic test-only password double: these tests prove service behavior,
// not Argon2 correctness. The actual password package has separate KDF tests.
type testPasswords struct{}

func (testPasswords) Hash(p string) (string, error)          { return "test-only:" + p, nil }
func (testPasswords) Verify(e, p string) (bool, bool, error) { return e == "test-only:"+p, false, nil }

type memoryStore struct {
	Store
	record       LoginRecord
	sessions     map[string]Session
	created      int
	failureCount int
	createError  error
	used         map[int64]bool
}

func (m *memoryStore) LoginRecord(_ context.Context, u string) (LoginRecord, error) {
	if u != strings.ToLower(m.record.User.Username) {
		return LoginRecord{}, ErrCredentials
	}
	return m.record, nil
}
func (m *memoryStore) AuditFailure(context.Context, string, Audit) error {
	m.failureCount++
	return nil
}
func (m *memoryStore) CreateSession(_ context.Context, r LoginRecord, s Session, use *FactorUse, replacement string, _ Audit) error {
	if m.createError != nil {
		return m.createError
	}
	if use != nil && use.Counter != nil {
		if m.used[*use.Counter] {
			return ErrCredentials
		}
		m.used[*use.Counter] = true
	}
	m.created++
	s.ID = "00000000-0000-4000-8000-000000000001"
	m.sessions[string(s.TokenHash)] = s
	return nil
}
func (m *memoryStore) Session(_ context.Context, h []byte, _ time.Duration) (Session, error) {
	v, ok := m.sessions[string(h)]
	if !ok {
		return v, ErrSession
	}
	return v, nil
}
func serviceFixture(t *testing.T) (*Service, *memoryStore) {
	t.Helper()
	m := &memoryStore{record: LoginRecord{User: User{ID: "00000000-0000-4000-8000-000000000001", Username: "alice", Enabled: true}, PasswordHash: "test-only:correct password"}, sessions: map[string]Session{}, used: map[int64]bool{}}
	s, e := NewService(m, testPasswords{}, []byte("0123456789abcdef0123456789abcdef"), time.Hour, 24*time.Hour)
	if e != nil {
		t.Fatal(e)
	}
	return s, m
}
func TestZeroRoleUserCanAuthenticate(t *testing.T) {
	s, m := serviceFixture(t)
	raw, e := s.Authenticate(context.Background(), " ALICE ", "correct password", "", "browser", Audit{IP: "127.0.0.1"})
	if e != nil {
		t.Fatal(e)
	}
	sess, e := s.Session(context.Background(), raw)
	if e != nil {
		t.Fatal(e)
	}
	if sess.Has("system.admin") || len(sess.Permissions) != 0 || m.created != 1 {
		t.Fatal("privileges invented")
	}
	if !s.ValidCSRF(sess, raw, s.CSRF(raw, "session")) {
		t.Fatal("valid CSRF failed")
	}
	if s.ValidCSRF(sess, raw, s.CSRF(raw, "browser")) {
		t.Fatal("cross-purpose CSRF accepted")
	}
	if string(sess.TokenHash) == raw || string(sess.CSRFHash) == s.CSRF(raw, "session") {
		t.Fatal("plaintext stored")
	}
}
func TestLoginFailureDoesNotMintSession(t *testing.T) {
	cases := []struct {
		name, username, password string
		disabled                 bool
	}{
		{"wrong password", "alice", "wrong", false}, {"unknown", "nobody", "correct password", false}, {"disabled", "alice", "correct password", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, m := serviceFixture(t)
			m.record.User.Enabled = !c.disabled
			raw, e := s.Authenticate(context.Background(), c.username, c.password, "", "", Audit{})
			if !errors.Is(e, ErrCredentials) || raw != "" || m.created != 0 || m.failureCount != 1 {
				t.Fatalf("%q %v %+v", raw, e, m)
			}
		})
	}
}
func TestMFAEnrolledAccountCannotBypassFactor(t *testing.T) {
	s, m := serviceFixture(t)
	secret := []byte("12345678901234567890")
	cipher, e := cryptoutil.Seal(s.key, secret, []byte("totp:"+m.record.User.ID))
	if e != nil {
		t.Fatal(e)
	}
	m.record.Factor = &Factor{Ciphertext: cipher}
	if raw, e := s.Authenticate(context.Background(), "alice", "correct password", "", "", Audit{}); !errors.Is(e, ErrCredentials) || raw != "" || m.created != 0 {
		t.Fatal("MFA bypass")
	}
	code, e := totp.Code(secret, time.Now().Unix()/30, 6)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := s.Authenticate(context.Background(), "alice", "correct password", code, "", Audit{})
	if e != nil {
		t.Fatal(e)
	}
	sess, e := s.Session(context.Background(), raw)
	if e != nil || !contains(sess.AuthMethods, "otp") {
		t.Fatal("MFA method missing")
	}
	if _, e = s.Authenticate(context.Background(), "alice", "correct password", code, "", Audit{}); !errors.Is(e, ErrCredentials) {
		t.Fatal("OTP replay accepted")
	}
}
func TestDatabaseRejectionNeverReturnsBearer(t *testing.T) {
	s, m := serviceFixture(t)
	m.createError = ErrConflict
	raw, e := s.Authenticate(context.Background(), "alice", "correct password", "", "", Audit{})
	if raw != "" || !errors.Is(e, ErrCredentials) {
		t.Fatal("stale credential proof yielded bearer")
	}
}
func TestHashConcurrencyIsBounded(t *testing.T) {
	s, _ := serviceFixture(t)
	for i := 0; i < cap(s.slots); i++ {
		s.slots <- struct{}{}
	}
	if _, e := s.hash(context.Background(), "new correct password"); !errors.Is(e, ErrRateLimited) {
		t.Fatal("unbounded hash workers")
	}
	for i := 0; i < cap(s.slots); i++ {
		<-s.slots
	}
}
func TestPasswordInputCountsUnicodeCharacters(t *testing.T) {
	s, _ := serviceFixture(t)
	if _, e := s.hash(context.Background(), strings.Repeat("é", 6)); e == nil {
		t.Fatal("bytes mistaken for characters")
	}
	if _, e := s.hash(context.Background(), strings.Repeat("é", 12)); e != nil {
		t.Fatal(e)
	}
}

func TestOversizedUsernameCannotFillLimiterWithLargeKeys(t *testing.T) {
	s, _ := serviceFixture(t)
	_, err := s.Authenticate(context.Background(), strings.Repeat("x", 32000), "correct password", "", "", Audit{})
	if !errors.Is(err, ErrCredentials) {
		t.Fatal(err)
	}
	for key := range s.limiter.entries {
		if len(key) > 256 {
			t.Fatal("unbounded limiter key")
		}
	}
}
func TestCancelledHashDoesNotStartWork(t *testing.T) {
	s, _ := serviceFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	err := s.withHash(ctx, func() error { called = true; return nil })
	if !errors.Is(err, context.Canceled) || called {
		t.Fatal("cancelled request started hash work")
	}
}
