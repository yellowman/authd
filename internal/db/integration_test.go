//go:build integration

package db_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/yellowman/authd/internal/cryptoutil"
	"github.com/yellowman/authd/internal/db"
	"github.com/yellowman/authd/internal/identity"
)

// This is a real-database repository suite. Password hashes are opaque fixture
// strings here because KDF verification belongs to the independently tested
// internal/password implementation, not the SQL adapter. No SQL mock is used.
// Missing database/consent is a FAILURE, never t.Skip.
func postgres(t *testing.T) (*db.IdentityStore, context.Context) {
	t.Helper()
	if os.Getenv("AUTHD_TEST_DISPOSABLE") != "1" {
		t.Fatal("AUTHD_TEST_DISPOSABLE=1 is required; use a disposable PostgreSQL database")
	}
	raw := os.Getenv("AUTHD_TEST_DATABASE_URL")
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || u.Host == "" {
		t.Fatal("AUTHD_TEST_DATABASE_URL must be a PostgreSQL URL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	root, err := sql.Open("pgx", raw)
	if err != nil {
		t.Fatal("open PostgreSQL driver:", err)
	}
	if err = root.PingContext(ctx); err != nil {
		root.Close()
		t.Fatal("disposable PostgreSQL is unavailable")
	}
	// UUID support is normally already part of PostgreSQL. Keep the baseline's
	// pgcrypto extension in public rather than deleting it with a test schema.
	if _, err = root.ExecContext(ctx, `CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public`); err != nil {
		root.Close()
		t.Fatal(err)
	}
	entropy := make([]byte, 12)
	if _, err = rand.Read(entropy); err != nil {
		root.Close()
		t.Fatal(err)
	}
	schema := "authd_it_" + hex.EncodeToString(entropy)
	if _, err = root.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		root.Close()
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema+",public")
	u.RawQuery = q.Encode()
	conn, err := sql.Open("pgx", u.String())
	if err != nil {
		t.Fatal(err)
	}
	conn.SetMaxOpenConns(16)
	t.Cleanup(func() {
		conn.Close()
		cleanup, done := context.WithTimeout(context.Background(), 15*time.Second)
		defer done()
		if _, err := root.ExecContext(cleanup, `DROP SCHEMA `+schema+` CASCADE`); err != nil {
			t.Error("test-schema cleanup:", err)
		}
		root.Close()
	})
	if err = db.Migrate(ctx, conn); err != nil {
		t.Fatal(err)
	}
	if err = db.Migrate(ctx, conn); err != nil {
		t.Fatal("idempotent migration:", err)
	}
	var n int
	if err = conn.QueryRowContext(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&n); err != nil || n != 2 {
		t.Fatalf("migration count %d: %v", n, err)
	}
	return &db.IdentityStore{DB: conn}, ctx
}
func require(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func token(t *testing.T) string {
	t.Helper()
	s, e := cryptoutil.RandomToken(32)
	require(t, e)
	return s
}

var auditFixture = identity.Audit{IP: "127.0.0.1", RequestID: "integration-test"}

func sessionFixture(t *testing.T, rec identity.LoginRecord, methods ...string) identity.Session {
	t.Helper()
	now := time.Now().UTC()
	return identity.Session{TokenHash: identity.Hash(token(t)), CSRFHash: identity.Hash(token(t)), User: rec.User, AuthTime: now, AuthMethods: methods, IdleExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(2 * time.Hour), IP: "127.0.0.1", UserAgent: "authd-integration"}
}
func bootstrap(t *testing.T, ctx context.Context, s *db.IdentityStore) (identity.LoginRecord, identity.Session) {
	t.Helper()
	raw := token(t)
	require(t, s.IssueBootstrap(ctx, identity.Hash(raw), time.Now().Add(time.Minute)))
	require(t, s.Bootstrap(ctx, identity.Hash(raw), identity.NewUser{Profile: identity.Profile{Username: "admin", Email: "admin@example.test"}, PasswordHash: "repository-test-admin-hash"}, auditFixture))
	rec, e := s.LoginRecord(ctx, "ADMIN")
	require(t, e)
	sess := sessionFixture(t, rec, "pwd")
	require(t, s.CreateSession(ctx, rec, sess, nil, "", auditFixture))
	sess, e = s.Session(ctx, sess.TokenHash, time.Hour)
	require(t, e)
	if !sess.Has("system.admin") {
		t.Fatal("bootstrap administrator lacks permission")
	}
	return rec, sess
}
func findRole(t *testing.T, data identity.AdminData, name string) identity.Role {
	t.Helper()
	for _, r := range data.Roles {
		if r.Name == name {
			return r
		}
	}
	t.Fatal("missing role", name)
	return identity.Role{}
}
func findPermission(t *testing.T, data identity.AdminData, name string) identity.Permission {
	t.Helper()
	for _, r := range data.Permissions {
		if r.Name == name {
			return r
		}
	}
	t.Fatal("missing permission", name)
	return identity.Permission{}
}
func TestPostgresIdentityLifecycle(t *testing.T) {
	s, ctx := postgres(t)
	admin, actor := bootstrap(t, ctx, s)
	require(t, s.CreatePermission(ctx, actor.TokenHash, "bdcmaps.network.read", "Read maps", auditFixture))
	data, e := s.AdminData(ctx, actor.TokenHash)
	require(t, e)
	perm := findPermission(t, data, "bdcmaps.network.read")
	builtin := findRole(t, data, "system-admin")
	require(t, s.SaveRole(ctx, actor.TokenHash, identity.RoleEdit{Name: "map-viewer", PermissionIDs: []string{perm.ID}}, auditFixture))
	data, e = s.AdminData(ctx, actor.TokenHash)
	require(t, e)
	viewer := findRole(t, data, "map-viewer")
	require(t, s.CreateUser(ctx, actor.TokenHash, identity.NewUser{Profile: identity.Profile{Username: "alice", Email: "alice@example.test"}, PasswordHash: "repository-test-alice-hash"}, auditFixture))
	alice, e := s.LoginRecord(ctx, "Alice")
	require(t, e)
	initial := sessionFixture(t, alice, "pwd")
	require(t, s.CreateSession(ctx, alice, initial, nil, "", auditFixture))
	initial, e = s.Session(ctx, initial.TokenHash, time.Hour)
	require(t, e)
	if len(initial.Permissions) != 0 || initial.Has("system.admin") {
		t.Fatal("zero-role user received permissions")
	}
	if _, e = s.AdminData(ctx, initial.TokenHash); !errors.Is(e, identity.ErrForbidden) {
		t.Fatalf("unprivileged admin read: %v", e)
	}
	if e = s.CreatePermission(ctx, initial.TokenHash, "evil.admin", "", auditFixture); !errors.Is(e, identity.ErrForbidden) {
		t.Fatalf("unprivileged write: %v", e)
	}

	edit := identity.UserEdit{ID: alice.User.ID, Profile: identity.Profile{Username: "alice", Email: "alice@example.test"}, Enabled: true, VerifyEmail: true, RoleIDs: []string{viewer.ID}}
	require(t, s.EditUser(ctx, actor.TokenHash, edit, auditFixture))
	updated, e := s.Session(ctx, initial.TokenHash, time.Hour)
	require(t, e)
	if !updated.Has(perm.Name) || !updated.User.EmailVerified {
		t.Fatal("live session did not read updated grants/profile")
	}
	edit.Email = "other@example.test"
	require(t, s.EditUser(ctx, actor.TokenHash, edit, auditFixture))
	updated, e = s.Session(ctx, initial.TokenHash, time.Hour)
	require(t, e)
	if updated.User.EmailVerified {
		t.Fatal("changing email preserved verification")
	}
	require(t, s.EditUser(ctx, actor.TokenHash, edit, auditFixture))
	updated, e = s.Session(ctx, initial.TokenHash, time.Hour)
	require(t, e)
	if !updated.User.EmailVerified {
		t.Fatal("explicit unchanged-address assertion failed")
	}
	_, e = s.DB.ExecContext(ctx, `UPDATE users SET email='third@example.test',email_verified=true WHERE id=$1::uuid`, alice.User.ID)
	require(t, e)
	updated, e = s.Session(ctx, initial.TokenHash, time.Hour)
	require(t, e)
	if updated.User.EmailVerified {
		t.Fatal("SQL update bypassed verification trigger")
	}

	require(t, s.SaveRole(ctx, actor.TokenHash, identity.RoleEdit{ID: viewer.ID, Name: viewer.Name}, auditFixture))
	updated, e = s.Session(ctx, initial.TokenHash, time.Hour)
	require(t, e)
	if updated.Has(perm.Name) {
		t.Fatal("removed permission survived a provider session read")
	}
	if e = s.SaveRole(ctx, actor.TokenHash, identity.RoleEdit{ID: builtin.ID, Name: builtin.Name}, auditFixture); !errors.Is(e, identity.ErrForbidden) {
		t.Fatalf("built-in role stripped: %v", e)
	}
	adminEdit := identity.UserEdit{ID: admin.User.ID, Profile: identity.Profile{Username: "admin", Email: "admin@example.test"}, Enabled: false, RoleIDs: []string{builtin.ID}}
	if e = s.EditUser(ctx, actor.TokenHash, adminEdit, auditFixture); !errors.Is(e, identity.ErrLastAdmin) {
		t.Fatalf("last administrator disabled: %v", e)
	}
	if _, e = s.Session(ctx, actor.TokenHash, time.Hour); e != nil {
		t.Fatal("failed last-admin transaction was not rolled back")
	}

	// Race: a password snapshot from before an administrator reset must not be
	// usable to create a fresh session after reset commits.
	alice, e = s.LoginRecord(ctx, "alice")
	require(t, e)
	stale := alice
	require(t, s.ResetPassword(ctx, actor.TokenHash, alice.User.ID, "replacement-repository-hash", true, auditFixture))
	if _, e = s.Session(ctx, initial.TokenHash, time.Hour); !errors.Is(e, identity.ErrSession) {
		t.Fatalf("reset retained old session: %v", e)
	}
	if e = s.CreateSession(ctx, stale, sessionFixture(t, stale, "pwd"), nil, "", auditFixture); !errors.Is(e, identity.ErrCredentials) {
		t.Fatalf("stale password snapshot accepted: %v", e)
	}
	alice, e = s.LoginRecord(ctx, "alice")
	require(t, e)
	forced := sessionFixture(t, alice, "pwd")
	require(t, s.CreateSession(ctx, alice, forced, nil, "", auditFixture))
	if e = s.BeginTOTP(ctx, forced.TokenHash, alice.PasswordHash, []byte("cipher"), auditFixture); !errors.Is(e, identity.ErrForbidden) {
		t.Fatalf("forced-change MFA bypass: %v", e)
	}
	require(t, s.ChangePassword(ctx, forced.TokenHash, alice.PasswordHash, "changed-repository-hash", auditFixture))
	if _, e = s.Session(ctx, forced.TokenHash, time.Hour); !errors.Is(e, identity.ErrSession) {
		t.Fatalf("password change retained session: %v", e)
	}
	alice, e = s.LoginRecord(ctx, "alice")
	require(t, e)
	if alice.User.ForcePasswordChange {
		t.Fatal("forced change flag not cleared")
	}

	// Enroll an encrypted authenticator. Another provider session cannot finish it.
	login := sessionFixture(t, alice, "pwd")
	require(t, s.CreateSession(ctx, alice, login, nil, "", auditFixture))
	second := sessionFixture(t, alice, "pwd")
	require(t, s.CreateSession(ctx, alice, second, nil, "", auditFixture))
	key := []byte("0123456789abcdef0123456789abcdef")
	cipher, e := cryptoutil.Seal(key, []byte("test-only-totp-seed!!"), []byte("totp:"+alice.User.ID))
	require(t, e)
	require(t, s.BeginTOTP(ctx, login.TokenHash, alice.PasswordHash, cipher, auditFixture))
	if _, e = s.PendingTOTP(ctx, second.TokenHash); e == nil {
		t.Fatal("another session can consume enrollment")
	}
	recovery := identity.Hash(token(t))
	require(t, s.ConfirmTOTP(ctx, login.TokenHash, cipher, 100, [][]byte{recovery}, auditFixture))
	if _, e = s.Session(ctx, login.TokenHash, time.Hour); !errors.Is(e, identity.ErrSession) {
		t.Fatal("MFA enrollment retained password-only session")
	}
	alice, e = s.LoginRecord(ctx, "alice")
	require(t, e)
	if !bytes.Equal(alice.Factor.Ciphertext, cipher) {
		t.Fatal("encrypted factor persistence differs")
	}
	if e = s.CreateSession(ctx, alice, sessionFixture(t, alice, "pwd"), nil, "", auditFixture); !errors.Is(e, identity.ErrCredentials) {
		t.Fatalf("password-only MFA bypass: %v", e)
	}

	// A failed session insertion must not consume the OTP. The first attempt
	// deliberately fails the audit insert after session insertion inside the tx.
	counter := int64(101)
	use := &identity.FactorUse{Ciphertext: cipher, Counter: &counter}
	failSession := sessionFixture(t, alice, "pwd", "otp")
	badAudit := identity.Audit{IP: "not-an-ip", RequestID: "rollback-witness"}
	if e = s.CreateSession(ctx, alice, failSession, use, "", badAudit); e == nil {
		t.Fatal("bad audit unexpectedly committed")
	}
	check, e := s.LoginRecord(ctx, "alice")
	require(t, e)
	if *check.Factor.LastCounter != 100 {
		t.Fatal("failed transaction consumed OTP")
	}
	if _, e = s.Session(ctx, failSession.TokenHash, time.Hour); !errors.Is(e, identity.ErrSession) {
		t.Fatal("failed transaction left a session")
	}

	sessions := []identity.Session{sessionFixture(t, alice, "pwd", "otp"), sessionFixture(t, alice, "pwd", "otp")}
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for _, candidate := range sessions {
		wg.Add(1)
		go func(v identity.Session) {
			defer wg.Done()
			results <- s.CreateSession(ctx, alice, v, use, "", auditFixture)
		}(candidate)
	}
	wg.Wait()
	close(results)
	success := 0
	for e := range results {
		if e == nil {
			success++
		} else if !errors.Is(e, identity.ErrCredentials) {
			t.Fatal(e)
		}
	}
	if success != 1 {
		t.Fatalf("concurrent OTP used %d times", success)
	}

	// Recovery code consumption has the same exactly-once transaction semantics.
	recoveryUse := &identity.FactorUse{Ciphertext: cipher, RecoveryHash: recovery}
	recovered := sessionFixture(t, alice, "pwd", "recovery")
	require(t, s.CreateSession(ctx, alice, recovered, recoveryUse, "", auditFixture))
	if e = s.CreateSession(ctx, alice, sessionFixture(t, alice, "pwd", "recovery"), recoveryUse, "", auditFixture); !errors.Is(e, identity.ErrCredentials) {
		t.Fatal("recovery code replay accepted", e)
	}
	require(t, s.RemoveTOTP(ctx, recovered.TokenHash, alice.PasswordHash, auditFixture))
	if _, e = s.Session(ctx, recovered.TokenHash, time.Hour); !errors.Is(e, identity.ErrSession) {
		t.Fatal("MFA removal retained session")
	}
	alice, e = s.LoginRecord(ctx, "alice")
	require(t, e)
	if alice.Factor != nil {
		t.Fatal("MFA factor not removed")
	}
	// Old-session authorization and disabled-user rejection are backend invariants.
	_, e = s.DB.ExecContext(ctx, `UPDATE sessions SET auth_time=now()-interval '11 minutes' WHERE token_hash=$1`, actor.TokenHash)
	require(t, e)
	if e = s.CreatePermission(ctx, actor.TokenHash, "stale.write", "", auditFixture); !errors.Is(e, identity.ErrForbidden) {
		t.Fatal("stale administrator write accepted", e)
	}
	data, e = s.AdminData(ctx, actor.TokenHash)
	require(t, e)
	if len(data.Events) == 0 {
		t.Fatal("no audit evidence")
	}
}
func TestPostgresBootstrapRaceAndStickyState(t *testing.T) {
	s, ctx := postgres(t)
	raw := token(t)
	require(t, s.IssueBootstrap(ctx, identity.Hash(raw), time.Now().Add(time.Minute)))
	results := make(chan error, 2)
	for _, name := range []string{"first", "second"} {
		go func(name string) {
			results <- s.Bootstrap(ctx, identity.Hash(raw), identity.NewUser{Profile: identity.Profile{Username: name}, PasswordHash: "repository-test-hash"}, auditFixture)
		}(name)
	}
	successes := 0
	for i := 0; i < 2; i++ {
		e := <-results
		if e == nil {
			successes++
		} else if !errors.Is(e, identity.ErrBootstrapClosed) {
			t.Fatal(e)
		}
	}
	if successes != 1 {
		t.Fatal("bootstrap was not single-use")
	}
	if e := s.IssueBootstrap(ctx, identity.Hash(token(t)), time.Now().Add(time.Minute)); !errors.Is(e, identity.ErrBootstrapClosed) {
		t.Fatal("issued bootstrap after setup", e)
	}
	// Simulate operator deletion; an empty users table MUST NOT reopen setup.
	_, e := s.DB.ExecContext(ctx, `DELETE FROM users`)
	require(t, e)
	open, e := s.BootstrapOpen(ctx)
	require(t, e)
	if open {
		t.Fatal("bootstrap reopened after users were deleted")
	}
}
