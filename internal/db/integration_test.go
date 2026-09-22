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
	if err = db.CheckSchema(ctx, conn); err != nil {
		t.Fatal("current schema rejected:", err)
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

func TestPostgresSchemaCheckRejectsMigrationHistoryDrift(t *testing.T) {
	s, ctx := postgres(t)
	if _, err := s.DB.ExecContext(ctx, `UPDATE schema_migrations SET name='003_tampered.sql' WHERE version=3`); err != nil {
		t.Fatal(err)
	}
	if err := db.CheckSchema(ctx, s.DB); !errors.Is(err, db.ErrSchemaOutdated) {
		t.Fatalf("tampered migration history accepted: %v", err)
	}
}

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
func findUser(t *testing.T, data identity.AdminData, username string) identity.User {
	t.Helper()
	for _, u := range data.Users {
		if u.Username == username {
			return u
		}
	}
	t.Fatal("missing user", username)
	return identity.User{}
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

	data, e = s.AdminData(ctx, actor.TokenHash)
	require(t, e)
	aliceAdmin := findUser(t, data, "alice")
	edit := identity.UserEdit{ID: alice.User.ID, Profile: identity.Profile{Username: "alice", Email: "alice@example.test"}, Enabled: true, VerifyEmail: true, RoleIDs: []string{viewer.ID}, ExpectedUpdatedAt: aliceAdmin.UpdatedAt}
	require(t, s.EditUser(ctx, actor.TokenHash, edit, auditFixture))
	updated, e := s.Session(ctx, initial.TokenHash, time.Hour)
	require(t, e)
	if !updated.Has(perm.Name) || !updated.User.EmailVerified {
		t.Fatal("live session did not read updated grants/profile")
	}
	// A stale form version must fail after the first successful mutation.
	if err := s.EditUser(ctx, actor.TokenHash, edit, auditFixture); !errors.Is(err, identity.ErrConflict) {
		t.Fatalf("stale user edit accepted: %v", err)
	}
	data, e = s.AdminData(ctx, actor.TokenHash)
	require(t, e)
	aliceAdmin = findUser(t, data, "alice")
	edit.ExpectedUpdatedAt = aliceAdmin.UpdatedAt
	edit.Email = "other@example.test"
	require(t, s.EditUser(ctx, actor.TokenHash, edit, auditFixture))
	updated, e = s.Session(ctx, initial.TokenHash, time.Hour)
	require(t, e)
	if updated.User.EmailVerified {
		t.Fatal("changing email preserved verification")
	}
	data, e = s.AdminData(ctx, actor.TokenHash)
	require(t, e)
	aliceAdmin = findUser(t, data, "alice")
	edit.ExpectedUpdatedAt = aliceAdmin.UpdatedAt
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

	require(t, s.SaveRole(ctx, actor.TokenHash, identity.RoleEdit{ID: viewer.ID, Name: viewer.Name, ExpectedUpdatedAt: viewer.UpdatedAt}, auditFixture))
	updated, e = s.Session(ctx, initial.TokenHash, time.Hour)
	require(t, e)
	if updated.Has(perm.Name) {
		t.Fatal("removed permission survived a provider session read")
	}
	if e = s.SaveRole(ctx, actor.TokenHash, identity.RoleEdit{ID: builtin.ID, Name: builtin.Name, ExpectedUpdatedAt: builtin.UpdatedAt}, auditFixture); !errors.Is(e, identity.ErrForbidden) {
		t.Fatalf("built-in role stripped: %v", e)
	}
	adminEdit := identity.UserEdit{ID: admin.User.ID, Profile: identity.Profile{Username: "admin", Email: "admin@example.test"}, Enabled: false, RoleIDs: []string{builtin.ID}, ExpectedUpdatedAt: admin.User.UpdatedAt}
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

func TestPostgresDestructiveLifecycleAndRecoveryRegeneration(t *testing.T) {
	s, ctx := postgres(t)
	admin, actor := bootstrap(t, ctx, s)

	// The final enabled administrator is protected from destructive deletion.
	if err := s.DeleteUser(ctx, actor.TokenHash, admin.User.ID, auditFixture); !errors.Is(err, identity.ErrLastAdmin) {
		t.Fatalf("last administrator deleted: %v", err)
	}

	require(t, s.CreatePermission(ctx, actor.TokenHash, "temporary.read", "temporary", auditFixture))
	data, err := s.AdminData(ctx, actor.TokenHash)
	require(t, err)
	perm := findPermission(t, data, "temporary.read")
	permEdit := identity.PermissionEdit{ID: perm.ID, Name: "temporary.view", Description: "renamed", ExpectedUpdatedAt: perm.UpdatedAt}
	require(t, s.SavePermission(ctx, actor.TokenHash, permEdit, auditFixture))
	if err = s.SavePermission(ctx, actor.TokenHash, permEdit, auditFixture); !errors.Is(err, identity.ErrConflict) {
		t.Fatalf("stale permission edit accepted: %v", err)
	}
	require(t, s.SaveRole(ctx, actor.TokenHash, identity.RoleEdit{Name: "temporary-role", PermissionIDs: []string{perm.ID}}, auditFixture))
	if err = s.DeletePermission(ctx, actor.TokenHash, perm.ID, auditFixture); !errors.Is(err, identity.ErrConflict) {
		t.Fatalf("referenced permission deleted: %v", err)
	}
	data, err = s.AdminData(ctx, actor.TokenHash)
	require(t, err)
	role := findRole(t, data, "temporary-role")
	roleEdit := identity.RoleEdit{ID: role.ID, Name: role.Name, Description: "updated", PermissionIDs: role.PermissionIDs, ExpectedUpdatedAt: role.UpdatedAt}
	require(t, s.SaveRole(ctx, actor.TokenHash, roleEdit, auditFixture))
	if err = s.SaveRole(ctx, actor.TokenHash, roleEdit, auditFixture); !errors.Is(err, identity.ErrConflict) {
		t.Fatalf("stale role edit accepted: %v", err)
	}
	require(t, s.DeleteRole(ctx, actor.TokenHash, role.ID, auditFixture))
	require(t, s.DeletePermission(ctx, actor.TokenHash, perm.ID, auditFixture))

	require(t, s.CreateUser(ctx, actor.TokenHash, identity.NewUser{Profile: identity.Profile{Username: "delete-me", Email: "delete@example.test"}, PasswordHash: "repository-test-delete-hash"}, auditFixture))
	victim, err := s.LoginRecord(ctx, "delete-me")
	require(t, err)
	victimSession := sessionFixture(t, victim, "pwd")
	require(t, s.CreateSession(ctx, victim, victimSession, nil, "", auditFixture))
	require(t, s.DeleteUser(ctx, actor.TokenHash, victim.User.ID, auditFixture))
	if _, err = s.LoginRecord(ctx, "delete-me"); !errors.Is(err, identity.ErrCredentials) {
		t.Fatalf("deleted user still authenticates: %v", err)
	}
	if _, err = s.Session(ctx, victimSession.TokenHash, time.Hour); !errors.Is(err, identity.ErrSession) {
		t.Fatalf("deleted user session survived: %v", err)
	}
	var passwordRows, roleRows int
	require(t, s.DB.QueryRowContext(ctx, `SELECT
		(SELECT count(*) FROM password_credentials WHERE user_id=$1::uuid),
		(SELECT count(*) FROM user_roles WHERE user_id=$1::uuid)`, victim.User.ID).Scan(&passwordRows, &roleRows))
	if passwordRows != 0 || roleRows != 0 {
		t.Fatalf("deleted identity retained credential/grants password=%d roles=%d", passwordRows, roleRows)
	}

	// Recovery regeneration is allowed only from a fresh MFA-authenticated session.
	require(t, s.CreateUser(ctx, actor.TokenHash, identity.NewUser{Profile: identity.Profile{Username: "mfa-user"}, PasswordHash: "repository-test-mfa-hash"}, auditFixture))
	mfaUser, err := s.LoginRecord(ctx, "mfa-user")
	require(t, err)
	cipher := []byte("integration-encrypted-seed")
	_, err = s.DB.ExecContext(ctx, `INSERT INTO totp_credentials(user_id,secret_ciphertext,last_counter,confirmed_at) VALUES($1::uuid,$2,1,now())`, mfaUser.User.ID, cipher)
	require(t, err)
	mfaUser, err = s.LoginRecord(ctx, "mfa-user")
	require(t, err)
	counter := int64(2)
	mfaSession := sessionFixture(t, mfaUser, "pwd", "otp")
	require(t, s.CreateSession(ctx, mfaUser, mfaSession, &identity.FactorUse{Ciphertext: cipher, Counter: &counter}, "", auditFixture))
	newCodes := [][]byte{identity.Hash("one"), identity.Hash("two"), identity.Hash("three")}
	require(t, s.ReplaceRecoveryCodes(ctx, mfaSession.TokenHash, newCodes, auditFixture))
	var recoveryCount int
	require(t, s.DB.QueryRowContext(ctx, `SELECT count(*) FROM recovery_codes WHERE user_id=$1::uuid AND consumed_at IS NULL`, mfaUser.User.ID).Scan(&recoveryCount))
	if recoveryCount != len(newCodes) {
		t.Fatalf("recovery rows=%d want=%d", recoveryCount, len(newCodes))
	}
	require(t, s.ResetMFA(ctx, actor.TokenHash, mfaUser.User.ID, auditFixture))
	mfaUser, err = s.LoginRecord(ctx, "mfa-user")
	require(t, err)
	if mfaUser.Factor != nil {
		t.Fatal("administrator MFA reset retained authenticator")
	}
	if _, err = s.Session(ctx, mfaSession.TokenHash, time.Hour); !errors.Is(err, identity.ErrSession) {
		t.Fatalf("MFA reset retained provider session: %v", err)
	}
}

func TestPostgresCleanupExpiredState(t *testing.T) {
	s, ctx := postgres(t)
	_, actor := bootstrap(t, ctx, s)
	now := time.Now().UTC()

	// Seed only states whose expiry semantics are independent of OIDC client setup.
	_, err := s.DB.ExecContext(ctx, `INSERT INTO bootstrap_tokens(token_hash,expires_at,consumed_at,created_at) VALUES($1,$2,$3,$4)`, identity.Hash("expired-bootstrap"), now.Add(-48*time.Hour), now.Add(-47*time.Hour), now.Add(-48*time.Hour))
	require(t, err)
	_, err = s.DB.ExecContext(ctx, `INSERT INTO pending_totp_enrollments(user_id,session_id,secret_ciphertext,expires_at) VALUES($1::uuid,$2::uuid,$3,$4)`, actor.User.ID, actor.ID, []byte("expired"), now.Add(-time.Hour))
	require(t, err)
	_, err = s.DB.ExecContext(ctx, `UPDATE sessions SET idle_expires_at=$2 WHERE id=$1::uuid`, actor.ID, now.Add(-time.Minute))
	require(t, err)
	_, err = s.DB.ExecContext(ctx, `INSERT INTO audit_events(event_type,occurred_at) VALUES('old.event',$1)`, now.Add(-400*24*time.Hour))
	require(t, err)

	stats, err := db.CleanupExpired(ctx, s.DB, now, 365*24*time.Hour)
	require(t, err)
	if stats.BootstrapTokens != 1 || stats.PendingTOTP != 1 || stats.Sessions != 1 || stats.AuditEvents != 1 {
		t.Fatalf("unexpected cleanup stats %#v", stats)
	}
}

func TestPostgresSelfProfileEditRequiresFreshSession(t *testing.T) {
	s, ctx := postgres(t)
	_, actor := bootstrap(t, ctx, s)
	_, err := s.DB.ExecContext(ctx, `UPDATE users SET email_verified=true WHERE id=$1::uuid`, actor.User.ID)
	require(t, err)
	require(t, s.EditOwnProfile(ctx, actor.TokenHash, identity.Profile{Username: actor.User.Username, DisplayName: "Primary Administrator", Email: "new-admin@example.test"}, auditFixture))
	updated, err := s.Session(ctx, actor.TokenHash, time.Hour)
	require(t, err)
	if updated.User.DisplayName != "Primary Administrator" || updated.User.Email != "new-admin@example.test" || updated.User.EmailVerified {
		t.Fatalf("unexpected self profile state: %+v", updated.User)
	}
	_, err = s.DB.ExecContext(ctx, `UPDATE sessions SET auth_time=now()-interval '11 minutes' WHERE id=$1::uuid`, actor.ID)
	require(t, err)
	if err = s.EditOwnProfile(ctx, actor.TokenHash, identity.Profile{Username: actor.User.Username, DisplayName: "Stale", Email: "stale@example.test"}, auditFixture); !errors.Is(err, identity.ErrForbidden) {
		t.Fatalf("stale session edited profile: %v", err)
	}
}

func TestPostgresMigrateRejectsAheadHistory(t *testing.T) {
	s, ctx := postgres(t)
	_, err := s.DB.ExecContext(ctx, `INSERT INTO schema_migrations(version,name) VALUES(999,'999_newer_release.sql')`)
	require(t, err)
	if err = db.Migrate(ctx, s.DB); !errors.Is(err, db.ErrSchemaOutdated) {
		t.Fatalf("migrator accepted newer history: %v", err)
	}
}
