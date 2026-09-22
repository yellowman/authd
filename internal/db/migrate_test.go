package db

import (
	"strings"
	"testing"
)

func TestInitialSchemaKeepsCredentialsSeparateFromUsers(t *testing.T) {
	body, err := migrationFS.ReadFile("migrations/001_init.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(body)
	if !strings.Contains(sql, "CREATE TABLE password_credentials") {
		t.Fatal("initial schema must contain password_credentials")
	}
	usersStart := strings.Index(sql, "CREATE TABLE users")
	if usersStart < 0 {
		t.Fatal("users table not found")
	}
	usersEnd := strings.Index(sql[usersStart:], ");")
	if usersEnd < 0 {
		t.Fatal("users table terminator not found")
	}
	usersDDL := sql[usersStart : usersStart+usersEnd]
	if strings.Contains(usersDDL, "password_hash") {
		t.Fatal("users table must not own password_hash")
	}
}

func TestInitialSchemaOIDCClientsAreNotGenericProtocolPeers(t *testing.T) {
	body, err := migrationFS.ReadFile("migrations/001_init.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(body)
	if strings.Contains(sql, "protocol_type") || strings.Contains(sql, "client_protocol") {
		t.Fatal("OIDC clients table must not become a polymorphic protocol registry")
	}
}

// Structural regression only; actual PostgreSQL execution is the integration gate.
func TestLifecycleMigrationRetainsBootstrapAndTriggerGuards(t *testing.T) {
	body, err := migrationFS.ReadFile("migrations/002_identity_lifecycle.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{"bootstrap_completed", "REFERENCES sessions(id) ON DELETE CASCADE", "END;\n$$;", "users_clear_email_verification"} {
		if !strings.Contains(string(body), marker) {
			t.Fatalf("missing migration guard %q", marker)
		}
	}
}

func TestOIDCMigrationAddsDurableContinuationsAndRefreshContext(t *testing.T) {
	body, err := migrationFS.ReadFile("migrations/003_oidc_authorization.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(body)
	for _, marker := range []string{"CREATE TABLE authorization_requests", "request_hash bytea PRIMARY KEY", "ADD COLUMN auth_methods", "ADD COLUMN scopes"} {
		if !strings.Contains(sql, marker) {
			t.Fatalf("missing OIDC migration guard %q", marker)
		}
	}
}

func TestOIDCRPContractMigrationAddsACRAndSID(t *testing.T) {
	body, err := migrationFS.ReadFile("migrations/004_oidc_rp_contract.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(body)
	for _, marker := range []string{"required_acr", "urn:authd:acr:mfa", "ADD COLUMN session_id uuid"} {
		if !strings.Contains(sql, marker) {
			t.Fatalf("missing RP contract migration guard %q", marker)
		}
	}
}

func TestMigrationManifestIsOrderedAndUnique(t *testing.T) {
	manifest, err := migrationManifest()
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest) == 0 {
		t.Fatal("empty migration manifest")
	}
	for i, m := range manifest {
		if m.Version != int64(i+1) || m.Name == "" {
			t.Fatalf("unordered manifest: %#v", manifest)
		}
	}
}

func TestAtomicGrantMigrationInvalidatesOnlyPendingFlows(t *testing.T) {
	body, err := migrationFS.ReadFile("migrations/005_oidc_atomic_grants.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{"browser_hash", "refresh_family_id", "max_age_seconds", "refresh_families_session_idx", "DELETE FROM authorization_requests"} {
		if !strings.Contains(string(body), marker) {
			t.Fatalf("missing atomic-grant migration rule %q", marker)
		}
	}
	if strings.Contains(string(body), "DELETE FROM users") || strings.Contains(string(body), "DELETE FROM signing_keys") {
		t.Fatal("upgrade destroyed durable identities or keys")
	}
}

func TestMigrationPrefixRejectsHolesAndFutureHistory(t *testing.T) {
	m := []migrationEntry{{1, "001.sql"}, {2, "002.sql"}, {3, "003.sql"}}
	for _, actual := range [][]migrationEntry{nil, m[:1], m[:2], m} {
		if !migrationPrefix(actual, m) {
			t.Fatalf("valid prefix rejected: %v", actual)
		}
	}
	for _, actual := range [][]migrationEntry{{m[1]}, {m[0], m[2]}, {{1, "renamed.sql"}}, append(append([]migrationEntry{}, m...), migrationEntry{4, "future.sql"})} {
		if migrationPrefix(actual, m) {
			t.Fatalf("invalid history accepted: %v", actual)
		}
	}
}
