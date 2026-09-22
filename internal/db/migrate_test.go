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
	want := []migrationEntry{{Version: 1, Name: "001_init.sql"}, {Version: 2, Name: "002_identity_lifecycle.sql"}, {Version: 3, Name: "003_oidc_authorization.sql"}, {Version: 4, Name: "004_oidc_rp_contract.sql"}}
	if len(manifest) != len(want) {
		t.Fatalf("migration count %d, want %d", len(manifest), len(want))
	}
	for i := range want {
		if manifest[i] != want[i] {
			t.Fatalf("migration %d = %#v, want %#v", i, manifest[i], want[i])
		}
	}
}
