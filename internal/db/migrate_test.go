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
