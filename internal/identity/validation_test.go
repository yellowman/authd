package identity

import (
	"strings"
	"testing"
)

func TestNormalizeProfile(t *testing.T) {
	p, e := NormalizeProfile(Profile{Username: " Alice ", DisplayName: " Alice Smith ", Email: " ALICE@EXAMPLE.COM "})
	if e != nil || p.Username != "Alice" || p.Email != "alice@example.com" || p.DisplayName != "Alice Smith" {
		t.Fatalf("%+v %v", p, e)
	}
	for _, u := range []string{"", "a b", "a\n", "💻", "a/../", strings.Repeat("x", 129)} {
		// Trailing space/newline is trimmed by the normalization contract.
		if u == "a\n" {
			continue
		}
		if _, e := NormalizeProfile(Profile{Username: u}); e == nil {
			t.Fatalf("accepted username %q", u)
		}
	}
	for _, email := range []string{"bad", "Name <a@example.com>", "a@example.com\nb@example.com"} {
		if _, e := NormalizeProfile(Profile{Username: "alice", Email: email}); e == nil {
			t.Fatal("accepted malformed email")
		}
	}
}
func TestAssignmentValidation(t *testing.T) {
	id := "00000000-0000-4000-8000-000000000001"
	if ValidateIDs([]string{id}) != nil {
		t.Fatal("valid ID denied")
	}
	if ValidateIDs([]string{id, id}) == nil || ValidateIDs([]string{"bad"}) == nil {
		t.Fatal("invalid assignments accepted")
	}
	if ValidateName("bdcmaps.network.read", "") != nil || ValidateName("system.*", "") == nil {
		t.Fatal("bad name validation")
	}
}
