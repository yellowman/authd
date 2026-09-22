package cryptoutil

import "testing"

func TestSealRoundTrip(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	sealed, err := Seal(key, []byte("secret"), []byte("totp:user-1"))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := Open(key, sealed, []byte("totp:user-1"))
	if err != nil || string(plain) != "secret" {
		t.Fatalf("open: %v", err)
	}
	if _, err := Open(key, sealed, []byte("totp:other")); err == nil {
		t.Fatal("wrong associated data accepted")
	}
	sealed[len(sealed)-1] ^= 1
	if _, err := Open(key, sealed, []byte("totp:user-1")); err == nil {
		t.Fatal("tampering accepted")
	}
}
