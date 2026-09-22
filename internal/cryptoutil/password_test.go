package cryptoutil

import "testing"

func TestPasswordRoundTrip(t *testing.T) {
	encoded, err := HashPassword("correct horse battery staple", DefaultArgon2Params)
	if err != nil {
		t.Fatal(err)
	}
	match, rehash, err := VerifyPassword(encoded, "correct horse battery staple", DefaultArgon2Params)
	if err != nil || !match || rehash {
		t.Fatalf("match=%v rehash=%v err=%v", match, rehash, err)
	}
	match, _, err = VerifyPassword(encoded, "definitely wrong", DefaultArgon2Params)
	if err != nil || match {
		t.Fatalf("wrong password match=%v err=%v", match, err)
	}
}

func TestSealRoundTrip(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	sealed, err := Seal(key, []byte("secret"), []byte("totp:user-1"))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := Open(key, sealed, []byte("totp:user-1"))
	if err != nil {
		t.Fatal(err)
	}
	if string(plain) != "secret" {
		t.Fatalf("got %q", plain)
	}
	if _, err := Open(key, sealed, []byte("totp:other")); err == nil {
		t.Fatal("wrong associated data was accepted")
	}
}
