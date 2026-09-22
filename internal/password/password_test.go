package password

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
