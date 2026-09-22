package cryptoutil

import (
	"crypto/hmac"
	"strings"
	"testing"
)

func TestCSRFBindsKeyBrowserAndPurpose(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	raw, err := RandomToken(32)
	if err != nil {
		t.Fatal(err)
	}
	want := CSRF(key, "session", raw)
	if !ValidToken(want) || !hmac.Equal([]byte(want), []byte(CSRF(key, "session", raw))) {
		t.Fatal("unstable token")
	}
	for _, got := range []string{CSRF(key, "browser", raw), CSRF(key, "session", raw+"x"), CSRF([]byte("different-key-material"), "session", raw)} {
		if got == want {
			t.Fatal("binding omitted")
		}
	}
}
func TestOpaqueTokensAndValidation(t *testing.T) {
	a, e := RandomToken(32)
	if e != nil {
		t.Fatal(e)
	}
	b, e := RandomToken(32)
	if e != nil {
		t.Fatal(e)
	}
	if a == b || !ValidToken(a) || !ValidToken(b) {
		t.Fatal("bad random tokens")
	}
	if _, e = RandomToken(1); e == nil {
		t.Fatal("accepted insufficient entropy")
	}
	for _, v := range []string{"", strings.Repeat("!", 43), a + "=", a[:42]} {
		if ValidToken(v) {
			t.Fatal("invalid token accepted")
		}
	}
	if HashOpaque(a) == HashOpaque(b) {
		t.Fatal("hash collision")
	}
}
