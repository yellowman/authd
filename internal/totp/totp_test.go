package totp

import "testing"

func TestRFC6238SHA1Vectors(t *testing.T) {
	secret := []byte("12345678901234567890")
	tests := []struct {
		unix int64
		want string
	}{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
		{20000000000, "65353130"},
	}
	for _, tc := range tests {
		got, err := Code(secret, tc.unix/30, 8)
		if err != nil {
			t.Fatal(err)
		}
		if got != tc.want {
			t.Fatalf("time %d: got %s want %s", tc.unix, got, tc.want)
		}
	}
}
