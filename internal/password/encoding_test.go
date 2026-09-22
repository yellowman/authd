package password

import (
	"encoding/base64"
	"strings"
	"testing"
)

func validEncoding() string {
	return "$argon2id$v=19$m=65536,t=3,p=2$" + base64.RawStdEncoding.EncodeToString(make([]byte, 16)) + "$" + base64.RawStdEncoding.EncodeToString(make([]byte, 32))
}
func TestPHCParserRejectsUnboundedAndMalformedInput(t *testing.T) {
	valid := validEncoding()
	cases := map[string]string{
		"memory bomb":    strings.Replace(valid, "m=65536", "m=4294967295", 1),
		"time bomb":      strings.Replace(valid, "t=3", "t=1000000", 1),
		"zero threads":   strings.Replace(valid, "p=2", "p=0", 1),
		"many threads":   strings.Replace(valid, "p=2", "p=255", 1),
		"version suffix": strings.Replace(valid, "v=19", "v=19junk", 1),
		"duplicate":      strings.Replace(valid, "m=65536,t=3,p=2", "m=65536,t=3,p=2,p=2", 1),
		"negative":       strings.Replace(valid, "m=65536", "m=-1", 1),
		"leading zero":   strings.Replace(valid, "t=3", "t=03", 1),
		"variant":        strings.Replace(valid, "argon2id", "argon2i", 1),
		"extra prefix":   "garbage" + valid,
		"base64 newline": valid[:len(valid)-1] + "\n" + valid[len(valid)-1:],
		"oversized":      strings.Repeat("a", 513),
		"missing":        strings.Replace(valid, ",p=2", "", 1),
		"short salt":     "$argon2id$v=19$m=65536,t=3,p=2$YWJj$" + base64.RawStdEncoding.EncodeToString(make([]byte, 32)),
	}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, _, err := parseArgon2id(value); err == nil {
				t.Fatal("invalid verifier accepted")
			}
		})
	}
}
func TestPHCParserValidBounds(t *testing.T) {
	p, salt, hash, err := parseArgon2id(validEncoding())
	if err != nil {
		t.Fatal(err)
	}
	if p.Memory != 65536 || p.Iterations != 3 || p.Parallelism != 2 || len(salt) != 16 || len(hash) != 32 {
		t.Fatalf("wrong parse: %+v", p)
	}
}
func FuzzPHCParser(f *testing.F) {
	f.Add(validEncoding())
	f.Add("")
	f.Add("$argon2id$v=19$m=4294967295,t=1000,p=255$x$y")
	f.Fuzz(func(t *testing.T, encoded string) {
		p, _, _, err := parseArgon2id(encoded)
		if err == nil && validateArgon2Params(p) != nil {
			t.Fatal("unsafe parsed parameters")
		}
	})
}
