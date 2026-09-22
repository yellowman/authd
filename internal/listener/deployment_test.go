//go:build linux || openbsd

package listener

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenBSDLauncherExportsEnvironmentAfterPrivilegeBoundary(t *testing.T) {
	// Exercise the actual launcher's shell/env/exec behavior, with only its two
	// installed paths redirected into a fixture. This is NOT an rc.subr/su test.
	body, err := os.ReadFile("../../deploy/openbsd/authd-run")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	envFile, executable := filepath.Join(dir, "authd.env"), filepath.Join(dir, "authd")
	if err = os.WriteFile(envFile, []byte("AUTHD_LISTEN='unix:/run/authd/authd.sock'\nDATABASE_URL='postgres://authd_runtime@localhost/authd'\nPGPASSFILE='/etc/authd/pgpass'\nAUTHD_MASTER_KEY_FILE='/etc/authd/master.key'\n"), 0600); err != nil {
		t.Fatal(err)
	}
	fake := `#!/bin/sh
set -eu
[ "$AUTHD_LISTEN" = 'unix:/run/authd/authd.sock' ]
[ "$DATABASE_URL" = 'postgres://authd_runtime@localhost/authd' ]
[ "$PGPASSFILE" = '/etc/authd/pgpass' ]
[ "$AUTHD_MASTER_KEY_FILE" = '/etc/authd/master.key' ]
printf 'environment received\n'
`
	if err = os.WriteFile(executable, []byte(fake), 0700); err != nil {
		t.Fatal(err)
	}
	launcher := filepath.Join(dir, "authd-run")
	text := strings.ReplaceAll(string(body), "/etc/authd/authd.env", envFile)
	text = strings.ReplaceAll(text, "/usr/local/bin/authd", executable)
	if err = os.WriteFile(launcher, []byte(text), 0700); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) ([]byte, error) {
		cmd := exec.Command("/bin/sh", append([]string{launcher}, args...)...)
		cmd.Env = []string{"PATH=/usr/bin:/bin"}
		return cmd.CombinedOutput()
	}
	out, err := run()
	if err != nil || string(out) != "environment received\n" {
		t.Fatalf("export/exec: %q, %v", out, err)
	}
	if out, err = run("migrate"); err == nil || strings.Contains(string(out), "environment received") {
		t.Fatalf("service must not run an administrative subcommand: %q, %v", out, err)
	}
	if err = os.Remove(envFile); err != nil {
		t.Fatal(err)
	}
	if out, err = run(); err == nil || strings.Contains(string(out), "environment received") {
		t.Fatalf("missing env must stop execution: %q, %v", out, err)
	}
}

func TestNativeSocketServiceContracts(t *testing.T) {
	read := func(path string) string {
		t.Helper()
		b, err := os.ReadFile(filepath.Join("../..", path))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	unit := read("deploy/systemd/authd.service")
	for _, want := range []string{"User=_authd", "Group=_authd", "RuntimeDirectory=authd", "RuntimeDirectoryMode=0711", "RuntimeDirectoryPreserve=yes", "ReadWritePaths=/run/authd", "ProtectSystem=strict", "EnvironmentFile=/etc/authd/authd.env"} {
		if !strings.Contains(unit, want+"\n") {
			t.Errorf("systemd lost %s", want)
		}
	}
	rc := read("deploy/openbsd/rc.d/authd")
	if strings.Contains(rc, "rc_start()") || !strings.Contains(rc, "rc_bg=YES") {
		t.Error("rc.d must use the standard background/start/wait implementation")
	}
	if strings.Index(rc, "pexp=") < strings.Index(rc, ". /etc/rc.d/rc.subr") {
		t.Error("rc.subr would overwrite the authd process expression")
	}
	for _, want := range []string{`daemon="/usr/local/libexec/authd-run"`, `pexp="^/usr/local/bin/authd$"`, "rc_pre()"} {
		if !strings.Contains(rc, want) {
			t.Errorf("rc.d lost %s", want)
		}
	}
	if !strings.Contains(read("Makefile"), "deploy/openbsd/authd-run") {
		t.Error("native installer must ship the referenced launcher")
	}
}

func TestSocketGroupRejectsChownSentinelAndOverflow(t *testing.T) {
	for _, group := range []string{"4294967295", "4294967296", "-1", "999999999999999999999999"} {
		if gid, err := socketGroup(group); err == nil {
			t.Fatalf("accepted %q as GID %d", group, gid)
		}
	}
}
