//go:build linux || openbsd

package listener

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"
)

func socketPath(t *testing.T) string {
	t.Helper()
	// Keep this below sockaddr_un's bound even when the test name is long.
	dir, err := os.MkdirTemp("", "authd-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "authd.sock")
}
func mustOpen(t *testing.T, path string) net.Listener {
	t.Helper()
	ln, err := Open(Options{Address: "unix:" + path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}
func mustInfo(t *testing.T, path string) os.FileInfo {
	t.Helper()
	i, e := os.Lstat(path)
	if e != nil {
		t.Fatal(e)
	}
	return i
}

func TestUnixHTTPModeAndCleanup(t *testing.T) {
	path := socketPath(t)
	ln := mustOpen(t, path)
	if m := mustInfo(t, path).Mode(); m&os.ModeSocket == 0 || m.Perm() != 0600 {
		t.Fatalf("mode %v", m)
	}
	if ln.Addr().String() != path {
		t.Fatal("published address missing", ln.Addr())
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := r.Context().Value(http.LocalAddrContextKey).(*net.UnixAddr); !ok {
			t.Error("Unix transport metadata missing")
		}
		_, _ = io.WriteString(w, "unix-http")
	})}
	go func() { done <- Serve(ctx, srv, ln, time.Second) }()
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", path)
	}}
	defer tr.CloseIdleConnections()
	resp, err := (&http.Client{Transport: tr, Timeout: time.Second}).Get("http://auth.example.test/healthz")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil || string(body) != "unix-http" {
		t.Fatalf("body=%q err=%v", body, err)
	}
	cancel()
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	if _, err = os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("socket left behind", err)
	}
	// The lock inode persists to avoid a split-lock race during restarts.
	if mode := mustInfo(t, path+".lock").Mode().Perm(); mode != 0600 {
		t.Fatal("lock mode", mode)
	}
	_ = mustOpen(t, path)
}

func TestUnixConfiguredGroup(t *testing.T) {
	path := socketPath(t)
	ln, err := Open(Options{Address: path, UnixMode: 0660, UnixGroup: strconv.Itoa(os.Getgid())})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	i := mustInfo(t, path)
	if i.Mode().Perm() != 0660 || i.Sys().(*syscall.Stat_t).Gid != uint32(os.Getgid()) {
		t.Fatal("mode/group not applied")
	}
}

func TestUnixRefusesInvalidModeAndGroup(t *testing.T) {
	path := socketPath(t)
	for _, o := range []Options{{Address: path, UnixMode: 0666}, {Address: path, UnixGroup: "authd-group-that-does-not-exist-xyz"}} {
		if ln, err := Open(o); err == nil {
			ln.Close()
			t.Fatal("invalid options accepted")
		}
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("invalid options published a socket")
	}
}

func TestUnixRefusesNonSocketTargets(t *testing.T) {
	for _, kind := range []string{"file", "directory", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			path := socketPath(t)
			switch kind {
			case "file":
				if err := os.WriteFile(path, []byte("keep"), 0600); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink("/does/not/exist", path); err != nil {
					t.Fatal(err)
				}
			}
			before := mustInfo(t, path)
			if ln, err := Open(Options{Address: path}); err == nil {
				ln.Close()
				t.Fatal("non-socket replaced")
			}
			if !os.SameFile(before, mustInfo(t, path)) {
				t.Fatal("target changed")
			}
		})
	}
}

func TestUnixRefusesLiveUnmanagedSocket(t *testing.T) {
	path := socketPath(t)
	old, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	before := mustInfo(t, path)
	if ln, err := Open(Options{Address: path}); err == nil {
		ln.Close()
		t.Fatal("live listener replaced")
	}
	if !os.SameFile(before, mustInfo(t, path)) {
		t.Fatal("live socket unlinked")
	}
}

func TestUnixRecoversStaleSocket(t *testing.T) {
	path := socketPath(t)
	old, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	old.SetUnlinkOnClose(false)
	if err = old.Close(); err != nil {
		t.Fatal(err)
	}
	mustInfo(t, path)
	_ = mustOpen(t, path)
}

func TestUnixConcurrentStartsOnlyOneWins(t *testing.T) {
	path := socketPath(t)
	const count = 20
	start := make(chan struct{})
	results := make(chan net.Listener, count)
	var wg sync.WaitGroup
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); <-start; ln, _ := Open(Options{Address: path}); results <- ln }()
	}
	close(start)
	wg.Wait()
	close(results)
	winners := 0
	for ln := range results {
		if ln != nil {
			winners++
			defer ln.Close()
		}
	}
	if winners != 1 {
		t.Fatalf("%d live listeners for one path", winners)
	}
}

func TestUnixLockRefusesSymlinkHardlinkAndFIFO(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "fifo", "permissive_file"} {
		t.Run(kind, func(t *testing.T) {
			path := socketPath(t)
			target := filepath.Join(filepath.Dir(path), "keep")
			if err := os.WriteFile(target, []byte("do-not-change"), 0600); err != nil {
				t.Fatal(err)
			}
			var err error
			switch kind {
			case "symlink":
				err = os.Symlink(target, path+".lock")
			case "hardlink":
				err = os.Link(target, path+".lock")
			case "fifo":
				err = syscall.Mkfifo(path+".lock", 0600)
			case "permissive_file":
				err = os.WriteFile(path+".lock", []byte("keep"), 0666)
				if err == nil {
					err = os.Chmod(path+".lock", 0666)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if ln, err := Open(Options{Address: path}); err == nil {
				ln.Close()
				t.Fatal("unsafe lock accepted")
			}
			body, _ := os.ReadFile(target)
			if string(body) != "do-not-change" {
				t.Fatal("lock followed/wrote target")
			}
		})
	}
}

func TestUnixParentPolicy(t *testing.T) {
	path := socketPath(t)
	if err := os.Chmod(filepath.Dir(path), 0777); err != nil {
		t.Fatal(err)
	}
	if ln, err := Open(Options{Address: path}); err == nil {
		ln.Close()
		t.Fatal("world-writable parent accepted")
	}
	if ln, err := Open(Options{Address: filepath.Join(filepath.Dir(path), "missing", "s")}); err == nil {
		ln.Close()
		t.Fatal("parent was silently created")
	}
}

func TestUnixParentAlias(t *testing.T) {
	path := socketPath(t)
	alias := filepath.Join(filepath.Dir(path), "alias")
	if err := os.Symlink(filepath.Dir(path), alias); err != nil {
		t.Fatal(err)
	}
	ln := mustOpen(t, filepath.Join(alias, "authd.sock"))
	if _, err := os.Lstat(path); err != nil {
		t.Fatal(err)
	}
	// Both spellings lock the same canonical inode.
	if other, err := Open(Options{Address: path}); err == nil {
		other.Close()
		t.Fatal("alias bypassed lifetime lock")
	}
	_ = ln.Close()
}

func TestUnixCloseDoesNotRemoveReplacement(t *testing.T) {
	path := socketPath(t)
	old := mustOpen(t, path)
	if err := os.Rename(path, path+".old"); err != nil {
		t.Fatal(err)
	}
	replacement, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Close()
	before := mustInfo(t, path)
	if err = old.Close(); err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, mustInfo(t, path)) {
		t.Fatal("old close deleted new listener")
	}
}

func TestUnixRejectsDifferentOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("different-owner witness requires root; normal suite does not")
	}
	path := socketPath(t)
	old, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	old.SetUnlinkOnClose(false)
	old.Close()
	if err = os.Chown(path, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	before := mustInfo(t, path)
	if ln, err := Open(Options{Address: path}); err == nil {
		ln.Close()
		t.Fatal("different owner's socket removed")
	}
	if !os.SameFile(before, mustInfo(t, path)) {
		t.Fatal("foreign socket replaced")
	}
}

func TestUnixCrashRecovery(t *testing.T) {
	path := socketPath(t)
	child := exec.Command(os.Args[0], "-test.run=^TestUnixCrashChild$")
	child.Env = append(os.Environ(), "AUTHD_LISTENER_CRASH_CHILD="+path)
	stdout, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = child.Process.Kill(); _ = child.Wait() }()
	ready := make(chan string, 1)
	go func() {
		s := bufio.NewScanner(stdout)
		if s.Scan() {
			ready <- s.Text()
		} else {
			ready <- ""
		}
	}()
	select {
	case line := <-ready:
		if line != "ready" {
			t.Fatal("child failed", line)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("child startup timed out")
	}
	before := mustInfo(t, path)
	if ln, err := Open(Options{Address: path}); err == nil {
		ln.Close()
		t.Fatal("live child lock bypassed")
	}
	if !os.SameFile(before, mustInfo(t, path)) {
		t.Fatal("live child socket replaced")
	}
	if err = child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = child.Wait()
	_ = mustOpen(t, path)
}

func TestUnixCrashChild(t *testing.T) {
	path := os.Getenv("AUTHD_LISTENER_CRASH_CHILD")
	if path == "" {
		return
	}
	ln, err := Open(Options{Address: path})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	fmt.Println("ready")
	for {
		time.Sleep(time.Hour)
	}
}
