//go:build linux || openbsd

package listener

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// A persistent sidecar inode serializes *the entire lifetime*, not only startup.
// Never unlink the lock file: two open descriptors of different inodes are not
// a lock. Kernel locks release on process death; the leftover file is harmless.
func lockSocket(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return nil, fmt.Errorf("open socket lock: %w", err)
	}
	fail := func(err error) (*os.File, error) { _ = f.Close(); return nil, err }
	info, err := f.Stat()
	if err != nil {
		return fail(err)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || st.Uid != uint32(os.Geteuid()) || st.Nlink != 1 || info.Mode().Perm() != 0600 {
		return fail(errors.New("socket lock must be an owned, single-link regular file with mode 0600"))
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return fail(fmt.Errorf("socket path is locked by another process: %w", err))
	}
	named, err := os.Lstat(path)
	if err != nil || !os.SameFile(info, named) {
		return fail(errors.New("socket lock path changed"))
	}
	return f, nil
}

func socketGroup(name string) (int, error) {
	if name == "" {
		return -1, nil
	}
	if n, err := strconv.Atoi(name); err == nil && validGID(n) && strconv.Itoa(n) == name {
		return n, nil
	}
	g, err := user.LookupGroup(name)
	if err != nil {
		return -1, errors.New("configured Unix socket group does not exist")
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil || !validGID(gid) {
		return -1, errors.New("configured Unix socket group has an invalid GID")
	}
	return gid, nil
}

// Both supported kernels use unsigned 32-bit GIDs; all-ones is chown's
// "leave unchanged" sentinel and must not be accepted as a requested group.
func validGID(gid int) bool {
	return gid >= 0 && uint64(gid) < (1<<32)-1
}

func openUnix(path string, opts Options) (net.Listener, error) {
	gid, err := socketGroup(opts.UnixGroup)
	if err != nil {
		return nil, err
	}
	// Resolve a normal /var/run -> /run alias once. All subsequent operations use
	// the resolved directory, not a repeatedly followed symlink from configuration.
	parent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return nil, fmt.Errorf("Unix socket parent must already exist: %w", err)
	}
	path = filepath.Join(parent, filepath.Base(path))
	if err = validateUnixPath(path); err != nil {
		return nil, err
	}
	info, err := os.Stat(parent)
	if err != nil {
		return nil, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || st.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0022 != 0 {
		return nil, errors.New("Unix socket parent must be owned by the daemon and not group/world writable")
	}
	lock, err := lockSocket(path + ".lock")
	if err != nil {
		return nil, err
	}
	success := false
	defer func() {
		if !success {
			_ = lock.Close()
		}
	}()
	if err = removeStaleSocket(path); err != nil {
		return nil, err
	}

	// Bind inside an owner-only directory instead of changing process-wide umask
	// or exposing a briefly permissive socket between bind and chmod/chown.
	stage, err := os.MkdirTemp(parent, ".authd-")
	if err != nil {
		return nil, err
	}
	staged := filepath.Join(stage, "s")
	defer func() { _ = os.Remove(staged); _ = os.Remove(stage) }()
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: staged, Net: "unix"})
	if err != nil {
		return nil, err
	}
	ln.SetUnlinkOnClose(false)
	defer func() {
		if !success {
			_ = ln.Close()
		}
	}()
	if gid != -1 {
		if err = os.Chown(staged, -1, gid); err != nil {
			return nil, fmt.Errorf("set Unix socket group (daemon must belong to the group): %w", err)
		}
	}
	if err = os.Chmod(staged, opts.UnixMode); err != nil {
		return nil, err
	}
	socketInfo, err := os.Lstat(staged)
	if err != nil {
		return nil, err
	}
	if _, err = os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("Unix socket destination appeared during startup")
	}
	// Only this daemon/root can mutate parent; the lifetime lock serializes all
	// authd starts. Publish with final permissions already in place.
	if err = os.Rename(staged, path); err != nil {
		return nil, err
	}
	success = true
	return &unixListener{UnixListener: ln, path: path, identity: socketInfo, lock: lock}, nil
}

func removeStaleSocket(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode()&os.ModeSocket == 0 || st.Uid != uint32(os.Geteuid()) {
		return errors.New("existing Unix socket path is not a socket owned by this daemon")
	}
	conn, err := net.DialTimeout("unix", path, 250*time.Millisecond)
	if err == nil {
		_ = conn.Close()
		return errors.New("Unix socket is already accepting connections")
	}
	// Permission failures, timeouts, backlog pressure and all unknown failures
	// are NOT evidence that an endpoint is stale.
	if !errors.Is(err, syscall.ECONNREFUSED) {
		return fmt.Errorf("cannot prove Unix socket is stale: %w", err)
	}
	now, err := os.Lstat(path)
	if err != nil || !os.SameFile(info, now) {
		return errors.New("Unix socket path changed during stale check")
	}
	return os.Remove(path)
}

type unixListener struct {
	*net.UnixListener
	path     string
	identity os.FileInfo
	lock     *os.File
	once     sync.Once
	closeErr error
}

func (l *unixListener) Addr() net.Addr { return &net.UnixAddr{Name: l.path, Net: "unix"} }

func (l *unixListener) Close() error {
	l.once.Do(func() {
		l.closeErr = l.UnixListener.Close()
		current, err := os.Lstat(l.path)
		switch {
		case err == nil && current.Mode()&os.ModeSocket != 0 && os.SameFile(l.identity, current):
			l.closeErr = errors.Join(l.closeErr, os.Remove(l.path))
		case err != nil && !errors.Is(err, os.ErrNotExist):
			l.closeErr = errors.Join(l.closeErr, err)
		}
		// Never remove a replacement path, and never remove the sidecar lock inode.
		l.closeErr = errors.Join(l.closeErr, l.lock.Close())
	})
	return l.closeErr
}
