// Package listener owns the HTTP transport, not the public OIDC issuer.
package listener

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"
)

// Options selects exactly one listening transport. UnixGroup changes only the
// socket group, never the daemon's primary group or access to its secret files.
type Options struct {
	Address   string
	UnixMode  os.FileMode
	UnixGroup string
}

// ParseAddress accepts existing TCP host:port values, unix:/absolute/path, or a
// bare absolute path. Abstract sockets and file/unix URL forms are not supported.
// Port zero is useful to internal tests; deployment configuration forbids it.
func ParseAddress(raw string) (network, address string, err error) {
	if raw == "" || raw != strings.TrimSpace(raw) || strings.IndexFunc(raw, unicode.IsControl) >= 0 {
		return "", "", errors.New("listener address is empty or contains whitespace/control characters")
	}
	if strings.HasPrefix(raw, "unix:") || filepath.IsAbs(raw) {
		path := strings.TrimPrefix(raw, "unix:")
		if err := validateUnixPath(path); err != nil {
			return "", "", err
		}
		return "unix", path, nil
	}
	_, port, err := net.SplitHostPort(raw)
	n, numberErr := strconv.Atoi(port)
	if err != nil || numberErr != nil || n < 0 || n > 65535 || strconv.Itoa(n) != port {
		return "", "", errors.New("listener must be TCP host:port or unix:/absolute/path")
	}
	return "tcp", raw, nil
}

func validateUnixPath(path string) error {
	if !filepath.IsAbs(path) || path == "/" || filepath.Clean(path) != path || strings.IndexFunc(path, unicode.IsControl) >= 0 {
		return errors.New("Unix socket requires a clean absolute filesystem path")
	}
	// OpenBSD's sockaddr_un has 104 path bytes, including the terminator.
	// Reserve room in the same directory for a private staging socket, so mode
	// and group are established before the public name becomes connectable.
	if len(path) > 103 || len(filepath.Dir(path))+20 > 103 {
		return errors.New("Unix socket path is too long (103 bytes total; parent at most 83 bytes)")
	}
	return nil
}

func Open(opts Options) (net.Listener, error) {
	network, address, err := ParseAddress(opts.Address)
	if err != nil {
		return nil, err
	}
	if network == "tcp" {
		if opts.UnixGroup != "" {
			return nil, errors.New("Unix socket group requires a Unix listener")
		}
		return net.Listen("tcp", address)
	}
	if opts.UnixMode == 0 {
		opts.UnixMode = 0600
	}
	if opts.UnixMode != 0600 && opts.UnixMode != 0660 {
		return nil, errors.New("Unix socket mode must be 0600 or 0660")
	}
	return openUnix(address, opts)
}
