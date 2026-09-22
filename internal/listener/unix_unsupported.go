//go:build !linux && !openbsd

package listener

import (
	"errors"
	"net"
)

func openUnix(string, Options) (net.Listener, error) {
	return nil, errors.New("authd Unix listeners are supported on Linux and OpenBSD")
}
