package listener

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"
)

// Serve owns ln and drains HTTP work on cancellation. A drain deadline forces
// connections closed; every exit closes the listener and its socket resources.
func Serve(ctx context.Context, server *http.Server, ln net.Listener, grace time.Duration) (err error) {
	defer func() {
		if closeErr := ln.Close(); !errors.Is(closeErr, net.ErrClosed) {
			err = errors.Join(err, closeErr)
		}
	}()
	defer server.Close()
	if ctx.Err() != nil {
		return nil
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(ln) }()
	select {
	case err = <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), grace)
		defer cancel()
		err = server.Shutdown(shutdownCtx)
		if err != nil {
			_ = server.Close()
		}
		serveErr := <-done
		if !errors.Is(serveErr, http.ErrServerClosed) {
			err = errors.Join(err, serveErr)
		}
		return err
	}
}
