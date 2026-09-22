package listener

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestParseAddress(t *testing.T) {
	for _, tc := range []struct{ raw, network, address string }{
		{"127.0.0.1:8080", "tcp", "127.0.0.1:8080"},
		{"[::1]:8080", "tcp", "[::1]:8080"},
		{"unix:/run/authd/authd.sock", "unix", "/run/authd/authd.sock"},
		{"/var/run/authd/authd.sock", "unix", "/var/run/authd/authd.sock"},
	} {
		n, a, err := ParseAddress(tc.raw)
		if err != nil || n != tc.network || a != tc.address {
			t.Fatalf("%q => %q %q %v", tc.raw, n, a, err)
		}
	}
	for _, raw := range []string{"", "unix:relative", "unix:@abstract", "unix:///run/authd/s", "unix:/", "/run/authd/../s", "/run/authd/", "http://localhost:80", "127.0.0.1:http", "127.0.0.1:65536", " /tmp/x", "unix:/tmp/a\x00b", "/tmp/" + strings.Repeat("a", 104)} {
		if _, _, err := ParseAddress(raw); err == nil {
			t.Fatalf("accepted %q", raw)
		}
	}
}

func TestServeTCPAndGracefulShutdown(t *testing.T) {
	ln, err := Open(Options{Address: "127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered, release := make(chan struct{}), make(chan struct{})
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
		_, _ = io.WriteString(w, "finished")
	})}
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, srv, ln, time.Second) }()
	received := make(chan error, 1)
	go func() {
		resp, err := http.Get("http://" + ln.Addr().String())
		if err == nil {
			body, e := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if e != nil {
				err = e
			} else if string(body) != "finished" {
				err = errors.New("response truncated")
			}
		}
		received <- err
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not start")
	}
	cancel()
	select {
	case err = <-done:
		t.Fatalf("did not drain handler: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err = <-received; err != nil {
		t.Fatal(err)
	}
	select {
	case err = <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown did not finish")
	}
}

func TestServeCancellationBeforeStart(t *testing.T) {
	ln, err := Open(Options{Address: "127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err = Serve(ctx, &http.Server{}, ln, time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err = ln.Accept(); err == nil {
		t.Fatal("listener leaked")
	}
}

func TestServeDeadlineClosesConnections(t *testing.T) {
	ln, err := Open(Options{Address: "127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered, finished := make(chan struct{}), make(chan struct{})
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(entered); <-r.Context().Done(); close(finished) })}
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, srv, ln, 20*time.Millisecond) }()
	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		resp, _ := http.Get("http://" + ln.Addr().String())
		if resp != nil {
			_ = resp.Body.Close()
		}
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("no request")
	}
	cancel()
	if err = <-done; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("lost shutdown deadline", err)
	}
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("connection not closed")
	}
	<-clientDone
}
