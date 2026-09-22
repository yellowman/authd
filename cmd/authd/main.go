package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/yellowman/authd/internal/config"
	"github.com/yellowman/authd/internal/db"
	"github.com/yellowman/authd/internal/identity"
	"github.com/yellowman/authd/internal/password"
	webserver "github.com/yellowman/authd/internal/web"
)

func main() {
	if err := run(); err != nil {
		slog.Error("authd stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) > 2 || (len(os.Args) == 2 && os.Args[1] != "bootstrap") {
		return errors.New("usage: authd [bootstrap]")
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pool, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := db.Migrate(ctx, pool); err != nil {
		return err
	}

	service, err := identity.NewService(&db.IdentityStore{DB: pool}, password.Hasher{Params: password.DefaultArgon2Params}, cfg.MasterKey, cfg.SessionIdleTTL, cfg.SessionAbsoluteTTL)
	if err != nil {
		return err
	}
	if len(os.Args) == 2 {
		token, err := service.IssueBootstrap(ctx)
		if err != nil {
			return err
		}
		// Explicit local command output, never the daemon's structured request log.
		fmt.Fprintln(os.Stdout, token)
		return nil
	}
	app, err := webserver.New(cfg, service, pool.PingContext)
	if err != nil {
		return err
	}
	handler, err := app.Handler()
	if err != nil {
		return err
	}

	httpServer := &http.Server{
		Addr:              cfg.Listen,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	errCh := make(chan error, 1)
	go func() {
		slog.Info("authd listening", "listen", cfg.Listen, "issuer", cfg.Issuer)
		errCh <- httpServer.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return httpServer.Shutdown(shutdownCtx)
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}
