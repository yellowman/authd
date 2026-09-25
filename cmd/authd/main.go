package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/yellowman/authd/internal/config"
	"github.com/yellowman/authd/internal/cryptoutil"
	"github.com/yellowman/authd/internal/db"
	"github.com/yellowman/authd/internal/identity"
	"github.com/yellowman/authd/internal/listener"
	"github.com/yellowman/authd/internal/oidc"
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
	registrationTokenCommand := len(os.Args) == 3 && os.Args[1] == "registration-token"
	if !registrationTokenCommand && (len(os.Args) > 2 || (len(os.Args) == 2 && os.Args[1] != "bootstrap" && os.Args[1] != "migrate")) {
		return errors.New("usage: authd [bootstrap|migrate|registration-token SCOPE_PREFIX]")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Migration is a deployment/DDL operation and intentionally has a much
	// smaller configuration surface than the daemon. The migration owner does
	// not need the issuer or master key, and its DATABASE_URL should never be
	// stored in the daemon environment file.
	if len(os.Args) == 2 && os.Args[1] == "migrate" {
		dsn := strings.TrimSpace(os.Getenv("DATABASE_URL"))
		if dsn == "" {
			return errors.New("DATABASE_URL is required")
		}
		pool, err := db.Open(ctx, dsn)
		if err != nil {
			return err
		}
		defer pool.Close()
		if err := db.Migrate(ctx, pool); err != nil {
			return fmt.Errorf("database migration failed: %w", err)
		}
		fmt.Fprintln(os.Stdout, "database schema is current")
		return nil
	}
	if registrationTokenCommand {
		prefix := os.Args[2]
		if !oidc.ValidRegistrationPrefix(prefix) {
			return errors.New("registration token scope prefix must be a lowercase namespace ending in a dot, e.g. inventory.")
		}
		dsn := strings.TrimSpace(os.Getenv("DATABASE_URL"))
		if dsn == "" {
			return errors.New("DATABASE_URL is required")
		}
		pool, err := db.Open(ctx, dsn)
		if err != nil {
			return err
		}
		defer pool.Close()
		if err := db.CheckSchema(ctx, pool); err != nil {
			return err
		}
		token, err := cryptoutil.RandomToken(32)
		if err != nil {
			return err
		}
		if err := db.IssueInitialRegistrationToken(ctx, pool, identity.Hash(token), prefix, time.Now().Add(15*time.Minute)); err != nil {
			return err
		}
		// One-time credential: only the issuing terminal sees the plaintext.
		fmt.Fprintln(os.Stdout, token)
		return nil
	}

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	pool, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := db.CheckSchema(ctx, pool); err != nil {
		if errors.Is(err, db.ErrSchemaOutdated) {
			return errors.New("database schema is missing or out of date; run authd migrate with the migration database role")
		}
		return errors.New("database schema could not be verified")
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
	oidcService, err := oidc.NewService(&db.OIDCStore{DB: pool}, service, cfg.Issuer, cfg.MasterKey, cfg.AuthorizationCodeTTL, cfg.RefreshIdleTTL, cfg.RefreshAbsoluteTTL)
	if err != nil {
		return err
	}
	if err = oidcService.EnsureSigningKey(ctx); err != nil {
		return err
	}
	cleanup := func() {
		cleanupCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		stats, cleanupErr := db.CleanupExpired(cleanupCtx, pool, time.Now().UTC(), cfg.AuditRetention)
		if cleanupErr != nil {
			if !errors.Is(cleanupErr, context.Canceled) {
				slog.Warn("expired-state cleanup failed", "class", "dependency_unavailable")
			}
			return
		}
		total := stats.AuthorizationRequests + stats.AuthorizationCodes + stats.Sessions + stats.PendingTOTP + stats.BootstrapTokens + stats.RefreshTokens + stats.RefreshFamilies + stats.AuditEvents
		if total != 0 || stats.More {
			slog.Info("expired state cleaned", "rows", total, "more", stats.More)
		}
	}
	cleanup()
	go func() {
		ticker := time.NewTicker(cfg.CleanupInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				cleanup()
			}
		}
	}()
	provider := oidc.NewHTTP(oidcService, cfg.Issuer, cfg.Development)
	app, err := webserver.New(cfg, service, pool.PingContext, provider)
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

	ln, err := listener.Open(listener.Options{Address: cfg.Listen, UnixMode: cfg.UnixSocketMode, UnixGroup: cfg.UnixSocketGroup})
	if err != nil {
		return fmt.Errorf("open HTTP listener: %w", err)
	}
	slog.Info("authd listening", "network", ln.Addr().Network(), "listen", ln.Addr().String(), "issuer", cfg.Issuer)
	return listener.Serve(ctx, httpServer, ln, 10*time.Second)
}
