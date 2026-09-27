//go:build integration

package db_test

import (
	"errors"
	"testing"
	"time"

	"github.com/yellowman/authd/internal/identity"
)

func TestPostgresBrandingAuthorizationAndVersion(t *testing.T) {
	s, ctx := postgres(t)
	_, admin := bootstrap(t, ctx, s)
	b, err := s.Branding(ctx)
	require(t, err)
	if b.Name != "authd" || len(b.Logo) != 0 {
		t.Fatal("invalid defaults")
	}
	b.Name = "Example Network"
	b.Logo = []byte("test-logo")
	require(t, s.SaveBranding(ctx, admin.TokenHash, b, true, false, auditFixture))
	if err = s.SaveBranding(ctx, admin.TokenHash, b, true, false, auditFixture); !errors.Is(err, identity.ErrConflict) {
		t.Fatal("stale save accepted", err)
	}
	b, err = s.Branding(ctx)
	require(t, err)
	if b.Name != "Example Network" || string(b.Logo) != "test-logo" {
		t.Fatal("branding not persisted")
	}
	if err = s.SaveBranding(ctx, identity.Hash("unknown-session"), b, false, false, auditFixture); err == nil {
		t.Fatal("anonymous update accepted")
	}
	require(t, s.SaveBranding(ctx, admin.TokenHash, b, false, true, auditFixture))
	b, err = s.Branding(ctx)
	require(t, err)
	if len(b.Logo) != 0 {
		t.Fatal("logo not removed")
	}
	_, err = s.DB.ExecContext(ctx, `UPDATE sessions SET auth_time=$1 WHERE id=$2`, time.Now().Add(-11*time.Minute), admin.ID)
	require(t, err)
	if err = s.SaveBranding(ctx, admin.TokenHash, b, false, false, auditFixture); !errors.Is(err, identity.ErrForbidden) {
		t.Fatal("stale admin accepted", err)
	}
	var n int
	require(t, s.DB.QueryRowContext(ctx, `SELECT count(*) FROM audit_events WHERE event_type='branding.updated'`).Scan(&n))
	if n != 2 {
		t.Fatal("successful saves not audited", n)
	}
}
