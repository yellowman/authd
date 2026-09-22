package db

import (
	"context"
	"database/sql"
	"time"
)

// CleanupStats is deliberately small and log-safe: it contains only row counts,
// never subjects, client IDs, tokens, or other identity material.
type CleanupStats struct {
	AuthorizationRequests int64
	AuthorizationCodes    int64
	Sessions              int64
	PendingTOTP           int64
	BootstrapTokens       int64
	RefreshFamilies       int64
	AuditEvents           int64
}

const cleanupLockID int64 = 0x6175746802

// CleanupExpired removes state that can no longer be valid. Refresh-token
// families are retained until their absolute expiry even after revocation so
// replay attempts can still be recognized for the full grant lifetime.
// Signing keys are intentionally not cleaned here; key-retention policy must
// never delete a public verification key before every token it signed has died.
func CleanupExpired(ctx context.Context, pool *sql.DB, now time.Time, auditRetention time.Duration) (CleanupStats, error) {
	var out CleanupStats
	if auditRetention <= 0 {
		return out, nil
	}
	tx, err := pool.BeginTx(ctx, nil)
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, cleanupLockID); err != nil {
		return out, err
	}
	cutoff := now.Add(-auditRetention)
	codeConsumedCutoff := now.Add(-24 * time.Hour)
	bootstrapCutoff := now.Add(-24 * time.Hour)

	for _, item := range []struct {
		query string
		args  []any
		dest  *int64
	}{
		{`DELETE FROM authorization_requests WHERE expires_at < $1`, []any{now}, &out.AuthorizationRequests},
		{`DELETE FROM authorization_codes WHERE expires_at < $1 OR (consumed_at IS NOT NULL AND consumed_at < $2)`, []any{now, codeConsumedCutoff}, &out.AuthorizationCodes},
		// Delete pending enrollments before sessions so operational row counts remain
		// meaningful even though the session FK also cascades them.
		{`DELETE FROM pending_totp_enrollments WHERE expires_at < $1`, []any{now}, &out.PendingTOTP},
		{`DELETE FROM sessions WHERE idle_expires_at < $1 OR absolute_expires_at < $1`, []any{now}, &out.Sessions},
		{`DELETE FROM bootstrap_tokens WHERE (expires_at < $1 OR consumed_at IS NOT NULL) AND created_at < $2`, []any{now, bootstrapCutoff}, &out.BootstrapTokens},
		{`DELETE FROM refresh_token_families WHERE absolute_expires_at < $1`, []any{now}, &out.RefreshFamilies},
		{`DELETE FROM audit_events WHERE occurred_at < $1`, []any{cutoff}, &out.AuditEvents},
	} {
		result, e := tx.ExecContext(ctx, item.query, item.args...)
		if e != nil {
			return out, e
		}
		*item.dest, e = result.RowsAffected()
		if e != nil {
			return out, e
		}
	}
	if err = tx.Commit(); err != nil {
		return CleanupStats{}, err
	}
	return out, nil
}
