package db

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Counts include only committed primary-row deletes (not FK cascades). More
// means the bounded maintenance budget was exhausted or a live writer won.
type CleanupStats struct {
	AuthorizationRequests, AuthorizationCodes, Sessions, PendingTOTP, BootstrapTokens, RefreshTokens, RefreshFamilies, AuditEvents int64
	More                                                                                                                           bool
}

const cleanupLockID int64 = 0x6175746802
const cleanupBatchSize = 256

// CleanupExpired yields between small transactions. It retains replay witnesses
// for the whole offline family lifetime, and never cleans signing public keys.
func CleanupExpired(ctx context.Context, pool *sql.DB, now time.Time, auditRetention time.Duration) (CleanupStats, error) {
	var out CleanupStats
	if auditRetention <= 0 {
		return out, nil
	}
	budget, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	items := []struct {
		query string
		args  []any
		dest  *int64
	}{
		{`DELETE FROM authorization_requests WHERE request_hash IN (SELECT request_hash FROM authorization_requests WHERE expires_at<$1 ORDER BY expires_at LIMIT 256)`, []any{now}, &out.AuthorizationRequests},
		{`DELETE FROM authorization_codes WHERE code_hash IN (SELECT code_hash FROM authorization_codes c WHERE (consumed_at IS NULL AND expires_at<$1) OR (consumed_at<$2 AND NOT EXISTS(SELECT 1 FROM refresh_token_families f WHERE f.id=c.refresh_family_id AND f.absolute_expires_at>$1)) ORDER BY expires_at LIMIT 256)`, []any{now, now.Add(-24 * time.Hour)}, &out.AuthorizationCodes},
		{`DELETE FROM pending_totp_enrollments WHERE user_id IN (SELECT user_id FROM pending_totp_enrollments WHERE expires_at<$1 ORDER BY expires_at LIMIT 256)`, []any{now}, &out.PendingTOTP},
		{`DELETE FROM sessions WHERE id IN (SELECT id FROM sessions WHERE idle_expires_at<$1 OR absolute_expires_at<$1 ORDER BY idle_expires_at LIMIT 256)`, []any{now}, &out.Sessions},
		{`DELETE FROM bootstrap_tokens WHERE token_hash IN (SELECT token_hash FROM bootstrap_tokens WHERE (expires_at<$1 OR consumed_at IS NOT NULL) AND created_at<$2 ORDER BY created_at LIMIT 256)`, []any{now, now.Add(-24 * time.Hour)}, &out.BootstrapTokens},
		// Delete children explicitly in batches: one expired family can own months
		// of rotation tombstones; an unbounded parent cascade is not a small batch.
		{`DELETE FROM refresh_tokens WHERE token_hash IN (SELECT t.token_hash FROM refresh_tokens t JOIN refresh_token_families f ON f.id=t.family_id WHERE f.absolute_expires_at<$1 ORDER BY f.absolute_expires_at LIMIT 256)`, []any{now}, &out.RefreshTokens},
		{`DELETE FROM refresh_token_families WHERE id IN (SELECT id FROM refresh_token_families f WHERE absolute_expires_at<$1 AND NOT EXISTS(SELECT 1 FROM refresh_tokens t WHERE t.family_id=f.id) ORDER BY absolute_expires_at LIMIT 256)`, []any{now}, &out.RefreshFamilies},
		{`DELETE FROM audit_events WHERE id IN (SELECT id FROM audit_events WHERE occurred_at<$1 ORDER BY occurred_at LIMIT 256)`, []any{now.Add(-auditRetention)}, &out.AuditEvents},
	}
	for pass := 0; pass < 64; pass++ {
		full := false
		for _, item := range items {
			if budget.Err() != nil {
				out.More = true
				return out, ctx.Err()
			}
			n, admitted, err := cleanupBatch(budget, pool, item.query, item.args)
			if err != nil {
				if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
					out.More = true
					return out, nil
				}
				return out, err
			}
			if !admitted {
				out.More = true
				return out, nil
			}
			*item.dest += n
			if n == cleanupBatchSize {
				full = true
			}
		}
		if !full {
			return out, nil
		}
	}
	out.More = true
	return out, nil
}

func cleanupBatch(ctx context.Context, pool *sql.DB, query string, args []any) (int64, bool, error) {
	tx, err := pool.BeginTx(ctx, nil)
	if err != nil {
		return 0, false, err
	}
	defer tx.Rollback()
	var owns bool
	if err = tx.QueryRowContext(ctx, `SELECT pg_try_advisory_xact_lock($1)`, cleanupLockID).Scan(&owns); err != nil {
		return 0, false, err
	}
	if !owns {
		return 0, false, nil
	}
	// Queue briefly rather than indefinitely starving behind a stream of shared
	// token readers. No batch holds the exclusive authority gate beyond its work.
	if _, err = tx.ExecContext(ctx, `SET LOCAL lock_timeout='100ms'`); err != nil {
		return 0, false, err
	}
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, identityLock); err != nil {
		var state interface{ SQLState() string }
		if errors.As(err, &state) && state.SQLState() == "55P03" {
			return 0, false, nil
		}
		return 0, false, err
	}
	result, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, false, err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return 0, false, err
	}
	if err = tx.Commit(); err != nil {
		return 0, false, err
	}
	return n, true, nil
}
