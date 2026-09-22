package db

import (
	"context"
	"crypto/hmac"
	"database/sql"
	"time"

	"github.com/yellowman/authd/internal/identity"
)

func (s *IdentityStore) BeginTOTP(ctx context.Context, hash []byte, password string, ciphertext []byte, a identity.Audit) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		sess, e := requireSession(ctx, tx, hash, false, true, false)
		if e != nil {
			return e
		}
		if e = checkPassword(ctx, tx, sess.User.ID, password); e != nil {
			return e
		}
		var exists bool
		if e = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM totp_credentials WHERE user_id=$1::uuid)`, sess.User.ID).Scan(&exists); e != nil {
			return e
		}
		if exists {
			return identity.ErrConflict
		}
		_, e = tx.ExecContext(ctx, `INSERT INTO pending_totp_enrollments(user_id,session_id,secret_ciphertext,expires_at) VALUES($1::uuid,$2::uuid,$3,now()+interval '10 minutes')
 ON CONFLICT(user_id) DO UPDATE SET session_id=EXCLUDED.session_id,secret_ciphertext=EXCLUDED.secret_ciphertext,expires_at=EXCLUDED.expires_at`, sess.User.ID, sess.ID, ciphertext)
		if e != nil {
			return e
		}
		return audit(ctx, tx, "mfa.enrollment_started", sess.User.ID, "user", sess.User.ID, a)
	})
}
func (s *IdentityStore) PendingTOTP(ctx context.Context, hash []byte) (out identity.PendingTOTP, err error) {
	err = s.write(ctx, func(tx *sql.Tx) error {
		sess, e := requireSession(ctx, tx, hash, false, true, false)
		if e != nil {
			return e
		}
		return tx.QueryRowContext(ctx, `SELECT secret_ciphertext,expires_at FROM pending_totp_enrollments WHERE user_id=$1::uuid AND session_id=$2::uuid AND expires_at>now()`, sess.User.ID, sess.ID).Scan(&out.Ciphertext, &out.ExpiresAt)
	})
	return
}
func (s *IdentityStore) ConfirmTOTP(ctx context.Context, hash, expected []byte, counter int64, codes [][]byte, a identity.Audit) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		sess, e := requireSession(ctx, tx, hash, false, true, false)
		if e != nil {
			return e
		}
		var cipher []byte
		var expiry time.Time
		if e = tx.QueryRowContext(ctx, `SELECT secret_ciphertext,expires_at FROM pending_totp_enrollments WHERE user_id=$1::uuid AND session_id=$2::uuid AND expires_at>now()`, sess.User.ID, sess.ID).Scan(&cipher, &expiry); e != nil {
			return e
		}
		if !hmac.Equal(cipher, expected) {
			return identity.ErrConflict
		}
		if _, e = tx.ExecContext(ctx, `INSERT INTO totp_credentials(user_id,secret_ciphertext,last_counter,confirmed_at) VALUES($1::uuid,$2,$3,now())`, sess.User.ID, cipher, counter); e != nil {
			return e
		}
		if _, e = tx.ExecContext(ctx, `DELETE FROM recovery_codes WHERE user_id=$1::uuid`, sess.User.ID); e != nil {
			return e
		}
		for _, code := range codes {
			if _, e = tx.ExecContext(ctx, `INSERT INTO recovery_codes(user_id,code_hash) VALUES($1::uuid,$2)`, sess.User.ID, code); e != nil {
				return e
			}
		}
		if e = revokeUser(ctx, tx, sess.User.ID, "mfa_enrolled"); e != nil {
			return e
		}
		return audit(ctx, tx, "mfa.enrolled", sess.User.ID, "user", sess.User.ID, a)
	})
}
func (s *IdentityStore) RemoveTOTP(ctx context.Context, hash []byte, password string, a identity.Audit) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		sess, e := requireSession(ctx, tx, hash, false, true, false)
		if e != nil {
			return e
		}
		complete := false
		for _, m := range sess.AuthMethods {
			if m == "otp" || m == "recovery" {
				complete = true
			}
		}
		if !complete {
			return identity.ErrForbidden
		}
		if e = checkPassword(ctx, tx, sess.User.ID, password); e != nil {
			return e
		}
		if _, e = tx.ExecContext(ctx, `DELETE FROM totp_credentials WHERE user_id=$1::uuid`, sess.User.ID); e != nil {
			return e
		}
		if _, e = tx.ExecContext(ctx, `DELETE FROM recovery_codes WHERE user_id=$1::uuid`, sess.User.ID); e != nil {
			return e
		}
		if e = revokeUser(ctx, tx, sess.User.ID, "mfa_removed"); e != nil {
			return e
		}
		return audit(ctx, tx, "mfa.removed", sess.User.ID, "user", sess.User.ID, a)
	})
}
