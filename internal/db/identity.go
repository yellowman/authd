package db

import (
	"context"
	"crypto/hmac"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/yellowman/authd/internal/identity"
)

type IdentityStore struct{ DB *sql.DB }

var _ identity.Store = (*IdentityStore)(nil)

const identityLock int64 = 0x6175746801

// Security mutations take the exclusive authority gate; unrelated OIDC grants
// share it and lock their own rows. Credential KDFs execute before this gate,
// then verified snapshots are rechecked inside the mutation transaction.
func (s *IdentityStore) write(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, identityLock); err != nil {
		return err
	}
	if err = fn(tx); err != nil {
		return dbError(err)
	}
	return dbError(tx.Commit())
}

// Read-only administration uses a coherent MVCC snapshot rather than serializing
// all token exchanges. Every mutation independently rechecks live authorization.
func (s *IdentityStore) read(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}
func dbError(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return identity.ErrConflict
	}
	var state interface{ SQLState() string }
	if errors.As(err, &state) {
		switch state.SQLState() {
		case "23505", "23503", "23514":
			return identity.ErrConflict
		}
	}
	return err
}
func listJSON(v []string) string {
	if v == nil {
		v = []string{}
	}
	b, _ := json.Marshal(v)
	return string(b)
}
func decodeList(raw string) ([]string, error) {
	var v []string
	err := json.Unmarshal([]byte(raw), &v)
	return v, err
}

const userColumns = `u.id::text,u.username,u.display_name,COALESCE(u.email,''),u.email_verified,u.enabled,u.force_password_change,u.created_at,u.updated_at,u.last_login_at`

type scanner interface{ Scan(...any) error }

func userDest(u *identity.User) []any {
	return []any{&u.ID, &u.Username, &u.DisplayName, &u.Email, &u.EmailVerified, &u.Enabled, &u.ForcePasswordChange, &u.CreatedAt, &u.UpdatedAt, &u.LastLoginAt}
}
func audit(ctx context.Context, tx *sql.Tx, event, actor, targetType, targetID string, a identity.Audit) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO audit_events(event_type,actor_user_id,target_type,target_id,source_ip,request_id)
 VALUES($1,NULLIF($2,'')::uuid,NULLIF($3,''),NULLIF($4,''),NULLIF($5,'')::inet,NULLIF($6,''))`, event, actor, targetType, targetID, a.IP, a.RequestID)
	return err
}
func (s *IdentityStore) AuditFailure(ctx context.Context, event string, a identity.Audit) error {
	// An append-only failure record does not mutate authority; no global gate.
	_, err := s.DB.ExecContext(ctx, `INSERT INTO audit_events(event_type,source_ip,request_id) VALUES($1,NULLIF($2,'')::inet,NULLIF($3,''))`, event, a.IP, a.RequestID)
	return err
}
func (s *IdentityStore) BootstrapOpen(ctx context.Context) (bool, error) {
	var open bool
	err := s.DB.QueryRowContext(ctx, `SELECT NOT bootstrap_completed AND NOT EXISTS(SELECT 1 FROM users) FROM installation_state WHERE singleton`).Scan(&open)
	return open, err
}
func bootstrapOpen(ctx context.Context, tx *sql.Tx) error {
	var open bool
	if err := tx.QueryRowContext(ctx, `SELECT NOT bootstrap_completed AND NOT EXISTS(SELECT 1 FROM users) FROM installation_state WHERE singleton FOR UPDATE`).Scan(&open); err != nil {
		return err
	}
	if !open {
		return identity.ErrBootstrapClosed
	}
	return nil
}
func (s *IdentityStore) IssueBootstrap(ctx context.Context, hash []byte, expires time.Time) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		if err := bootstrapOpen(ctx, tx); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE bootstrap_tokens SET consumed_at=now() WHERE consumed_at IS NULL`); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO bootstrap_tokens(token_hash,expires_at) VALUES($1,$2)`, hash, expires)
		return err
	})
}
func (s *IdentityStore) Bootstrap(ctx context.Context, hash []byte, user identity.NewUser, a identity.Audit) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		if err := bootstrapOpen(ctx, tx); err != nil {
			return err
		}
		var accepted int
		if err := tx.QueryRowContext(ctx, `UPDATE bootstrap_tokens SET consumed_at=now() WHERE token_hash=$1 AND consumed_at IS NULL AND expires_at>now() RETURNING 1`, hash).Scan(&accepted); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return identity.ErrCredentials
			}
			return err
		}
		id, err := insertUser(ctx, tx, user)
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO user_roles(user_id,role_id) SELECT $1::uuid,id FROM roles WHERE name='system-admin' AND built_in`, id); err != nil {
			return err
		}
		if err = lastAdmin(ctx, tx); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE installation_state SET bootstrap_completed=true,initialized_at=now() WHERE singleton`); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE bootstrap_tokens SET consumed_at=now() WHERE consumed_at IS NULL`); err != nil {
			return err
		}
		return audit(ctx, tx, "bootstrap.completed", id, "user", id, a)
	})
}
func insertUser(ctx context.Context, tx *sql.Tx, u identity.NewUser) (string, error) {
	var id string
	err := tx.QueryRowContext(ctx, `INSERT INTO users(username,display_name,email,force_password_change)
 VALUES($1,$2,NULLIF($3,''),$4) RETURNING id::text`, u.Username, u.DisplayName, u.Email, u.ForcePasswordChange).Scan(&id)
	if err != nil {
		return "", err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO password_credentials(user_id,password_hash) VALUES($1::uuid,$2)`, id, u.PasswordHash); err != nil {
		return "", err
	}
	return id, replaceUserRoles(ctx, tx, id, u.RoleIDs)
}
func (s *IdentityStore) LoginRecord(ctx context.Context, username string) (identity.LoginRecord, error) {
	var out identity.LoginRecord
	var ciphertext []byte
	var counter *int64
	args := append(userDest(&out.User), &out.PasswordHash, &ciphertext, &counter)
	err := s.DB.QueryRowContext(ctx, `SELECT `+userColumns+`,COALESCE(p.password_hash,''),t.secret_ciphertext,t.last_counter
 FROM users u LEFT JOIN password_credentials p ON p.user_id=u.id LEFT JOIN totp_credentials t ON t.user_id=u.id
 WHERE lower(u.username)=lower($1) AND u.deleted_at IS NULL`, username).Scan(args...)
	if errors.Is(err, sql.ErrNoRows) {
		return out, identity.ErrCredentials
	}
	if err != nil {
		return out, err
	}
	if ciphertext != nil {
		out.Factor = &identity.Factor{Ciphertext: ciphertext, LastCounter: counter}
	}
	return out, nil
}
func (s *IdentityStore) CreateSession(ctx context.Context, expected identity.LoginRecord, session identity.Session, factor *identity.FactorUse, replacement string, a identity.Audit) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		var password string
		var seed []byte
		err := tx.QueryRowContext(ctx, `SELECT p.password_hash,t.secret_ciphertext FROM users u JOIN password_credentials p ON p.user_id=u.id
 LEFT JOIN totp_credentials t ON t.user_id=u.id WHERE u.id=$1::uuid AND u.enabled AND u.deleted_at IS NULL`, expected.User.ID).Scan(&password, &seed)
		if errors.Is(err, sql.ErrNoRows) {
			return identity.ErrCredentials
		}
		if err != nil {
			return err
		}
		if password != expected.PasswordHash {
			return identity.ErrCredentials
		}
		if (seed != nil) != (factor != nil) {
			return identity.ErrCredentials
		}
		if seed != nil {
			if !hmac.Equal(seed, factor.Ciphertext) {
				return identity.ErrCredentials
			}
			var res sql.Result
			if factor.Counter != nil {
				res, err = tx.ExecContext(ctx, `UPDATE totp_credentials SET last_counter=$2 WHERE user_id=$1::uuid AND (last_counter IS NULL OR last_counter<$2)`, expected.User.ID, *factor.Counter)
			} else {
				res, err = tx.ExecContext(ctx, `UPDATE recovery_codes SET consumed_at=now() WHERE user_id=$1::uuid AND code_hash=$2 AND consumed_at IS NULL`, expected.User.ID, factor.RecoveryHash)
			}
			if err != nil {
				return err
			}
			n, err := res.RowsAffected()
			if err != nil {
				return err
			}
			if n != 1 {
				return identity.ErrCredentials
			}
		}
		if replacement != "" {
			if _, err = tx.ExecContext(ctx, `UPDATE password_credentials SET password_hash=$2 WHERE user_id=$1::uuid`, expected.User.ID, replacement); err != nil {
				return err
			}
		}
		if len(session.ReplacesTokenHash) > 0 {
			var oldSID, oldUser string
			e := tx.QueryRowContext(ctx, `SELECT id::text,user_id::text FROM sessions WHERE token_hash=$1`, session.ReplacesTokenHash).Scan(&oldSID, &oldUser)
			if e != nil && !errors.Is(e, sql.ErrNoRows) {
				return e
			}
			if e == nil {
				if _, err = tx.ExecContext(ctx, `DELETE FROM authorization_codes WHERE session_id=$1::uuid AND consumed_at IS NULL`, oldSID); err != nil {
					return err
				}
				if _, err = tx.ExecContext(ctx, `DELETE FROM sessions WHERE id=$1::uuid`, oldSID); err != nil {
					return err
				}
				if err = audit(ctx, tx, "session.replaced", oldUser, "session", oldSID, a); err != nil {
					return err
				}
			}
		}
		// Credential epochs were rechecked above. Password reset, disable and MFA
		// changes take this same lock and cannot race a stale password proof.
		if _, err = tx.ExecContext(ctx, `INSERT INTO sessions(token_hash,csrf_hash,user_id,auth_time,auth_methods,idle_expires_at,absolute_expires_at,ip_address,user_agent)
 VALUES($1,$2,$3::uuid,$4,ARRAY(SELECT jsonb_array_elements_text($5::jsonb)),$6,$7,NULLIF($8,'')::inet,$9)`, session.TokenHash, session.CSRFHash, expected.User.ID, session.AuthTime, listJSON(session.AuthMethods), session.IdleExpiresAt, session.AbsoluteExpiresAt, session.IP, session.UserAgent); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE users SET last_login_at=now() WHERE id=$1::uuid`, expected.User.ID); err != nil {
			return err
		}
		return audit(ctx, tx, "login.success", expected.User.ID, "user", expected.User.ID, a)
	})
}

const sessionColumns = `s.id::text,s.token_hash,s.csrf_hash,s.auth_time,s.created_at,s.last_seen_at,s.idle_expires_at,s.absolute_expires_at,COALESCE(host(s.ip_address),''),s.user_agent,array_to_json(s.auth_methods)::text,` + userColumns + `,
 EXISTS(SELECT 1 FROM totp_credentials t WHERE t.user_id=u.id),
 COALESCE((SELECT json_agg(r.name ORDER BY r.name) FROM user_roles ur JOIN roles r ON r.id=ur.role_id WHERE ur.user_id=u.id),'[]'::json)::text,
 COALESCE((SELECT json_agg(x.name ORDER BY x.name) FROM (SELECT DISTINCT p.name FROM user_roles ur JOIN role_permissions rp ON rp.role_id=ur.role_id JOIN permissions p ON p.id=rp.permission_id WHERE ur.user_id=u.id) x),'[]'::json)::text`

func scanSession(row scanner) (identity.Session, error) {
	var s identity.Session
	var methods, roles, permissions string
	args := []any{&s.ID, &s.TokenHash, &s.CSRFHash, &s.AuthTime, &s.CreatedAt, &s.LastSeenAt, &s.IdleExpiresAt, &s.AbsoluteExpiresAt, &s.IP, &s.UserAgent, &methods}
	args = append(args, userDest(&s.User)...)
	args = append(args, &s.User.MFAEnabled, &roles, &permissions)
	if err := row.Scan(args...); err != nil {
		return s, err
	}
	var err error
	if s.AuthMethods, err = decodeList(methods); err != nil {
		return s, err
	}
	if s.Roles, err = decodeList(roles); err != nil {
		return s, err
	}
	s.Permissions, err = decodeList(permissions)
	return s, err
}
func requireSession(ctx context.Context, tx *sql.Tx, hash []byte, admin, fresh, allowForced bool) (identity.Session, error) {
	s, err := scanSession(tx.QueryRowContext(ctx, `SELECT `+sessionColumns+` FROM sessions s JOIN users u ON u.id=s.user_id
 WHERE s.token_hash=$1 AND s.idle_expires_at>clock_timestamp() AND s.absolute_expires_at>clock_timestamp() AND u.enabled AND u.deleted_at IS NULL`, hash))
	if errors.Is(err, sql.ErrNoRows) {
		return s, identity.ErrSession
	}
	if err != nil {
		return s, err
	}
	if (!allowForced && s.User.ForcePasswordChange) || (admin && !s.Has("system.admin")) {
		return s, identity.ErrForbidden
	}
	if fresh && time.Since(s.AuthTime) > 10*time.Minute {
		return s, identity.ErrForbidden
	}
	return s, nil
}
func (s *IdentityStore) Session(ctx context.Context, hash []byte, idle time.Duration) (identity.Session, error) {
	// Authorization is always read live; only the activity write is throttled.
	// Keep a short-idle configuration alive too, without updating every request.
	touch := idle / 4
	if touch > time.Minute {
		touch = time.Minute
	}
	if touch < time.Millisecond {
		touch = time.Millisecond
	}
	out, err := scanSession(s.DB.QueryRowContext(ctx, `WITH touched AS (
 UPDATE sessions s SET last_seen_at=clock_timestamp(),idle_expires_at=LEAST(absolute_expires_at,clock_timestamp()+$2::bigint*interval '1 second')
 FROM users u WHERE s.token_hash=$1 AND u.id=s.user_id AND u.enabled AND u.deleted_at IS NULL
 AND s.idle_expires_at>clock_timestamp() AND s.absolute_expires_at>clock_timestamp()
 AND s.last_seen_at <= clock_timestamp()-$3::bigint*interval '1 millisecond' RETURNING s.*),
 live AS (SELECT * FROM touched UNION ALL SELECT s.* FROM sessions s WHERE s.token_hash=$1 AND NOT EXISTS(SELECT 1 FROM touched))
 SELECT `+sessionColumns+` FROM live s JOIN users u ON u.id=s.user_id WHERE s.idle_expires_at>clock_timestamp() AND s.absolute_expires_at>clock_timestamp() AND u.enabled AND u.deleted_at IS NULL`, hash, int64(idle.Seconds()), int64(touch/time.Millisecond)))
	if errors.Is(err, sql.ErrNoRows) {
		return out, identity.ErrSession
	}
	return out, err
}
func (s *IdentityStore) Sessions(ctx context.Context, hash []byte) (out []identity.Session, err error) {
	err = s.read(ctx, func(tx *sql.Tx) error {
		sess, e := requireSession(ctx, tx, hash, false, false, true)
		if e != nil {
			return e
		}
		rows, e := tx.QueryContext(ctx, `SELECT `+sessionColumns+` FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.user_id=$1::uuid AND s.idle_expires_at>clock_timestamp() AND s.absolute_expires_at>clock_timestamp() ORDER BY s.created_at DESC LIMIT 200`, sess.User.ID)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			v, e := scanSession(rows)
			if e != nil {
				return e
			}
			out = append(out, v)
		}
		return rows.Err()
	})
	return
}
func (s *IdentityStore) RevokeSession(ctx context.Context, hash []byte, target string, others bool, a identity.Audit) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		sess, e := requireSession(ctx, tx, hash, false, false, true)
		if e != nil {
			return e
		}
		if others {
			if e = revokeSessionGrants(ctx, tx, `SELECT id FROM sessions WHERE user_id=$1::uuid AND id<>$2::uuid`, sess.User.ID, sess.ID); e != nil {
				return e
			}
			if _, e = tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=$1::uuid AND id<>$2::uuid`, sess.User.ID, sess.ID); e != nil {
				return e
			}
			return audit(ctx, tx, "session.others_revoked", sess.User.ID, "user", sess.User.ID, a)
		}
		if !identity.ValidID(target) {
			return identity.ErrForbidden
		}
		var owner string
		if e = tx.QueryRowContext(ctx, `SELECT user_id::text FROM sessions WHERE id=$1::uuid`, target).Scan(&owner); e != nil {
			return e
		}
		if owner != sess.User.ID && (!sess.Has("system.admin") || sess.User.ForcePasswordChange || time.Since(sess.AuthTime) > 10*time.Minute) {
			return identity.ErrForbidden
		}
		if e = revokeSessionGrants(ctx, tx, `SELECT id FROM sessions WHERE id=$1::uuid`, target); e != nil {
			return e
		}
		if _, e = tx.ExecContext(ctx, `DELETE FROM sessions WHERE id=$1::uuid`, target); e != nil {
			return e
		}
		return audit(ctx, tx, "session.revoked", sess.User.ID, "session", target, a)
	})
}
func (s *IdentityStore) EditOwnProfile(ctx context.Context, hash []byte, p identity.Profile, a identity.Audit) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		sess, e := requireSession(ctx, tx, hash, false, true, false)
		if e != nil {
			return e
		}
		res, e := tx.ExecContext(ctx, `UPDATE users SET display_name=$2,email=NULLIF($3,''),updated_at=now() WHERE id=$1::uuid AND deleted_at IS NULL`, sess.User.ID, p.DisplayName, p.Email)
		if e != nil {
			return e
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return identity.ErrConflict
		}
		return audit(ctx, tx, "user.profile_updated", sess.User.ID, "user", sess.User.ID, a)
	})
}
func revokeUser(ctx context.Context, tx *sql.Tx, id, reason string) error {
	if _, e := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=$1::uuid`, id); e != nil {
		return e
	}
	if _, e := tx.ExecContext(ctx, `DELETE FROM authorization_codes WHERE user_id=$1::uuid`, id); e != nil {
		return e
	}
	_, e := tx.ExecContext(ctx, `UPDATE refresh_token_families SET revoked_at=now(),revoke_reason=$2 WHERE user_id=$1::uuid AND revoked_at IS NULL`, id, reason)
	return e
}
func setPassword(ctx context.Context, tx *sql.Tx, id, hash string, force bool) error {
	if _, e := tx.ExecContext(ctx, `INSERT INTO password_credentials(user_id,password_hash) VALUES($1::uuid,$2)
 ON CONFLICT(user_id) DO UPDATE SET password_hash=EXCLUDED.password_hash,changed_at=now()`, id, hash); e != nil {
		return e
	}
	if _, e := tx.ExecContext(ctx, `UPDATE users SET force_password_change=$2,updated_at=now() WHERE id=$1::uuid`, id, force); e != nil {
		return e
	}
	return revokeUser(ctx, tx, id, "password_changed")
}
func checkPassword(ctx context.Context, tx *sql.Tx, id, expected string) error {
	var actual string
	if e := tx.QueryRowContext(ctx, `SELECT password_hash FROM password_credentials WHERE user_id=$1::uuid`, id).Scan(&actual); e != nil {
		return e
	}
	if actual != expected {
		return identity.ErrConflict
	}
	return nil
}
func (s *IdentityStore) ChangePassword(ctx context.Context, hash []byte, expected, replacement string, a identity.Audit) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		sess, e := requireSession(ctx, tx, hash, false, false, true)
		if e != nil {
			return e
		}
		if e = checkPassword(ctx, tx, sess.User.ID, expected); e != nil {
			return e
		}
		if e = setPassword(ctx, tx, sess.User.ID, replacement, false); e != nil {
			return e
		}
		return audit(ctx, tx, "user.password_changed", sess.User.ID, "user", sess.User.ID, a)
	})
}
func replaceUserRoles(ctx context.Context, tx *sql.Tx, user string, roles []string) error {
	if _, e := tx.ExecContext(ctx, `DELETE FROM user_roles WHERE user_id=$1::uuid`, user); e != nil {
		return e
	}
	_, e := tx.ExecContext(ctx, `INSERT INTO user_roles(user_id,role_id) SELECT $1::uuid,value::uuid FROM jsonb_array_elements_text($2::jsonb)`, user, listJSON(roles))
	return e
}
func lastAdmin(ctx context.Context, tx *sql.Tx) error {
	var present bool
	e := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM users u JOIN user_roles ur ON ur.user_id=u.id
 JOIN role_permissions rp ON rp.role_id=ur.role_id JOIN permissions p ON p.id=rp.permission_id
 WHERE u.enabled AND u.deleted_at IS NULL AND p.name='system.admin')`).Scan(&present)
	if e != nil {
		return e
	}
	if !present {
		return identity.ErrLastAdmin
	}
	return nil
}
func (s *IdentityStore) CreateUser(ctx context.Context, hash []byte, u identity.NewUser, a identity.Audit) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		actor, e := requireSession(ctx, tx, hash, true, true, false)
		if e != nil {
			return e
		}
		id, e := insertUser(ctx, tx, u)
		if e != nil {
			return e
		}
		return audit(ctx, tx, "user.created", actor.User.ID, "user", id, a)
	})
}
func (s *IdentityStore) EditUser(ctx context.Context, hash []byte, u identity.UserEdit, a identity.Audit) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		actor, e := requireSession(ctx, tx, hash, true, true, false)
		if e != nil {
			return e
		}
		var before identity.User
		if e = tx.QueryRowContext(ctx, `SELECT `+userColumns+` FROM users u WHERE u.id=$1::uuid AND u.deleted_at IS NULL FOR UPDATE`, u.ID).Scan(userDest(&before)...); e != nil {
			return e
		}
		if u.ExpectedUpdatedAt.IsZero() || !before.UpdatedAt.Equal(u.ExpectedUpdatedAt) {
			return identity.ErrConflict
		}
		verified := u.VerifyEmail && u.Email != "" && u.Email == before.Email
		if _, e = tx.ExecContext(ctx, `UPDATE users SET username=$2,display_name=$3,email=NULLIF($4,''),email_verified=$5,enabled=$6,force_password_change=$7,updated_at=now() WHERE id=$1::uuid`, u.ID, u.Username, u.DisplayName, u.Email, verified, u.Enabled, u.ForcePasswordChange); e != nil {
			return e
		}
		if e = replaceUserRoles(ctx, tx, u.ID, u.RoleIDs); e != nil {
			return e
		}
		if e = lastAdmin(ctx, tx); e != nil {
			return e
		}
		if !u.Enabled || u.ForcePasswordChange {
			if e = revokeUser(ctx, tx, u.ID, "user_disabled_or_password_change_required"); e != nil {
				return e
			}
		}
		return audit(ctx, tx, "user.updated", actor.User.ID, "user", u.ID, a)
	})
}
func (s *IdentityStore) DeleteUser(ctx context.Context, hash []byte, id string, a identity.Audit) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		actor, e := requireSession(ctx, tx, hash, true, true, false)
		if e != nil {
			return e
		}
		var exists bool
		if e = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE id=$1::uuid AND deleted_at IS NULL)`, id).Scan(&exists); e != nil {
			return e
		}
		if !exists {
			return identity.ErrConflict
		}
		if e = revokeUser(ctx, tx, id, "user_deleted"); e != nil {
			return e
		}
		for _, q := range []string{
			`DELETE FROM pending_totp_enrollments WHERE user_id=$1::uuid`,
			`DELETE FROM recovery_codes WHERE user_id=$1::uuid`,
			`DELETE FROM totp_credentials WHERE user_id=$1::uuid`,
			`DELETE FROM password_credentials WHERE user_id=$1::uuid`,
			`DELETE FROM user_roles WHERE user_id=$1::uuid`,
		} {
			if _, e = tx.ExecContext(ctx, q, id); e != nil {
				return e
			}
		}
		if _, e = tx.ExecContext(ctx, `UPDATE users SET enabled=false,force_password_change=false,email_verified=false,deleted_at=now(),updated_at=now() WHERE id=$1::uuid AND deleted_at IS NULL`, id); e != nil {
			return e
		}
		if e = lastAdmin(ctx, tx); e != nil {
			return e
		}
		return audit(ctx, tx, "user.deleted", actor.User.ID, "user", id, a)
	})
}

func (s *IdentityStore) ResetPassword(ctx context.Context, hash []byte, id, password string, force bool, a identity.Audit) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		actor, e := requireSession(ctx, tx, hash, true, true, false)
		if e != nil {
			return e
		}
		var exists bool
		if e = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE id=$1::uuid AND deleted_at IS NULL)`, id).Scan(&exists); e != nil {
			return e
		}
		if !exists {
			return identity.ErrConflict
		}
		if e = setPassword(ctx, tx, id, password, force); e != nil {
			return e
		}
		return audit(ctx, tx, "user.password_reset", actor.User.ID, "user", id, a)
	})
}
func (s *IdentityStore) ResetMFA(ctx context.Context, hash []byte, id string, a identity.Audit) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		actor, e := requireSession(ctx, tx, hash, true, true, false)
		if e != nil {
			return e
		}
		var exists bool
		if e = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE id=$1::uuid AND deleted_at IS NULL)`, id).Scan(&exists); e != nil {
			return e
		}
		if !exists {
			return identity.ErrConflict
		}
		for _, q := range []string{
			`DELETE FROM pending_totp_enrollments WHERE user_id=$1::uuid`,
			`DELETE FROM recovery_codes WHERE user_id=$1::uuid`,
			`DELETE FROM totp_credentials WHERE user_id=$1::uuid`,
		} {
			if _, e = tx.ExecContext(ctx, q, id); e != nil {
				return e
			}
		}
		if e = revokeUser(ctx, tx, id, "mfa_reset"); e != nil {
			return e
		}
		return audit(ctx, tx, "mfa.reset", actor.User.ID, "user", id, a)
	})
}

func (s *IdentityStore) SaveRole(ctx context.Context, hash []byte, edit identity.RoleEdit, a identity.Audit) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		actor, e := requireSession(ctx, tx, hash, true, true, false)
		if e != nil {
			return e
		}
		id := edit.ID
		builtIn := false
		if id == "" {
			if e = tx.QueryRowContext(ctx, `INSERT INTO roles(name,description) VALUES($1,$2) RETURNING id::text`, edit.Name, edit.Description).Scan(&id); e != nil {
				return e
			}
		} else {
			var oldName string
			var updatedAt time.Time
			if e = tx.QueryRowContext(ctx, `SELECT built_in,name,updated_at FROM roles WHERE id=$1::uuid FOR UPDATE`, id).Scan(&builtIn, &oldName, &updatedAt); e != nil {
				return e
			}
			if edit.ExpectedUpdatedAt.IsZero() || !updatedAt.Equal(edit.ExpectedUpdatedAt) {
				return identity.ErrConflict
			}
			if builtIn && oldName != edit.Name {
				return identity.ErrForbidden
			}
			if _, e = tx.ExecContext(ctx, `UPDATE roles SET name=$2,description=$3,updated_at=now() WHERE id=$1::uuid`, id, edit.Name, edit.Description); e != nil {
				return e
			}
		}
		if _, e = tx.ExecContext(ctx, `DELETE FROM role_permissions WHERE role_id=$1::uuid`, id); e != nil {
			return e
		}
		if _, e = tx.ExecContext(ctx, `INSERT INTO role_permissions(role_id,permission_id) SELECT $1::uuid,value::uuid FROM jsonb_array_elements_text($2::jsonb)`, id, listJSON(edit.PermissionIDs)); e != nil {
			return e
		}
		if builtIn {
			var ok bool
			if e = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM role_permissions rp JOIN permissions p ON p.id=rp.permission_id WHERE rp.role_id=$1::uuid AND p.name='system.admin')`, id).Scan(&ok); e != nil {
				return e
			}
			if !ok {
				return identity.ErrForbidden
			}
		}
		if e = lastAdmin(ctx, tx); e != nil {
			return e
		}
		return audit(ctx, tx, "role.saved", actor.User.ID, "role", id, a)
	})
}
func (s *IdentityStore) DeleteRole(ctx context.Context, hash []byte, id string, a identity.Audit) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		actor, e := requireSession(ctx, tx, hash, true, true, false)
		if e != nil {
			return e
		}
		var builtIn bool
		if e = tx.QueryRowContext(ctx, `SELECT built_in FROM roles WHERE id=$1::uuid`, id).Scan(&builtIn); e != nil {
			return e
		}
		if builtIn {
			return identity.ErrForbidden
		}
		if _, e = tx.ExecContext(ctx, `DELETE FROM roles WHERE id=$1::uuid`, id); e != nil {
			return e
		}
		if e = lastAdmin(ctx, tx); e != nil {
			return e
		}
		return audit(ctx, tx, "role.deleted", actor.User.ID, "role", id, a)
	})
}

func (s *IdentityStore) CreatePermission(ctx context.Context, hash []byte, name, description string, a identity.Audit) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		actor, e := requireSession(ctx, tx, hash, true, true, false)
		if e != nil {
			return e
		}
		var id string
		if e = tx.QueryRowContext(ctx, `INSERT INTO permissions(name,description) VALUES($1,$2) RETURNING id::text`, name, description).Scan(&id); e != nil {
			return e
		}
		return audit(ctx, tx, "permission.created", actor.User.ID, "permission", id, a)
	})
}

func (s *IdentityStore) SavePermission(ctx context.Context, hash []byte, edit identity.PermissionEdit, a identity.Audit) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		actor, e := requireSession(ctx, tx, hash, true, true, false)
		if e != nil {
			return e
		}
		var oldName string
		var updatedAt time.Time
		if e = tx.QueryRowContext(ctx, `SELECT name,updated_at FROM permissions WHERE id=$1::uuid FOR UPDATE`, edit.ID).Scan(&oldName, &updatedAt); e != nil {
			return e
		}
		if edit.ExpectedUpdatedAt.IsZero() || !updatedAt.Equal(edit.ExpectedUpdatedAt) {
			return identity.ErrConflict
		}
		if oldName == "system.admin" && edit.Name != oldName {
			return identity.ErrForbidden
		}
		if _, e = tx.ExecContext(ctx, `UPDATE permissions SET name=$2,description=$3,updated_at=now() WHERE id=$1::uuid`, edit.ID, edit.Name, edit.Description); e != nil {
			return e
		}
		return audit(ctx, tx, "permission.updated", actor.User.ID, "permission", edit.ID, a)
	})
}

func (s *IdentityStore) DeletePermission(ctx context.Context, hash []byte, id string, a identity.Audit) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		actor, e := requireSession(ctx, tx, hash, true, true, false)
		if e != nil {
			return e
		}
		var name string
		if e = tx.QueryRowContext(ctx, `SELECT name FROM permissions WHERE id=$1::uuid`, id).Scan(&name); e != nil {
			return e
		}
		if name == "system.admin" {
			return identity.ErrForbidden
		}
		var refs int
		if e = tx.QueryRowContext(ctx, `SELECT
			(SELECT count(*) FROM role_permissions WHERE permission_id=$1::uuid) +
			(SELECT count(*) FROM client_permissions WHERE permission_id=$1::uuid)`, id).Scan(&refs); e != nil {
			return e
		}
		if refs != 0 {
			return identity.ErrConflict
		}
		if _, e = tx.ExecContext(ctx, `DELETE FROM permissions WHERE id=$1::uuid`, id); e != nil {
			return e
		}
		return audit(ctx, tx, "permission.deleted", actor.User.ID, "permission", id, a)
	})
}

// The SQL selector is an internal constant, never caller input. Both operations
// execute under the identity mutation lock before session rows are removed.
func revokeSessionGrants(ctx context.Context, tx *sql.Tx, selector string, args ...any) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM authorization_codes WHERE consumed_at IS NULL AND session_id IN (`+selector+`)`, args...); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `UPDATE refresh_token_families SET revoked_at=clock_timestamp(),revoke_reason='session_revoked' WHERE revoked_at IS NULL AND session_id IN (`+selector+`)`, args...)
	return err
}
