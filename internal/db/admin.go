package db

import (
	"context"
	"database/sql"

	"github.com/yellowman/authd/internal/identity"
)

func (s *IdentityStore) AdminData(ctx context.Context, hash []byte) (out identity.AdminData, err error) {
	err = s.read(ctx, func(tx *sql.Tx) error {
		if _, e := requireSession(ctx, tx, hash, true, false, false); e != nil {
			return e
		}
		var tooMany bool
		if e := tx.QueryRowContext(ctx, `SELECT
         (SELECT count(*) FROM (SELECT 1 FROM users WHERE deleted_at IS NULL LIMIT 201) q)>200 OR
         (SELECT count(*) FROM (SELECT 1 FROM roles LIMIT 201) q)>200 OR
         (SELECT count(*) FROM (SELECT 1 FROM permissions LIMIT 201) q)>200`).Scan(&tooMany); e != nil {
			return e
		}
		if tooMany {
			return identity.Invalid("This early admin UI supports at most 200 users, roles, or permissions. Pagination is required before editing a larger catalog; no partial assignment list is shown.")
		}
		rows, e := tx.QueryContext(ctx, `SELECT `+userColumns+`,
 COALESCE((SELECT json_agg(ur.role_id::text ORDER BY ur.role_id) FROM user_roles ur WHERE ur.user_id=u.id),'[]'::json)::text,
 COALESCE((SELECT json_agg(r.name ORDER BY r.name) FROM user_roles ur JOIN roles r ON r.id=ur.role_id WHERE ur.user_id=u.id),'[]'::json)::text,
 EXISTS(SELECT 1 FROM totp_credentials t WHERE t.user_id=u.id)
 FROM users u WHERE u.deleted_at IS NULL ORDER BY lower(u.username) LIMIT 200`)
		if e != nil {
			return e
		}
		for rows.Next() {
			var u identity.User
			var ids, names string
			args := append(userDest(&u), &ids, &names, &u.MFAEnabled)
			if e = rows.Scan(args...); e != nil {
				rows.Close()
				return e
			}
			if u.RoleIDs, e = decodeList(ids); e != nil {
				rows.Close()
				return e
			}
			if u.Roles, e = decodeList(names); e != nil {
				rows.Close()
				return e
			}
			out.Users = append(out.Users, u)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
		rows, e = tx.QueryContext(ctx, `SELECT r.id::text,r.name,r.description,r.built_in,r.updated_at,
 COALESCE((SELECT json_agg(rp.permission_id::text ORDER BY rp.permission_id) FROM role_permissions rp WHERE rp.role_id=r.id),'[]'::json)::text,
 COALESCE((SELECT json_agg(p.name ORDER BY p.name) FROM role_permissions rp JOIN permissions p ON p.id=rp.permission_id WHERE rp.role_id=r.id),'[]'::json)::text
 FROM roles r ORDER BY r.name LIMIT 200`)
		if e != nil {
			return e
		}
		for rows.Next() {
			var role identity.Role
			var ids, names string
			if e = rows.Scan(&role.ID, &role.Name, &role.Description, &role.BuiltIn, &role.UpdatedAt, &ids, &names); e != nil {
				rows.Close()
				return e
			}
			if role.PermissionIDs, e = decodeList(ids); e != nil {
				rows.Close()
				return e
			}
			if role.Permissions, e = decodeList(names); e != nil {
				rows.Close()
				return e
			}
			out.Roles = append(out.Roles, role)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
		rows, e = tx.QueryContext(ctx, `SELECT id::text,name,description,updated_at FROM permissions ORDER BY name LIMIT 200`)
		if e != nil {
			return e
		}
		for rows.Next() {
			var p identity.Permission
			if e = rows.Scan(&p.ID, &p.Name, &p.Description, &p.UpdatedAt); e != nil {
				rows.Close()
				return e
			}
			out.Permissions = append(out.Permissions, p)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
		rows, e = tx.QueryContext(ctx, `SELECT `+sessionColumns+` FROM sessions s JOIN users u ON u.id=s.user_id
 WHERE s.idle_expires_at>now() AND s.absolute_expires_at>now() AND u.enabled AND u.deleted_at IS NULL ORDER BY s.created_at DESC LIMIT 200`)
		if e != nil {
			return e
		}
		for rows.Next() {
			v, e := scanSession(rows)
			if e != nil {
				rows.Close()
				return e
			}
			out.Sessions = append(out.Sessions, v)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
		rows, e = tx.QueryContext(ctx, `SELECT a.id,a.occurred_at,a.event_type,COALESCE(u.username,''),COALESCE(a.target_id,''),COALESCE(host(a.source_ip),'') FROM audit_events a LEFT JOIN users u ON u.id=a.actor_user_id ORDER BY a.id DESC LIMIT 200`)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var v identity.AuditEvent
			if e = rows.Scan(&v.ID, &v.At, &v.Event, &v.Actor, &v.Target, &v.IP); e != nil {
				return e
			}
			out.Events = append(out.Events, v)
		}
		return rows.Err()
	})
	return
}
