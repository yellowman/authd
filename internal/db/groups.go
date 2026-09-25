package db

import (
	"context"
	"database/sql"

	"github.com/yellowman/authd/internal/identity"
)

// Group membership and role assignment are one administration transaction.
// Sessions and token grants read effective permissions from live membership.
func (s *IdentityStore) SaveGroup(ctx context.Context, actorHash []byte, edit identity.GroupEdit, a identity.Audit) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		actor, err := requireSession(ctx, tx, actorHash, true, true, false)
		if err != nil {
			return err
		}
		if edit.ID == "" {
			err = tx.QueryRowContext(ctx, `INSERT INTO groups(name,description) VALUES($1,$2) RETURNING id::text`, edit.Name, edit.Description).Scan(&edit.ID)
		} else {
			var result sql.Result
			result, err = tx.ExecContext(ctx, `UPDATE groups SET name=$2,description=$3,updated_at=now() WHERE id=$1::uuid AND updated_at=$4`, edit.ID, edit.Name, edit.Description, edit.ExpectedUpdatedAt)
			if err == nil {
				var count int64
				count, err = result.RowsAffected()
				if err == nil && count != 1 {
					return identity.ErrConflict
				}
			}
		}
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `DELETE FROM group_roles WHERE group_id=$1::uuid`, edit.ID); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `DELETE FROM user_groups WHERE group_id=$1::uuid`, edit.ID); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO group_roles(group_id,role_id) SELECT $1::uuid,value::uuid FROM jsonb_array_elements_text($2::jsonb)`, edit.ID, listJSON(edit.RoleIDs)); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO user_groups(group_id,user_id) SELECT $1::uuid,value::uuid FROM jsonb_array_elements_text($2::jsonb)`, edit.ID, listJSON(edit.UserIDs)); err != nil {
			return err
		}
		return audit(ctx, tx, "group.saved", actor.User.ID, "group", edit.ID, a)
	})
}

func (s *IdentityStore) DeleteGroup(ctx context.Context, actorHash []byte, id string, a identity.Audit) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		actor, err := requireSession(ctx, tx, actorHash, true, true, false)
		if err != nil {
			return err
		}
		result, err := tx.ExecContext(ctx, `DELETE FROM groups WHERE id=$1::uuid`, id)
		if err != nil {
			return err
		}
		count, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if count != 1 {
			return identity.ErrConflict
		}
		return audit(ctx, tx, "group.deleted", actor.User.ID, "group", id, a)
	})
}
