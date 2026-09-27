package db

import (
	"context"
	"database/sql"

	"github.com/yellowman/authd/internal/identity"
)

func (s *IdentityStore) Branding(ctx context.Context) (out identity.Branding, err error) {
	err = s.DB.QueryRowContext(ctx, `SELECT name,logo,updated_at FROM login_branding WHERE singleton`).Scan(&out.Name, &out.Logo, &out.UpdatedAt)
	return
}

func (s *IdentityStore) SaveBranding(ctx context.Context, hash []byte, edit identity.Branding, replaceLogo, removeLogo bool, a identity.Audit) error {
	if err := identity.ValidateBrandName(edit.Name); err != nil {
		return err
	}
	if edit.UpdatedAt.IsZero() || len(edit.Logo) > 256<<10 || (replaceLogo && removeLogo) {
		return identity.Invalid("Invalid branding update.")
	}
	if edit.Logo == nil {
		edit.Logo = []byte{}
	}
	return s.write(ctx, func(tx *sql.Tx) error {
		actor, err := requireSession(ctx, tx, hash, true, true, false)
		if err != nil {
			return err
		}
		result, err := tx.ExecContext(ctx, `UPDATE login_branding SET name=$1,logo=CASE WHEN $2 THEN $3 WHEN $4 THEN ''::bytea ELSE logo END,updated_at=clock_timestamp() WHERE singleton AND updated_at=$5`, edit.Name, replaceLogo, edit.Logo, removeLogo, edit.UpdatedAt)
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 {
			return identity.ErrConflict
		}
		return audit(ctx, tx, "branding.updated", actor.User.ID, "login_branding", "", a)
	})
}
