package db

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

const migrationLockID int64 = 0x6175746864

var ErrSchemaOutdated = errors.New("database schema is not current")

type migrationEntry struct {
	Version int64
	Name    string
}

func migrationManifest() ([]migrationEntry, error) {
	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	out := make([]migrationEntry, 0, len(entries))
	seen := map[int64]bool{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		version, err := migrationVersion(entry.Name())
		if err != nil {
			return nil, err
		}
		if seen[version] {
			return nil, fmt.Errorf("duplicate migration version %d", version)
		}
		seen[version] = true
		out = append(out, migrationEntry{Version: version, Name: entry.Name()})
	}
	if len(out) == 0 {
		return nil, errors.New("no embedded database migrations")
	}
	return out, nil
}

// Migrate is an explicit deployment operation. Normal daemon startup calls
// CheckSchema instead, allowing its PostgreSQL role to operate without DDL
// privileges.
func Migrate(ctx context.Context, pool *sql.DB) error {
	manifest, err := migrationManifest()
	if err != nil {
		return err
	}
	tx, err := pool.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, migrationLockID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
 version bigint PRIMARY KEY, name text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return err
	}
	for _, migration := range manifest {
		var name string
		err = tx.QueryRowContext(ctx, `SELECT name FROM schema_migrations WHERE version=$1`, migration.Version).Scan(&name)
		switch {
		case err == nil:
			if name != migration.Name {
				return fmt.Errorf("migration version %d recorded as %q, expected %q", migration.Version, name, migration.Name)
			}
			continue
		case !errors.Is(err, sql.ErrNoRows):
			return err
		}
		body, readErr := migrationFS.ReadFile("migrations/" + migration.Name)
		if readErr != nil {
			return readErr
		}
		if _, err = tx.ExecContext(ctx, string(body)); err != nil {
			return fmt.Errorf("migration %s failed: %w", migration.Name, err)
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO schema_migrations(version,name) VALUES($1,$2)`, migration.Version, migration.Name); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// CheckSchema performs no DDL. It verifies that the connected database has
// exactly the embedded migration history authd expects. This is the normal
// daemon/bootstrap startup path and is safe for a DML-only runtime role.
func CheckSchema(ctx context.Context, pool *sql.DB) error {
	manifest, err := migrationManifest()
	if err != nil {
		return err
	}
	var exists bool
	if err = pool.QueryRowContext(ctx, `SELECT to_regclass('schema_migrations') IS NOT NULL`).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return ErrSchemaOutdated
	}
	rows, err := pool.QueryContext(ctx, `SELECT version,name FROM schema_migrations ORDER BY version`)
	if err != nil {
		return err
	}
	defer rows.Close()
	actual := make([]migrationEntry, 0, len(manifest))
	for rows.Next() {
		var entry migrationEntry
		if err = rows.Scan(&entry.Version, &entry.Name); err != nil {
			return err
		}
		actual = append(actual, entry)
	}
	if err = rows.Err(); err != nil {
		return err
	}
	if len(actual) != len(manifest) {
		return ErrSchemaOutdated
	}
	for i := range manifest {
		if actual[i] != manifest[i] {
			return ErrSchemaOutdated
		}
	}
	return nil
}

func migrationVersion(name string) (int64, error) {
	prefix := strings.SplitN(name, "_", 2)[0]
	version, err := strconv.ParseInt(prefix, 10, 64)
	if err != nil || version <= 0 {
		return 0, fmt.Errorf("invalid migration version: %q", name)
	}
	return version, nil
}
