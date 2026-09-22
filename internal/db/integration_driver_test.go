//go:build integration

package db_test

// The real PostgreSQL driver is deliberately present only in the integration
// build. Unit tests never substitute a fake module for pgx.
import _ "github.com/jackc/pgx/v5/stdlib"
