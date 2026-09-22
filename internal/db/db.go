package db

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// The executable registers pgx's database/sql driver. Keeping the registration
// at that boundary avoids importing a driver into identity and HTTP packages.
func Open(ctx context.Context, dsn string) (*sql.DB, error) {
	pool, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, errors.New("invalid PostgreSQL connection configuration")
	}
	pool.SetMaxOpenConns(16)
	pool.SetMaxIdleConns(4)
	pool.SetConnMaxLifetime(30 * time.Minute)
	pool.SetConnMaxIdleTime(5 * time.Minute)
	ping, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err = pool.PingContext(ping); err != nil {
		pool.Close()
		return nil, errors.New("PostgreSQL is unavailable")
	}
	return pool, nil
}
