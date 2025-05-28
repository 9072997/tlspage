package main

import (
	"context"
	"database/sql"

	"golang.org/x/crypto/acme/autocert"
)

type AutoCertCache struct {
	db *sql.DB
}

func NewAutoCertCache(db *sql.DB) (*AutoCertCache, error) {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS autocert (
			key TEXT PRIMARY KEY,
			data BLOB
		);
	`)
	if err != nil {
		return nil, err
	}

	return &AutoCertCache{
		db: db,
	}, nil
}

func (c *AutoCertCache) Get(ctx context.Context, key string) ([]byte, error) {
	var data []byte
	err := c.db.QueryRowContext(
		ctx,
		"SELECT data FROM autocert WHERE key = ?",
		key,
	).Scan(&data)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, autocert.ErrCacheMiss
		}
		return nil, err
	}
	return data, nil
}

func (c *AutoCertCache) Put(ctx context.Context, key string, data []byte) error {
	_, err := c.db.ExecContext(
		ctx,
		"INSERT OR REPLACE INTO autocert (key, data) VALUES (?, ?)",
		key,
		data,
	)
	if err != nil {
		return err
	}
	return nil
}

func (c *AutoCertCache) Delete(ctx context.Context, key string) error {
	_, err := c.db.ExecContext(ctx, "DELETE FROM autocert WHERE key = ?", key)
	if err != nil {
		return err
	}
	return nil
}
