package main

import (
	"bytes"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/9072997/tlspage"
	_ "github.com/glebarez/go-sqlite"
)

type CertCache struct {
	file string
	db   *sql.DB
}

func NewCertCache(file string) (*CertCache, error) {
	c := &CertCache{file: file}
	if err := c.setupDB(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *CertCache) setupDB() error {
	// Open the database file
	db, err := sql.Open("sqlite", c.file)
	if err != nil {
		return err
	}
	db.SetMaxOpenConns(1)
	c.db = db

	// Create the table if it doesn't exist
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS certs (
			subject TEXT PRIMARY KEY,
			csr BLOB NOT NULL,
			cert TEXT NULL,
			expiry INTEGER NOT NULL DEFAULT 0
		);
	`)
	if err != nil {
		return err
	}
	return nil
}

func (c *CertCache) Close() error {
	if c.db != nil {
		return c.db.Close()
	}
	return nil
}

func (c *CertCache) Get(subject string) ([]byte, []byte, time.Time, error) {
	var csr, cert []byte
	var expiry int64

	err := c.db.QueryRow(
		`SELECT csr, cert, expiry FROM certs WHERE subject = ?`,
		subject,
	).Scan(&csr, &cert, &expiry)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil, time.Time{}, nil // No entry found
		}
		return nil, nil, time.Time{}, err // Other error
	}

	return csr, cert, time.Unix(expiry, 0), nil
}

func (c *CertCache) Put(csr, cert []byte) error {
	// cert is a PEM-encoded certificate chain.
	// decode it and get the subject & expiry date of the first certificate.
	block, _ := pem.Decode(cert)
	if block == nil {
		return fmt.Errorf("failed to decode PEM certificate")
	}
	certObj, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %v", err)
	}
	var subject string
	if certObj.Subject.CommonName != "" {
		subject = certObj.Subject.CommonName
	} else if len(certObj.DNSNames) > 0 {
		subject = certObj.DNSNames[0]
	} else {
		return fmt.Errorf("no common name or DNS names found in certificate")
	}

	_, err = c.db.Exec(
		`INSERT OR REPLACE INTO certs (subject, csr, cert, expiry) VALUES (?, ?, ?, ?)`,
		subject,
		csr,
		cert,
		certObj.NotAfter.Unix(),
	)
	return err
}

func (c *CertCache) PutCSR(csr []byte, origin string) error {
	if bytes.Contains(csr, []byte("----")) {
		block, _ := pem.Decode(csr)
		if block == nil {
			return fmt.Errorf("failed to decode PEM CSR")
		}
		csr = block.Bytes
	}

	// only store the CSR if there is no CSR for this subject already.
	baseName, err := CSRPinnedBaseName(csr, origin)
	if err != nil {
		return fmt.Errorf("failed to get pinned base name: %v", err)
	}
	_, err = c.db.Exec(
		`INSERT OR IGNORE INTO certs (subject, csr) VALUES (?, ?)`,
		"*."+baseName,
		csr,
	)
	if err != nil {
		return fmt.Errorf("failed to insert CSR: %v", err)
	}
	return nil
}

func (c *CertCache) PutKey(key, origin string) error {
	hostname, err := tlspage.Hostname(key, origin)
	if err != nil {
		return fmt.Errorf("failed to get hostname from key: %v", err)
	}

	csr, err := tlspage.GenerateCSR(key, hostname)
	if err != nil {
		return fmt.Errorf("failed to generate CSR: %v", err)
	}
	return c.PutCSR([]byte(csr), origin)
}
