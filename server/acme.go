package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
)

type ACME struct {
	client  *acme.Client
	account *acme.Account
	cache   *CertCache
	MinLife time.Duration
}

// NewACME creates a new ACME instance, registering or loading an account from the given file.
func NewACME(accountFile, cacheFile, directoryURL string) (ACME, error) {
	client := &acme.Client{
		DirectoryURL: directoryURL,
	}

	var account *acme.Account
	_, err := os.Stat(accountFile)
	if os.IsNotExist(err) {
		// generate a new key pair for the account
		key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return ACME{}, fmt.Errorf("failed to generate key: %v", err)
		}
		client.Key = key

		// Register a new account
		account = &acme.Account{
			Contact: []string{},
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		account, err = client.Register(ctx, account, acme.AcceptTOS)
		cancel()
		if err != nil {
			return ACME{}, fmt.Errorf("failed to register ACME account: %v", err)
		}

		// encode key to PEM format
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return ACME{}, fmt.Errorf("failed to marshal private key: %v", err)
		}
		block := &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: der,
		}
		keyData := pem.EncodeToMemory(block)
		// append the account information to the key data
		keyData = append(keyData, []byte(client.KID)...)
		keyData = append(keyData, []byte("\n")...)

		// save the account information to a file
		err = os.WriteFile(accountFile, keyData, 0600)
		if err != nil {
			return ACME{}, fmt.Errorf("failed to save account information: %v", err)
		}
	} else {
		// Load account information from file
		keyData, err := os.ReadFile(accountFile)
		if err != nil {
			return ACME{}, fmt.Errorf("failed to read account file: %v", err)
		}
		block, otherData := pem.Decode(keyData)
		if block == nil || block.Type != "PRIVATE KEY" {
			return ACME{}, fmt.Errorf("failed to decode private key or invalid key format")
		}
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return ACME{}, fmt.Errorf("failed to parse private key: %v", err)
		}
		client.Key = key.(*ecdsa.PrivateKey)
		kid := strings.TrimSpace(string(otherData))
		if len(kid) == 0 {
			return ACME{}, fmt.Errorf("failed to parse key ID from account file")
		}
		client.KID = acme.KeyID(kid)

		// Load account information from ACME server
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		account, err = client.GetReg(ctx, kid)
		cancel()
		if err != nil {
			return ACME{}, fmt.Errorf("failed to get account information: %v", err)
		}
	}

	cache, err := NewCertCache(cacheFile)
	if err != nil {
		return ACME{}, fmt.Errorf("failed to create certificate cache: %v", err)
	}

	return ACME{
		client:  client,
		account: account,
		cache:   cache,
		MinLife: 60 * 24 * time.Hour,
	}, nil
}

func (a *ACME) Close() error {
	if a.cache != nil {
		return a.cache.Close()
	}
	return nil
}

// RequestCert requests a certificate using the provided CSR, DNSBackend, and context.
func (a *ACME) RequestCert(ctx context.Context, baseName string, csrData []byte, backend DNSBackend) ([]byte, error) {
	// first, check if we have an eligible certificate in the cache
	_, cachedCert, expiry, err := a.cache.Get("*." + baseName)
	if err != nil {
		return nil, fmt.Errorf("certificate cache error: %v", err)
	}
	if time.Until(expiry) > a.MinLife {
		// we have a valid certificate in the cache, return it
		return cachedCert, nil
	}

	// Start the certificate order
	order, err := a.client.AuthorizeOrder(
		ctx,
		[]acme.AuthzID{
			{
				Type:  "dns",
				Value: "*." + baseName,
			},
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to start certificate order: %v", err)
	}

	// Complete the DNS-01 challenge
	for _, authz := range order.AuthzURLs {
		auth, err := a.client.GetAuthorization(ctx, authz)
		if err != nil {
			return nil, fmt.Errorf("failed to get authorization: %v", err)
		}

		var challenge *acme.Challenge
		for _, c := range auth.Challenges {
			if c.Type == "dns-01" {
				challenge = c
				break
			}
		}
		if challenge == nil {
			return nil, fmt.Errorf("no DNS-01 challenge found")
		}

		// Get the DNS-01 challenge key
		key, err := a.client.DNS01ChallengeRecord(challenge.Token)
		if err != nil {
			return nil, fmt.Errorf("failed to get DNS-01 challenge key: %v", err)
		}

		// Add the TXT record to the DNS backend
		backend.ValidationRecords.Set(
			"_acme-challenge."+baseName+".",
			key,
			0,
		)

		// Wait for DNS propagation
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(10 * time.Second):
		}

		// Complete the challenge
		_, err = a.client.Accept(ctx, challenge)
		if err != nil {
			return nil, fmt.Errorf("failed to accept challenge: %v", err)
		}

		// Wait for the authorization to be valid
		_, err = a.client.WaitAuthorization(ctx, authz)
		if err != nil {
			return nil, fmt.Errorf("authorization failed: %v", err)
		}
	}

	// Finalize the order with the CSR
	certs, _, err := a.client.CreateOrderCert(ctx, order.FinalizeURL, csrData, true)
	if err != nil {
		return nil, fmt.Errorf("failed to finalize order: %v", err)
	}

	// PEM encode the certificate
	var encoded []byte
	for _, cert := range certs {
		block := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert,
		}
		encoded = append(encoded, pem.EncodeToMemory(block)...)
	}

	// Save the certificate to the cache
	err = a.cache.Put(csrData, encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to save certificate to cache: %v", err)
	}

	return encoded, nil
}
