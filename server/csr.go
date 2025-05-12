package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
)

func getCSRNames(csr *x509.CertificateRequest) []string {
	var names []string

	// Add the Common Name (CN) if it exists
	if len(csr.Subject.CommonName) > 0 {
		names = append(names, csr.Subject.CommonName)
	}

	// Add all Subject Alternative Names (SANs)
	names = append(names, csr.DNSNames...)
	names = append(names, csr.EmailAddresses...)
	for _, ip := range csr.IPAddresses {
		names = append(names, ip.String())
	}
	for _, uri := range csr.URIs {
		names = append(names, uri.String())
	}

	return names
}

func CSRPinnedBaseName(csrData []byte, origin string) (subject string, err error) {
	// Parse the CSR
	csr, err := x509.ParseCertificateRequest(csrData)
	if err != nil {
		return "", fmt.Errorf("failed to parse CSR: %v", err)
	}

	// Get the public key bytes
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %v", err)
	}

	// Calculate the SHA-256 hash
	hash := sha256.Sum256(pubKeyBytes)

	// Convert the hash to hex
	fingerprint := hex.EncodeToString(hash[:])

	// calculate expected key-pinned hostname
	// DNS labels are limited to 63 characters, so use 2x32 labels
	baseName := fingerprint[:32] + "." + fingerprint[32:] + "." + origin
	expected := "*." + baseName

	// check if the expected hostname matched the names in the CSR
	names := getCSRNames(csr)
	for _, name := range names {
		if name != expected {
			return "", fmt.Errorf("CSR does not match expected hostname: %s", name)
		}
	}
	if len(names) == 0 {
		return "", fmt.Errorf("CSR does not contain any names")
	}

	return baseName, nil
}
