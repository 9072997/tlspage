package tlspage

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
)

// GenerateKey generates a new ECDSA P-256 private key and returns it as a PEM-encoded string.
func GenerateKey() (privKeyPEM string, err error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", fmt.Errorf("failed to generate key pair: %v", err)
	}

	pkcs8, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal private key: %v", err)
	}

	keyBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8,
	}
	return string(pem.EncodeToMemory(keyBlock)), nil
}

// Hostname calculates the key-pinned hostname corresponding to the public key for the given private key.
// The format will be "{32 chars}.{32 chars}.origin".
func Hostname(privKeyPEM string, origin string) (string, error) {
	privKey, err := parsePrivateKey(privKeyPEM)
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %v", err)
	}

	pkix, err := x509.MarshalPKIXPublicKey(privKey.Public())
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %v", err)
	}

	hash := sha256.Sum256(pkix)
	fingerprint := hex.EncodeToString(hash[:])
	return fingerprint[:32] + "." + fingerprint[32:] + "." + origin, nil
}

// GenerateCSR generates a PEM-encoded CSR with the given private key for the given hostname.
func GenerateCSR(privKeyPEM string, hostname string) (csrPEM string, err error) {
	privKey, err := parsePrivateKey(privKeyPEM)
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %v", err)
	}

	csr, err := x509.CreateCertificateRequest(
		rand.Reader,
		&x509.CertificateRequest{
			DNSNames: []string{"*." + hostname},
		},
		privKey,
	)
	if err != nil {
		return "", fmt.Errorf("failed to create CSR: %v", err)
	}

	csrBlock := &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr,
	}
	return string(pem.EncodeToMemory(csrBlock)), nil
}

// GetCertificate submits the CSR to the server specified by origin and returns a list of certificates.
// The first certificate is the leaf certificate.
func GetCertificate(csrPEM string, origin string) (certificatePEMs []string, err error) {
	resp, err := http.Post(
		fmt.Sprintf("https://%s/cert-from-csr", origin),
		"application/pkcs10",
		bytes.NewReader([]byte(csrPEM)),
	)
	if err != nil {
		return nil, fmt.Errorf("error sending request to server: %v", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(
			"server returned non-200 status: %s\n%s",
			resp.Status,
			respBody,
		)
	}

	var certPEMs []string
	for {
		block, remaining := pem.Decode(respBody)
		if block == nil {
			break
		}
		certPEMs = append(certPEMs, string(pem.EncodeToMemory(block)))
		respBody = remaining
	}
	if len(certPEMs) == 0 {
		return nil, fmt.Errorf("no PEM blocks found in response")
	}
	return certPEMs, nil
}

// parsePrivateKey parses a PEM-encoded private key and returns the ECDSA private key.
func parsePrivateKey(privKeyPEM string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM private key")
	}

	privKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	ecdsaKey, ok := privKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not ECDSA")
	}
	return ecdsaKey, nil
}
