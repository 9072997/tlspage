package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/canonical/go-dqlite/v3/app"
)

func myIPv6() (net.IP, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			if ipnet.IP.To4() != nil {
				continue
			}
			if !ipnet.IP.IsGlobalUnicast() {
				continue
			}
			return ipnet.IP, nil
		}
	}
	return nil, nil
}

func NewDqlite(dataDir, certFile, keyFile, peersFile string) (*sql.DB, error) {
	// read the peers file into []string
	peersRaw, err := os.ReadFile(peersFile)
	if err != nil {
		err = fmt.Errorf("failed to read peers file: %v", err)
		return nil, err
	}
	var peers []string
	for _, peer := range bytes.Split(peersRaw, []byte{'\n'}) {
		trimmed := bytes.TrimSpace(peer)
		if len(trimmed) > 0 {
			peers = append(peers, string(trimmed))
		}
	}

	// create the data directory if it doesn't exist
	err = os.MkdirAll(dataDir, 0755)
	if err != nil {
		err = fmt.Errorf("failed to create data directory: %v", err)
		return nil, err
	}

	// get our own IPv6 address
	selfV6, err := myIPv6()
	if err != nil {
		err = fmt.Errorf("failed to get our IPv6 address: %v", err)
		return nil, err
	}
	selfAddr := net.JoinHostPort(selfV6.String(), "9000")
	log.Printf("Using dqlite address %s\n", selfAddr)

	cert, pool, err := dqliteKeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	app, err := app.New(
		dataDir,
		app.WithAddress(selfAddr),
		app.WithCluster(peers),
		app.WithTLS(app.SimpleTLSConfig(cert, pool)),
	)
	if err != nil {
		return nil, err
	}

	// Register a shutdown handler to close the dqlite app
	ProcessShutdownHandlers = append(ProcessShutdownHandlers, func() {
		log.Println("Closing dqlite")
		ctx, _ := context.WithTimeout(
			context.Background(),
			ShutdownTimeout,
		)
		err := app.Handover(ctx)
		if err != nil {
			log.Printf("Error doing dqlite handover: %v", err)
		}
		err = app.Close()
		if err != nil {
			log.Printf("Error closing dqlite: %v", err)
		}
	})

	log.Println("Starting dqlite")
	ctx, cancel := context.WithTimeout(context.Background(), DqliteTimeout)
	err = app.Ready(ctx)
	cancel()
	if err != nil {
		return nil, err
	}
	log.Println("dqlite is ready")

	db, err := app.Open(context.Background(), PackageNameVersion)
	if err != nil {
		return nil, err
	}

	return db, nil
}

func generateSelfSignedCert(certFile, keyFile string) error {
	// if both files already exist, return
	_, cErr := os.Stat(certFile)
	_, kErr := os.Stat(keyFile)
	if cErr == nil && kErr == nil {
		return nil
	}

	// Generate a private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	// Create a certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "dqlite",
		},
		DNSNames:  []string{"dqlite"},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(10 * 365 * 24 * time.Hour), // Valid for 10 years
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
	}

	// Self-sign the certificate
	certBytes, err := x509.CreateCertificate(
		rand.Reader,
		&template,
		&template,
		&privateKey.PublicKey,
		privateKey,
	)
	if err != nil {
		return err
	}

	// Write the certificate to a file
	certOut, err := os.Create(certFile)
	if err != nil {
		return err
	}
	defer certOut.Close()
	err = pem.Encode(certOut, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	if err != nil {
		return err
	}

	// Write the private key to a file
	keyOut, err := os.Create(keyFile)
	if err != nil {
		return err
	}
	defer keyOut.Close()
	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return err
	}
	err = pem.Encode(keyOut, &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateKeyBytes,
	})
	if err != nil {
		return err
	}

	return nil
}

func dqliteKeyPair(certFile, keyFile string) (tls.Certificate, *x509.CertPool, error) {
	// this is a no-op if the files already exist
	if err := generateSelfSignedCert(certFile, keyFile); err != nil {
		return tls.Certificate{}, nil, err
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return tls.Certificate{}, nil, err
	}

	certPool := x509.NewCertPool()
	caCert, err := os.ReadFile(certFile)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	certPool.AppendCertsFromPEM(caCert)

	return cert, certPool, nil
}
