package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	mrand "math/rand"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/canonical/go-dqlite/v3/app"
	"github.com/canonical/go-dqlite/v3/client"
)

const DBName = "tlspage.sqlite3"

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

func newRolesAdjustmentHook(a *app.App) func(client.NodeInfo, []client.NodeInfo) error {
	return func(leader client.NodeInfo, cluster []client.NodeInfo) error {
		// a healthy cluster should have at least 3 nodes
		if len(cluster) <= 3 {
			return nil
		}

		// random delay to avoid all nodes doing
		// the same thing at the same time
		time.Sleep(time.Duration(mrand.Intn(1000)) * time.Millisecond)

		// loop over each non-voting node and do a liveness check
		for _, node := range cluster {
			if node.ID == leader.ID {
				continue
			}
			if node.Role == client.Voter {
				continue
			}

			conn, err := net.DialTimeout("tcp", node.Address, time.Second)
			if err != nil {
				log.Printf("Node %d is dead: %v", node.ID, err)
				// remove the node from the cluster
				ctx, cancel := context.WithTimeout(
					context.Background(),
					DqliteTimeout,
				)
				defer cancel()
				leader, err := a.FindLeader(ctx)
				if err != nil {
					log.Println("Error getting dqlite client:", err)
					return err
				}
				defer leader.Close()
				err = leader.Remove(ctx, node.ID)
				if err != nil {
					log.Printf("Error removing node %d: %v", node.ID, err)
					return err
				}
				continue
			}
			conn.Close()
		}
		return nil
	}
}

func readPeersFile(peersFile string) ([]string, error) {
	selfV6, err := myIPv6()
	if err != nil {
		err = fmt.Errorf("failed to get our IPv6 address: %v", err)
		return nil, err
	}

	peersRaw, err := os.ReadFile(peersFile)
	if err != nil {
		err = fmt.Errorf("failed to read peers file: %v", err)
		return nil, err
	}

	var peers []string
	for _, peer := range bytes.Split(peersRaw, []byte{'\n'}) {
		trimmed := bytes.TrimSpace(peer)
		if len(trimmed) > 0 {
			// skip lines starting with #
			if trimmed[0] == '#' {
				continue
			}

			// skip if this is our own address
			parsed := net.ParseIP(string(trimmed))
			if parsed.Equal(selfV6) {
				continue
			}

			hp := net.JoinHostPort(string(trimmed), "9000")
			peers = append(peers, hp)
		}
	}

	return peers, nil
}

func NewDqlite(dataDir, certFile, keyFile, peersFile string) (*sql.DB, error) {
	// get our own IPv6 address
	selfV6, err := myIPv6()
	if err != nil {
		err = fmt.Errorf("failed to get our IPv6 address: %v", err)
		return nil, err
	}
	selfAddr := net.JoinHostPort(selfV6.String(), "9000")
	log.Printf("Using dqlite address %s\n", selfAddr)

	// read the peers file into []string
	peers, err := readPeersFile(peersFile)
	if err != nil {
		err = fmt.Errorf("failed to read peers file: %v", err)
		return nil, err
	}

	// create the data directory if it doesn't exist
	err = os.MkdirAll(dataDir, 0755)
	if err != nil {
		err = fmt.Errorf("failed to create data directory: %v", err)
		return nil, err
	}

	cert, pool, err := dqliteKeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	var a *app.App
	a, err = app.New(
		dataDir,
		app.WithAddress(selfAddr),
		app.WithCluster(peers),
		app.WithTLS(app.SimpleTLSConfig(cert, pool)),
		app.WithDiskMode(true),
		app.WithRolesAdjustmentHook(
			newRolesAdjustmentHook(a),
		),
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
		err := a.Handover(ctx)
		if err != nil {
			log.Printf("Error doing dqlite handover: %v", err)
		}
		err = a.Close()
		if err != nil {
			log.Printf("Error closing dqlite: %v", err)
		}
	})

	log.Println("Starting dqlite")
	ctx, cancel := context.WithTimeout(context.Background(), DqliteTimeout)
	err = a.Ready(ctx)
	cancel()
	if err != nil {
		return nil, err
	}
	log.Println("dqlite is ready")

	// register a status endpoint
	err = startStatusServer(a, "localhost:9001")
	if err != nil {
		return nil, err
	}

	db, err := a.Open(context.Background(), DBName)
	if err != nil {
		return nil, err
	}

	return db, nil
}

type nodeStatusHandlers struct {
	*client.Client
}

func (c nodeStatusHandlers) listNodesHandler(resp http.ResponseWriter, req *http.Request) {
	nodes, err := c.Cluster(req.Context())
	if err != nil {
		http.Error(
			resp,
			err.Error(),
			http.StatusInternalServerError,
		)
		return
	}
	resp.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(resp)
	enc.SetIndent("", "\t")
	err = enc.Encode(nodes)
	if err != nil {
		http.Error(
			resp,
			err.Error(),
			http.StatusInternalServerError,
		)
		return
	}
}

func (c nodeStatusHandlers) dumpHandler(resp http.ResponseWriter, req *http.Request) {
	files, err := c.Dump(req.Context(), DBName)
	if err != nil {
		http.Error(
			resp,
			err.Error(),
			http.StatusInternalServerError,
		)
		return
	}

	// compress to zip
	zipWriter := zip.NewWriter(resp)
	defer zipWriter.Close()
	for _, file := range files {
		f, err := zipWriter.Create(file.Name)
		if err != nil {
			http.Error(
				resp,
				err.Error(),
				http.StatusInternalServerError,
			)
			return
		}
		_, err = f.Write(file.Data)
		if err != nil {
			http.Error(
				resp,
				err.Error(),
				http.StatusInternalServerError,
			)
			return
		}
	}
	resp.Header().Set("Content-Type", "application/zip")
}

func startStatusServer(a *app.App, addr string) error {
	ctx, cancel := context.WithTimeout(context.Background(), DqliteTimeout)
	c, err := a.Client(ctx)
	cancel()
	if err != nil {
		return err
	}

	handlers := nodeStatusHandlers{c}
	mux := http.NewServeMux()
	mux.HandleFunc("/nodes", handlers.listNodesHandler)
	mux.HandleFunc("/dump", handlers.dumpHandler)
	srv := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	go func() {
		err := srv.ListenAndServe()
		if err != nil {
			log.Printf("Error starting dqlite status server: %v", err)
		}
	}()

	return nil
}

func generateSelfSignedCert(certFile, keyFile string) error {
	// if both files already exist, return
	_, cErr := os.Stat(certFile)
	_, kErr := os.Stat(keyFile)
	if cErr == nil && kErr == nil {
		return nil
	}

	// Generate a private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
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
		crand.Reader,
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
