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
	"encoding/csv"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
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
	for i := range 2 {
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
		if i == 0 {
			// wait a bit before trying again
			log.Println("No IPv6 address found, retrying in 5 seconds...")
			time.Sleep(5 * time.Second)
		}
	}
	return nil, nil
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
	*sql.DB
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

func (c nodeStatusHandlers) cleanupHandler(resp http.ResponseWriter, req *http.Request) {
	nodes, err := c.Cluster(req.Context())
	if err != nil {
		http.Error(
			resp,
			err.Error(),
			http.StatusInternalServerError,
		)
		return
	}

	// a healthy cluster should have at least 3 nodes
	if len(nodes) <= 3 {
		http.Error(
			resp,
			"not enough nodes to do cleanup",
			http.StatusInternalServerError,
		)
		return
	}

	// random delay to avoid all nodes doing
	// the same thing at the same time
	time.Sleep(time.Duration(mrand.Intn(1000)) * time.Millisecond)

	// loop over each non-voting node and do a liveness check
	for _, node := range nodes {
		if node.Role == client.Voter {
			fmt.Fprintf(resp, "Node %s is a voter, skipping\n", node.Address)
			continue
		}

		conn, err := net.DialTimeout("tcp", node.Address, time.Second)
		if err != nil {
			fmt.Fprintf(resp, "Node %s is not reachable, removing\n", node.Address)
			// remove the node from the cluster
			ctx, cancel := context.WithTimeout(
				context.Background(),
				DqliteTimeout,
			)
			defer cancel()
			err = c.Remove(ctx, node.ID)
			if err != nil {
				fmt.Fprintf(resp, "Error removing node %s: %v\n", node.Address, err)
			} else {
				fmt.Fprintf(resp, "Node %s removed\n", node.Address)
			}
			continue
		}
		conn.Close()
	}
	resp.Write([]byte("OK\n"))
}

func (c nodeStatusHandlers) sqlHandler(resp http.ResponseWriter, req *http.Request) {
	ctx, cancel := context.WithTimeout(req.Context(), DqliteTimeout)
	defer cancel()

	// get the SQL query from the request
	var query string
	if req.Method == http.MethodPost {
		// read the query from the request body
		queryBytes, err := io.ReadAll(req.Body)
		if err != nil {
			http.Error(resp, "Failed to read request body", http.StatusBadRequest)
			return
		}
		query = string(queryBytes)
	} else if req.Method == http.MethodGet {
		// get the query from the URL query parameters
		query = req.URL.Query().Get("q")
		if query == "" {
			http.Error(resp, "Missing q parameter", http.StatusBadRequest)
			return
		}
	} else {
		http.Error(resp, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// execute the query
	rows, err := c.DB.QueryContext(ctx, query)
	if err != nil {
		http.Error(resp, fmt.Sprintf("Failed to execute query: %v", err), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	// write the results as CSV
	resp.Header().Set("Content-Type", "text/csv")
	csvWriter := csv.NewWriter(resp)
	defer csvWriter.Flush()
	columns, err := rows.Columns()
	if err != nil {
		http.Error(resp, fmt.Sprintf("Failed to get columns: %v", err), http.StatusInternalServerError)
		return
	}
	err = csvWriter.Write(columns)
	if err != nil {
		http.Error(resp, fmt.Sprintf("Failed to write header: %v", err), http.StatusInternalServerError)
		return
	}

	for rows.Next() {
		values := make([]interface{}, len(columns))
		valuePtrs := make([]interface{}, len(columns))
		for i := range values {
			valuePtrs[i] = &values[i]
		}
		err = rows.Scan(valuePtrs...)
		if err != nil {
			http.Error(resp, fmt.Sprintf("Failed to scan row: %v", err), http.StatusInternalServerError)
			return
		}

		row := make([]string, len(columns))
		for i, val := range values {
			if val == nil {
				row[i] = "NULL"
			} else {
				row[i] = fmt.Sprintf("%v", val)
			}
		}
		err = csvWriter.Write(row)
		if err != nil {
			http.Error(resp, fmt.Sprintf("Failed to write row: %v", err), http.StatusInternalServerError)
			return
		}
	}
	if err = rows.Err(); err != nil {
		http.Error(resp, fmt.Sprintf("Error iterating rows: %v", err), http.StatusInternalServerError)
		return
	}
}

func startStatusServer(a *app.App, addr string) error {
	ctx, cancel := context.WithTimeout(context.Background(), DqliteTimeout)
	c, err := a.Client(ctx)
	cancel()
	if err != nil {
		return err
	}
	ctx, cancel = context.WithTimeout(context.Background(), DqliteTimeout)
	db, err := a.Open(ctx, DBName)
	cancel()
	if err != nil {
		return fmt.Errorf("failed to open dqlite database: %w", err)
	}

	handlers := nodeStatusHandlers{c, db}
	mux := http.NewServeMux()
	mux.HandleFunc("/nodes", handlers.listNodesHandler)
	mux.HandleFunc("/dump", handlers.dumpHandler)
	mux.HandleFunc("/cleanup", handlers.cleanupHandler)
	mux.HandleFunc("/sql", handlers.sqlHandler)
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
