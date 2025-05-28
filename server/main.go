package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
)

func main() {
	stateDir := os.Getenv("STATE_DIRECTORY")
	confDir := os.Getenv("CONFIGURATION_DIRECTORY")
	fmt.Printf("State Directory: %s\n", stateDir)
	fmt.Printf("Configuration Directory: %s\n", confDir)
	acmeAccountFile := filepath.Join(stateDir, "acme-account")
	eabFile := filepath.Join(confDir, "eab")
	zonefile := filepath.Join(confDir, "zonefile")
	dnsKeyFile := filepath.Join(confDir, "dns-key")
	wwwDir := filepath.Join(confDir, "www")
	dbDir := filepath.Join(stateDir, "db")
	dqliteCertFile := filepath.Join(confDir, "dqlite.cert")
	dqliteKeyFile := filepath.Join(confDir, "dqlite.key")
	peersFile := filepath.Join(confDir, "peers")

	db, err := NewDqlite(dbDir, dqliteCertFile, dqliteKeyFile, peersFile)
	if err != nil {
		panic(err)
	}
	if len(os.Getenv("DB_ONLY")) > 0 {
		fmt.Println("DB_ONLY is set")
		select {} // Block forever
	}

	a, err := NewACME(
		acmeAccountFile,
		eabFile,
		ACMEDirectoryURL,
		db,
	)
	if err != nil {
		panic(err)
	}

	zone, err := NewDNSBackend(Origin, zonefile, db)
	if err != nil {
		panic(err)
	}
	zone.SetCAA(CAAIdentifier, a)
	zone.GoServeDNS(dnsKeyFile)

	acc, err := NewAutoCertCache(db)
	if err != nil {
		panic(fmt.Errorf("failed to create autocert cache: %v", err))
	}

	h := &HTTPHandler{
		ACME:       a,
		DNSBackend: zone,
		FSHandler:  http.FileServer(http.Dir(wwwDir)),
		CertCache:  acc,
	}
	err = h.ListenAndServe()
	panic(err)
}
