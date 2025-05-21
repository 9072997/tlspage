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
	zonefile := filepath.Join(confDir, "zonefile")
	dnsKeyFile := filepath.Join(stateDir, "dns-key")
	homePageCertDir := filepath.Join(stateDir, "certs")
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
		"https://acme-v02.api.letsencrypt.org/directory",
		db,
	)
	if err != nil {
		panic(err)
	}

	zone := NewDNSBackend("tls.page", zonefile)
	zone.SetCAA("letsencrypt.org", a)
	zone.GoServeDNS(dnsKeyFile)

	h := &HTTPHandler{
		ACME:         a,
		DNSBackend:   zone,
		FSHandler:    http.FileServer(http.Dir(wwwDir)),
		CertCacheDir: homePageCertDir,
	}
	err = h.ListenAndServe()
	panic(err)
}
