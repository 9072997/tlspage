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
	certsDBFile := filepath.Join(stateDir, "certs.sqlite3")
	zonefile := filepath.Join(confDir, "zonefile")
	dnsKeyFile := filepath.Join(stateDir, "dns-key")
	homePageCertDir := filepath.Join(stateDir, "certs")
	wwwDir := filepath.Join(confDir, "www")

	a, err := NewACME(
		acmeAccountFile,
		certsDBFile,
		"https://acme-v02.api.letsencrypt.org/directory",
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
