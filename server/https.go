package main

import (
	"net/http"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

type HTTPHandler struct {
	FSHandler    http.Handler
	ACME         ACME
	DNSBackend   DNSBackend
	CertCacheDir string
	mux          *http.ServeMux
}

func (h *HTTPHandler) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	// CORS headers
	resp.Header().Set("Access-Control-Allow-Origin", "*")
	resp.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	h.mux.ServeHTTP(resp, req)
}

func (h *HTTPHandler) ListenAndServe() error {
	// create a servemux for the HTTP server
	h.mux = http.NewServeMux()
	h.mux.Handle("/", h.FSHandler)
	h.mux.HandleFunc("/hostname-from-cert", h.hostnameFromCertHandler)
	h.mux.HandleFunc("/hostname-from-csr", h.hostnameFromCSRHandler)
	h.mux.HandleFunc("/hostname-from-key", h.hostnameFromKeyHandler)
	h.mux.HandleFunc("/cert-from-csr", h.certFromCSRHandler)
	h.mux.HandleFunc("/cert-from-key", h.certFromKeyHandler)
	h.mux.HandleFunc("/csr-from-key", h.csrFromKeyHandler)
	h.mux.HandleFunc("/key", h.keyHandler)
	h.mux.HandleFunc("/cert/", h.certForHostnameHandler)

	// listen and serve HTTPS
	srv := &http.Server{
		Addr: ":443",
		TLSConfig: (&autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			Cache:      autocert.DirCache(h.CertCacheDir),
			HostPolicy: autocert.HostWhitelist(h.DNSBackend.Origin),
			Client:     h.ACME.client,
		}).TLSConfig(),
		Handler: h,

		// safe defaults
		ReadTimeout:    5 * time.Second,
		WriteTimeout:   120 * time.Second,
		IdleTimeout:    5 * time.Second,
		MaxHeaderBytes: 10 * 1024, // 10KB
	}
	return srv.ListenAndServeTLS("", "")
}
