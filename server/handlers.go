package main

import (
	"bytes"
	"crypto/x509"
	"embed"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/9072997/tlspage"
)

//go:embed apidocs
var apidocs embed.FS

func serveAPIDocs(resp http.ResponseWriter, name string) {
	data, err := apidocs.ReadFile("apidocs/" + name)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to read API documentation: %v", err)
		http.Error(resp, errMsg, http.StatusInternalServerError)
		return
	}
	resp.Header().Set("Content-Type", "text/plain")
	resp.Write(data)
}

func (h *HTTPHandler) hostnameFromCertHandler(resp http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodGet || req.Method == http.MethodHead {
		serveAPIDocs(resp, "hostname-from-cert")
		return
	}

	certData, err := io.ReadAll(req.Body)
	if err != nil {
		http.Error(resp, "Failed to read request body", http.StatusInternalServerError)
		return
	}
	req.Body.Close()

	block, _ := pem.Decode(certData)
	if block == nil {
		http.Error(resp, "Failed to decode PEM certificate", http.StatusBadRequest)
		return
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to parse certificate: %v", err)
		http.Error(resp, errMsg, http.StatusBadRequest)
		return
	}

	hostname := cert.Subject.CommonName
	if hostname == "" && len(cert.DNSNames) > 0 {
		hostname = cert.DNSNames[0]
	}
	if hostname == "" {
		http.Error(resp, "No common name or DNS names found in certificate", http.StatusBadRequest)
		return
	}

	hostname = strings.TrimPrefix(hostname, "*.")

	resp.Header().Set("Content-Type", "text/plain")
	resp.Write([]byte(hostname))
}

func (h *HTTPHandler) hostnameFromCSRHandler(resp http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodGet || req.Method == http.MethodHead {
		serveAPIDocs(resp, "hostname-from-csr")
		return
	}

	csrData, err := io.ReadAll(req.Body)
	if err != nil {
		http.Error(resp, "Failed to read request body", http.StatusInternalServerError)
		return
	}
	req.Body.Close()

	var csr []byte
	if bytes.Contains(csrData, []byte("----")) {
		block, _ := pem.Decode(csrData)
		if block == nil {
			http.Error(resp, "Failed to decode PEM CSR", http.StatusBadRequest)
			return
		}
		csr = block.Bytes
	} else {
		csr = csrData
	}

	baseName, err := CSRPinnedBaseName(csr, h.DNSBackend.Origin)
	if err != nil {
		errMsg := fmt.Sprintf("CSR validation failed: %v", err)
		http.Error(resp, errMsg, http.StatusBadRequest)
		return
	}

	// cache the CSR (we validated it already)
	err = h.ACME.cache.PutCSR(csr, h.DNSBackend.Origin)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to cache CSR: %v", err)
		http.Error(resp, errMsg, http.StatusInternalServerError)
		return
	}

	resp.Header().Set("Content-Type", "text/plain")
	resp.Write([]byte(baseName))
}

func (h *HTTPHandler) hostnameFromKeyHandler(resp http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodGet || req.Method == http.MethodHead {
		serveAPIDocs(resp, "hostname-from-key")
		return
	}

	keyData, err := io.ReadAll(req.Body)
	if err != nil {
		http.Error(resp, "Failed to read request body", http.StatusInternalServerError)
		return
	}
	req.Body.Close()

	hostname, err := tlspage.Hostname(string(keyData), h.DNSBackend.Origin)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to extract hostname: %v", err)
		http.Error(resp, errMsg, http.StatusBadRequest)
		return
	}

	// just in-case this is the first time we see this key generate a CSR and cache it
	err = h.ACME.cache.PutKey(string(keyData), h.DNSBackend.Origin)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to cache CSR: %v", err)
		http.Error(resp, errMsg, http.StatusInternalServerError)
		return
	}

	resp.Header().Set("Content-Type", "text/plain")
	resp.Write([]byte(hostname))
}

func (h *HTTPHandler) certFromCSRHandler(resp http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodGet || req.Method == http.MethodHead {
		serveAPIDocs(resp, "cert-from-csr")
		return
	}

	// CSR should never be larger than 10KB
	if req.ContentLength > 10*1024 {
		http.Error(resp, "Request too large", http.StatusRequestEntityTooLarge)
		return
	}

	reqBody, err := io.ReadAll(req.Body)
	if err != nil {
		http.Error(resp, "Failed to read request body", http.StatusInternalServerError)
		return
	}
	req.Body.Close()

	var csr []byte
	if bytes.Contains(reqBody, []byte("----")) {
		block, _ := pem.Decode(reqBody)
		if block == nil {
			http.Error(resp, "Failed to decode PEM CSR", http.StatusBadRequest)
			return
		}
		csr = block.Bytes
	} else {
		csr = reqBody
	}

	baseName, err := CSRPinnedBaseName(csr, h.DNSBackend.Origin)
	if err != nil {
		errMsg := fmt.Sprintf("CSR validation failed: %v", err)
		http.Error(resp, errMsg, http.StatusBadRequest)
		return
	}

	// also caches the CSR
	cert, err := h.ACME.RequestCert(req.Context(), baseName, csr, h.DNSBackend)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to get certificate: %v", err)
		http.Error(resp, errMsg, http.StatusInternalServerError)
		return
	}

	resp.Header().Set("Content-Type", "application/x-x509-ca-cert")
	resp.Header().Set("Content-Disposition", "attachment; filename=\"cert.pem\"")
	resp.Write(cert)
}

func (h *HTTPHandler) certFromKeyHandler(resp http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodGet || req.Method == http.MethodHead {
		serveAPIDocs(resp, "cert-from-key")
		return
	}

	keyData, err := io.ReadAll(req.Body)
	if err != nil {
		http.Error(resp, "Failed to read request body", http.StatusInternalServerError)
		return
	}
	req.Body.Close()

	hostname, err := tlspage.Hostname(string(keyData), h.DNSBackend.Origin)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to generate hostname: %v", err)
		http.Error(resp, errMsg, http.StatusInternalServerError)
		return
	}

	csr, err := tlspage.GenerateCSR(string(keyData), hostname)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to generate CSR: %v", err)
		http.Error(resp, errMsg, http.StatusInternalServerError)
		return
	}

	block, _ := pem.Decode([]byte(csr))
	if block == nil {
		http.Error(resp, "Failed to decode PEM CSR", http.StatusBadRequest)
		return
	}

	// this will also cache the CSR
	cert, err := h.ACME.RequestCert(req.Context(), hostname, block.Bytes, h.DNSBackend)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to get certificate: %v", err)
		http.Error(resp, errMsg, http.StatusInternalServerError)
		return
	}

	resp.Header().Set("Content-Type", "application/x-x509-ca-cert")
	resp.Header().Set("Content-Disposition", "attachment; filename=\"cert.pem\"")
	resp.Write(cert)
}

func (h *HTTPHandler) csrFromKeyHandler(resp http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodGet || req.Method == http.MethodHead {
		serveAPIDocs(resp, "csr-from-key")
		return
	}

	keyData, err := io.ReadAll(req.Body)
	if err != nil {
		http.Error(resp, "Failed to read request body", http.StatusInternalServerError)
		return
	}
	req.Body.Close()

	hostname, err := tlspage.Hostname(string(keyData), h.DNSBackend.Origin)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to generate hostname: %v", err)
		http.Error(resp, errMsg, http.StatusInternalServerError)
		return
	}

	csr, err := tlspage.GenerateCSR(string(keyData), hostname)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to generate CSR: %v", err)
		http.Error(resp, errMsg, http.StatusInternalServerError)
		return
	}

	// cache the CSR
	err = h.ACME.cache.PutCSR([]byte(csr), h.DNSBackend.Origin)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to cache CSR: %v", err)
		http.Error(resp, errMsg, http.StatusInternalServerError)
		return
	}

	resp.Header().Set("Content-Type", "application/x-pem-file")
	resp.Header().Set("Content-Disposition", "attachment; filename=\"csr.pem\"")
	resp.Write([]byte(csr))
}

func (h *HTTPHandler) keyHandler(resp http.ResponseWriter, req *http.Request) {
	key, err := tlspage.GenerateKey()
	if err != nil {
		errMsg := fmt.Sprintf("Failed to generate key: %v", err)
		http.Error(resp, errMsg, http.StatusInternalServerError)
		return
	}

	// cache the CSR from the key
	err = h.ACME.cache.PutKey(key, h.DNSBackend.Origin)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to cache CSR: %v", err)
		http.Error(resp, errMsg, http.StatusInternalServerError)
		return
	}

	resp.Header().Set("Content-Type", "application/x-pem-file")
	resp.Header().Set("Content-Disposition", "attachment; filename=\"key.pem\"")
	resp.Write([]byte(key))
}

func (h *HTTPHandler) certForHostnameHandler(resp http.ResponseWriter, req *http.Request) {
	hostname := req.URL.Path[len("/cert/"):]

	csr, _, _, err := h.ACME.cache.Get("*." + hostname)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to get CSR from cache: %v", err)
		http.Error(resp, errMsg, http.StatusInternalServerError)
		return
	}
	if csr == nil {
		http.Error(resp, "CSR not found in cache", http.StatusNotFound)
		return
	}

	cert, err := h.ACME.RequestCert(req.Context(), hostname, csr, h.DNSBackend)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to retrieve certificate: %v", err)
		http.Error(resp, errMsg, http.StatusInternalServerError)
		return
	}

	resp.Header().Set("Content-Type", "application/x-x509-ca-cert")
	resp.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s.pem\"", hostname))
	resp.Write(cert)
}
