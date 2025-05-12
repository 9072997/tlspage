package main

import (
	"strings"
	"syscall/js"

	"github.com/9072997/tlspage"
)

func main() {
	js.Global().Set("GenerateKey", js.FuncOf(GenerateKey))
	js.Global().Set("Hostname", js.FuncOf(Hostname))
	js.Global().Set("GenerateCSR", js.FuncOf(GenerateCSR))
	js.Global().Set("GetCertificate", js.FuncOf(GetCertificate))

	js.Global().Get("GoReady").Invoke()
	select {}
}

// GenerateKey generates a new ECDSA P-256 private key and returns it as a PEM-encoded string.
func GenerateKey(this js.Value, args []js.Value) any {
	pem, _ := tlspage.GenerateKey()
	return js.ValueOf(pem)
}

// Hostname calculates the key-pinned hostname corresponding to the public key for the given private key.
// The format will be "{32 chars}.{32 chars}.origin".
func Hostname(this js.Value, args []js.Value) any {
	if len(args) < 2 {
		return js.ValueOf("error: insufficient arguments")
	}
	privKeyPEM := args[0].String()
	origin := args[1].String()
	hostname, err := tlspage.Hostname(privKeyPEM, origin)
	if err != nil {
		return js.ValueOf("error: " + err.Error())
	}
	return js.ValueOf(hostname)
}

// GenerateCSR generates a PEM-encoded CSR with the given private key for the given hostname.
func GenerateCSR(this js.Value, args []js.Value) any {
	if len(args) < 2 {
		return js.ValueOf("error: insufficient arguments")
	}
	privKeyPEM := args[0].String()
	hostname := args[1].String()
	csrPEM, err := tlspage.GenerateCSR(privKeyPEM, hostname)
	if err != nil {
		return js.ValueOf("error: " + err.Error())
	}
	return js.ValueOf(csrPEM)
}

// GetCertificate submits the CSR to the server specified by origin and returns a list of certificates.
// The first certificate is the leaf certificate.
func GetCertificate(this js.Value, args []js.Value) any {
	if len(args) < 2 {
		return js.ValueOf("error: insufficient arguments")
	}
	csrPEM := args[0].String()
	origin := args[1].String()

	// Create a new promise to handle the asynchronous operation
	promise := newPromise(func(resolve, reject js.Value) {
		certificatePEMs, err := tlspage.GetCertificate(csrPEM, origin)
		if err != nil {
			reject.Invoke("error: " + err.Error())
			return
		}
		resolve.Invoke(joinPEMs(certificatePEMs))
	})

	return js.ValueOf(promise)
}

func newPromise(resolver func(resolve, reject js.Value)) js.Value {
	var f js.Func
	f = js.FuncOf(func(this js.Value, p []js.Value) any {
		resolve := p[0]
		reject := p[1]
		go resolver(resolve, reject)
		f.Release()
		return nil
	})

	promise := js.Global().Get("Promise").New(f)
	return promise
}

func joinPEMs(pems []string) string {
	var sb strings.Builder
	for _, pem := range pems {
		sb.WriteString(pem)
	}
	return sb.String()
}
