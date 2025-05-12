package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/9072997/tlspage"
)

func main() {
	origin := flag.String("origin", "tls.page", "Server from which to get the certificate")
	outCert := flag.String("cert", "", "Output certificate file")
	outFullChain := flag.String("chain", "", "Output full-chain file (without private key)")
	outKey := flag.String("key", "", "Output private key file")
	outCombined := flag.String("combined", "", "Output combined file (with private key)")
	requireDays := flag.Int("days", 30, "Minimum time remaining before certificate expiration in days")
	flag.Parse()

	validateOutputFiles(outKey, outCombined, outCert, outFullChain)

	privKeyPEM, err := loadOrGeneratePrivateKey(outKey, outCombined)
	if err != nil {
		log.Fatalf("Error loading or generating private key: %v", err)
	}

	hostname, err := tlspage.Hostname(privKeyPEM, *origin)
	if err != nil {
		log.Fatalf("Error generating hostname: %v", err)
	}

	if checkExistingCertificate(outCert, outFullChain, outCombined, requireDays) {
		fmt.Println(hostname)
		return
	}

	csrPEM, err := tlspage.GenerateCSR(privKeyPEM, hostname)
	if err != nil {
		log.Fatalf("Error generating CSR: %v", err)
	}

	certPEMs, err := tlspage.GetCertificate(csrPEM, *origin)
	if err != nil {
		log.Fatalf("Error fetching certificate from server: %v", err)
	}

	saveCertificates(certPEMs, privKeyPEM, outCert, outFullChain, outKey, outCombined)

	fmt.Println(hostname)
}

func validateOutputFiles(outKey, outCombined, outCert, outFullChain *string) {
	if *outKey == "" && *outCombined == "" {
		log.Fatal("You must specify at least one of --key or --combined to save the private key")
	}
	if *outCert == "" && *outFullChain == "" && *outCombined == "" {
		log.Fatal("You must specify at least one of --cert, --chain, or --combined to save the certificate")
	}
}

func loadOrGeneratePrivateKey(outKey, outCombined *string) (string, error) {
	for _, filename := range []string{*outKey, *outCombined} {
		if filename == "" {
			continue
		}
		privKeyPEM, err := os.ReadFile(filename)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return "", fmt.Errorf("error reading private key file: %v", err)
		}

		// parse as PEM and return the first PRIVATE KEY block
		block, rest := pem.Decode(privKeyPEM)
		for block != nil {
			if block.Type == "PRIVATE KEY" {
				return string(pem.EncodeToMemory(block)), nil
			}
			block, rest = pem.Decode(rest)
		}
		if len(rest) > 0 {
			return "", fmt.Errorf("invalid private key format in file %s", filename)
		}
		return "", fmt.Errorf("no valid private key found in file %s", filename)
	}

	privKeyPEM, err := tlspage.GenerateKey()
	if err != nil {
		return "", fmt.Errorf("failed to generate private key: %v", err)
	}
	return privKeyPEM, nil
}

func checkExistingCertificate(outCert, outFullChain, outCombined *string, requireDays *int) bool {
	for _, filename := range []string{*outCert, *outFullChain, *outCombined} {
		if filename == "" {
			continue
		}
		certData, err := os.ReadFile(filename)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			log.Fatalf("Error reading certificate file: %v", err)
		}

		remaining := certData
		for {
			var block *pem.Block
			block, remaining = pem.Decode(remaining)
			if block == nil {
				break
			}
			if block.Type != "CERTIFICATE" {
				continue
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				log.Fatalf("Error parsing certificate: %v", err)
			}
			requireTime := time.Duration(*requireDays) * 24 * time.Hour
			if time.Until(cert.NotAfter) > requireTime && *requireDays > 0 {
				log.Printf("Existing certificate is valid until %s", cert.NotAfter.Format(time.RFC3339))
				return true
			}
		}
	}
	return false
}

func saveCertificates(certPEMs []string, privKeyPEM string, outCert, outFullChain, outKey, outCombined *string) {
	if *outCert != "" {
		err := os.WriteFile(*outCert, []byte(certPEMs[0]), 0644)
		if err != nil {
			log.Fatalf("Error writing certificate file: %v", err)
		}
	}
	if *outFullChain != "" {
		err := os.WriteFile(*outFullChain, []byte(joinPEMs(certPEMs)), 0644)
		if err != nil {
			log.Fatalf("Error writing full-chain file: %v", err)
		}
	}
	if *outKey != "" {
		err := os.WriteFile(*outKey, []byte(privKeyPEM), 0600)
		if err != nil {
			log.Fatalf("Error writing private key file: %v", err)
		}
	}
	if *outCombined != "" {
		combined := privKeyPEM + joinPEMs(certPEMs)
		err := os.WriteFile(*outCombined, []byte(combined), 0600)
		if err != nil {
			log.Fatalf("Error writing combined file: %v", err)
		}
	}
}

func joinPEMs(pems []string) string {
	var sb strings.Builder
	for _, pem := range pems {
		sb.WriteString(pem)
	}
	return sb.String()
}
