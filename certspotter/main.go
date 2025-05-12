// this is intended to be a hook for use with
// https://github.com/SSLMate/certspotter/blob/master/man/certspotter-script.md
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/gregdel/pushover"
)

// CertSpotterJSON represents the structure of the JSON file saved by CertSpotter.
type CertSpotterJSON struct {
	TbsSHA256    string    `json:"tbs_sha256"`    // Hex-encoded SHA-256 digest of the TBSCertificate
	PubkeySHA256 string    `json:"pubkey_sha256"` // Hex-encoded SHA-256 digest of the Subject Public Key Info
	DNSNames     []string  `json:"dns_names"`     // DNS names for which the certificate is valid
	IPAddresses  []string  `json:"ip_addresses"`  // IP addresses for which the certificate is valid
	NotBefore    time.Time `json:"not_before"`    // Not before time in RFC3339 format
	NotAfter     time.Time `json:"not_after"`     // Not after (expiration) time in RFC3339 format
}

func main() {
	jsonFilename := os.Getenv("JSON_FILENAME")
	if jsonFilename == "" {
		notify("JSON_FILENAME environment variable is not set")
	}
	watchItem := os.Getenv("WATCH_ITEM") // ex: ".tls.page"
	if watchItem == "" {
		notify("WATCH_ITEM environment variable is not set")
	}
	root := strings.TrimPrefix(watchItem, ".")

	jsonData, err := os.ReadFile(jsonFilename)
	if err != nil {
		notify("Failed to read JSON file: %v", err)
	}

	var certData CertSpotterJSON
	err = json.Unmarshal(jsonData, &certData)
	if err != nil {
		notify("Failed to unmarshal JSON data: %v", err)
	}

	if len(certData.PubkeySHA256) != 64 {
		notify("Invalid PubkeySHA256 length: %d", len(certData.PubkeySHA256))
	}
	if len(certData.DNSNames) != 1 {
		notify("Unexpected DNSNames length: %d", len(certData.DNSNames))
	}
	if len(certData.IPAddresses) != 0 {
		notify("Unexpected IPAddresses length: %d", len(certData.IPAddresses))
	}
	subject := certData.DNSNames[0]
	if subject == root {
		return
	}

	expected := fmt.Sprintf(
		"*.%s.%s%s",
		certData.PubkeySHA256[0:32],
		certData.PubkeySHA256[32:64],
		watchItem,
	)
	if subject != expected {
		notify("Unexpected subject: %s, expected: %s", subject, expected)
	}

	// TODO remove this once we are confident everything is working
	notify("%s valid", subject)
}

func notify(format string, args ...interface{}) {
	s := fmt.Sprintf(format, args...)

	// send message via Pushover
	apiKey := os.Getenv("PUSHOVER_API_KEY")
	if apiKey == "" {
		log.Println("PUSHOVER_API_KEY environment variable is not set")
		os.Exit(1)
	}
	userKey := os.Getenv("PUSHOVER_USER_KEY")
	if userKey == "" {
		log.Println("PUSHOVER_USER_KEY environment variable is not set")
		os.Exit(1)
	}

	app := pushover.New(apiKey)
	recipient := pushover.NewRecipient(userKey)
	message := pushover.NewMessage(s)
	_, err := app.SendMessage(message, recipient)
	if err != nil {
		log.Println(s)
		log.Printf("Failed to send message: %v", err)
		os.Exit(1)
	}

	os.Exit(0)
}
