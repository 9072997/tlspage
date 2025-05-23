package main

import (
	"bytes"
	"crypto"
	"database/sql"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"strings"

	"github.com/9072997/tlspage/dnspriv"
	"github.com/9072997/tlspage/madns"
	"github.com/miekg/dns"
)

type DNSBackend struct {
	Origin        string
	StaticRecords map[string][]dns.RR

	db              *sql.DB
	wildcardDNSName regexp.Regexp
}

// This populates ZoneData, which is not thread-safe
// The intent is that it is initialized once at startup and never modified
func NewDNSBackend(origin, zoneFile string, db *sql.DB) (DNSBackend, error) {
	// TODO: better logic for finding/live-reloading zone file
	data, err := os.ReadFile(zoneFile)
	if err != nil {
		log.Fatal("Error reading zone file:", err)
	}
	parser := dns.NewZoneParser(
		bytes.NewBuffer(data),
		origin+".",
		zoneFile,
	)
	// we expect the zonefile to set a default TTL
	// if it doesn't we are probably debugging and want a low TTL
	parser.SetDefaultTTL(5 * 60) // 5 minutes

	// Parse the zone file and populate staticRecords
	staticRecords := make(map[string][]dns.RR)
	rCount := 0
	for {
		rr, ok := parser.Next()
		if !ok {
			break
		}
		if rr == nil {
			log.Printf("Error parsing zone file: %v", parser.Err())
			break
		}

		name := rr.Header().Name
		staticRecords[name] = append(staticRecords[name], rr)
		rCount++
	}
	log.Printf("Loaded %d records from zone file", rCount)

	// compile the regex for wildcard DNS names
	escapedOrigin := regexp.QuoteMeta(origin)
	wildcardDNSName := regexp.MustCompile(
		`^[0-9a-f-]{3,45}\.[0-9a-f]{32}\.[0-9a-f]{32}\.` + escapedOrigin + `\.$`,
	)

	// create validation records table if it does not exist
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS validation_records (
			qname TEXT PRIMARY KEY,
			value TEXT NOT NULL,
			created INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
		);
	`)
	if err != nil {
		err = fmt.Errorf("failed to create validation records table: %v", err)
		return DNSBackend{}, err
	}

	return DNSBackend{
		Origin:          origin,
		StaticRecords:   staticRecords,
		db:              db,
		wildcardDNSName: *wildcardDNSName,
	}, nil
}

func (b DNSBackend) SetValidationRecord(qname, value string) error {
	// set the validation record in the database
	// at the same time, clean up old records
	_, err := b.db.Exec(
		`
			INSERT OR REPLACE INTO validation_records (qname, value)
			VALUES (?, ?);
			DELETE FROM validation_records
			WHERE created < (strftime('%s', 'now') - 10 * 60);
		`,
		qname,
		value,
	)
	if err != nil {
		return fmt.Errorf("failed to set validation record: %v", err)
	}
	return nil
}

func (b DNSBackend) GetValidationRecord(qname string) (string, error) {
	// get the validation record from the database
	var value string
	err := b.db.QueryRow(
		`
			SELECT value FROM validation_records
			WHERE qname = ?
		`,
		qname,
	).Scan(&value)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", nil // No entry found
		}
		return "", fmt.Errorf("failed to get validation record: %v", err)
	}
	return value, nil
}

func (b DNSBackend) Lookup(qname, streamIsolationID string) (rr []dns.RR, err error) {
	qname = dns.CanonicalName(qname)

	// handle ACME challenge records
	if strings.HasPrefix(qname, "_acme-challenge.") {
		vRecord, err := b.GetValidationRecord(qname)
		if err != nil {
			return nil, fmt.Errorf("failed to get validation record: %v", err)
		}
		if vRecord != "" {
			rr = append(rr, &dns.TXT{
				Hdr: dns.RR_Header{
					Name:   qname,
					Rrtype: dns.TypeTXT,
					Class:  dns.ClassINET,
					Ttl:    0,
				},
				Txt: []string{vRecord},
			})
		}
		return rr, nil
	}

	// handle ipv4 and ipv6 records
	if b.wildcardDNSName.MatchString(qname) {
		ipPart, _, _ := strings.Cut(qname, ".")
		// try as IPv4
		parsed := net.ParseIP(strings.ReplaceAll(ipPart, "-", "."))
		if parsed != nil {
			rr = append(rr, &dns.A{
				Hdr: dns.RR_Header{
					Name:   qname,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    30 * 24 * 60 * 60, // 30 days
				},
				A: parsed.To4(),
			})
			return
		}

		// try as IPv6
		parsed = net.ParseIP(strings.ReplaceAll(ipPart, "-", ":"))
		if parsed != nil {
			// this is an IPv6 address
			rr = append(rr, &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   qname,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    30 * 24 * 60 * 60, // 30 days
				},
				AAAA: parsed.To16(),
			})
			return
		}
	}

	// handle static records
	rr = b.StaticRecords[qname]

	// handle wildcard records
	if len(rr) == 0 {
		parts := strings.Split(qname, ".")
		for i := 1; i < len(parts); i++ {
			rest := strings.Join(parts[i:], ".")
			wcQname := "*." + rest
			matches := b.StaticRecords[wcQname]
			if len(matches) > 0 {
				for _, r := range matches {
					rCopy := dns.Copy(r)
					rCopy.Header().Name = qname
					rr = append(rr, rCopy)
				}
				break
			}
		}
	}

	return rr, nil
}

func (b DNSBackend) SetCAA(caDomain string, a ACME) {
	// set the CAA record for the root domain
	rr := &dns.CAA{
		Hdr: dns.RR_Header{
			Name:   b.Origin + ".",
			Rrtype: dns.TypeCAA,
			Class:  dns.ClassINET,
			Ttl:    5 * 60, // 5 minutes
		},
		Flag:  128,
		Tag:   "issue",
		Value: caDomain,
	}
	b.StaticRecords[b.Origin+"."] = append(
		b.StaticRecords[b.Origin+"."],
		rr,
	)
	// don't allow non-wildcard certs for subdomains
	rr = &dns.CAA{
		Hdr: dns.RR_Header{
			Name:   "*." + b.Origin + ".",
			Rrtype: dns.TypeCAA,
			Class:  dns.ClassINET,
			Ttl:    5 * 60, // 5 minutes
		},
		Flag:  128,
		Tag:   "issue",
		Value: ";",
	}
	b.StaticRecords["*."+b.Origin+"."] = append(
		b.StaticRecords["*."+b.Origin+"."],
		rr,
	)
	// set an issuewild record for the all subdomains
	rr = &dns.CAA{
		Hdr: dns.RR_Header{
			Name:   "*." + b.Origin + ".",
			Rrtype: dns.TypeCAA,
			Class:  dns.ClassINET,
			Ttl:    5 * 60, // 5 minutes
		},
		Flag:  128,
		Tag:   "issuewild",
		Value: caDomain,
	}
	b.StaticRecords["*."+b.Origin+"."] = append(
		b.StaticRecords["*."+b.Origin+"."],
		rr,
	)
}

func (b DNSBackend) GoServeDNS(keyFile string) {
	pubKey, privKey := b.loadOrGenerateKey(keyFile)

	// add DNSSEC related keys to the zone
	var dnssecRRs []dns.RR
	dnssecRRs = append(dnssecRRs, pubKey.ToCDNSKEY())
	dnssecRRs = append(dnssecRRs, pubKey.ToDS(dns.SHA256).ToCDS())
	b.StaticRecords[b.Origin+"."] = append(
		b.StaticRecords[b.Origin+"."],
		dnssecRRs...,
	)

	engine, err := madns.NewEngine(&madns.EngineConfig{
		Backend:       b,
		ZSK:           &pubKey,
		ZSKPrivate:    privKey,
		VersionString: PackageNameVersion,
	})
	if err != nil {
		log.Fatalf("Error creating DNS engine: %v", err)
	}
	mux := dns.NewServeMux()
	mux.Handle(b.Origin+".", engine)
	go func() {
		err = dns.ListenAndServe("[::]:53", "udp", mux)
		panic(err)
	}()
	go func() {
		err = dns.ListenAndServe("[::]:53", "tcp", mux)
		panic(err)
	}()
}

func (b DNSBackend) loadOrGenerateKey(filename string) (dnsKey dns.DNSKEY, privKey crypto.PrivateKey) {
	// there are customizations to the dns library to support ECDSA
	// changing it would be a lot of work
	dnsKey = dns.DNSKEY{
		Hdr: dns.RR_Header{
			Class:  dns.ClassINET,
			Rrtype: dns.TypeDNSKEY,
			Ttl:    5 * 60,
			Name:   b.Origin + ".",
		},
		Flags:     dns.SEP | dns.ZONE,
		Protocol:  3, // it's always 3 for DNSSEC
		Algorithm: dns.ECDSAP256SHA256,
	}

	// try to load the contents of the 2 files
	keyData, err := os.ReadFile(filename)
	// check file not found error
	if os.IsNotExist(err) {
		log.Printf("Key file not found: %s", filename)
	} else if err != nil {
		log.Fatalf("Error reading key file: %v", err)
	} else {
		// try to load key from file
		var dnsFormatPubKey string
		privKey, dnsFormatPubKey, err = dnspriv.ParseECDSAPrivateKey(
			bytes.NewReader(keyData),
		)
		if err != nil {
			print(string(keyData))
			log.Fatalf("Error parsing key file: %v", err)
		}
		dnsKey.PublicKey = dnsFormatPubKey
		return
	}

	// generate a new key
	privKey, err = dnsKey.Generate(256)
	if err != nil {
		log.Fatalf("Error generating key: %v", err)
	}
	// print new key
	log.Printf(
		"Generated new key. Add this record to the parent zone:\n%s\n",
		dnsKey.ToDS(dns.SHA256),
	)
	// save the private key to a file
	keyData = []byte(dnsKey.PrivateKeyString(privKey))
	err = os.WriteFile(filename, []byte(keyData), 0600)
	if err != nil {
		log.Fatalf("Error writing private key file: %v", err)
	}
	// return the new key and private key
	return
}
