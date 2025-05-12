// modified from github.com/miekg/dns
package dnspriv

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
)

// Errors
var (
	ErrPrivKey = errors.New("invalid private key")
	ErrAlg     = errors.New("unsupported algorithm")
	ErrKey     = errors.New("invalid key")
)

// ParseECDSAPrivateKey reads an ECDSA private key from an io.Reader and returns the private key and dns.DNSKEY.
func ParseECDSAPrivateKey(r io.Reader) (priv *ecdsa.PrivateKey, dnsFormatPubKey string, err error) {
	m, err := parseKey(r)
	if err != nil {
		return nil, "", err
	}

	if m["private-key-format"] != "v1.2" && m["private-key-format"] != "v1.3" {
		return nil, "", ErrPrivKey
	}

	algoStr, _, _ := strings.Cut(m["algorithm"], " ")
	var curve elliptic.Curve
	switch algoStr {
	case "13": // ECDSAP256SHA256
		curve = elliptic.P256()
	case "14": // ECDSAP384SHA384
		curve = elliptic.P384()
	default:
		return nil, "", fmt.Errorf("%w: %s", ErrAlg, algoStr)
	}

	priv = new(ecdsa.PrivateKey)
	priv.D = new(big.Int)
	if v, ok := m["privatekey"]; ok {
		v1, err := fromBase64([]byte(v))
		if err != nil {
			return nil, "", err
		}
		priv.D.SetBytes(v1)
	} else {
		return nil, "", ErrPrivKey
	}

	priv.PublicKey.Curve = curve
	priv.PublicKey.X, priv.PublicKey.Y = curve.ScalarBaseMult(priv.D.Bytes())

	dnsFormatPubKey = dnsPublicKeyECDSA(
		priv.PublicKey.X,
		priv.PublicKey.Y,
	)
	if dnsFormatPubKey == "" {
		return nil, "", ErrKey
	}

	return priv, dnsFormatPubKey, nil
}

func dnsPublicKeyECDSA(x, y *big.Int) string {
	if x == nil || y == nil {
		return ""
	}
	intlen := 32 // Default to P256
	if x.BitLen() > 256 {
		intlen = 48 // P384
	}
	return toBase64(curveToBuf(x, y, intlen))
}

// parseKey reads a private key from an io.Reader and returns a map of key-value pairs.
func parseKey(r io.Reader) (map[string]string, error) {
	m := make(map[string]string)
	var k string

	c := newKLexer(r)
	for l, ok := c.Next(); ok; l, ok = c.Next() {
		switch l.value {
		case zKey:
			k = l.token
		case zValue:
			if k == "" {
				return nil, errors.New("no private key seen")
			}
			m[strings.ToLower(k)] = l.token
			k = ""
		}
	}

	if err := c.Err(); err != nil {
		return nil, err
	}

	return m, nil
}

// Helper functions for encoding and decoding.
func fromBase64(b []byte) ([]byte, error) {
	return base64.StdEncoding.DecodeString(string(b))
}

func toBase64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

// curveToBuf concatenates the X and Y coordinates of an elliptic curve point.
func curveToBuf(x, y *big.Int, intlen int) []byte {
	buf := intToBytes(x, intlen)
	buf = append(buf, intToBytes(y, intlen)...)
	return buf
}

// intToBytes converts a big.Int to a fixed-length byte slice.
func intToBytes(i *big.Int, length int) []byte {
	b := i.Bytes()
	if len(b) > length {
		return b[len(b)-length:]
	}
	padded := make([]byte, length)
	copy(padded[length-len(b):], b)
	return padded
}

// Lexer for parsing key-value pairs.
type klexer struct {
	br      io.ByteReader
	readErr error
	line    int
	column  int
	key     bool
	eol     bool
}

func newKLexer(r io.Reader) *klexer {
	br, ok := r.(io.ByteReader)
	if !ok {
		br = bufio.NewReaderSize(r, 1024)
	}
	return &klexer{br: br, line: 1, key: true}
}

func (kl *klexer) Err() error {
	if kl.readErr == io.EOF {
		return nil
	}
	return kl.readErr
}

func (kl *klexer) readByte() (byte, bool) {
	if kl.readErr != nil {
		return 0, false
	}
	c, err := kl.br.ReadByte()
	if err != nil {
		kl.readErr = err
		return 0, false
	}
	if kl.eol {
		kl.line++
		kl.column = 0
		kl.eol = false
	}
	if c == '\n' {
		kl.eol = true
	} else {
		kl.column++
	}
	return c, true
}

func (kl *klexer) Next() (lex, bool) {
	var l lex
	var str strings.Builder
	commt := false

	for x, ok := kl.readByte(); ok; x, ok = kl.readByte() {
		l.line, l.column = kl.line, kl.column
		switch x {
		case ':':
			if commt || !kl.key {
				break
			}
			kl.key = false
			kl.readByte() // Skip space
			l.value = zKey
			l.token = str.String()
			return l, true
		case ';':
			commt = true
		case '\n':
			if commt {
				commt = false
			}
			if kl.key && str.Len() == 0 {
				break
			}
			kl.key = true
			l.value = zValue
			l.token = str.String()
			return l, true
		default:
			if commt {
				break
			}
			str.WriteByte(x)
		}
	}

	if kl.readErr != nil && kl.readErr != io.EOF {
		return lex{value: zEOF}, false
	}

	if str.Len() > 0 {
		l.value = zValue
		l.token = str.String()
		return l, true
	}

	return lex{value: zEOF}, false
}

// Lexer token types.
const (
	zKey   = "key"
	zValue = "value"
	zEOF   = "eof"
)

type lex struct {
	value  string
	token  string
	line   int
	column int
}
