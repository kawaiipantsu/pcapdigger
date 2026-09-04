// Package proto contains light-weight, best-effort application-layer
// parsers (TLS ClientHello/Certificate, DNS, HTTP, plaintext credential
// protocols) used by both the flow builder and the security detectors.
package proto

import (
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
)

// TLSVersion is a TLS/SSL protocol version, as advertised on the wire.
type TLSVersion uint16

const (
	SSL30 TLSVersion = 0x0300
	TLS10 TLSVersion = 0x0301
	TLS11 TLSVersion = 0x0302
	TLS12 TLSVersion = 0x0303
	TLS13 TLSVersion = 0x0304
)

// String renders a human-readable TLS/SSL version name.
func (v TLSVersion) String() string {
	switch v {
	case SSL30:
		return "SSLv3"
	case TLS10:
		return "TLS 1.0"
	case TLS11:
		return "TLS 1.1"
	case TLS12:
		return "TLS 1.2"
	case TLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown (0x%04x)", uint16(v))
	}
}

// IsWeak reports whether v is a deprecated/insecure TLS/SSL version.
func (v TLSVersion) IsWeak() bool {
	return v == SSL30 || v == TLS10 || v == TLS11
}

// ClientHello holds the fields extracted from a TLS ClientHello message.
type ClientHello struct {
	Version      TLSVersion
	SNI          string
	CipherSuites []uint16
}

// ServerCertificates holds X.509 certificates extracted from a TLS
// Certificate handshake message.
type ServerCertificates struct {
	Certs []*x509.Certificate
}

const (
	recTypeHandshake  = 0x16
	hsTypeClientHello = 0x01
	hsTypeCertificate = 0x0b
	extSNI            = 0x0000
)

// ParseClientHello attempts to parse a TLS record buffer (starting at the
// TLS record layer) as a ClientHello. Returns an error if the buffer is not
// a recognizable ClientHello.
func ParseClientHello(b []byte) (*ClientHello, error) {
	rec, err := firstHandshakeBody(b, hsTypeClientHello)
	if err != nil {
		return nil, err
	}
	return parseClientHelloBody(rec)
}

// firstHandshakeBody walks one or more concatenated TLS records of type
// Handshake looking for a handshake message of the given type, returning its
// body (without the handshake header).
func firstHandshakeBody(b []byte, want byte) ([]byte, error) {
	for len(b) >= 5 {
		recType := b[0]
		verMajor, verMinor := b[1], b[2]
		length := int(binary.BigEndian.Uint16(b[3:5]))
		if len(b) < 5+length {
			return nil, errors.New("truncated TLS record")
		}
		payload := b[5 : 5+length]
		if recType != recTypeHandshake || verMajor != 3 || verMinor > 4 {
			b = b[5+length:]
			continue
		}
		for len(payload) >= 4 {
			hsType := payload[0]
			hsLen := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
			if len(payload) < 4+hsLen {
				return nil, errors.New("truncated TLS handshake message")
			}
			body := payload[4 : 4+hsLen]
			if hsType == want {
				return body, nil
			}
			payload = payload[4+hsLen:]
		}
		b = b[5+length:]
	}
	return nil, errors.New("handshake message not found")
}

func parseClientHelloBody(b []byte) (*ClientHello, error) {
	if len(b) < 2 {
		return nil, errors.New("client hello too short")
	}
	ch := &ClientHello{Version: TLSVersion(binary.BigEndian.Uint16(b[0:2]))}
	pos := 2 + 32 // version + random
	if len(b) < pos+1 {
		return nil, errors.New("client hello truncated (session id)")
	}
	sessIDLen := int(b[pos])
	pos += 1 + sessIDLen
	if len(b) < pos+2 {
		return nil, errors.New("client hello truncated (cipher suites)")
	}
	csLen := int(binary.BigEndian.Uint16(b[pos : pos+2]))
	pos += 2
	if len(b) < pos+csLen {
		return nil, errors.New("client hello truncated (cipher suites body)")
	}
	for i := 0; i+1 < csLen; i += 2 {
		ch.CipherSuites = append(ch.CipherSuites, binary.BigEndian.Uint16(b[pos+i:pos+i+2]))
	}
	pos += csLen
	if len(b) < pos+1 {
		return ch, nil // no compression/extensions present
	}
	compLen := int(b[pos])
	pos += 1 + compLen
	if len(b) < pos+2 {
		return ch, nil
	}
	extTotalLen := int(binary.BigEndian.Uint16(b[pos : pos+2]))
	pos += 2
	end := pos + extTotalLen
	if end > len(b) {
		end = len(b)
	}
	for pos+4 <= end {
		extType := binary.BigEndian.Uint16(b[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(b[pos+2 : pos+4]))
		pos += 4
		if pos+extLen > end {
			break
		}
		if extType == extSNI {
			ch.SNI = parseSNIExtension(b[pos : pos+extLen])
		}
		pos += extLen
	}
	return ch, nil
}

func parseSNIExtension(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	listLen := int(binary.BigEndian.Uint16(b[0:2]))
	pos := 2
	end := pos + listLen
	if end > len(b) {
		end = len(b)
	}
	for pos+3 <= end {
		nameType := b[pos]
		nameLen := int(binary.BigEndian.Uint16(b[pos+1 : pos+3]))
		pos += 3
		if pos+nameLen > end {
			break
		}
		if nameType == 0 { // host_name
			return string(b[pos : pos+nameLen])
		}
		pos += nameLen
	}
	return ""
}

// ParseServerCertificates attempts to parse a TLS record buffer as a
// Certificate handshake message, returning the decoded X.509 chain.
func ParseServerCertificates(b []byte) (*ServerCertificates, error) {
	body, err := firstHandshakeBody(b, hsTypeCertificate)
	if err != nil {
		return nil, err
	}
	if len(body) < 3 {
		return nil, errors.New("certificate message too short")
	}
	listLen := int(body[0])<<16 | int(body[1])<<8 | int(body[2])
	pos := 3
	end := pos + listLen
	if end > len(body) {
		end = len(body)
	}
	out := &ServerCertificates{}
	for pos+3 <= end {
		certLen := int(body[pos])<<16 | int(body[pos+1])<<8 | int(body[pos+2])
		pos += 3
		if pos+certLen > end {
			break
		}
		der := body[pos : pos+certLen]
		pos += certLen
		cert, err := x509.ParseCertificate(der)
		if err == nil {
			out.Certs = append(out.Certs, cert)
		}
	}
	if len(out.Certs) == 0 {
		return nil, errors.New("no certificates parsed")
	}
	return out, nil
}

// WeakCipherSuites lists suite IDs considered broken/export-grade: NULL
// (no encryption), RC4/DES/3DES (cryptographically broken or deprecated by
// every major browser and CA/B Forum guidance). Deliberately excludes
// merely "older" AEAD-less suites like TLS_RSA_WITH_AES_128_CBC_SHA
// (0x002f) -- nearly every modern client still *offers* those as a
// compatibility fallback in ClientHello even though it will negotiate a
// modern suite, so flagging them on offer alone (rather than on what the
// server actually selected) is pure false-positive noise.
var WeakCipherSuites = map[uint16]string{
	0x0000: "TLS_NULL_WITH_NULL_NULL",
	0x0001: "TLS_RSA_WITH_NULL_MD5",
	0x0002: "TLS_RSA_WITH_NULL_SHA",
	0x0004: "TLS_RSA_WITH_RC4_128_MD5",
	0x0005: "TLS_RSA_WITH_RC4_128_SHA",
	0x0009: "TLS_RSA_WITH_DES_CBC_SHA",
	0x000a: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
	0x0015: "TLS_DHE_RSA_WITH_DES_CBC_SHA",
	0x0016: "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
}
