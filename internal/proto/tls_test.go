package proto

import (
	"encoding/binary"
	"testing"
)

// buildClientHello constructs a minimal, well-formed TLS record containing
// a ClientHello handshake message with the given SNI and cipher suites.
func buildClientHello(sni string, ciphers []uint16) []byte {
	var body []byte
	body = append(body, 0x03, 0x03)          // client_version: TLS 1.2
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0x00)                // session_id_len = 0

	var cs []byte
	for _, c := range ciphers {
		cs = binary.BigEndian.AppendUint16(cs, c)
	}
	body = binary.BigEndian.AppendUint16(body, uint16(len(cs)))
	body = append(body, cs...)

	body = append(body, 0x01, 0x00) // compression methods: len=1, [null]

	// SNI extension.
	nameBytes := []byte(sni)
	var serverNameEntry []byte
	serverNameEntry = append(serverNameEntry, 0x00) // host_name type
	serverNameEntry = binary.BigEndian.AppendUint16(serverNameEntry, uint16(len(nameBytes)))
	serverNameEntry = append(serverNameEntry, nameBytes...)

	var serverNameList []byte
	serverNameList = binary.BigEndian.AppendUint16(serverNameList, uint16(len(serverNameEntry)))
	serverNameList = append(serverNameList, serverNameEntry...)

	var sniExt []byte
	sniExt = binary.BigEndian.AppendUint16(sniExt, 0x0000) // extension type: server_name
	sniExt = binary.BigEndian.AppendUint16(sniExt, uint16(len(serverNameList)))
	sniExt = append(sniExt, serverNameList...)

	body = binary.BigEndian.AppendUint16(body, uint16(len(sniExt)))
	body = append(body, sniExt...)

	var handshake []byte
	handshake = append(handshake, 0x01) // ClientHello
	hsLen := len(body)
	handshake = append(handshake, byte(hsLen>>16), byte(hsLen>>8), byte(hsLen))
	handshake = append(handshake, body...)

	var record []byte
	record = append(record, 0x16, 0x03, 0x01) // Handshake, TLS 1.0 record version
	record = binary.BigEndian.AppendUint16(record, uint16(len(handshake)))
	record = append(record, handshake...)
	return record
}

func TestParseClientHello(t *testing.T) {
	ciphers := []uint16{0x1301, 0x1302, 0x002f}
	raw := buildClientHello("example.com", ciphers)

	ch, err := ParseClientHello(raw)
	if err != nil {
		t.Fatalf("ParseClientHello failed: %v", err)
	}
	if ch.SNI != "example.com" {
		t.Errorf("SNI = %q, want %q", ch.SNI, "example.com")
	}
	if ch.Version != TLS12 {
		t.Errorf("Version = %v, want TLS12", ch.Version)
	}
	if len(ch.CipherSuites) != len(ciphers) {
		t.Fatalf("CipherSuites = %v, want %v", ch.CipherSuites, ciphers)
	}
	for i, c := range ciphers {
		if ch.CipherSuites[i] != c {
			t.Errorf("CipherSuites[%d] = %#04x, want %#04x", i, ch.CipherSuites[i], c)
		}
	}
	if _, weak := WeakCipherSuites[0x002f]; !weak {
		t.Errorf("expected 0x002f to be flagged as a weak cipher suite")
	}
}

func TestParseClientHelloTruncated(t *testing.T) {
	raw := buildClientHello("example.com", []uint16{0x1301})
	for _, n := range []int{0, 1, 5, 10, len(raw) / 2} {
		if _, err := ParseClientHello(raw[:n]); err == nil {
			t.Errorf("expected error parsing truncated (%d byte) ClientHello, got none", n)
		}
	}
}
