package tlscrypto

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// The values below are taken verbatim from RFC 8448 ("Example Handshake
// Traces for TLS 1.3"), Section 3 (Simple 1-RTT Handshake), and were
// extracted programmatically from the RFC's own hex dumps rather than
// retyped by hand, to avoid transcription errors in a security-sensitive
// piece of code.

func hexb(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// TestDeriveSecretRFC8448 checks Derive-Secret against the "derive secret
// for handshake 'tls13 derived'" step: deriving the salt for the
// handshake-secret Extract from the early secret and the empty-message
// transcript hash (SHA-256 of the empty string).
func TestDeriveSecretRFC8448(t *testing.T) {
	earlySecret := hexb(t, "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a")
	emptyHash := hexb(t, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

	got := DeriveSecret(SHA256, earlySecret, "derived", emptyHash)
	want := hexb(t, "6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba")
	if !bytes.Equal(got, want) {
		t.Fatalf("derived secret = %x, want %x", got, want)
	}
}

// TestHKDFExpandLabelKeyIV checks HKDF-Expand-Label "key"/"iv" derivation
// from the RFC's server application traffic secret against the RFC's own
// recorded server application write key/IV.
func TestHKDFExpandLabelKeyIV(t *testing.T) {
	serverAppTrafficSecret := hexb(t, "a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643")

	key := HKDFExpandLabel(SHA256, serverAppTrafficSecret, "key", nil, 16)
	iv := HKDFExpandLabel(SHA256, serverAppTrafficSecret, "iv", nil, 12)

	if want := hexb(t, "9f02283b6c9c07efc26bb9f2ac92e356"); !bytes.Equal(key, want) {
		t.Fatalf("key = %x, want %x", key, want)
	}
	if want := hexb(t, "cf782b88dd83549aadf1e984"); !bytes.Equal(iv, want) {
		t.Fatalf("iv = %x, want %x", iv, want)
	}
}
