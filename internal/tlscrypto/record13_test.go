package tlscrypto

import (
	"bytes"
	"testing"
)

// TestOpenTLS13RecordRFC8448 decrypts the exact server application_data
// record given in RFC 8448 Section 3, deriving its key/IV from the RFC's
// own server application traffic secret, and checks the recovered
// plaintext against the RFC's stated 50-byte payload.
func TestOpenTLS13RecordRFC8448(t *testing.T) {
	serverAppTrafficSecret := hexb(t, "a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643")
	key := HKDFExpandLabel(SHA256, serverAppTrafficSecret, "key", nil, 16)
	iv := HKDFExpandLabel(SHA256, serverAppTrafficSecret, "iv", nil, 12)

	completeRecord := hexb(t, "17030300432e937e11ef4ac740e538ad36005fc4a46932fc3225d05f82aa1b36e30efaf97d90e6dffc602dcb501a59a8fcc49c4bf2e5f0a21c0047c2abf332540dd032e167c2955d")
	header := completeRecord[:5]
	ciphertext := completeRecord[5:]

	// Sequence 1, not 0: earlier in the same trace the server already sent
	// one NewSessionTicket record under these same application-traffic
	// keys (post-handshake messages use application keys in TLS 1.3), so
	// this application_data record is the second one protected by this key.
	contentType, plaintext, err := OpenTLS13Record(AES128GCM, key, iv, 1, header, ciphertext)
	if err != nil {
		t.Fatalf("OpenTLS13Record: %v", err)
	}
	if contentType != 0x17 { // application_data
		t.Errorf("contentType = %#x, want 0x17", contentType)
	}
	want := hexb(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031")
	if !bytes.Equal(plaintext, want) {
		t.Fatalf("plaintext = %x, want %x", plaintext, want)
	}
}
