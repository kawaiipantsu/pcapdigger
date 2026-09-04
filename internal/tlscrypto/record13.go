package tlscrypto

import (
	"errors"
)

// OpenTLS13Record decrypts one TLS 1.3 record. header must be the exact
// 5-byte on-wire record header (type=0x17, version, ciphertext length),
// which doubles as the AEAD associated data per RFC 8446 section 5.2.
// ciphertext is the record body (encrypted content + inner padding +
// content-type byte, followed by the AEAD tag). Returns the real inner
// content type and the unpadded content.
func OpenTLS13Record(algo AEADAlgo, key, writeIV []byte, seq uint64, header, ciphertext []byte) (contentType byte, plaintext []byte, err error) {
	aead, err := NewAEAD(algo, key)
	if err != nil {
		return 0, nil, err
	}
	nonce := Nonce12(writeIV, seq)
	inner, err := aead.Open(nil, nonce, ciphertext, header)
	if err != nil {
		return 0, nil, err
	}
	// TLSInnerPlaintext = content || ContentType || zeros*; the real type
	// is the last non-zero byte.
	i := len(inner) - 1
	for i >= 0 && inner[i] == 0 {
		i--
	}
	if i < 0 {
		return 0, nil, errors.New("tls13: inner plaintext has no content type byte")
	}
	return inner[i], inner[:i], nil
}
