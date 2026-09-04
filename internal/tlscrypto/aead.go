package tlscrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// AEADAlgo identifies a bulk AEAD cipher usable by TLS 1.2/1.3.
type AEADAlgo int

const (
	AES128GCM AEADAlgo = iota
	AES256GCM
	ChaCha20Poly1305
)

// NewAEAD constructs the AEAD cipher for the given algorithm and key.
func NewAEAD(algo AEADAlgo, key []byte) (cipher.AEAD, error) {
	switch algo {
	case AES128GCM, AES256GCM:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("aes key: %w", err)
		}
		return cipher.NewGCM(block)
	case ChaCha20Poly1305:
		return chacha20poly1305.New(key)
	default:
		return nil, fmt.Errorf("unsupported AEAD algo %d", algo)
	}
}

// Nonce12 builds the 12-byte per-record nonce used by both TLS 1.3 and by
// TLS 1.2's ChaCha20-Poly1305 (RFC 7905): the 12-byte write IV XORed with
// the 64-bit sequence number, right-aligned and big-endian.
func Nonce12(writeIV []byte, seq uint64) []byte {
	nonce := make([]byte, 12)
	copy(nonce, writeIV)
	var seqBytes [8]byte
	binary.BigEndian.PutUint64(seqBytes[:], seq)
	for i := 0; i < 8; i++ {
		nonce[4+i] ^= seqBytes[i]
	}
	return nonce
}

// NonceGCM12 builds the 12-byte nonce used by TLS 1.2 AES-GCM (RFC 5288):
// a 4-byte fixed IV (client/server_write_IV) concatenated with an 8-byte
// explicit nonce that is carried on the wire in each record.
func NonceGCM12(fixedIV [4]byte, explicitNonce [8]byte) []byte {
	nonce := make([]byte, 12)
	copy(nonce[:4], fixedIV[:])
	copy(nonce[4:], explicitNonce[:])
	return nonce
}
