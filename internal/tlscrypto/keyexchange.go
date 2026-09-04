package tlscrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"fmt"
)

// PSKPremasterSecret builds the TLS 1.2 premaster secret for the plain
// PSK, DHE_PSK, and ECDHE_PSK key-exchange families (RFC 4279 section 2):
// two-byte length of N zero bytes, N zero bytes, two-byte length of the
// PSK, then the PSK itself, where N = len(psk). RSA_PSK is not supported
// here since its "other_secret" comes from an RSA-encrypted random value
// rather than being all-zero.
func PSKPremasterSecret(psk []byte) []byte {
	n := len(psk)
	out := make([]byte, 0, 2+n+2+n)
	out = binary.BigEndian.AppendUint16(out, uint16(n))
	out = append(out, make([]byte, n)...)
	out = binary.BigEndian.AppendUint16(out, uint16(n))
	out = append(out, psk...)
	return out
}

// DecryptRSAPremaster decrypts a ClientKeyExchange RSA-encrypted premaster
// secret (RFC 5246 section 7.4.7.1) using a loaded static RSA private key.
// Passive/offline use only -- this is not constant-time and would be
// unsafe against an online Bleichenbacher oracle attack, which is not a
// concern when decrypting an already-captured file.
func DecryptRSAPremaster(priv *rsa.PrivateKey, encryptedPremaster []byte) ([]byte, error) {
	pm, err := rsa.DecryptPKCS1v15(rand.Reader, priv, encryptedPremaster)
	if err != nil {
		return nil, fmt.Errorf("rsa decrypt: %w", err)
	}
	if len(pm) != 48 {
		return nil, fmt.Errorf("decrypted premaster is %d bytes, want 48", len(pm))
	}
	return pm, nil
}

// NewCBCBlockDecrypter returns a block-decrypt function suitable for
// OpenTLS12CBCRecord, for the AES (128/256) or 3DES block ciphers.
func NewCBCBlockDecrypter(key []byte) (decrypt func(dst, src []byte), blockSize int, err error) {
	switch len(key) {
	case 16, 32:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, 0, err
		}
		return blockDecryptFunc(block), block.BlockSize(), nil
	case 24:
		block, err := des.NewTripleDESCipher(key)
		if err != nil {
			return nil, 0, err
		}
		return blockDecryptFunc(block), block.BlockSize(), nil
	default:
		return nil, 0, fmt.Errorf("unsupported CBC key length %d", len(key))
	}
}

func blockDecryptFunc(block cipher.Block) func(dst, src []byte) {
	return func(dst, src []byte) { block.Decrypt(dst, src) }
}
