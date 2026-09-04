package tlscrypto

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
)

// MACAlgo identifies the HMAC hash backing a TLS 1.2 CBC cipher suite.
type MACAlgo int

const (
	MACNone MACAlgo = iota
	MACMD5
	MACSHA1
	MACSHA256
	MACSHA384
)

func (m MACAlgo) Size() int {
	switch m {
	case MACMD5:
		return 16
	case MACSHA1:
		return 20
	case MACSHA256:
		return 32
	case MACSHA384:
		return 48
	default:
		return 0
	}
}

func (m MACAlgo) newHash() func() hash.Hash {
	switch m {
	case MACMD5:
		return md5.New
	case MACSHA1:
		return sha1.New
	case MACSHA256:
		return sha256.New
	case MACSHA384:
		return sha512.New384
	default:
		return nil
	}
}

// aeadAdditionalData12 builds additional_data = seq_num(8) + type(1) +
// version(2) + length(2), per RFC 5246 section 6.2.3.3, where length is
// the plaintext (TLSCompressed) length.
func aeadAdditionalData12(seq uint64, recordType byte, version uint16, plaintextLen int) []byte {
	ad := make([]byte, 13)
	binary.BigEndian.PutUint64(ad[0:8], seq)
	ad[8] = recordType
	binary.BigEndian.PutUint16(ad[9:11], version)
	binary.BigEndian.PutUint16(ad[11:13], uint16(plaintextLen))
	return ad
}

// OpenTLS12AEADRecordGCM decrypts a TLS 1.2 AES-GCM record (RFC 5288): the
// record body is an 8-byte explicit nonce followed by the AEAD-protected
// content. fixedIV is the 4-byte client/server_write_IV from the key block.
func OpenTLS12AEADRecordGCM(algo AEADAlgo, key []byte, fixedIV [4]byte, seq uint64, recordType byte, version uint16, body []byte) ([]byte, error) {
	if len(body) < 8 {
		return nil, errors.New("tls12 gcm: record body too short for explicit nonce")
	}
	var explicit [8]byte
	copy(explicit[:], body[:8])
	ciphertext := body[8:]

	aead, err := NewAEAD(algo, key)
	if err != nil {
		return nil, err
	}
	nonce := NonceGCM12(fixedIV, explicit)
	plaintextLen := len(ciphertext) - aead.Overhead()
	if plaintextLen < 0 {
		return nil, errors.New("tls12 gcm: ciphertext shorter than AEAD tag")
	}
	aad := aeadAdditionalData12(seq, recordType, version, plaintextLen)
	return aead.Open(nil, nonce, ciphertext, aad)
}

// OpenTLS12AEADRecordImplicit decrypts a TLS 1.2 AEAD record that uses a
// fully-implicit nonce (ChaCha20-Poly1305, RFC 7905): writeIV is the full
// 12-byte fixed IV, XORed with the sequence number exactly as in TLS 1.3.
func OpenTLS12AEADRecordImplicit(algo AEADAlgo, key, writeIV []byte, seq uint64, recordType byte, version uint16, ciphertext []byte) ([]byte, error) {
	aead, err := NewAEAD(algo, key)
	if err != nil {
		return nil, err
	}
	nonce := Nonce12(writeIV, seq)
	plaintextLen := len(ciphertext) - aead.Overhead()
	if plaintextLen < 0 {
		return nil, errors.New("tls12 aead: ciphertext shorter than AEAD tag")
	}
	aad := aeadAdditionalData12(seq, recordType, version, plaintextLen)
	return aead.Open(nil, nonce, ciphertext, aad)
}

// OpenTLS12CBCRecord decrypts a TLS 1.2/1.1/1.0 CBC-mode record: an
// explicit IV (block-sized, TLS 1.1+) or implicit IV (TLS 1.0) followed by
// the encrypted (content + HMAC + padding), verifies the HMAC, and strips
// the padding. blockDecrypter must already be keyed for this direction.
func OpenTLS12CBCRecord(blockDecrypt func(dst, src []byte), blockSize int, macAlgo MACAlgo, macKey []byte, seq uint64, recordType byte, version uint16, body []byte) ([]byte, error) {
	if len(body) < blockSize || len(body)%blockSize != 0 {
		return nil, errors.New("tls12 cbc: record body not a multiple of the block size")
	}
	explicitIV := body[:blockSize]
	ciphertext := body[blockSize:]
	if len(ciphertext) == 0 {
		return nil, errors.New("tls12 cbc: no ciphertext after IV")
	}

	plain := make([]byte, len(ciphertext))
	cbcDecrypt(blockDecrypt, blockSize, explicitIV, ciphertext, plain)

	macSize := macAlgo.Size()
	if len(plain) < 1 {
		return nil, errors.New("tls12 cbc: empty decrypted block")
	}
	padLen := int(plain[len(plain)-1])
	if padLen+1 > len(plain) || len(plain)-padLen-1 < macSize {
		return nil, errors.New("tls12 cbc: invalid padding length")
	}
	content := plain[:len(plain)-padLen-1-macSize]
	gotMAC := plain[len(plain)-padLen-1-macSize : len(plain)-padLen-1]

	mac := hmac.New(macAlgo.newHash(), macKey)
	ad := make([]byte, 13)
	binary.BigEndian.PutUint64(ad[0:8], seq)
	ad[8] = recordType
	binary.BigEndian.PutUint16(ad[9:11], version)
	binary.BigEndian.PutUint16(ad[11:13], uint16(len(content)))
	mac.Write(ad)
	mac.Write(content)
	wantMAC := mac.Sum(nil)
	if !hmac.Equal(gotMAC, wantMAC) {
		return nil, fmt.Errorf("tls12 cbc: MAC mismatch")
	}
	return content, nil
}

// OpenTLS12CBCRecordEtM decrypts a TLS 1.2/1.1 CBC-mode record protected
// with Encrypt-then-MAC (RFC 7366): body is [explicit IV][AES-CBC
// ciphertext][MAC], where the MAC covers seq_num+type+version+length(of
// IV+ciphertext)+IV+ciphertext -- i.e. it authenticates the wire bytes
// before decryption, rather than the plaintext. The MAC is verified
// before any decryption is attempted.
func OpenTLS12CBCRecordEtM(blockDecrypt func(dst, src []byte), blockSize int, macAlgo MACAlgo, macKey []byte, seq uint64, recordType byte, version uint16, body []byte) ([]byte, error) {
	macSize := macAlgo.Size()
	if len(body) < macSize {
		return nil, errors.New("tls12 cbc/etm: record body shorter than the MAC")
	}
	protected := body[:len(body)-macSize] // IV + ciphertext
	gotMAC := body[len(body)-macSize:]

	mac := hmac.New(macAlgo.newHash(), macKey)
	ad := make([]byte, 13)
	binary.BigEndian.PutUint64(ad[0:8], seq)
	ad[8] = recordType
	binary.BigEndian.PutUint16(ad[9:11], version)
	binary.BigEndian.PutUint16(ad[11:13], uint16(len(protected)))
	mac.Write(ad)
	mac.Write(protected)
	if !hmac.Equal(gotMAC, mac.Sum(nil)) {
		return nil, fmt.Errorf("tls12 cbc/etm: MAC mismatch")
	}

	if len(protected) < blockSize || len(protected)%blockSize != 0 {
		return nil, errors.New("tls12 cbc/etm: protected region not a multiple of the block size")
	}
	explicitIV := protected[:blockSize]
	ciphertext := protected[blockSize:]
	if len(ciphertext) == 0 {
		return nil, errors.New("tls12 cbc/etm: no ciphertext after IV")
	}

	plain := make([]byte, len(ciphertext))
	cbcDecrypt(blockDecrypt, blockSize, explicitIV, ciphertext, plain)

	if len(plain) < 1 {
		return nil, errors.New("tls12 cbc/etm: empty decrypted block")
	}
	padLen := int(plain[len(plain)-1])
	if padLen+1 > len(plain) {
		return nil, errors.New("tls12 cbc/etm: invalid padding length")
	}
	return plain[:len(plain)-padLen-1], nil
}

// cbcDecrypt performs plain CBC-mode decryption (dst may alias src's
// tail): for each block, plaintext[i] = Decrypt(ciphertext[i]) XOR prev,
// where prev starts as the IV and becomes ciphertext[i-1] thereafter.
func cbcDecrypt(blockDecrypt func(dst, src []byte), blockSize int, iv, ciphertext, dst []byte) {
	prev := iv
	buf := make([]byte, blockSize)
	for off := 0; off < len(ciphertext); off += blockSize {
		block := ciphertext[off : off+blockSize]
		blockDecrypt(buf, block)
		for i := 0; i < blockSize; i++ {
			dst[off+i] = buf[i] ^ prev[i]
		}
		prev = block
	}
}
