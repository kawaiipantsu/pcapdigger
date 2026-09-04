// Package tlscrypto implements the key-derivation and record-decryption
// primitives needed to decrypt captured TLS 1.2/1.3 traffic when a matching
// secret is available (an NSS-format key log entry, a static RSA private
// key, or a pre-shared key) -- never anything else. There is no attempt at
// live key exchange or forward-secret key recovery without such a secret.
package tlscrypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
)

// HashAlgo identifies the hash function backing a TLS 1.2 PRF or TLS 1.3
// HKDF instance.
type HashAlgo int

const (
	SHA256 HashAlgo = iota
	SHA384
)

func newHash(h HashAlgo) func() hash.Hash {
	if h == SHA384 {
		return sha512.New384
	}
	return sha256.New
}

// --- TLS 1.2 PRF (RFC 5246 section 5) ---

// P_hash implements the P_hash(secret, seed) data-expansion function.
func pHash(h func() hash.Hash, secret, seed []byte, length int) []byte {
	out := make([]byte, 0, length)
	a := seed
	for len(out) < length {
		mac := hmac.New(h, secret)
		mac.Write(a)
		a = mac.Sum(nil)

		mac2 := hmac.New(h, secret)
		mac2.Write(a)
		mac2.Write(seed)
		out = append(out, mac2.Sum(nil)...)
	}
	return out[:length]
}

// PRF12 implements PRF(secret, label, seed) = P_hash(secret, label+seed)
// as defined by RFC 5246 section 5, for TLS 1.2's SHA-256/SHA-384 PRF.
func PRF12(h HashAlgo, secret []byte, label string, seed []byte, length int) []byte {
	labelSeed := append([]byte(label), seed...)
	return pHash(newHash(h), secret, labelSeed, length)
}

// HashSum hashes data with the given algorithm, for computing the RFC 7627
// Extended Master Secret session_hash over a handshake transcript.
func HashSum(h HashAlgo, data []byte) []byte {
	hh := newHash(h)()
	hh.Write(data)
	return hh.Sum(nil)
}

// MasterSecret12 computes master_secret = PRF(pre_master_secret,
// "master secret", ClientHello.random + ServerHello.random)[0..47].
func MasterSecret12(h HashAlgo, preMasterSecret, clientRandom, serverRandom []byte) []byte {
	seed := append(append([]byte{}, clientRandom...), serverRandom...)
	return PRF12(h, preMasterSecret, "master secret", seed, 48)
}

// ExtendedMasterSecret12 computes master_secret = PRF(pre_master_secret,
// "extended master secret", session_hash)[0..47] per RFC 7627, used
// instead of MasterSecret12 whenever both sides negotiated the
// extended_master_secret extension -- the default in virtually every
// modern TLS 1.2 stack (OpenSSL, browsers, etc.).
func ExtendedMasterSecret12(h HashAlgo, preMasterSecret, sessionHash []byte) []byte {
	return PRF12(h, preMasterSecret, "extended master secret", sessionHash, 48)
}

// KeyBlock12 computes key_block = PRF(master_secret, "key expansion",
// server_random + client_random) truncated to length bytes.
func KeyBlock12(h HashAlgo, masterSecret, clientRandom, serverRandom []byte, length int) []byte {
	seed := append(append([]byte{}, serverRandom...), clientRandom...)
	return PRF12(h, masterSecret, "key expansion", seed, length)
}

// --- TLS 1.3 HKDF (RFC 5869, RFC 8446 section 7.1) ---

// HKDFExtract implements HKDF-Extract(salt, ikm) = HMAC-Hash(salt, ikm).
func HKDFExtract(h HashAlgo, salt, ikm []byte) []byte {
	mac := hmac.New(newHash(h), salt)
	mac.Write(ikm)
	return mac.Sum(nil)
}

// HKDFExpand implements HKDF-Expand(prk, info, length) per RFC 5869.
func HKDFExpand(h HashAlgo, prk, info []byte, length int) []byte {
	hashFn := newHash(h)
	hashLen := hashFn().Size()
	out := make([]byte, 0, length+hashLen)
	var t []byte
	counter := byte(1)
	for len(out) < length {
		mac := hmac.New(hashFn, prk)
		mac.Write(t)
		mac.Write(info)
		mac.Write([]byte{counter})
		t = mac.Sum(nil)
		out = append(out, t...)
		counter++
	}
	return out[:length]
}

// HKDFExpandLabel implements RFC 8446 section 7.1:
//
//	HkdfLabel { uint16 length; opaque label<7..255> = "tls13 "+Label;
//	            opaque context<0..255> = Context; }
//	HKDF-Expand-Label(Secret, Label, Context, Length) =
//	    HKDF-Expand(Secret, HkdfLabel, Length)
func HKDFExpandLabel(h HashAlgo, secret []byte, label string, context []byte, length int) []byte {
	fullLabel := "tls13 " + label
	info := make([]byte, 0, 2+1+len(fullLabel)+1+len(context))
	info = append(info, byte(length>>8), byte(length))
	info = append(info, byte(len(fullLabel)))
	info = append(info, fullLabel...)
	info = append(info, byte(len(context)))
	info = append(info, context...)
	return HKDFExpand(h, secret, info, length)
}

// DeriveSecret implements RFC 8446 section 7.1:
//
//	Derive-Secret(Secret, Label, Messages) =
//	    HKDF-Expand-Label(Secret, Label, Transcript-Hash(Messages), Hash.length)
func DeriveSecret(h HashAlgo, secret []byte, label string, transcriptHash []byte) []byte {
	return HKDFExpandLabel(h, secret, label, transcriptHash, newHash(h)().Size())
}
