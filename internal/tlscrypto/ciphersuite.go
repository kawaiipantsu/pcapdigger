package tlscrypto

// Kind identifies which record-decryption path a cipher suite needs.
type Kind int

const (
	KindTLS13        Kind = iota // fully implicit nonce, TLS 1.3 record framing
	KindGCMExplicit              // TLS 1.2 GCM: 4-byte fixed IV + 8-byte on-wire nonce
	KindAEADImplicit             // TLS 1.2 ChaCha20-Poly1305: 12-byte fixed IV, no on-wire nonce
	KindCBC                      // TLS 1.2/1.1/1.0 CBC + HMAC
)

// Suite describes everything needed to derive keys and decrypt records
// for one cipher suite, once a master/traffic secret is available. Suite
// says nothing about the key-exchange method (RSA/DHE/ECDHE/PSK): that
// only matters for how the secret itself is obtained (keylog, RSA
// decrypt, or PSK), not for record decryption.
type Suite struct {
	Kind       Kind
	AEAD       AEADAlgo // meaningful for KindTLS13/KindGCMExplicit/KindAEADImplicit
	KeyLen     int
	FixedIVLen int      // 4 for GCM-explicit, 12 for implicit/TLS1.3
	BlockSize  int      // meaningful for KindCBC (16 AES, 8 3DES)
	MAC        MACAlgo  // meaningful for KindCBC
	PRFHash    HashAlgo // TLS 1.2 PRF / TLS 1.3 HKDF hash for this suite
}

// Suites maps a cipher suite's two-byte wire ID to its Suite description.
// This deliberately covers the common, still-seen-in-the-wild suites
// rather than the full IANA registry (obsolete export/anonymous/NULL
// suites, and ones using algorithms without a Go stdlib implementation,
// are intentionally omitted).
var Suites = map[uint16]Suite{
	// TLS 1.3.
	0x1301: {Kind: KindTLS13, AEAD: AES128GCM, KeyLen: 16, FixedIVLen: 12, PRFHash: SHA256},
	0x1302: {Kind: KindTLS13, AEAD: AES256GCM, KeyLen: 32, FixedIVLen: 12, PRFHash: SHA384},
	0x1303: {Kind: KindTLS13, AEAD: ChaCha20Poly1305, KeyLen: 32, FixedIVLen: 12, PRFHash: SHA256},

	// TLS 1.2 AES-GCM (RSA/DHE/ECDHE, RSA or ECDSA auth -- key exchange
	// doesn't affect record decryption once the master secret is known).
	0x009C: {Kind: KindGCMExplicit, AEAD: AES128GCM, KeyLen: 16, FixedIVLen: 4, PRFHash: SHA256}, // RSA_AES128GCM_SHA256
	0x009D: {Kind: KindGCMExplicit, AEAD: AES256GCM, KeyLen: 32, FixedIVLen: 4, PRFHash: SHA384}, // RSA_AES256GCM_SHA384
	0x009E: {Kind: KindGCMExplicit, AEAD: AES128GCM, KeyLen: 16, FixedIVLen: 4, PRFHash: SHA256}, // DHE_RSA_AES128GCM_SHA256
	0x009F: {Kind: KindGCMExplicit, AEAD: AES256GCM, KeyLen: 32, FixedIVLen: 4, PRFHash: SHA384}, // DHE_RSA_AES256GCM_SHA384
	0xC02B: {Kind: KindGCMExplicit, AEAD: AES128GCM, KeyLen: 16, FixedIVLen: 4, PRFHash: SHA256}, // ECDHE_ECDSA_AES128GCM_SHA256
	0xC02C: {Kind: KindGCMExplicit, AEAD: AES256GCM, KeyLen: 32, FixedIVLen: 4, PRFHash: SHA384}, // ECDHE_ECDSA_AES256GCM_SHA384
	0xC02F: {Kind: KindGCMExplicit, AEAD: AES128GCM, KeyLen: 16, FixedIVLen: 4, PRFHash: SHA256}, // ECDHE_RSA_AES128GCM_SHA256
	0xC030: {Kind: KindGCMExplicit, AEAD: AES256GCM, KeyLen: 32, FixedIVLen: 4, PRFHash: SHA384}, // ECDHE_RSA_AES256GCM_SHA384

	// TLS 1.2 PSK-family AES-GCM (RFC 5487/8442).
	0x00A8: {Kind: KindGCMExplicit, AEAD: AES128GCM, KeyLen: 16, FixedIVLen: 4, PRFHash: SHA256}, // PSK_AES128GCM_SHA256
	0x00A9: {Kind: KindGCMExplicit, AEAD: AES256GCM, KeyLen: 32, FixedIVLen: 4, PRFHash: SHA384}, // PSK_AES256GCM_SHA384
	0x00AA: {Kind: KindGCMExplicit, AEAD: AES128GCM, KeyLen: 16, FixedIVLen: 4, PRFHash: SHA256}, // DHE_PSK_AES128GCM_SHA256
	0x00AB: {Kind: KindGCMExplicit, AEAD: AES256GCM, KeyLen: 32, FixedIVLen: 4, PRFHash: SHA384}, // DHE_PSK_AES256GCM_SHA384
	0x00AC: {Kind: KindGCMExplicit, AEAD: AES128GCM, KeyLen: 16, FixedIVLen: 4, PRFHash: SHA256}, // RSA_PSK_AES128GCM_SHA256
	0x00AD: {Kind: KindGCMExplicit, AEAD: AES256GCM, KeyLen: 32, FixedIVLen: 4, PRFHash: SHA384}, // RSA_PSK_AES256GCM_SHA384

	// TLS 1.2 ChaCha20-Poly1305 (RFC 7905): fully implicit nonce.
	0xCCA8: {Kind: KindAEADImplicit, AEAD: ChaCha20Poly1305, KeyLen: 32, FixedIVLen: 12, PRFHash: SHA256}, // ECDHE_RSA
	0xCCA9: {Kind: KindAEADImplicit, AEAD: ChaCha20Poly1305, KeyLen: 32, FixedIVLen: 12, PRFHash: SHA256}, // ECDHE_ECDSA
	0xCCAA: {Kind: KindAEADImplicit, AEAD: ChaCha20Poly1305, KeyLen: 32, FixedIVLen: 12, PRFHash: SHA256}, // DHE_RSA
	0xCCAB: {Kind: KindAEADImplicit, AEAD: ChaCha20Poly1305, KeyLen: 32, FixedIVLen: 12, PRFHash: SHA256}, // PSK
	0xCCAC: {Kind: KindAEADImplicit, AEAD: ChaCha20Poly1305, KeyLen: 32, FixedIVLen: 12, PRFHash: SHA256}, // ECDHE_PSK
	0xCCAD: {Kind: KindAEADImplicit, AEAD: ChaCha20Poly1305, KeyLen: 32, FixedIVLen: 12, PRFHash: SHA256}, // DHE_PSK
	0xCCAE: {Kind: KindAEADImplicit, AEAD: ChaCha20Poly1305, KeyLen: 32, FixedIVLen: 12, PRFHash: SHA256}, // RSA_PSK

	// TLS 1.2 CBC, SHA-256/384 PRF (RFC 5246/5289).
	0x003C: {Kind: KindCBC, KeyLen: 16, BlockSize: 16, MAC: MACSHA256, PRFHash: SHA256}, // RSA_AES128_CBC_SHA256
	0x003D: {Kind: KindCBC, KeyLen: 32, BlockSize: 16, MAC: MACSHA256, PRFHash: SHA256}, // RSA_AES256_CBC_SHA256
	0xC027: {Kind: KindCBC, KeyLen: 16, BlockSize: 16, MAC: MACSHA256, PRFHash: SHA256}, // ECDHE_RSA_AES128_CBC_SHA256
	0xC028: {Kind: KindCBC, KeyLen: 32, BlockSize: 16, MAC: MACSHA384, PRFHash: SHA384}, // ECDHE_RSA_AES256_CBC_SHA384

	// TLS 1.2/1.1/1.0 CBC, legacy SHA-1 MAC, PRF is always SHA-256 once
	// TLS 1.2 is negotiated (RFC 5246 section 5) regardless of suite name.
	0x002F: {Kind: KindCBC, KeyLen: 16, BlockSize: 16, MAC: MACSHA1, PRFHash: SHA256}, // RSA_AES128_CBC_SHA
	0x0035: {Kind: KindCBC, KeyLen: 32, BlockSize: 16, MAC: MACSHA1, PRFHash: SHA256}, // RSA_AES256_CBC_SHA
	0xC013: {Kind: KindCBC, KeyLen: 16, BlockSize: 16, MAC: MACSHA1, PRFHash: SHA256}, // ECDHE_RSA_AES128_CBC_SHA
	0xC014: {Kind: KindCBC, KeyLen: 32, BlockSize: 16, MAC: MACSHA1, PRFHash: SHA256}, // ECDHE_RSA_AES256_CBC_SHA
	0x000A: {Kind: KindCBC, KeyLen: 24, BlockSize: 8, MAC: MACSHA1, PRFHash: SHA256},  // RSA_3DES_EDE_CBC_SHA
	0x008C: {Kind: KindCBC, KeyLen: 16, BlockSize: 16, MAC: MACSHA1, PRFHash: SHA256}, // PSK_AES128_CBC_SHA
	0x008D: {Kind: KindCBC, KeyLen: 32, BlockSize: 16, MAC: MACSHA1, PRFHash: SHA256}, // PSK_AES256_CBC_SHA
	0x0090: {Kind: KindCBC, KeyLen: 16, BlockSize: 16, MAC: MACSHA1, PRFHash: SHA256}, // DHE_PSK_AES128_CBC_SHA
	0x0091: {Kind: KindCBC, KeyLen: 32, BlockSize: 16, MAC: MACSHA1, PRFHash: SHA256}, // DHE_PSK_AES256_CBC_SHA
	0x0094: {Kind: KindCBC, KeyLen: 16, BlockSize: 16, MAC: MACSHA1, PRFHash: SHA256}, // RSA_PSK_AES128_CBC_SHA
	0x0095: {Kind: KindCBC, KeyLen: 32, BlockSize: 16, MAC: MACSHA1, PRFHash: SHA256}, // RSA_PSK_AES256_CBC_SHA
	0xC035: {Kind: KindCBC, KeyLen: 16, BlockSize: 16, MAC: MACSHA1, PRFHash: SHA256}, // ECDHE_PSK_AES128_CBC_SHA
	0xC036: {Kind: KindCBC, KeyLen: 32, BlockSize: 16, MAC: MACSHA1, PRFHash: SHA256}, // ECDHE_PSK_AES256_CBC_SHA
}

// IsPSK reports whether suiteID is one of the PSK-family key-exchange
// suites (plain PSK, DHE_PSK, ECDHE_PSK, or RSA_PSK), which all need a
// pre-shared key (rather than a certificate private key) to compute the
// premaster/master secret when no key-log entry is available.
func IsPSK(suiteID uint16) bool {
	switch suiteID {
	case 0x00A8, 0x00A9, 0x00AA, 0x00AB, 0x00AC, 0x00AD,
		0xCCAB, 0xCCAC, 0xCCAD, 0xCCAE,
		0x008C, 0x008D, 0x0090, 0x0091, 0x0094, 0x0095, 0xC035, 0xC036:
		return true
	default:
		return false
	}
}

// IsRSAKeyExchange reports whether suiteID uses plain RSA key transport
// (ClientKeyExchange carries an RSA-encrypted premaster secret directly),
// as opposed to (EC)DHE or a PSK-based exchange.
func IsRSAKeyExchange(suiteID uint16) bool {
	switch suiteID {
	case 0x009C, 0x009D, 0x002F, 0x0035, 0x003C, 0x003D, 0x000A:
		return true
	default:
		return false
	}
}
