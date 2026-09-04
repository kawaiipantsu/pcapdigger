package tlssession

import (
	"encoding/hex"

	"pcapdigger/internal/tlscrypto"
	"pcapdigger/internal/tlskeys"
)

// Direction identifies which side of a TCP flow sent a chunk of bytes.
type Direction int

const (
	ClientToServer Direction = iota
	ServerToClient
)

type phase int

const (
	phaseCleartext phase = iota
	phaseEncrypted12
	phaseEncryptedHandshake13
	phaseEncryptedApp13
)

type dirState struct {
	recvBuf  []byte // raw bytes not yet formed into complete records
	hsBuf    []byte // cleartext handshake-message reassembly (ClientHello/ServerHello, and TLS1.2's full flow up to CCS)
	decHSBuf []byte // TLS1.3 only: decrypted handshake-phase bytes, to find Finished
	phase    phase
	seq      uint64
}

// Plaintext is one chunk of recovered application data.
type Plaintext struct {
	Direction Direction
	Data      []byte
}

// Session reconstructs one TLS connection from its two reassembled byte
// streams and decrypts whatever it can once matching keys are found.
type Session struct {
	keys *tlskeys.Store

	clientRandom []byte
	serverRandom []byte
	cipherSuite  uint16
	version      uint16
	suite        tlscrypto.Suite
	haveSuite    bool

	pendingCKE []byte // raw ClientKeyExchange body, interpreted once cipherSuite is known

	// Extended Master Secret (RFC 7627) support: transcript accumulates
	// every cleartext handshake message (ClientHello through
	// ClientKeyExchange, across both directions, in true chronological
	// order) so its hash can replace plain client||server random in the
	// master-secret PRF when both sides negotiated the extension --
	// which is the default for virtually every modern TLS 1.2 stack.
	// Irrelevant when a key-log entry supplies the master secret directly.
	transcript           []byte
	emsClient, emsServer bool
	sessionHashAtCKE     []byte // snapshot of Hash(transcript) taken when ClientKeyExchange completes it

	// Encrypt-then-MAC (RFC 7366): if both sides negotiated it, TLS 1.2
	// CBC records are framed as IV+ciphertext+MAC (MAC over the wire
	// bytes) instead of the classic MAC-then-encrypt layout. This is the
	// default in modern OpenSSL for CBC suites, so it's common in
	// practice, not a rare edge case.
	etmClient, etmServer bool

	resolved     bool
	unresolvable bool // sticky: we tried and there's no usable secret

	tls12 tls12Keys
	tls13 tls13Keys

	dirs [2]dirState

	// Decrypted bool and a short summary are exposed for reporting even
	// when the caller doesn't care about the actual plaintext.
	Decrypted   bool
	KeySource   string // "keylog", "rsa-key", "psk", or "" if never resolved
	TLSVersion  string
	CipherSuite uint16
}

type tls12Keys struct {
	clientKey, serverKey         []byte
	clientFixedIV, serverFixedIV []byte
	clientMACKey, serverMACKey   []byte
}

type tls13Keys struct {
	clientHSKey, serverHSKey   []byte
	clientHSIV, serverHSIV     []byte
	clientAppKey, serverAppKey []byte
	clientAppIV, serverAppIV   []byte
}

// New creates a Session that will try to resolve keys from keys.
func New(keys *tlskeys.Store) *Session {
	return &Session{keys: keys}
}

// Feed appends newly-reassembled bytes for one direction and returns any
// application data recovered as a result.
func (s *Session) Feed(dir Direction, data []byte) []Plaintext {
	d := &s.dirs[dir]
	d.recvBuf = append(d.recvBuf, data...)

	recs, consumed := extractRecords(d.recvBuf)
	d.recvBuf = d.recvBuf[consumed:]

	var out []Plaintext
	for _, r := range recs {
		out = append(out, s.processRecord(dir, r)...)
	}
	return out
}

func (s *Session) processRecord(dir Direction, r record) []Plaintext {
	d := &s.dirs[dir]

	switch {
	case r.Type == recChangeCipherSpec:
		// Meaningful only for TLS 1.2 (in 1.3 it's a no-op sent purely for
		// middlebox compatibility and MUST be ignored).
		if s.version != 0 && s.version < 0x0304 {
			d.phase = phaseEncrypted12
			d.seq = 0
		}
		return nil

	case r.Type == recHandshake && d.phase == phaseCleartext:
		d.hsBuf = append(d.hsBuf, r.Body...)
		return s.drainCleartextHandshake(dir)

	case d.phase == phaseCleartext:
		// ApplicationData (or anything else) before any encryption is
		// established shouldn't happen; nothing useful to do with it.
		return nil

	default:
		return s.decryptRecord(dir, r)
	}
}

// drainCleartextHandshake extracts and dispatches complete handshake
// messages accumulated in dirs[dir].hsBuf.
func (s *Session) drainCleartextHandshake(dir Direction) []Plaintext {
	d := &s.dirs[dir]
	msgs, consumed := extractHandshakeMessages(d.hsBuf)
	d.hsBuf = d.hsBuf[consumed:]
	for _, m := range msgs {
		s.transcript = append(s.transcript, m.Raw...)
		switch m.Type {
		case hsClientHello:
			if ch, err := parseClientHello(m.Body); err == nil {
				s.clientRandom = ch.Random
				s.emsClient = ch.SupportsEMS
				s.etmClient = ch.SupportsEtM
			}
		case hsServerHello:
			if sh, err := parseServerHello(m.Body); err == nil {
				s.serverRandom = sh.Random
				s.cipherSuite = sh.CipherSuite
				s.version = sh.Version
				s.emsServer = sh.SupportsEMS
				s.etmServer = sh.SupportsEtM
				if suite, ok := tlscrypto.Suites[sh.CipherSuite]; ok {
					s.suite = suite
					s.haveSuite = true
				}
				if s.version >= 0x0304 {
					// From here on, everything both sides send is
					// disguised as application_data on the wire.
					s.dirs[ClientToServer].phase = phaseEncryptedHandshake13
					s.dirs[ServerToClient].phase = phaseEncryptedHandshake13
				}
				s.tryResolve()
			}
		case hsClientKeyExchange:
			s.pendingCKE = append([]byte{}, m.Body...)
			if s.haveSuite {
				s.sessionHashAtCKE = tlscrypto.HashSum(s.suite.PRFHash, s.transcript)
			}
			s.tryResolve()
		}
	}
	return nil
}

func clientRandomHex(b []byte) string { return hex.EncodeToString(b) }

// useEncryptThenMAC reports whether both sides negotiated RFC 7366.
func (s *Session) useEncryptThenMAC() bool { return s.etmClient && s.etmServer }
