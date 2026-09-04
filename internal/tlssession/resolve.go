package tlssession

import "pcapdigger/internal/tlscrypto"

// tryResolve attempts key derivation once enough handshake state is
// available. It's safe to call repeatedly; it no-ops once resolved (or
// once permanently marked unresolvable).
func (s *Session) tryResolve() {
	if s.resolved || s.unresolvable || !s.haveSuite {
		return
	}
	if s.clientRandom == nil || s.serverRandom == nil {
		return
	}

	if s.version >= 0x0304 {
		s.tryResolveTLS13()
		return
	}
	s.tryResolveTLS12()
}

func (s *Session) tryResolveTLS12() {
	if secret := s.keylogMasterSecret(); secret != nil {
		s.deriveTLS12(secret)
		s.KeySource = "keylog"
		s.finishResolve()
		return
	}

	if s.pendingCKE == nil {
		return // wait for ClientKeyExchange before trying RSA/PSK paths
	}

	if tlscrypto.IsRSAKeyExchange(s.cipherSuite) {
		encPremaster, err := clientKeyExchangeRSA(s.pendingCKE)
		if err != nil {
			s.unresolvable = true
			return
		}
		for _, key := range s.keys.RSAKeys {
			pm, err := tlscrypto.DecryptRSAPremaster(key, encPremaster)
			if err != nil {
				continue
			}
			secret := s.masterSecretFrom(pm)
			s.deriveTLS12(secret)
			s.KeySource = "rsa-key"
			s.finishResolve()
			return
		}
		s.unresolvable = true
		return
	}

	if tlscrypto.IsPSK(s.cipherSuite) {
		identity, err := clientKeyExchangePSKIdentity(s.pendingCKE)
		if err != nil {
			s.unresolvable = true
			return
		}
		psk, ok := s.keys.PSKs[identity]
		if !ok {
			s.unresolvable = true
			return
		}
		premaster := tlscrypto.PSKPremasterSecret(psk)
		secret := s.masterSecretFrom(premaster)
		s.deriveTLS12(secret)
		s.KeySource = "psk"
		s.finishResolve()
		return
	}

	// (EC)DHE without a matching key-log entry: no static secret can
	// recover this connection's traffic.
	s.unresolvable = true
}

func (s *Session) tryResolveTLS13() {
	secrets := s.keys.Keylog[clientRandomHex(s.clientRandom)]
	if secrets == nil {
		s.unresolvable = true // TLS 1.3 without a key-log entry is never recoverable here
		return
	}
	find := func(label string) []byte {
		for _, sec := range secrets {
			if sec.Label == label {
				return sec.Secret
			}
		}
		return nil
	}
	chs := find("CLIENT_HANDSHAKE_TRAFFIC_SECRET")
	shs := find("SERVER_HANDSHAKE_TRAFFIC_SECRET")
	cap0 := find("CLIENT_TRAFFIC_SECRET_0")
	sap0 := find("SERVER_TRAFFIC_SECRET_0")
	if chs == nil || shs == nil || cap0 == nil || sap0 == nil {
		s.unresolvable = true
		return
	}

	h := s.suite.PRFHash
	s.tls13.clientHSKey = tlscrypto.HKDFExpandLabel(h, chs, "key", nil, s.suite.KeyLen)
	s.tls13.clientHSIV = tlscrypto.HKDFExpandLabel(h, chs, "iv", nil, s.suite.FixedIVLen)
	s.tls13.serverHSKey = tlscrypto.HKDFExpandLabel(h, shs, "key", nil, s.suite.KeyLen)
	s.tls13.serverHSIV = tlscrypto.HKDFExpandLabel(h, shs, "iv", nil, s.suite.FixedIVLen)
	s.tls13.clientAppKey = tlscrypto.HKDFExpandLabel(h, cap0, "key", nil, s.suite.KeyLen)
	s.tls13.clientAppIV = tlscrypto.HKDFExpandLabel(h, cap0, "iv", nil, s.suite.FixedIVLen)
	s.tls13.serverAppKey = tlscrypto.HKDFExpandLabel(h, sap0, "key", nil, s.suite.KeyLen)
	s.tls13.serverAppIV = tlscrypto.HKDFExpandLabel(h, sap0, "iv", nil, s.suite.FixedIVLen)

	s.KeySource = "keylog"
	s.finishResolve()
}

// masterSecretFrom computes the TLS 1.2 master secret from a premaster
// secret, using the Extended Master Secret (RFC 7627) transcript-hash
// formula when both sides negotiated it, or the plain client||server
// random formula otherwise.
func (s *Session) masterSecretFrom(premaster []byte) []byte {
	if s.emsClient && s.emsServer && s.sessionHashAtCKE != nil {
		return tlscrypto.ExtendedMasterSecret12(s.suite.PRFHash, premaster, s.sessionHashAtCKE)
	}
	return tlscrypto.MasterSecret12(s.suite.PRFHash, premaster, s.clientRandom, s.serverRandom)
}

// keylogMasterSecret looks up a plain CLIENT_RANDOM keylog entry (TLS 1.2).
func (s *Session) keylogMasterSecret() []byte {
	for _, sec := range s.keys.Keylog[clientRandomHex(s.clientRandom)] {
		if sec.Label == "CLIENT_RANDOM" {
			return sec.Secret
		}
	}
	return nil
}

func (s *Session) deriveTLS12(masterSecret []byte) {
	macLen := s.suite.MAC.Size()
	total := 2*macLen + 2*s.suite.KeyLen + 2*s.suite.FixedIVLen
	block := tlscrypto.KeyBlock12(s.suite.PRFHash, masterSecret, s.clientRandom, s.serverRandom, total)

	pos := 0
	take := func(n int) []byte {
		b := block[pos : pos+n]
		pos += n
		return b
	}
	s.tls12.clientMACKey = take(macLen)
	s.tls12.serverMACKey = take(macLen)
	s.tls12.clientKey = take(s.suite.KeyLen)
	s.tls12.serverKey = take(s.suite.KeyLen)
	s.tls12.clientFixedIV = take(s.suite.FixedIVLen)
	s.tls12.serverFixedIV = take(s.suite.FixedIVLen)
}

func (s *Session) finishResolve() {
	s.resolved = true
	s.Decrypted = true
	s.CipherSuite = s.cipherSuite
	if s.version >= 0x0304 {
		s.TLSVersion = "TLS 1.3"
	} else {
		s.TLSVersion = "TLS 1.2"
	}
}
