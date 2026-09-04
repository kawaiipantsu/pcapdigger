package tlssession

import "pcapdigger/internal/tlscrypto"

// decryptRecord decrypts one already-past-handshake record (TLS 1.2 post
// ChangeCipherSpec, or TLS 1.3 anything after ServerHello) and returns any
// application data it yields.
func (s *Session) decryptRecord(dir Direction, r record) []Plaintext {
	if !s.resolved {
		return nil // no usable secret; nothing more we can do with this record
	}
	d := &s.dirs[dir]

	switch d.phase {
	case phaseEncrypted12:
		return s.decryptTLS12(dir, d, r)
	case phaseEncryptedHandshake13, phaseEncryptedApp13:
		return s.decryptTLS13(dir, d, r)
	default:
		return nil
	}
}

func (s *Session) decryptTLS12(dir Direction, d *dirState, r record) []Plaintext {
	var key, macKey []byte
	var fixedIV [4]byte
	var fixedIVFull []byte
	if dir == ClientToServer {
		key, macKey = s.tls12.clientKey, s.tls12.clientMACKey
		fixedIVFull = s.tls12.clientFixedIV
	} else {
		key, macKey = s.tls12.serverKey, s.tls12.serverMACKey
		fixedIVFull = s.tls12.serverFixedIV
	}
	if len(fixedIVFull) >= 4 {
		copy(fixedIV[:], fixedIVFull[:4])
	}

	seq := d.seq
	d.seq++

	var plain []byte
	var err error
	switch s.suite.Kind {
	case tlscrypto.KindGCMExplicit:
		plain, err = tlscrypto.OpenTLS12AEADRecordGCM(s.suite.AEAD, key, fixedIV, seq, r.Type, r.Version, r.Body)
	case tlscrypto.KindAEADImplicit:
		plain, err = tlscrypto.OpenTLS12AEADRecordImplicit(s.suite.AEAD, key, fixedIVFull, seq, r.Type, r.Version, r.Body)
	case tlscrypto.KindCBC:
		blockDecrypt, blockSize, derr := tlscrypto.NewCBCBlockDecrypter(key)
		if derr != nil {
			return nil
		}
		if s.useEncryptThenMAC() {
			plain, err = tlscrypto.OpenTLS12CBCRecordEtM(blockDecrypt, blockSize, s.suite.MAC, macKey, seq, r.Type, r.Version, r.Body)
		} else {
			plain, err = tlscrypto.OpenTLS12CBCRecord(blockDecrypt, blockSize, s.suite.MAC, macKey, seq, r.Type, r.Version, r.Body)
		}
	default:
		return nil
	}
	if err != nil {
		return nil
	}
	if r.Type != recApplicationData {
		return nil // encrypted Finished/Alert: nothing to surface
	}
	return []Plaintext{{Direction: dir, Data: plain}}
}

func (s *Session) decryptTLS13(dir Direction, d *dirState, r record) []Plaintext {
	if r.Type != recApplicationData {
		return nil // TLS 1.3 disguises everything encrypted as this type
	}

	handshakePhase := d.phase == phaseEncryptedHandshake13
	var key, iv []byte
	if handshakePhase {
		if dir == ClientToServer {
			key, iv = s.tls13.clientHSKey, s.tls13.clientHSIV
		} else {
			key, iv = s.tls13.serverHSKey, s.tls13.serverHSIV
		}
	} else {
		if dir == ClientToServer {
			key, iv = s.tls13.clientAppKey, s.tls13.clientAppIV
		} else {
			key, iv = s.tls13.serverAppKey, s.tls13.serverAppIV
		}
	}

	seq := d.seq
	d.seq++
	contentType, plain, err := tlscrypto.OpenTLS13Record(s.suite.AEAD, key, iv, seq, r.Header[:], r.Body)
	if err != nil {
		return nil
	}

	if !handshakePhase {
		if contentType == recApplicationData {
			return []Plaintext{{Direction: dir, Data: plain}}
		}
		return nil // Alert or a post-handshake NewSessionTicket/KeyUpdate: nothing to surface
	}

	// Still in the handshake-secret phase: accumulate and look for this
	// direction's Finished message, which marks the switch to the
	// application traffic key (with sequence reset to 0).
	d.decHSBuf = append(d.decHSBuf, plain...)
	msgs, consumed := extractHandshakeMessages(d.decHSBuf)
	d.decHSBuf = d.decHSBuf[consumed:]
	for _, m := range msgs {
		if m.Type == hsFinished {
			d.phase = phaseEncryptedApp13
			d.seq = 0
			d.decHSBuf = nil
			break
		}
	}
	return nil
}
