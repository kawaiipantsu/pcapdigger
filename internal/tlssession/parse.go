package tlssession

import "encoding/binary"

const (
	hsClientHello       = 1
	hsServerHello       = 2
	hsCertificate       = 11
	hsServerKeyExchange = 12
	hsClientKeyExchange = 16
	hsFinished          = 20
)

const (
	extSupportedVersions    = 0x002b
	extExtendedMasterSecret = 0x0017
	extEncryptThenMAC       = 0x0016
)

// parsedClientHello holds the fields needed to resolve decryption keys.
type parsedClientHello struct {
	Random      []byte // 32 bytes
	SupportsEMS bool   // offered the extended_master_secret extension (RFC 7627)
	SupportsEtM bool   // offered the encrypt_then_mac extension (RFC 7366)
}

func parseClientHello(body []byte) (*parsedClientHello, error) {
	if len(body) < 2+32 {
		return nil, errShortBuffer
	}
	ch := &parsedClientHello{Random: append([]byte{}, body[2:34]...)}
	pos := 34
	if len(body) < pos+1 {
		return ch, nil
	}
	sessIDLen := int(body[pos])
	pos += 1 + sessIDLen
	if len(body) < pos+2 {
		return ch, nil
	}
	csLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
	pos += 2 + csLen
	if len(body) < pos+1 {
		return ch, nil
	}
	compLen := int(body[pos])
	pos += 1 + compLen
	if len(body) < pos+2 {
		return ch, nil
	}
	extTotal := int(binary.BigEndian.Uint16(body[pos : pos+2]))
	pos += 2
	end := pos + extTotal
	if end > len(body) {
		end = len(body)
	}
	for pos+4 <= end {
		extType := binary.BigEndian.Uint16(body[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(body[pos+2 : pos+4]))
		pos += 4
		if pos+extLen > end {
			break
		}
		if extType == extExtendedMasterSecret {
			ch.SupportsEMS = true
		}
		if extType == extEncryptThenMAC {
			ch.SupportsEtM = true
		}
		pos += extLen
	}
	return ch, nil
}

// parsedServerHello holds the fields needed to resolve decryption keys.
type parsedServerHello struct {
	Random      []byte // 32 bytes
	CipherSuite uint16
	Version     uint16 // effective version: legacy_version, overridden by supported_versions if present
	SupportsEMS bool   // accepted the extended_master_secret extension (RFC 7627)
	SupportsEtM bool   // accepted the encrypt_then_mac extension (RFC 7366)
}

func parseServerHello(body []byte) (*parsedServerHello, error) {
	if len(body) < 2+32+1 {
		return nil, errShortBuffer
	}
	sh := &parsedServerHello{Version: binary.BigEndian.Uint16(body[0:2])}
	sh.Random = append([]byte{}, body[2:34]...)
	pos := 34
	sessIDLen := int(body[pos])
	pos += 1 + sessIDLen
	if len(body) < pos+2 {
		return nil, errShortBuffer
	}
	sh.CipherSuite = binary.BigEndian.Uint16(body[pos : pos+2])
	pos += 2
	if len(body) < pos+1 {
		return sh, nil // no compression/extensions (shouldn't happen, but tolerate)
	}
	pos += 1 // compression method
	if len(body) < pos+2 {
		return sh, nil
	}
	extTotal := int(binary.BigEndian.Uint16(body[pos : pos+2]))
	pos += 2
	end := pos + extTotal
	if end > len(body) {
		end = len(body)
	}
	for pos+4 <= end {
		extType := binary.BigEndian.Uint16(body[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(body[pos+2 : pos+4]))
		pos += 4
		if pos+extLen > end {
			break
		}
		if extType == extSupportedVersions && extLen >= 2 {
			sh.Version = binary.BigEndian.Uint16(body[pos : pos+2])
		}
		if extType == extExtendedMasterSecret {
			sh.SupportsEMS = true
		}
		if extType == extEncryptThenMAC {
			sh.SupportsEtM = true
		}
		pos += extLen
	}
	return sh, nil
}

// clientKeyExchangeRSA extracts the RSA-encrypted premaster secret from a
// ClientKeyExchange message (RFC 5246 section 7.4.7.1): a 2-byte length
// followed by the encrypted opaque blob.
func clientKeyExchangeRSA(body []byte) ([]byte, error) {
	if len(body) < 2 {
		return nil, errShortBuffer
	}
	l := int(binary.BigEndian.Uint16(body[0:2]))
	if len(body) < 2+l {
		return nil, errShortBuffer
	}
	return body[2 : 2+l], nil
}

// clientKeyExchangePSKIdentity extracts the psk_identity from a
// ClientKeyExchange message for plain-PSK cipher suites (RFC 4279
// section 2): a 2-byte length followed by the identity bytes.
func clientKeyExchangePSKIdentity(body []byte) (string, error) {
	if len(body) < 2 {
		return "", errShortBuffer
	}
	l := int(binary.BigEndian.Uint16(body[0:2]))
	if len(body) < 2+l {
		return "", errShortBuffer
	}
	return string(body[2 : 2+l]), nil
}
