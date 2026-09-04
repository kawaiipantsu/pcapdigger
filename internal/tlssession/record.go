// Package tlssession reconstructs a single TLS connection from a
// reassembled bidirectional TCP byte stream, resolves its keys (from an
// NSS key-log entry, a static RSA private key, or a pre-shared key), and
// decrypts application data. It never attempts key recovery without one
// of those three explicit secrets.
package tlssession

import "errors"

// record is one complete TLS record extracted from the wire.
type record struct {
	Type    byte
	Version uint16
	Header  [5]byte // the raw 5-byte record header, needed as AEAD AAD
	Body    []byte  // record payload: cleartext content, or ciphertext
}

const (
	recChangeCipherSpec = 20
	recAlert            = 21
	recHandshake        = 22
	recApplicationData  = 23
)

// extractRecords pulls as many complete records as are available from the
// front of buf, returning them plus the number of bytes consumed. Bytes
// after the last complete record are left for the next call.
func extractRecords(buf []byte) (recs []record, consumed int) {
	for {
		if len(buf)-consumed < 5 {
			return recs, consumed
		}
		hdr := buf[consumed : consumed+5]
		length := int(hdr[3])<<8 | int(hdr[4])
		if len(buf)-consumed < 5+length {
			return recs, consumed
		}
		r := record{Type: hdr[0], Version: uint16(hdr[1])<<8 | uint16(hdr[2])}
		copy(r.Header[:], hdr)
		r.Body = buf[consumed+5 : consumed+5+length]
		recs = append(recs, r)
		consumed += 5 + length
	}
}

// handshakeMsg is one complete handshake-protocol message (type + body),
// which may have been split across one or more records/decrypted chunks.
// Raw is the full message including its 4-byte header, needed verbatim
// when building the Extended Master Secret transcript hash (RFC 7627).
type handshakeMsg struct {
	Type byte
	Body []byte
	Raw  []byte
}

// extractHandshakeMessages pulls as many complete handshake messages as
// available from the front of buf (4-byte header: type + 3-byte length),
// returning them plus bytes consumed.
func extractHandshakeMessages(buf []byte) (msgs []handshakeMsg, consumed int) {
	for {
		if len(buf)-consumed < 4 {
			return msgs, consumed
		}
		hdr := buf[consumed : consumed+4]
		length := int(hdr[1])<<16 | int(hdr[2])<<8 | int(hdr[3])
		if len(buf)-consumed < 4+length {
			return msgs, consumed
		}
		msgs = append(msgs, handshakeMsg{
			Type: hdr[0],
			Body: buf[consumed+4 : consumed+4+length],
			Raw:  buf[consumed : consumed+4+length],
		})
		consumed += 4 + length
	}
}

var errShortBuffer = errors.New("tlssession: buffer too short")
