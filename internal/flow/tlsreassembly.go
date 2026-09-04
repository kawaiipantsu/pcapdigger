package flow

import (
	"time"

	"github.com/google/gopacket/layers"

	"pcapdigger/internal/proto"
	"pcapdigger/internal/tlskeys"
	"pcapdigger/internal/tlssession"
)

// maxPendingReassemblyBytes bounds how much out-of-order data a single
// TCP direction will buffer before giving up on reassembling that
// connection -- a defensive cap against pathological/crafted captures.
const maxPendingReassemblyBytes = 1 << 20 // 1 MiB

// EnableTLSDecryption turns on best-effort TLS decryption using the given
// key store (NSS keylog / RSA private keys / PSK entries). Without this
// call, TCP payloads that look like TLS are simply skipped, exactly as
// before -- no reassembly work happens unless a key store is supplied.
func (b *Builder) EnableTLSDecryption(keys *tlskeys.Store) {
	if keys == nil || keys.Empty() {
		return
	}
	b.tlsKeys = keys
	b.tlsConns = make(map[string]*tlsConnState)
}

type tlsConnState struct {
	session   *tlssession.Session
	flow      *Flow
	dirs      [2]reassemblyBuf
	abandoned bool
}

type reassemblyBuf struct {
	started      bool
	nextSeq      uint32
	pending      map[uint32][]byte
	pendingBytes int
}

// feedTLS reassembles one TCP segment into its connection's byte stream
// and, once in-order bytes are available, hands them to the TLS session.
// Only ever called for flows whose first observed payload byte was 0x16
// (a TLS handshake record) -- see maybeStartTLS.
func (b *Builder) feedTLS(fl *Flow, srcIP string, tcp *layers.TCP, ts time.Time) {
	conn := b.tlsConns[fl.Key]
	if conn == nil || conn.abandoned {
		return
	}

	dir := tlssession.ClientToServer
	if !fl.IsSideA(srcIP, int(tcp.SrcPort)) {
		dir = tlssession.ServerToClient
	}
	buf := &conn.dirs[dir]
	if !buf.started {
		buf.started = true
		buf.nextSeq = uint32(tcp.Seq)
		buf.pending = map[uint32][]byte{}
	}

	seq := uint32(tcp.Seq)
	payload := tcp.Payload
	if len(payload) == 0 {
		return
	}

	// Signed 32-bit difference correctly handles sequence-number wraparound.
	switch diff := int32(seq - buf.nextSeq); {
	case diff > 0:
		// Out of order / a gap: buffer it, bounded.
		if buf.pendingBytes+len(payload) > maxPendingReassemblyBytes {
			conn.abandoned = true
			return
		}
		buf.pending[seq] = append([]byte{}, payload...)
		buf.pendingBytes += len(payload)
		return
	case diff < 0:
		// Fully- or partially-retransmitted data already consumed.
		overlap := int(-diff)
		if overlap >= len(payload) {
			return
		}
		payload = payload[overlap:]
		seq = buf.nextSeq
	}

	b.advanceTLS(conn, dir, buf, seq, payload, ts)
}

func (b *Builder) advanceTLS(conn *tlsConnState, dir tlssession.Direction, buf *reassemblyBuf, seq uint32, payload []byte, ts time.Time) {
	for {
		buf.nextSeq = seq + uint32(len(payload))
		for _, pt := range conn.session.Feed(dir, payload) {
			b.consumeTLSPlaintext(conn, pt, ts)
		}
		next, ok := buf.pending[buf.nextSeq]
		if !ok {
			return
		}
		delete(buf.pending, buf.nextSeq)
		buf.pendingBytes -= len(next)
		seq, payload = buf.nextSeq, next
	}
}

// consumeTLSPlaintext runs the same cleartext scanning (credentials, HTTP
// Host header) on recovered plaintext that already runs on genuinely
// cleartext TCP payloads, and marks the flow as decrypted.
func (b *Builder) consumeTLSPlaintext(conn *tlsConnState, pt tlssession.Plaintext, ts time.Time) {
	fl := conn.flow
	if fl.TLS == nil {
		fl.TLS = &TLSInfo{}
	}
	fl.TLS.Decrypted = true
	fl.TLS.KeySource = conn.session.KeySource
	if fl.TLS.Version == "" {
		fl.TLS.Version = conn.session.TLSVersion
	}

	srcIP, dstIP := fl.IPA, fl.IPB
	dstPort := fl.PortB
	if pt.Direction == tlssession.ServerToClient {
		srcIP, dstIP = fl.IPB, fl.IPA
		dstPort = fl.PortA
	}
	creds, host := proto.ScanHTTPCleartext(pt.Data)
	if host != "" {
		if h, ok := b.res.Hosts[dstIP]; ok {
			h.addHostname(host)
		}
	}
	b.recordCreds(ts, srcIP, dstIP, dstPort, creds)
}

// maybeStartTLS begins tracking a flow for TLS decryption the first time
// its initiator's payload looks like a TLS ClientHello record (type 0x16).
// Called once per new flow's first TCP payload, from Add().
func (b *Builder) maybeStartTLS(fl *Flow, srcIP string, srcPort int, payload []byte) {
	if b.tlsKeys == nil || !fl.IsSideA(srcIP, srcPort) || len(payload) == 0 || payload[0] != 0x16 {
		return
	}
	if _, exists := b.tlsConns[fl.Key]; exists {
		return
	}
	b.tlsConns[fl.Key] = &tlsConnState{
		session: tlssession.New(b.tlsKeys),
		flow:    fl,
	}
}
