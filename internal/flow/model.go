// Package flow builds a host inventory and a bidirectional conversation
// (flow) table from a decoded packet stream, in a single pass. It also
// collects a handful of lightweight side-signals (ARP events, DNS queries,
// cleartext credentials, malformed-packet events) that the security
// detectors need but that don't belong in the flow/host aggregates.
package flow

import (
	"crypto/x509"
	"math"
	"time"
)

// Host is a network endpoint (by IP) observed in the capture.
type Host struct {
	IP         string
	MACs       []string
	Hostnames  []string // from DNS answers, TLS SNI, HTTP Host header
	IsPrivate  bool
	BytesOut   uint64
	BytesIn    uint64
	PacketsOut uint64
	PacketsIn  uint64
	PortsOpen  []int // distinct destination ports this host was contacted on (i.e. likely services)
	FirstSeen  time.Time
	LastSeen   time.Time

	macSet  map[string]bool
	hostSet map[string]bool
	portSet map[int]bool
}

// TLSInfo holds what was recoverable from a flow's TLS handshake.
type TLSInfo struct {
	Version      string
	SNI          string
	CipherSuites []uint16
	WeakCipher   bool
	Cert         *CertInfo
}

// CertInfo summarizes a parsed X.509 server certificate.
type CertInfo struct {
	Subject     string
	Issuer      string
	NotBefore   time.Time
	NotAfter    time.Time
	SelfSigned  bool
	DNSNames    []string
	SNIMismatch bool
	Expired     bool
	NotYetValid bool
	Raw         *x509.Certificate
}

// TCPFlagStats tallies which TCP flag combinations were observed on a flow.
type TCPFlagStats struct {
	SYN, SYNACK, RST, FIN, PSH, NullScan, FINScan, XMASScan bool
}

// Flow is a bidirectional 5-tuple conversation, keyed canonically so that
// A->B and B->A packets land in the same record.
type Flow struct {
	Key       string
	Protocol  string // "TCP", "UDP", "ICMP", "ICMPv6", "ARP", "OTHER"
	AppProto  string // best-effort guess: HTTP, TLS, DNS, SSH, FTP, TELNET, SMTP, POP3, IMAP, ""
	IPA, IPB  string // IPA initiated the flow (first packet's source)
	PortA     int
	PortB     int
	PacketsAB uint64 // A -> B
	PacketsBA uint64 // B -> A
	BytesAB   uint64
	BytesBA   uint64
	FirstSeen time.Time
	LastSeen  time.Time
	Flags     TCPFlagStats
	TLS       *TLSInfo

	// Beaconing/periodicity support: Welford's online mean/variance of
	// inter-arrival times between A->B packets, kept O(1) in memory.
	iaCount int
	iaMean  float64
	iaM2    float64
	lastAB  time.Time
}

// IntervalStats returns the count, mean and coefficient of variation of
// inter-arrival times between A->B packets (low CoV ~ periodic/beacon-like).
func (f *Flow) IntervalStats() (count int, meanSeconds, coeffOfVariation float64) {
	if f.iaCount < 2 {
		return f.iaCount, 0, 0
	}
	variance := f.iaM2 / float64(f.iaCount-1)
	stddev := math.Sqrt(variance)
	cov := 0.0
	if f.iaMean > 0 {
		cov = stddev / f.iaMean
	}
	return f.iaCount, f.iaMean, cov
}

func (f *Flow) observeInterval(t time.Time) {
	if !f.lastAB.IsZero() {
		d := t.Sub(f.lastAB).Seconds()
		if d > 0 {
			f.iaCount++
			delta := d - f.iaMean
			f.iaMean += delta / float64(f.iaCount)
			delta2 := d - f.iaMean
			f.iaM2 += delta * delta2
		}
	}
	f.lastAB = t
}

// ARPEvent records a single ARP packet for spoofing/sweep detection.
type ARPEvent struct {
	Timestamp    time.Time
	SrcIP        string
	SrcMAC       string
	DstIP        string
	Operation    string // "request" or "reply"
	IsGratuitous bool
}

// DNSQuery records one DNS question/answer pair for anomaly detection.
type DNSQuery struct {
	Timestamp time.Time
	SrcIP     string
	DstIP     string
	Name      string
	QType     string
	RCode     string
	NXDomain  bool
	AnswerLen int // for detecting oversized TXT/exfil-style answers
}

// CredentialEvent pairs a recovered plaintext credential with its context.
type CredentialEvent struct {
	Timestamp time.Time
	SrcIP     string
	DstIP     string
	DstPort   int
	Protocol  string
	Detail    string
	Username  string
	Password  string
}

// MalformedEvent records a packet that violated basic protocol expectations.
type MalformedEvent struct {
	Timestamp time.Time
	SrcIP     string
	DstIP     string
	Reason    string
}

// Meta holds capture-wide metadata.
type Meta struct {
	FileName     string
	LinkType     string
	FirstPacket  time.Time
	LastPacket   time.Time
	TotalPackets int
	TotalBytes   uint64
}

// Result is the complete output of a single pass over a capture file.
type Result struct {
	Meta        Meta
	Hosts       map[string]*Host
	Flows       map[string]*Flow
	ARPEvents   []ARPEvent
	DNSQueries  []DNSQuery
	Credentials []CredentialEvent
	Malformed   []MalformedEvent

	// Link/network-layer protocol mix, keyed by protocol name (ARP, TCP,
	// UDP, ICMP, ICMPv6, OTHER), independent of the flow table (which only
	// covers IP-based conversations).
	ProtoPackets map[string]int
	ProtoBytes   map[string]uint64
}
