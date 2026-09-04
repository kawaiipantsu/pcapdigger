package flow

import (
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"pcapdigger/internal/pcapdata"
	"pcapdigger/internal/proto"
)

// Builder consumes a decoded packet stream and produces a Result.
type Builder struct {
	res *Result

	// pendingNames holds hostnames learned (via DNS answers, TLS SNI, or
	// HTTP Host headers) for an IP before that IP's Host record exists yet
	// -- the common case for DNS, since resolution happens before any
	// packet reaches the resolved address. Applied whenever host() is
	// called for that IP, regardless of processing order.
	pendingNames map[string]map[string]bool
}

// New creates a Builder for a capture with the given file name/link type.
func New(fileName, linkType string) *Builder {
	return &Builder{
		res: &Result{
			Meta:         Meta{FileName: fileName, LinkType: linkType},
			Hosts:        make(map[string]*Host),
			Flows:        make(map[string]*Flow),
			ProtoPackets: make(map[string]int),
			ProtoBytes:   make(map[string]uint64),
		},
		pendingNames: make(map[string]map[string]bool),
	}
}

// Add processes one packet, folding it into the running Result.
func (b *Builder) Add(pkt pcapdata.Packet) {
	r := b.res
	ts := pkt.Info.Timestamp
	if r.Meta.TotalPackets == 0 || ts.Before(r.Meta.FirstPacket) {
		r.Meta.FirstPacket = ts
	}
	if ts.After(r.Meta.LastPacket) {
		r.Meta.LastPacket = ts
	}
	r.Meta.TotalPackets++
	r.Meta.TotalBytes += uint64(pkt.Info.Length)

	p := pkt.Data

	if errLayer := p.ErrorLayer(); errLayer != nil {
		b.recordMalformed(ts, p, errLayer.Error().Error())
	}
	if pkt.Info.CaptureLength < pkt.Info.Length {
		b.recordMalformed(ts, p, "packet truncated by capture snaplen")
	}

	var srcMAC, dstMAC string
	if eth, ok := p.Layer(layers.LayerTypeEthernet).(*layers.Ethernet); ok {
		srcMAC, dstMAC = eth.SrcMAC.String(), eth.DstMAC.String()
	}

	if arp, ok := p.Layer(layers.LayerTypeARP).(*layers.ARP); ok {
		b.handleARP(ts, arp, srcMAC, dstMAC)
	}

	srcIP, dstIP, ipProto := extractIPs(p)
	plen := uint64(pkt.Info.Length)
	b.tallyProtoMix(p, ipProto, plen)
	if srcIP == "" || dstIP == "" {
		return // no IP layer (pure ARP/other link-layer only packet)
	}

	sHost := b.host(srcIP, srcMAC, ts)
	dHost := b.host(dstIP, dstMAC, ts)
	sHost.BytesOut += plen
	sHost.PacketsOut++
	dHost.BytesIn += plen
	dHost.PacketsIn++

	var srcPort, dstPort int
	var payload []byte
	var flagBits string

	switch ipProto {
	case "TCP":
		if tcp, ok := p.Layer(layers.LayerTypeTCP).(*layers.TCP); ok {
			srcPort, dstPort = int(tcp.SrcPort), int(tcp.DstPort)
			payload = tcp.Payload
			flagBits = tcpFlagString(tcp)
		}
	case "UDP":
		if udp, ok := p.Layer(layers.LayerTypeUDP).(*layers.UDP); ok {
			srcPort, dstPort = int(udp.SrcPort), int(udp.DstPort)
			payload = udp.Payload
		}
	}

	fl, isNewFlow := b.flow(ipProto, srcIP, dstIP, srcPort, dstPort, ts)
	if isNewFlow {
		// Attribute the contacted port to whichever side is actually the
		// server, based on the very first captured packet of this flow --
		// doing this unconditionally on every packet would also record the
		// client's own ephemeral port as "open" on every reply it
		// receives, which is not a port it exposes at all.
		switch {
		case ipProto == "TCP" && flagBits == "SA":
			// This flow's first captured packet is a SYN-ACK, meaning the
			// connection's SYN predates the capture window and the real
			// server is the current packet's source, not destination.
			sHost.addPort(srcPort)
		case ipProto == "TCP" && flagBits != "S":
			// Neither a SYN nor a SYN-ACK: the handshake wasn't captured
			// at all, so which side is the server is unknown -- skip
			// rather than guess.
		default:
			dHost.addPort(dstPort)
		}
	}
	b.updateFlow(fl, srcIP, ts, plen, flagBits)

	if ipProto == "TCP" && len(payload) > 0 {
		b.inspectTCPPayload(fl, sHost, dHost, srcIP, dstIP, srcPort, dstPort, ts, payload)
	}
	if ipProto == "UDP" && len(payload) > 0 && (srcPort == 53 || dstPort == 53) {
		b.inspectDNS(srcIP, dstIP, ts, payload, sHost, dHost)
	}
}

// Result returns the finished aggregation. Call after all Add calls.
func (b *Builder) Result() *Result {
	for _, h := range b.res.Hosts {
		h.MACs = setToSlice(h.macSet)
		h.Hostnames = setToSlice(h.hostSet)
		for p := range h.portSet {
			h.PortsOpen = append(h.PortsOpen, p)
		}
	}
	return b.res
}

func (b *Builder) host(ip, mac string, ts time.Time) *Host {
	h, ok := b.res.Hosts[ip]
	if !ok {
		h = &Host{
			IP:        ip,
			IsPrivate: isPrivate(net.ParseIP(ip)),
			FirstSeen: ts,
			LastSeen:  ts,
			macSet:    map[string]bool{},
			hostSet:   map[string]bool{},
			portSet:   map[int]bool{},
		}
		b.res.Hosts[ip] = h
	}
	if ts.Before(h.FirstSeen) {
		h.FirstSeen = ts
	}
	if ts.After(h.LastSeen) {
		h.LastSeen = ts
	}
	if mac != "" {
		h.macSet[mac] = true
	}
	for name := range b.pendingNames[ip] {
		h.hostSet[name] = true
	}
	return h
}

func (h *Host) addHostname(name string) {
	if name != "" {
		h.hostSet[name] = true
	}
}

// addHostnameFor records a learned hostname for ip: applied immediately if
// that Host already exists, and also remembered in pendingNames so it is
// still applied if the Host record is created later (the common case for
// DNS resolution, which precedes any packet to the resolved address).
func (b *Builder) addHostnameFor(ip, name string) {
	if ip == "" || name == "" {
		return
	}
	if h, ok := b.res.Hosts[ip]; ok {
		h.addHostname(name)
	}
	if b.pendingNames[ip] == nil {
		b.pendingNames[ip] = map[string]bool{}
	}
	b.pendingNames[ip][name] = true
}

func (h *Host) addPort(p int) {
	if p > 0 {
		h.portSet[p] = true
	}
}

func (b *Builder) flow(proto_, ipA, ipB string, portA, portB int, ts time.Time) (*Flow, bool) {
	key := flowKey(proto_, ipA, ipB, portA, portB)
	fl, ok := b.res.Flows[key]
	if !ok {
		fl = &Flow{
			Key:       key,
			Protocol:  proto_,
			AppProto:  guessAppProto(proto_, portA, portB),
			IPA:       ipA,
			IPB:       ipB,
			PortA:     portA,
			PortB:     portB,
			FirstSeen: ts,
			LastSeen:  ts,
		}
		b.res.Flows[key] = fl
		return fl, true
	}
	if ts.After(fl.LastSeen) {
		fl.LastSeen = ts
	}
	return fl, false
}

func (b *Builder) updateFlow(fl *Flow, srcIP string, ts time.Time, plen uint64, flagBits string) {
	if srcIP == fl.IPA {
		fl.PacketsAB++
		fl.BytesAB += plen
		fl.observeInterval(ts)
	} else {
		fl.PacketsBA++
		fl.BytesBA += plen
	}
	applyFlags(&fl.Flags, flagBits)
}

func (b *Builder) handleARP(ts time.Time, arp *layers.ARP, srcMAC, dstMAC string) {
	srcIP := net.IP(arp.SourceProtAddress).String()
	dstIP := net.IP(arp.DstProtAddress).String()
	op := "request"
	if arp.Operation == layers.ARPReply {
		op = "reply"
	}
	b.res.ARPEvents = append(b.res.ARPEvents, ARPEvent{
		Timestamp:    ts,
		SrcIP:        srcIP,
		SrcMAC:       srcMAC,
		DstIP:        dstIP,
		Operation:    op,
		IsGratuitous: srcIP == dstIP,
	})
	_ = dstMAC
}

func (b *Builder) inspectDNS(srcIP, dstIP string, ts time.Time, payload []byte, sHost, dHost *Host) {
	dnsPkt := gopacket.NewPacket(payload, layers.LayerTypeDNS, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
	dns, ok := dnsPkt.Layer(layers.LayerTypeDNS).(*layers.DNS)
	if !ok || len(dns.Questions) == 0 {
		return
	}
	q := dns.Questions[0]
	if !dns.QR {
		// This is the query, not the response: nothing more to learn from
		// it (no RCode/answers yet), and recording it here too would
		// double-count every exchange in DNS anomaly detection. The
		// response (below) carries the same question plus the outcome.
		return
	}
	rcode := dns.ResponseCode.String()
	nx := dns.ResponseCode == layers.DNSResponseCodeNXDomain
	answerLen := 0
	for _, a := range dns.Answers {
		answerLen += len(a.Data)
		if ip := answerIP(a); ip != "" {
			b.addHostnameFor(ip, string(q.Name))
		}
	}
	// srcIP/dstIP here are the response packet's (server -> client)
	// direction; DNSQuery.SrcIP is documented (and used by every detector)
	// as the querying client, so swap them back.
	b.res.DNSQueries = append(b.res.DNSQueries, DNSQuery{
		Timestamp: ts, SrcIP: dstIP, DstIP: srcIP,
		Name: string(q.Name), QType: q.Type.String(), RCode: rcode, NXDomain: nx, AnswerLen: answerLen,
	})
	_ = sHost
	_ = dHost
}

func answerIP(a layers.DNSResourceRecord) string {
	if a.IP != nil {
		return a.IP.String()
	}
	return ""
}

func (b *Builder) inspectTCPPayload(fl *Flow, sHost, dHost *Host, srcIP, dstIP string, srcPort, dstPort int, ts time.Time, payload []byte) {
	// TLS: sniff regardless of port, since TLS on non-443 ports is common.
	if len(payload) > 5 && payload[0] == 0x16 {
		if ch, err := proto.ParseClientHello(payload); err == nil {
			fl.TLS = &TLSInfo{Version: ch.Version.String(), SNI: ch.SNI, CipherSuites: ch.CipherSuites}
			for _, cs := range ch.CipherSuites {
				if _, weak := proto.WeakCipherSuites[cs]; weak {
					fl.TLS.WeakCipher = true
				}
			}
			if ch.SNI != "" {
				dHost.addHostname(ch.SNI)
			}
		} else if certs, err := proto.ParseServerCertificates(payload); err == nil && len(certs.Certs) > 0 {
			cert := certs.Certs[0]
			ci := &CertInfo{
				Subject: cert.Subject.String(), Issuer: cert.Issuer.String(),
				NotBefore: cert.NotBefore, NotAfter: cert.NotAfter,
				DNSNames: cert.DNSNames, Raw: cert,
			}
			ci.SelfSigned = cert.Subject.String() == cert.Issuer.String()
			ci.Expired = ts.After(cert.NotAfter)
			ci.NotYetValid = ts.Before(cert.NotBefore)
			if fl.TLS == nil {
				fl.TLS = &TLSInfo{}
			}
			if fl.TLS.SNI != "" {
				ci.SNIMismatch = !certMatchesName(cert, fl.TLS.SNI)
			}
			fl.TLS.Cert = ci
		}
	}

	switch {
	case dstPort == 80 || srcPort == 80:
		creds, host := proto.ScanHTTPCleartext(payload)
		if host != "" {
			dHost.addHostname(host)
		}
		b.recordCreds(ts, srcIP, dstIP, dstPort, creds)
	case dstPort == 21 || srcPort == 21:
		if c := proto.ScanFTP(string(payload)); c != nil {
			b.recordCreds(ts, srcIP, dstIP, dstPort, []proto.PlaintextCredential{*c})
		}
	case dstPort == 23 || srcPort == 23:
		if c := proto.ScanTelnetLogin(payload); c != nil {
			b.recordCreds(ts, srcIP, dstIP, dstPort, []proto.PlaintextCredential{*c})
		}
	case dstPort == 110 || srcPort == 110:
		if c := proto.ScanMailLogin("POP3", string(payload)); c != nil {
			b.recordCreds(ts, srcIP, dstIP, dstPort, []proto.PlaintextCredential{*c})
		}
	case dstPort == 143 || srcPort == 143:
		if c := proto.ScanMailLogin("IMAP", string(payload)); c != nil {
			b.recordCreds(ts, srcIP, dstIP, dstPort, []proto.PlaintextCredential{*c})
		}
	}
}

func certMatchesName(cert interface{ VerifyHostname(string) error }, name string) bool {
	return cert.VerifyHostname(name) == nil
}

func (b *Builder) recordCreds(ts time.Time, srcIP, dstIP string, dstPort int, creds []proto.PlaintextCredential) {
	for _, c := range creds {
		b.res.Credentials = append(b.res.Credentials, CredentialEvent{
			Timestamp: ts, SrcIP: srcIP, DstIP: dstIP, DstPort: dstPort,
			Protocol: c.Protocol, Detail: c.Detail, Username: c.Username, Password: c.Password,
		})
	}
}

func (b *Builder) recordMalformed(ts time.Time, p gopacket.Packet, reason string) {
	var src, dst string
	if nl := p.NetworkLayer(); nl != nil {
		f := nl.NetworkFlow()
		src, dst = f.Src().String(), f.Dst().String()
	}
	b.res.Malformed = append(b.res.Malformed, MalformedEvent{Timestamp: ts, SrcIP: src, DstIP: dst, Reason: reason})
}

func (b *Builder) tallyProtoMix(p gopacket.Packet, ipProto string, plen uint64) {
	name := ipProto
	if name == "" {
		switch {
		case p.Layer(layers.LayerTypeARP) != nil:
			name = "ARP"
		default:
			name = "OTHER"
		}
	}
	b.res.ProtoPackets[name]++
	b.res.ProtoBytes[name] += plen
}

func extractIPs(p gopacket.Packet) (src, dst, proto_ string) {
	if ip4, ok := p.Layer(layers.LayerTypeIPv4).(*layers.IPv4); ok {
		return ip4.SrcIP.String(), ip4.DstIP.String(), transportProto(p)
	}
	if ip6, ok := p.Layer(layers.LayerTypeIPv6).(*layers.IPv6); ok {
		return ip6.SrcIP.String(), ip6.DstIP.String(), transportProto(p)
	}
	return "", "", ""
}

func transportProto(p gopacket.Packet) string {
	switch {
	case p.Layer(layers.LayerTypeTCP) != nil:
		return "TCP"
	case p.Layer(layers.LayerTypeUDP) != nil:
		return "UDP"
	case p.Layer(layers.LayerTypeICMPv4) != nil:
		return "ICMP"
	case p.Layer(layers.LayerTypeICMPv6) != nil:
		return "ICMPv6"
	default:
		return "OTHER"
	}
}

func guessAppProto(proto_ string, portA, portB int) string {
	byPort := map[int]string{
		20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
		53: "DNS", 80: "HTTP", 110: "POP3", 123: "NTP", 143: "IMAP",
		443: "TLS", 445: "SMB", 465: "SMTPS", 587: "SMTP", 993: "IMAPS",
		995: "POP3S", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
	}
	if proto_ == "ICMP" || proto_ == "ICMPv6" {
		return proto_
	}
	if name, ok := byPort[portA]; ok {
		return name
	}
	if name, ok := byPort[portB]; ok {
		return name
	}
	return ""
}

func flowKey(proto_, ipA, ipB string, portA, portB int) string {
	// Canonical, direction-independent key so both packet directions of a
	// conversation map to the same Flow.
	a := endpoint{ipA, portA}
	c := endpoint{ipB, portB}
	if a.String() <= c.String() {
		return proto_ + "|" + a.String() + "|" + c.String()
	}
	return proto_ + "|" + c.String() + "|" + a.String()
}

type endpoint struct {
	ip   string
	port int
}

func (e endpoint) String() string {
	return e.ip + ":" + itoa(e.port)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [12]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

func tcpFlagString(tcp *layers.TCP) string {
	s := ""
	if tcp.SYN {
		s += "S"
	}
	if tcp.ACK {
		s += "A"
	}
	if tcp.FIN {
		s += "F"
	}
	if tcp.RST {
		s += "R"
	}
	if tcp.PSH {
		s += "P"
	}
	if tcp.URG {
		s += "U"
	}
	if s == "" {
		s = "N" // NULL scan: no flags set at all
	}
	return s
}

func applyFlags(fs *TCPFlagStats, bits string) {
	if bits == "" {
		return
	}
	switch bits {
	case "S":
		fs.SYN = true
	case "SA":
		fs.SYNACK = true
	case "N":
		fs.NullScan = true
	case "F":
		fs.FINScan = true
	case "FPU":
		fs.XMASScan = true
	}
	if contains(bits, 'R') {
		fs.RST = true
	}
	if contains(bits, 'F') {
		fs.FIN = true
	}
	if contains(bits, 'P') {
		fs.PSH = true
	}
}

func contains(s string, c byte) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return true
		}
	}
	return false
}

func isPrivate(ip net.IP) bool {
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast()
}

func setToSlice(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
