package security

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"pcapdigger/internal/flow"
)

func newResult() *flow.Result {
	return &flow.Result{
		Hosts:        map[string]*flow.Host{},
		Flows:        map[string]*flow.Flow{},
		ProtoPackets: map[string]int{},
		ProtoBytes:   map[string]uint64{},
	}
}

func host(ip string, private bool) *flow.Host {
	return &flow.Host{IP: ip, IsPrivate: private}
}

func hasTitle(findings []Finding, substr string) bool {
	for _, f := range findings {
		if strings.Contains(f.Title, substr) {
			return true
		}
	}
	return false
}

func TestScanDetectorVertical(t *testing.T) {
	res := newResult()
	src, dst := "10.0.0.99", "10.0.0.1"
	for port := 1; port <= 20; port++ {
		res.Flows[fmt.Sprintf("TCP|scan|%d", port)] = &flow.Flow{
			Protocol: "TCP", IPA: src, IPB: dst, PortA: 50000 + port, PortB: port,
			Flags: flow.TCPFlagStats{SYN: true},
		}
	}
	findings := (&ScanDetector{}).Detect(&Context{Result: res})
	if !hasTitle(findings, "Vertical port scan") {
		t.Errorf("expected a vertical port scan finding, got %+v", findings)
	}
}

func TestScanDetectorIgnoresAnsweredSYNs(t *testing.T) {
	res := newResult()
	src, dst := "10.0.0.99", "10.0.0.1"
	for port := 1; port <= 20; port++ {
		res.Flows[fmt.Sprintf("TCP|answered|%d", port)] = &flow.Flow{
			Protocol: "TCP", IPA: src, IPB: dst, PortA: 50000 + port, PortB: port,
			Flags: flow.TCPFlagStats{SYN: true, SYNACK: true}, // handshake completed
		}
	}
	findings := (&ScanDetector{}).Detect(&Context{Result: res})
	if hasTitle(findings, "Vertical port scan") {
		t.Errorf("did not expect a scan finding for completed handshakes, got %+v", findings)
	}
}

func TestARPSpoofDetector(t *testing.T) {
	res := newResult()
	res.ARPEvents = []flow.ARPEvent{
		{Timestamp: time.Now(), SrcIP: "10.0.0.1", SrcMAC: "aa:aa:aa:aa:aa:aa"},
		{Timestamp: time.Now(), SrcIP: "10.0.0.1", SrcMAC: "bb:bb:bb:bb:bb:bb"},
	}
	findings := (&ARPSpoofDetector{}).Detect(&Context{Result: res})
	if !hasTitle(findings, "Conflicting ARP mappings") {
		t.Errorf("expected a conflicting-ARP finding, got %+v", findings)
	}
}

func TestARPSpoofDetectorNoConflict(t *testing.T) {
	res := newResult()
	res.ARPEvents = []flow.ARPEvent{
		{Timestamp: time.Now(), SrcIP: "10.0.0.1", SrcMAC: "aa:aa:aa:aa:aa:aa"},
		{Timestamp: time.Now(), SrcIP: "10.0.0.1", SrcMAC: "aa:aa:aa:aa:aa:aa"},
	}
	findings := (&ARPSpoofDetector{}).Detect(&Context{Result: res})
	if len(findings) != 0 {
		t.Errorf("expected no findings for a single consistent MAC, got %+v", findings)
	}
}

func TestCredentialDetectorSeverity(t *testing.T) {
	res := newResult()
	res.Credentials = []flow.CredentialEvent{
		{Protocol: "HTTP", Detail: "Authorization: Basic header", Username: "admin", Password: "secret", SrcIP: "1.2.3.4", DstIP: "5.6.7.8"},
		{Protocol: "TELNET", Detail: "login prompt observed", SrcIP: "1.2.3.4", DstIP: "5.6.7.8"},
	}
	findings := (&CredentialDetector{}).Detect(&Context{Result: res})
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	if findings[0].Severity != Critical {
		t.Errorf("expected Critical severity for a captured password, got %v", findings[0].Severity)
	}
	if findings[1].Severity != Medium {
		t.Errorf("expected Medium severity for a bare login prompt, got %v", findings[1].Severity)
	}
}

func TestWeakTLSDetector(t *testing.T) {
	res := newResult()
	res.Flows["f1"] = &flow.Flow{
		Protocol: "TCP", IPA: "10.0.0.1", IPB: "1.2.3.4",
		TLS: &flow.TLSInfo{Version: "TLS 1.0", SNI: "example.com"},
	}
	findings := (&WeakTLSDetector{}).Detect(&Context{Result: res})
	if !hasTitle(findings, "Legacy TLS 1.0") {
		t.Errorf("expected a legacy-TLS finding, got %+v", findings)
	}
}

func TestWeakTLSDetectorExpiredCert(t *testing.T) {
	res := newResult()
	res.Flows["f1"] = &flow.Flow{
		Protocol: "TCP", IPA: "10.0.0.1", IPB: "1.2.3.4",
		TLS: &flow.TLSInfo{Version: "TLS 1.2", Cert: &flow.CertInfo{Subject: "CN=old", Expired: true}},
	}
	findings := (&WeakTLSDetector{}).Detect(&Context{Result: res})
	if !hasTitle(findings, "Expired TLS certificate") {
		t.Errorf("expected an expired-certificate finding, got %+v", findings)
	}
}

func TestDNSAnomalyDetectorEntropy(t *testing.T) {
	res := newResult()
	labels := []string{
		"x7fQ2pL9zR4mK1vN8cT6bH3jY0wD5s.tunnel.example.com",
		"a8gR3qM0aS5nL2wO9dU7cI4kZ1xE6t.tunnel.example.com",
		"b9hS4rN1bT6oM3xP0eV8dJ5lA2yF7u.tunnel.example.com",
		"c0iT5sO2cU7pN4yQ1fW9eK6mB3zG8v.tunnel.example.com",
		"d1jU6tP3dV8qO5zR2gX0fL7nC4aH9w.tunnel.example.com",
	}
	for i, l := range labels {
		res.DNSQueries = append(res.DNSQueries, flow.DNSQuery{SrcIP: "10.0.0.5", Name: l, QType: "A", Timestamp: time.Now().Add(time.Duration(i) * time.Second)})
	}
	findings := (&DNSAnomalyDetector{}).Detect(&Context{Result: res})
	if !hasTitle(findings, "Possible DNS tunneling") {
		t.Errorf("expected a DNS tunneling finding, got %+v", findings)
	}
}

func TestDNSAnomalyDetectorNXDOMAINFlood(t *testing.T) {
	res := newResult()
	for i := 0; i < 25; i++ {
		res.DNSQueries = append(res.DNSQueries, flow.DNSQuery{SrcIP: "10.0.0.5", Name: "x.example.com", NXDomain: true})
	}
	findings := (&DNSAnomalyDetector{}).Detect(&Context{Result: res})
	if !hasTitle(findings, "Excessive NXDOMAIN") {
		t.Errorf("expected an NXDOMAIN-flood finding, got %+v", findings)
	}
}

func TestExfilDetectorAsymmetricTransfer(t *testing.T) {
	res := newResult()
	res.Hosts["10.0.0.5"] = host("10.0.0.5", true)
	res.Hosts["1.2.3.4"] = host("1.2.3.4", false)
	res.Flows["f1"] = &flow.Flow{
		Protocol: "TCP", IPA: "10.0.0.5", IPB: "1.2.3.4",
		BytesAB: 50 * 1024 * 1024, BytesBA: 1024,
	}
	findings := (&ExfilDetector{}).Detect(&Context{Result: res})
	if !hasTitle(findings, "Large asymmetric outbound transfer") {
		t.Errorf("expected an exfiltration finding, got %+v", findings)
	}
}

func TestExfilDetectorIgnoresSmallTransfer(t *testing.T) {
	res := newResult()
	res.Hosts["10.0.0.5"] = host("10.0.0.5", true)
	res.Hosts["1.2.3.4"] = host("1.2.3.4", false)
	res.Flows["f1"] = &flow.Flow{
		Protocol: "TCP", IPA: "10.0.0.5", IPB: "1.2.3.4",
		BytesAB: 1024, BytesBA: 1024,
	}
	findings := (&ExfilDetector{}).Detect(&Context{Result: res})
	if hasTitle(findings, "Large asymmetric outbound transfer") {
		t.Errorf("did not expect an exfiltration finding for a small transfer, got %+v", findings)
	}
}

func TestRiskyPortDetector(t *testing.T) {
	res := newResult()
	h := host("10.0.0.1", true)
	h.PortsOpen = []int{23, 8000}
	res.Hosts["10.0.0.1"] = h
	findings := (&RiskyPortDetector{}).Detect(&Context{Result: res})
	if !hasTitle(findings, "Telnet") {
		t.Errorf("expected a Telnet exposure finding, got %+v", findings)
	}
	for _, f := range findings {
		if strings.Contains(f.Title, "8000") {
			t.Errorf("did not expect port 8000 to be flagged as risky, got %+v", f)
		}
	}
}

func TestIOCDetector(t *testing.T) {
	res := newResult()
	res.Hosts["6.6.6.6"] = host("6.6.6.6", false)
	ctx := &Context{Result: res, IOCs: IOCSet{"6.6.6.6": "known C2 server"}}
	findings := (&IOCDetector{}).Detect(ctx)
	if len(findings) != 1 || findings[0].Severity != Critical {
		t.Fatalf("expected exactly one Critical IOC finding, got %+v", findings)
	}
}

func TestSortFindingsSeverityOrder(t *testing.T) {
	in := []Finding{{Severity: Low}, {Severity: Critical}, {Severity: Medium}, {Severity: High}, {Severity: Info}}
	sortFindings(in)
	want := []Severity{Critical, High, Medium, Low, Info}
	for i, s := range want {
		if in[i].Severity != s {
			t.Fatalf("position %d: got %v, want %v", i, in[i].Severity, s)
		}
	}
}
