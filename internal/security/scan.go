package security

import (
	"fmt"
	"sort"
)

const (
	verticalScanThreshold   = 15 // distinct ports on one host from one source
	horizontalScanThreshold = 15 // distinct hosts on one port from one source
	icmpSweepThreshold      = 10 // distinct hosts pinged by one source
)

// ScanDetector flags TCP port scans (vertical/horizontal) and ICMP sweeps.
type ScanDetector struct{}

func (d *ScanDetector) Name() string { return "port-host-scan" }

func (d *ScanDetector) Detect(ctx *Context) []Finding {
	var findings []Finding

	// half-open (SYN seen, no SYN-ACK) TCP attempts, grouped by source.
	byDstPerSrc := map[string]map[string]map[int]bool{}  // srcIP -> dstIP -> ports
	byPortPerSrc := map[string]map[int]map[string]bool{} // srcIP -> port -> dstIPs

	for _, fl := range ctx.Result.Flows {
		if fl.Protocol != "TCP" || !fl.Flags.SYN || fl.Flags.SYNACK {
			continue
		}
		src, dst, port := fl.IPA, fl.IPB, fl.PortB
		if byDstPerSrc[src] == nil {
			byDstPerSrc[src] = map[string]map[int]bool{}
		}
		if byDstPerSrc[src][dst] == nil {
			byDstPerSrc[src][dst] = map[int]bool{}
		}
		byDstPerSrc[src][dst][port] = true

		if byPortPerSrc[src] == nil {
			byPortPerSrc[src] = map[int]map[string]bool{}
		}
		if byPortPerSrc[src][port] == nil {
			byPortPerSrc[src][port] = map[string]bool{}
		}
		byPortPerSrc[src][port][dst] = true
	}

	for src, dsts := range byDstPerSrc {
		for dst, ports := range dsts {
			if len(ports) >= verticalScanThreshold {
				findings = append(findings, Finding{
					Severity:       High,
					Category:       "Reconnaissance",
					Title:          fmt.Sprintf("Vertical port scan from %s to %s", src, dst),
					Description:    fmt.Sprintf("%s sent unanswered SYNs to %d distinct ports on %s, consistent with a port scan.", src, len(ports), dst),
					Recommendation: "Investigate the source host; block or rate-limit scanning sources at the perimeter/firewall.",
					Evidence:       []string{fmt.Sprintf("%d distinct destination ports probed, e.g. %v", len(ports), samplePorts(ports, 10))},
					Hosts:          []string{src, dst},
				})
			}
		}
	}

	for src, ports := range byPortPerSrc {
		for port, dsts := range ports {
			if len(dsts) >= horizontalScanThreshold {
				findings = append(findings, Finding{
					Severity:       High,
					Category:       "Reconnaissance",
					Title:          fmt.Sprintf("Horizontal network scan from %s on port %d", src, port),
					Description:    fmt.Sprintf("%s sent unanswered SYNs to port %d on %d distinct hosts, consistent with a network sweep for that service.", src, port, len(dsts)),
					Recommendation: "Investigate the source host for compromise; segment/limit lateral scanning ability.",
					Evidence:       []string{fmt.Sprintf("%d distinct destination hosts probed on port %d", len(dsts), port)},
					Hosts:          []string{src},
				})
			}
		}
	}

	// ICMP sweeps.
	icmpDsts := map[string]map[string]bool{}
	for _, fl := range ctx.Result.Flows {
		if fl.Protocol != "ICMP" && fl.Protocol != "ICMPv6" {
			continue
		}
		if icmpDsts[fl.IPA] == nil {
			icmpDsts[fl.IPA] = map[string]bool{}
		}
		icmpDsts[fl.IPA][fl.IPB] = true
	}
	for src, dsts := range icmpDsts {
		if len(dsts) >= icmpSweepThreshold {
			findings = append(findings, Finding{
				Severity:       Medium,
				Category:       "Reconnaissance",
				Title:          fmt.Sprintf("ICMP ping sweep from %s", src),
				Description:    fmt.Sprintf("%s sent ICMP echo requests to %d distinct hosts, consistent with host discovery (ping sweep).", src, len(dsts)),
				Recommendation: "Confirm this is authorized network discovery; otherwise investigate the source host.",
				Evidence:       []string{fmt.Sprintf("%d distinct destination hosts", len(dsts))},
				Hosts:          []string{src},
			})
		}
	}

	return findings
}

func samplePorts(m map[int]bool, n int) []int {
	out := make([]int, 0, len(m))
	for p := range m {
		out = append(out, p)
	}
	sort.Ints(out)
	if len(out) > n {
		out = out[:n]
	}
	return out
}
