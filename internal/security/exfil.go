package security

import "fmt"

const (
	exfilMinBytes       = 10 * 1024 * 1024 // 10 MiB
	exfilAsymmetryRatio = 10.0
	exfilDNSAnswerBytes = 512
	icmpCovertAvgBytes  = 100 // normal echo payload is ~56-64 bytes
)

// ExfilDetector flags asymmetric large outbound transfers to external
// hosts, oversized DNS answers, and oversized ICMP payloads — all common
// covert-channel / data-exfiltration heuristics.
type ExfilDetector struct{}

func (d *ExfilDetector) Name() string { return "data-exfiltration" }

func (d *ExfilDetector) Detect(ctx *Context) []Finding {
	var findings []Finding

	for _, fl := range ctx.Result.Flows {
		hostA, hostB := ctx.Result.Hosts[fl.IPA], ctx.Result.Hosts[fl.IPB]
		if hostA == nil || hostB == nil {
			continue
		}
		// Outbound: A is internal, B is external, A sent much more than it received.
		if hostA.IsPrivate && !hostB.IsPrivate && fl.BytesAB >= exfilMinBytes {
			ratio := float64(fl.BytesAB) / float64(maxU64(fl.BytesBA, 1))
			if ratio >= exfilAsymmetryRatio {
				findings = append(findings, Finding{
					Severity:       High,
					Category:       "Data Exfiltration",
					Title:          fmt.Sprintf("Large asymmetric outbound transfer from %s to %s", fl.IPA, fl.IPB),
					Description:    fmt.Sprintf("%s sent %s to external host %s while receiving only %s back (ratio %.0fx), consistent with bulk data exfiltration.", fl.IPA, humanBytes(fl.BytesAB), fl.IPB, humanBytes(fl.BytesBA), ratio),
					Recommendation: "Review what data was transferred and whether it was authorized; consider DLP/egress monitoring for this host.",
					Evidence:       []string{fmt.Sprintf("bytes out: %d, bytes in: %d", fl.BytesAB, fl.BytesBA)},
					Hosts:          []string{fl.IPA, fl.IPB},
					FirstSeen:      fl.FirstSeen, LastSeen: fl.LastSeen,
				})
			}
		}
		if fl.Protocol == "ICMP" || fl.Protocol == "ICMPv6" {
			total := fl.PacketsAB + fl.PacketsBA
			if total > 0 {
				avg := float64(fl.BytesAB+fl.BytesBA) / float64(total)
				if avg > icmpCovertAvgBytes {
					findings = append(findings, Finding{
						Severity:       Medium,
						Category:       "Covert Channel",
						Title:          fmt.Sprintf("Oversized ICMP payloads between %s and %s", fl.IPA, fl.IPB),
						Description:    fmt.Sprintf("Average ICMP packet size on this conversation was %.0f bytes, well above a normal echo payload, which can indicate an ICMP covert channel.", avg),
						Recommendation: "Inspect ICMP payload content; consider restricting ICMP payload size at the firewall.",
						Evidence:       []string{fmt.Sprintf("avg packet size: %.0f bytes over %d packets", avg, total)},
						Hosts:          []string{fl.IPA, fl.IPB},
						FirstSeen:      fl.FirstSeen, LastSeen: fl.LastSeen,
					})
				}
			}
		}
	}

	for _, q := range ctx.Result.DNSQueries {
		if q.AnswerLen > exfilDNSAnswerBytes {
			findings = append(findings, Finding{
				Severity:       Medium,
				Category:       "Covert Channel",
				Title:          fmt.Sprintf("Unusually large DNS answer for %q", q.Name),
				Description:    fmt.Sprintf("A DNS response to %s for %q carried %d bytes of answer data, larger than typical, which can indicate data smuggled via DNS.", q.SrcIP, q.Name, q.AnswerLen),
				Recommendation: "Inspect the DNS record content; consider limiting DNS response sizes / TXT record abuse at the resolver.",
				Evidence:       []string{fmt.Sprintf("answer length: %d bytes", q.AnswerLen)},
				Hosts:          []string{q.SrcIP, q.DstIP},
				FirstSeen:      q.Timestamp, LastSeen: q.Timestamp,
			})
		}
	}
	return findings
}

func maxU64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}

func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	units := "KMGTPE"
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), units[exp])
}
