package security

import (
	"fmt"
	"strings"

	"pcapdigger/internal/proto"
)

const (
	entropyThreshold     = 3.5 // bits/char
	entropyMinLabelLen   = 20
	entropyMinHitsPerSrc = 5
	nxdomainFloodPerSrc  = 20
)

// DNSAnomalyDetector flags high-entropy subdomains (tunneling heuristic)
// and excessive NXDOMAIN responses (DGA/domain-fluxing heuristic).
type DNSAnomalyDetector struct{}

func (d *DNSAnomalyDetector) Name() string { return "dns-anomaly" }

func (d *DNSAnomalyDetector) Detect(ctx *Context) []Finding {
	var findings []Finding

	entropyHits := map[string][]string{} // srcIP -> sample names
	nxCounts := map[string]int{}
	for _, q := range ctx.Result.DNSQueries {
		label := firstLabel(q.Name)
		if len(label) >= entropyMinLabelLen && proto.ShannonEntropy(label) >= entropyThreshold {
			entropyHits[q.SrcIP] = append(entropyHits[q.SrcIP], q.Name)
		}
		if q.NXDomain {
			nxCounts[q.SrcIP]++
		}
	}

	for src, names := range entropyHits {
		if len(names) >= entropyMinHitsPerSrc {
			findings = append(findings, Finding{
				Severity:       High,
				Category:       "Covert Channel",
				Title:          fmt.Sprintf("Possible DNS tunneling from %s", src),
				Description:    fmt.Sprintf("%s issued %d DNS queries with high-entropy, long subdomain labels, a common indicator of DNS tunneling / data exfiltration over DNS.", src, len(names)),
				Recommendation: "Inspect the resolved domains; block DNS tunneling tools at the resolver/firewall; consider egress DNS filtering.",
				Evidence:       []string{fmt.Sprintf("sample queries: %v", sampleStrings(names, 5))},
				Hosts:          []string{src},
			})
		}
	}
	for src, n := range nxCounts {
		if n >= nxdomainFloodPerSrc {
			findings = append(findings, Finding{
				Severity:       Medium,
				Category:       "Covert Channel",
				Title:          fmt.Sprintf("Excessive NXDOMAIN responses for %s", src),
				Description:    fmt.Sprintf("%s triggered %d NXDOMAIN DNS responses, which can indicate domain-generation-algorithm (DGA) malware probing for a live C2 domain.", src, n),
				Recommendation: "Investigate the querying host for malware; consider DNS sinkholing/blocking of failing lookups at scale.",
				Evidence:       []string{fmt.Sprintf("%d NXDOMAIN responses", n)},
				Hosts:          []string{src},
			})
		}
	}
	return findings
}

func firstLabel(fqdn string) string {
	parts := strings.Split(strings.TrimSuffix(fqdn, "."), ".")
	if len(parts) == 0 {
		return fqdn
	}
	// The most information-dense label in a tunneling scheme is typically
	// the left-most (innermost) subdomain component.
	return parts[0]
}

func sampleStrings(s []string, n int) []string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
