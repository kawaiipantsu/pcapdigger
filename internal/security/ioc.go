package security

import "fmt"

// IOCDetector flags any host IP or DNS query name matching a user-supplied
// indicator-of-compromise blocklist (loaded via --ioc-file).
type IOCDetector struct{}

func (d *IOCDetector) Name() string { return "ioc-match" }

func (d *IOCDetector) Detect(ctx *Context) []Finding {
	if len(ctx.IOCs) == 0 {
		return nil
	}
	var findings []Finding
	seen := map[string]bool{}

	for ip := range ctx.Result.Hosts {
		if desc, ok := ctx.IOCs[ip]; ok && !seen["ip:"+ip] {
			seen["ip:"+ip] = true
			findings = append(findings, Finding{
				Severity:       Critical,
				Category:       "Threat Intelligence Match",
				Title:          fmt.Sprintf("Traffic involving known-malicious indicator %s", ip),
				Description:    fmt.Sprintf("Host %s matches a supplied indicator of compromise: %s.", ip, desc),
				Recommendation: "Treat any host that communicated with this indicator as potentially compromised; isolate and investigate immediately.",
				Hosts:          []string{ip},
			})
		}
	}
	for _, q := range ctx.Result.DNSQueries {
		key := "dns:" + q.Name
		if desc, ok := ctx.IOCs[q.Name]; ok && !seen[key] {
			seen[key] = true
			findings = append(findings, Finding{
				Severity:       Critical,
				Category:       "Threat Intelligence Match",
				Title:          fmt.Sprintf("DNS lookup for known-malicious domain %s", q.Name),
				Description:    fmt.Sprintf("%s queried %s, which matches a supplied indicator of compromise: %s.", q.SrcIP, q.Name, desc),
				Recommendation: "Treat the querying host as potentially compromised; isolate and investigate immediately.",
				Hosts:          []string{q.SrcIP},
				FirstSeen:      q.Timestamp, LastSeen: q.Timestamp,
			})
		}
	}
	return findings
}
