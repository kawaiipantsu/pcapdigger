package security

import "fmt"

const malformedSummaryThreshold = 1

// MalformedPacketDetector flags decode-error/truncated packets and
// stealth-scan-style TCP flag combinations (NULL/FIN/XMAS scans).
type MalformedPacketDetector struct{}

func (d *MalformedPacketDetector) Name() string { return "malformed-packets" }

func (d *MalformedPacketDetector) Detect(ctx *Context) []Finding {
	var findings []Finding

	byReason := map[string]int{}
	for _, m := range ctx.Result.Malformed {
		byReason[m.Reason]++
	}
	for reason, count := range byReason {
		if count < malformedSummaryThreshold {
			continue
		}
		findings = append(findings, Finding{
			Severity:       Low,
			Category:       "Protocol Violation",
			Title:          "Malformed or truncated packets observed",
			Description:    fmt.Sprintf("%d packets triggered: %s. This can be benign (capture snaplen truncation) or indicate malformed/crafted traffic.", count, reason),
			Recommendation: "If not explained by capture snaplen settings, investigate the source of malformed traffic.",
			Evidence:       []string{fmt.Sprintf("%d occurrences of %q", count, reason)},
		})
	}

	nullSrc, finSrc, xmasSrc := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, fl := range ctx.Result.Flows {
		if fl.Protocol != "TCP" {
			continue
		}
		switch {
		case fl.Flags.NullScan:
			nullSrc[fl.IPA] = true
		case fl.Flags.FINScan:
			finSrc[fl.IPA] = true
		case fl.Flags.XMASScan:
			xmasSrc[fl.IPA] = true
		}
	}
	emit := func(set map[string]bool, kind string) {
		for src := range set {
			findings = append(findings, Finding{
				Severity:       High,
				Category:       "Reconnaissance",
				Title:          fmt.Sprintf("%s scan pattern from %s", kind, src),
				Description:    fmt.Sprintf("%s sent TCP segments with a %s flag pattern, a stealth-scan technique used to probe firewall/host state while evading simple SYN-scan detection.", src, kind),
				Recommendation: "Investigate the source host; these flag combinations are not used by normal application traffic.",
				Hosts:          []string{src},
			})
		}
	}
	emit(nullSrc, "NULL")
	emit(finSrc, "FIN")
	emit(xmasSrc, "XMAS")

	return findings
}
