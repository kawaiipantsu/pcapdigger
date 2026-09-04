package security

import "fmt"

// CredentialDetector turns recovered plaintext credentials into findings.
type CredentialDetector struct{}

func (d *CredentialDetector) Name() string { return "plaintext-credentials" }

func (d *CredentialDetector) Detect(ctx *Context) []Finding {
	var findings []Finding
	for _, c := range ctx.Result.Credentials {
		sev := Medium
		desc := fmt.Sprintf("%s cleartext exchange observed between %s and %s (%s).", c.Protocol, c.SrcIP, c.DstIP, c.Detail)
		evidence := []string{fmt.Sprintf("%s -> %s:%d, %s", c.SrcIP, c.DstIP, c.DstPort, c.Detail)}
		if c.Password != "" {
			sev = Critical
			desc = fmt.Sprintf("A cleartext %s credential was captured between %s and %s (%s). The full username/password pair is recorded in the technical evidence below — treat it as compromised and rotate it.", c.Protocol, c.SrcIP, c.DstIP, c.Detail)
			evidence = append(evidence, fmt.Sprintf("username=%q password=%q", maskEmpty(c.Username), c.Password))
		} else if c.Username != "" {
			sev = High
			evidence = append(evidence, fmt.Sprintf("username=%q", c.Username))
		}
		findings = append(findings, Finding{
			Severity:       sev,
			Category:       "Credential Exposure",
			Title:          fmt.Sprintf("Plaintext %s credential exposure", c.Protocol),
			Description:    desc,
			Recommendation: "Migrate this service to an encrypted transport (TLS/SSH) and rotate any exposed credentials immediately.",
			Evidence:       evidence,
			Hosts:          []string{c.SrcIP, c.DstIP},
			FirstSeen:      c.Timestamp,
			LastSeen:       c.Timestamp,
		})
	}
	return findings
}

func maskEmpty(s string) string {
	if s == "" {
		return "(unknown)"
	}
	return s
}
