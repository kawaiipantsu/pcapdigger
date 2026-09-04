package security

import (
	"fmt"

	"pcapdigger/internal/flow"
)

// WeakTLSDetector flags legacy protocol versions, weak cipher suites, and
// certificate problems (expired, self-signed, SNI mismatch).
type WeakTLSDetector struct{}

func (d *WeakTLSDetector) Name() string { return "weak-tls" }

func (d *WeakTLSDetector) Detect(ctx *Context) []Finding {
	var findings []Finding
	for _, fl := range ctx.Result.Flows {
		if fl.TLS == nil {
			continue
		}
		t := fl.TLS
		switch t.Version {
		case "SSLv3", "TLS 1.0", "TLS 1.1":
			findings = append(findings, Finding{
				Severity:       High,
				Category:       "Weak Cryptography",
				Title:          fmt.Sprintf("Legacy %s in use", t.Version),
				Description:    fmt.Sprintf("%s negotiated %s with %s, a deprecated protocol version with known weaknesses.", fl.IPA, t.Version, sniOr(t.SNI, fl.IPB)),
				Recommendation: "Disable SSLv3/TLS 1.0/1.1 on the server and require TLS 1.2+.",
				Evidence:       []string{fmt.Sprintf("TLS version: %s, SNI: %s", t.Version, t.SNI)},
				Hosts:          []string{fl.IPA, fl.IPB},
				FirstSeen:      fl.FirstSeen, LastSeen: fl.LastSeen,
			})
		}
		if t.WeakCipher {
			findings = append(findings, Finding{
				Severity:       Medium,
				Category:       "Weak Cryptography",
				Title:          "Weak TLS cipher suite offered",
				Description:    fmt.Sprintf("%s offered a weak/export-grade cipher suite to %s.", fl.IPA, sniOr(t.SNI, fl.IPB)),
				Recommendation: "Restrict the client/server cipher suite list to modern AEAD ciphers (AES-GCM, ChaCha20-Poly1305).",
				Evidence:       []string{fmt.Sprintf("cipher suites: %v", t.CipherSuites)},
				Hosts:          []string{fl.IPA, fl.IPB},
				FirstSeen:      fl.FirstSeen, LastSeen: fl.LastSeen,
			})
		}
		if c := t.Cert; c != nil {
			if c.Expired {
				findings = append(findings, certFinding(High, "Expired TLS certificate", fmt.Sprintf("Certificate for %s (subject %q) expired on %s.", fl.IPB, c.Subject, c.NotAfter.Format("2006-01-02")), fl))
			}
			if c.NotYetValid {
				findings = append(findings, certFinding(Medium, "TLS certificate not yet valid", fmt.Sprintf("Certificate for %s (subject %q) is not valid until %s.", fl.IPB, c.Subject, c.NotBefore.Format("2006-01-02")), fl))
			}
			if c.SelfSigned {
				findings = append(findings, certFinding(Medium, "Self-signed TLS certificate", fmt.Sprintf("Certificate for %s (subject %q) is self-signed.", fl.IPB, c.Subject), fl))
			}
			if c.SNIMismatch {
				findings = append(findings, certFinding(High, "TLS certificate does not match requested hostname", fmt.Sprintf("Certificate for %s does not cover the requested SNI %q (subject %q).", fl.IPB, t.SNI, c.Subject), fl))
			}
		}
	}
	return findings
}

func certFinding(sev Severity, title, desc string, fl *flow.Flow) Finding {
	return Finding{
		Severity:       sev,
		Category:       "Weak Cryptography",
		Title:          title,
		Description:    desc,
		Recommendation: "Replace the certificate with a valid one from a trusted CA covering the correct hostname.",
		Hosts:          []string{fl.IPA, fl.IPB},
		FirstSeen:      fl.FirstSeen,
		LastSeen:       fl.LastSeen,
	}
}

func sniOr(sni, fallback string) string {
	if sni != "" {
		return sni
	}
	return fallback
}
