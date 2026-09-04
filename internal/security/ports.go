package security

import "fmt"

type riskyPort struct {
	severity Severity
	label    string
}

// riskyPorts lists ports that, when seen exposed on the wire, typically
// warrant attention: legacy/unencrypted admin protocols and well-known
// malware/backdoor listener ports.
var riskyPorts = map[int]riskyPort{
	23:    {Medium, "Telnet (unencrypted remote admin)"},
	21:    {Low, "FTP (unencrypted file transfer)"},
	69:    {Low, "TFTP (unauthenticated file transfer)"},
	135:   {Low, "MS-RPC endpoint mapper"},
	139:   {Medium, "NetBIOS session service"},
	445:   {Medium, "SMB (frequent lateral-movement target)"},
	512:   {Medium, "rexec (unencrypted)"},
	513:   {Medium, "rlogin (unencrypted)"},
	514:   {Medium, "rsh (unencrypted)"},
	1433:  {Low, "MS-SQL exposed"},
	1521:  {Low, "Oracle DB exposed"},
	1337:  {High, "commonly used backdoor/leet port"},
	3389:  {Medium, "RDP exposed"},
	4444:  {High, "common Metasploit/backdoor default port"},
	5900:  {Medium, "VNC exposed"},
	5985:  {Low, "WinRM (HTTP) exposed"},
	6379:  {Medium, "Redis exposed (often unauthenticated)"},
	6666:  {High, "commonly used backdoor port"},
	6667:  {Low, "IRC (historically used for botnet C2)"},
	9999:  {Medium, "commonly used backdoor port"},
	11211: {Medium, "Memcached exposed (often unauthenticated)"},
	12345: {High, "NetBus/commonly used backdoor default port"},
	27017: {Medium, "MongoDB exposed (often unauthenticated)"},
	27374: {High, "SubSeven trojan default port"},
	31337: {High, "Back Orifice / classic backdoor default port"},
}

// RiskyPortDetector flags hosts exposing known-risky or backdoor-associated
// ports.
type RiskyPortDetector struct{}

func (d *RiskyPortDetector) Name() string { return "risky-ports" }

func (d *RiskyPortDetector) Detect(ctx *Context) []Finding {
	var findings []Finding
	for _, h := range ctx.Result.Hosts {
		for _, p := range h.PortsOpen {
			info, ok := riskyPorts[p]
			if !ok {
				continue
			}
			findings = append(findings, Finding{
				Severity:       info.severity,
				Category:       "Exposed Service",
				Title:          fmt.Sprintf("Port %d (%s) exposed on %s", p, info.label, h.IP),
				Description:    fmt.Sprintf("%s was reached on port %d, associated with: %s.", h.IP, p, info.label),
				Recommendation: "Confirm this service is required and authorized; if not, disable it or restrict access with firewall rules.",
				Hosts:          []string{h.IP},
				FirstSeen:      h.FirstSeen, LastSeen: h.LastSeen,
			})
		}
	}
	return findings
}
