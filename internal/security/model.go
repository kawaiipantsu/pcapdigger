// Package security runs a battery of heuristic detectors over a flow.Result
// to surface possible attack vectors, exposures, and protocol anomalies.
package security

import (
	"time"

	"pcapdigger/internal/flow"
)

// Severity ranks a Finding's urgency.
type Severity int

const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

// String renders a human-readable severity label.
func (s Severity) String() string {
	switch s {
	case Critical:
		return "Critical"
	case High:
		return "High"
	case Medium:
		return "Medium"
	case Low:
		return "Low"
	default:
		return "Info"
	}
}

// Finding is one detected issue, attack indicator, or anomaly.
type Finding struct {
	Severity       Severity
	Category       string
	Title          string
	Description    string
	Recommendation string
	Evidence       []string
	Hosts          []string
	FirstSeen      time.Time
	LastSeen       time.Time
}

// IOCSet is an optional user-supplied indicator-of-compromise blocklist
// (loaded from --ioc-file), mapping an IP or domain to a description.
type IOCSet map[string]string

// Context bundles everything a Detector needs.
type Context struct {
	Result *flow.Result
	IOCs   IOCSet
}

// Detector produces zero or more Findings from a Context.
type Detector interface {
	Name() string
	Detect(ctx *Context) []Finding
}

// AllDetectors returns every built-in detector, in a stable order.
func AllDetectors() []Detector {
	return []Detector{
		&ScanDetector{},
		&ARPSpoofDetector{},
		&CredentialDetector{},
		&WeakTLSDetector{},
		&DNSAnomalyDetector{},
		&ExfilDetector{},
		&BeaconingDetector{},
		&MalformedPacketDetector{},
		&IOCDetector{},
		&RiskyPortDetector{},
	}
}

// Run executes every detector and returns all findings, most severe first.
func Run(ctx *Context, detectors []Detector) []Finding {
	var all []Finding
	for _, d := range detectors {
		all = append(all, d.Detect(ctx)...)
	}
	sortFindings(all)
	return all
}

func sortFindings(f []Finding) {
	// simple insertion sort by descending severity; finding counts are small
	// enough (dozens, not millions) that O(n^2) is a non-issue.
	for i := 1; i < len(f); i++ {
		j := i
		for j > 0 && f[j-1].Severity < f[j].Severity {
			f[j-1], f[j] = f[j], f[j-1]
			j--
		}
	}
}
