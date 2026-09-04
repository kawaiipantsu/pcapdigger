package model

import (
	"fmt"
	"time"
)

// NetworkView is the full technical view for the network-engineering report.
type NetworkView struct {
	Meta        Meta            `json:"meta"`
	ProtocolMix []ProtoStat     `json:"protocol_mix"`
	AppProtoMix []ProtoStat     `json:"app_protocol_mix"`
	TopTalkers  []Host          `json:"top_talkers"`
	TopPorts    []NameCountPort `json:"top_ports"`
	Hosts       []Host          `json:"hosts"`
	Flows       []Flow          `json:"flows"`
	DNS         DNSSummary      `json:"dns"`
	TLS         TLSSummary      `json:"tls"`
	DiagramPath string          `json:"diagram_path,omitempty"`
	GeoIPNote   string          `json:"geoip_note,omitempty"`
	WHOISNote   string          `json:"whois_note,omitempty"`
}

// Network builds the network-engineering view.
func (r *Report) Network() NetworkView {
	return NetworkView{
		Meta: r.Meta, ProtocolMix: r.ProtocolMix, AppProtoMix: r.AppProtoMix,
		TopTalkers: r.TopTalkers, TopPorts: r.TopPorts, Hosts: r.Hosts, Flows: r.Flows,
		DNS: r.DNS, TLS: r.TLS, DiagramPath: r.DiagramPath, GeoIPNote: r.GeoIPNote, WHOISNote: r.WHOISNote,
	}
}

// SecurityView is the findings-centric view for the security-architect report.
type SecurityView struct {
	Meta         Meta           `json:"meta"`
	Risk         RiskAssessment `json:"risk"`
	Findings     []Finding      `json:"findings"`
	FlaggedHosts []Host         `json:"flagged_hosts"`
	DiagramPath  string         `json:"diagram_path,omitempty"`
	WHOISNote    string         `json:"whois_note,omitempty"`
}

// Security builds the security-architect view.
func (r *Report) Security() SecurityView {
	sv := SecurityView{Meta: r.Meta, Risk: r.Risk, Findings: r.Findings, DiagramPath: r.DiagramPath, WHOISNote: r.WHOISNote}
	for _, h := range r.Hosts {
		if len(h.FindingIDs) > 0 {
			sv.FlaggedHosts = append(sv.FlaggedHosts, h)
		}
	}
	return sv
}

// ExecutiveView is the condensed, plain-language view for leadership.
type ExecutiveView struct {
	SourceFile        string         `json:"source_file"`
	GeneratedAt       time.Time      `json:"generated_at"`
	DurationSecs      float64        `json:"duration_seconds"`
	TotalPackets      int            `json:"total_packets"`
	TotalBytes        uint64         `json:"total_bytes"`
	HostCount         int            `json:"host_count"`
	ExternalHostCount int            `json:"external_host_count"`
	Risk              RiskAssessment `json:"risk"`
	TopFindings       []Finding      `json:"top_findings"`
	Highlights        []string       `json:"highlights"`
}

// Executive builds the executive view.
func (r *Report) Executive() ExecutiveView {
	ev := ExecutiveView{
		SourceFile: r.Meta.SourceFile, GeneratedAt: r.Meta.GeneratedAt,
		DurationSecs: r.Meta.DurationSecs, TotalPackets: r.Meta.TotalPackets, TotalBytes: r.Meta.TotalBytes,
		HostCount: len(r.Hosts), Risk: r.Risk,
	}
	for _, h := range r.Hosts {
		if !h.IsPrivate {
			ev.ExternalHostCount++
		}
	}
	byID := map[int]Finding{}
	for _, f := range r.Findings {
		byID[f.ID] = f
	}
	for _, id := range r.Risk.TopFindingIDs {
		if f, ok := byID[id]; ok {
			ev.TopFindings = append(ev.TopFindings, f)
		}
	}
	ev.Highlights = buildHighlights(r, ev)
	return ev
}

func buildHighlights(r *Report, ev ExecutiveView) []string {
	var h []string
	h = append(h, fmt.Sprintf("Analyzed %d packets (%s) captured over %s.", ev.TotalPackets, humanBytes(ev.TotalBytes), humanDuration(ev.DurationSecs)))
	h = append(h, fmt.Sprintf("%d distinct hosts observed, %d of them external to the local network.", ev.HostCount, ev.ExternalHostCount))
	if len(r.ProtocolMix) > 0 {
		top := r.ProtocolMix[0]
		h = append(h, fmt.Sprintf("Dominant traffic protocol: %s (%.0f%% of bytes).", top.Protocol, top.PctBytes))
	}
	total := r.Risk.CriticalCount + r.Risk.HighCount + r.Risk.MediumCount + r.Risk.LowCount + r.Risk.InfoCount
	h = append(h, fmt.Sprintf("Overall risk rating: %s (%d findings: %d critical, %d high, %d medium, %d low).",
		r.Risk.OverallRisk, total, r.Risk.CriticalCount, r.Risk.HighCount, r.Risk.MediumCount, r.Risk.LowCount))
	if r.TLS.WeakCount > 0 {
		h = append(h, fmt.Sprintf("%d TLS sessions used weak/legacy cryptography.", r.TLS.WeakCount))
	}
	return h
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

func humanDuration(seconds float64) string {
	d := time.Duration(seconds * float64(time.Second))
	if d < time.Minute {
		return fmt.Sprintf("%.1fs", seconds)
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm%ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
}
