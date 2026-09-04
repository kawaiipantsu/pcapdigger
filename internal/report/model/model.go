// Package model defines the report data structures shared by every output
// format (JSON/CSV/Markdown) and every report persona (network engineering,
// security architect, executive).
package model

import "time"

// Meta holds capture-level identification info.
type Meta struct {
	SourceFile   string    `json:"source_file"`
	LinkType     string    `json:"link_type"`
	ToolVersion  string    `json:"tool_version"`
	GeneratedAt  time.Time `json:"generated_at"`
	FirstPacket  time.Time `json:"first_packet"`
	LastPacket   time.Time `json:"last_packet"`
	DurationSecs float64   `json:"duration_seconds"`
	TotalPackets int       `json:"total_packets"`
	TotalBytes   uint64    `json:"total_bytes"`
}

// ProtoStat is one protocol/app-protocol mix row.
type ProtoStat struct {
	Protocol string  `json:"protocol"`
	Packets  int     `json:"packets"`
	Bytes    uint64  `json:"bytes"`
	PctBytes float64 `json:"pct_bytes"`
}

// GeoInfo is optional GeoIP/ASN enrichment for a host.
type GeoInfo struct {
	Country     string  `json:"country,omitempty"`
	CountryCode string  `json:"country_code,omitempty"`
	City        string  `json:"city,omitempty"`
	Latitude    float64 `json:"latitude,omitempty"`
	Longitude   float64 `json:"longitude,omitempty"`
	ASN         uint    `json:"asn,omitempty"`
	ASOrg       string  `json:"as_org,omitempty"`
}

// WHOISInfo is optional WHOIS enrichment for a host.
type WHOISInfo struct {
	Organization string `json:"organization,omitempty"`
	NetRange     string `json:"net_range,omitempty"`
	Country      string `json:"country,omitempty"`
	AbuseContact string `json:"abuse_contact,omitempty"`
	Registry     string `json:"registry,omitempty"`
}

// Host is one entry of the host inventory, with optional enrichment.
type Host struct {
	IP         string     `json:"ip"`
	Hostnames  []string   `json:"hostnames,omitempty"`
	MACs       []string   `json:"macs,omitempty"`
	IsPrivate  bool       `json:"is_private"`
	BytesOut   uint64     `json:"bytes_out"`
	BytesIn    uint64     `json:"bytes_in"`
	PacketsOut uint64     `json:"packets_out"`
	PacketsIn  uint64     `json:"packets_in"`
	PortsOpen  []int      `json:"ports_open,omitempty"`
	FirstSeen  time.Time  `json:"first_seen"`
	LastSeen   time.Time  `json:"last_seen"`
	Geo        *GeoInfo   `json:"geo,omitempty"`
	WHOIS      *WHOISInfo `json:"whois,omitempty"`
	FindingIDs []int      `json:"finding_ids,omitempty"`
}

// Flow is one conversation row.
type Flow struct {
	Protocol  string    `json:"protocol"`
	AppProto  string    `json:"app_protocol,omitempty"`
	HostA     string    `json:"host_a"`
	PortA     int       `json:"port_a"`
	HostB     string    `json:"host_b"`
	PortB     int       `json:"port_b"`
	PacketsAB uint64    `json:"packets_a_to_b"`
	PacketsBA uint64    `json:"packets_b_to_a"`
	BytesAB   uint64    `json:"bytes_a_to_b"`
	BytesBA   uint64    `json:"bytes_b_to_a"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	TLSVer    string    `json:"tls_version,omitempty"`
	TLSSNI    string    `json:"tls_sni,omitempty"`
}

// Finding is one security detector result, with a stable ID for
// cross-referencing from the Host table.
type Finding struct {
	ID             int       `json:"id"`
	Severity       string    `json:"severity"`
	Category       string    `json:"category"`
	Title          string    `json:"title"`
	Description    string    `json:"description"`
	Recommendation string    `json:"recommendation"`
	Evidence       []string  `json:"evidence,omitempty"`
	Hosts          []string  `json:"hosts,omitempty"`
	FirstSeen      time.Time `json:"first_seen,omitempty"`
	LastSeen       time.Time `json:"last_seen,omitempty"`
}

// NameCount pairs a name with an occurrence count (top talkers/queries).
type NameCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// DNSSummary condenses the DNS query log.
type DNSSummary struct {
	TotalQueries  int         `json:"total_queries"`
	UniqueNames   int         `json:"unique_names"`
	NXDomainCount int         `json:"nxdomain_count"`
	TopNames      []NameCount `json:"top_names,omitempty"`
}

// TLSSummary condenses TLS handshake observations.
type TLSSummary struct {
	TotalHandshakes int            `json:"total_handshakes"`
	VersionCounts   map[string]int `json:"version_counts,omitempty"`
	WeakCount       int            `json:"weak_count"`
	UniqueSNIs      []string       `json:"unique_snis,omitempty"`
}

// RiskAssessment is the composite security posture summary.
type RiskAssessment struct {
	Score         int    `json:"score"` // 0-100
	OverallRisk   string `json:"overall_risk"`
	CriticalCount int    `json:"critical_count"`
	HighCount     int    `json:"high_count"`
	MediumCount   int    `json:"medium_count"`
	LowCount      int    `json:"low_count"`
	InfoCount     int    `json:"info_count"`
	TopFindingIDs []int  `json:"top_finding_ids,omitempty"`
}

// Report is the complete, format-agnostic analysis result. Every renderer
// (json/csv/markdown) and every persona (network/security/executive) reads
// from this single structure, selecting/framing a subset of it.
type Report struct {
	Meta        Meta            `json:"meta"`
	ProtocolMix []ProtoStat     `json:"protocol_mix"`
	AppProtoMix []ProtoStat     `json:"app_protocol_mix"`
	TopTalkers  []Host          `json:"top_talkers"`
	TopPorts    []NameCountPort `json:"top_ports"`
	Hosts       []Host          `json:"hosts"`
	Flows       []Flow          `json:"flows"`
	Findings    []Finding       `json:"findings"`
	DNS         DNSSummary      `json:"dns"`
	TLS         TLSSummary      `json:"tls"`
	Risk        RiskAssessment  `json:"risk"`
	DiagramPath string          `json:"diagram_path,omitempty"`
	WHOISNote   string          `json:"whois_note,omitempty"`
	GeoIPNote   string          `json:"geoip_note,omitempty"`
}

// NameCountPort pairs a port with an occurrence count.
type NameCountPort struct {
	Port  int `json:"port"`
	Count int `json:"count"`
}
