package model

import (
	"sort"
	"time"

	"pcapdigger/internal/analyze"
	"pcapdigger/internal/enrich/geoip"
	"pcapdigger/internal/enrich/whois"
	"pcapdigger/internal/flow"
	"pcapdigger/internal/security"
	"pcapdigger/internal/version"
)

// BuildInput bundles every piece produced by the earlier pipeline stages.
type BuildInput struct {
	Result      *flow.Result
	Summary     *analyze.Summary
	Findings    []security.Finding
	Geo         *geoip.Lookup
	WHOIS       map[string]*whois.Record // keyed by IP, only populated for a capped subset
	DiagramPath string
	GeoIPNote   string
	WHOISNote   string
}

// Build assembles the final format/persona-agnostic Report.
func Build(in BuildInput) *Report {
	res, sum := in.Result, in.Summary

	r := &Report{
		Meta: Meta{
			SourceFile:   res.Meta.FileName,
			LinkType:     res.Meta.LinkType,
			ToolVersion:  version.Version,
			GeneratedAt:  time.Now().UTC(),
			FirstPacket:  res.Meta.FirstPacket,
			LastPacket:   res.Meta.LastPacket,
			DurationSecs: sum.Duration.Seconds(),
			TotalPackets: res.Meta.TotalPackets,
			TotalBytes:   res.Meta.TotalBytes,
		},
		DiagramPath: in.DiagramPath,
		GeoIPNote:   in.GeoIPNote,
		WHOISNote:   in.WHOISNote,
	}

	for _, p := range sum.ProtocolMix {
		r.ProtocolMix = append(r.ProtocolMix, ProtoStat{Protocol: p.Protocol, Packets: p.Packets, Bytes: p.Bytes, PctBytes: p.PctBytes})
	}
	for _, p := range sum.AppProtoMix {
		r.AppProtoMix = append(r.AppProtoMix, ProtoStat{Protocol: p.Protocol, Packets: p.Packets, Bytes: p.Bytes, PctBytes: p.PctBytes})
	}
	for _, p := range sum.TopPorts {
		r.TopPorts = append(r.TopPorts, NameCountPort{Port: p.Port, Count: p.Count})
	}

	findingIDsByHost := map[string][]int{}
	for i, f := range in.Findings {
		id := i + 1
		mf := Finding{
			ID: id, Severity: f.Severity.String(), Category: f.Category,
			Title: f.Title, Description: f.Description, Recommendation: f.Recommendation,
			Evidence: f.Evidence, Hosts: f.Hosts, FirstSeen: f.FirstSeen, LastSeen: f.LastSeen,
		}
		r.Findings = append(r.Findings, mf)
		for _, h := range f.Hosts {
			findingIDsByHost[h] = append(findingIDsByHost[h], id)
		}
	}

	for ip, h := range res.Hosts {
		mh := hostView(ip, h, in.Geo, in.WHOIS)
		mh.FindingIDs = findingIDsByHost[ip]
		r.Hosts = append(r.Hosts, mh)
	}
	sort.Slice(r.Hosts, func(i, j int) bool { return r.Hosts[i].IP < r.Hosts[j].IP })

	for _, t := range sum.TopTalkers {
		if h, ok := res.Hosts[t.IP]; ok {
			r.TopTalkers = append(r.TopTalkers, hostView(t.IP, h, in.Geo, in.WHOIS))
		}
	}

	for _, fl := range res.Flows {
		mf := Flow{
			Protocol: fl.Protocol, AppProto: fl.AppProto,
			HostA: fl.IPA, PortA: fl.PortA, HostB: fl.IPB, PortB: fl.PortB,
			PacketsAB: fl.PacketsAB, PacketsBA: fl.PacketsBA,
			BytesAB: fl.BytesAB, BytesBA: fl.BytesBA,
			FirstSeen: fl.FirstSeen, LastSeen: fl.LastSeen,
		}
		if fl.TLS != nil {
			mf.TLSVer = fl.TLS.Version
			mf.TLSSNI = fl.TLS.SNI
		}
		r.Flows = append(r.Flows, mf)
	}
	sort.Slice(r.Flows, func(i, j int) bool {
		return r.Flows[i].BytesAB+r.Flows[i].BytesBA > r.Flows[j].BytesAB+r.Flows[j].BytesBA
	})

	for _, n := range sum.DNS.TopNames {
		r.DNS.TopNames = append(r.DNS.TopNames, NameCount{Name: n.Name, Count: n.Count})
	}
	r.DNS.TotalQueries = sum.DNS.TotalQueries
	r.DNS.UniqueNames = sum.DNS.UniqueNames
	r.DNS.NXDomainCount = sum.DNS.NXDomainCount

	r.TLS = TLSSummary{
		TotalHandshakes: sum.TLS.TotalHandshakes,
		VersionCounts:   sum.TLS.VersionCounts,
		WeakCount:       sum.TLS.WeakCount,
		UniqueSNIs:      sum.TLS.UniqueSNIs,
	}

	r.Risk = riskAssessment(in.Findings)

	return r
}

func hostView(ip string, h *flow.Host, geoLookup *geoip.Lookup, whoisRecs map[string]*whois.Record) Host {
	mh := Host{
		IP: ip, Hostnames: h.Hostnames, MACs: h.MACs, IsPrivate: h.IsPrivate,
		BytesOut: h.BytesOut, BytesIn: h.BytesIn, PacketsOut: h.PacketsOut, PacketsIn: h.PacketsIn,
		PortsOpen: h.PortsOpen, FirstSeen: h.FirstSeen, LastSeen: h.LastSeen,
	}
	if geoLookup != nil {
		if info := geoLookup.Lookup(ip); info != nil {
			mh.Geo = &GeoInfo{
				Country: info.Country, CountryCode: info.CountryCode, City: info.City,
				Latitude: info.Latitude, Longitude: info.Longitude, ASN: info.ASN, ASOrg: info.ASOrg,
			}
		}
	}
	if rec, ok := whoisRecs[ip]; ok && rec != nil {
		mh.WHOIS = &WHOISInfo{
			Organization: rec.Organization, NetRange: rec.NetRange,
			Country: rec.Country, AbuseContact: rec.AbuseContact, Registry: rec.Registry,
		}
	}
	return mh
}

func riskAssessment(findings []security.Finding) RiskAssessment {
	ra := RiskAssessment{}
	for i, f := range findings {
		switch f.Severity {
		case security.Critical:
			ra.CriticalCount++
		case security.High:
			ra.HighCount++
		case security.Medium:
			ra.MediumCount++
		case security.Low:
			ra.LowCount++
		default:
			ra.InfoCount++
		}
		if len(ra.TopFindingIDs) < 5 {
			ra.TopFindingIDs = append(ra.TopFindingIDs, i+1)
		}
	}
	score := ra.CriticalCount*40 + ra.HighCount*15 + ra.MediumCount*5 + ra.LowCount*1
	if score > 100 {
		score = 100
	}
	ra.Score = score
	switch {
	case ra.CriticalCount > 0 || score >= 70:
		ra.OverallRisk = "Critical"
	case ra.HighCount > 0 || score >= 40:
		ra.OverallRisk = "High"
	case ra.MediumCount > 0 || score >= 15:
		ra.OverallRisk = "Medium"
	case score > 0:
		ra.OverallRisk = "Low"
	default:
		ra.OverallRisk = "Minimal"
	}
	return ra
}
