// Package analyze derives summary statistics (protocol mix, top talkers,
// bandwidth timeline, DNS/TLS summaries) from a flow.Result.
package analyze

import (
	"sort"
	"time"

	"pcapdigger/internal/flow"
)

// ProtoStat is one row of a protocol-mix breakdown.
type ProtoStat struct {
	Protocol string
	Packets  int
	Bytes    uint64
	PctBytes float64
}

// TalkerStat is one row of a top-talkers table.
type TalkerStat struct {
	IP         string
	Hostnames  []string
	BytesTotal uint64
	Packets    uint64
	IsPrivate  bool
}

// PortStat is one row of a top-ports table.
type PortStat struct {
	Port  int
	Count int
}

// TimelineBucket is one point of the bandwidth-over-time timeline.
type TimelineBucket struct {
	Start   time.Time
	Packets int
	Bytes   uint64
}

// DNSSummary condenses the DNS query log.
type DNSSummary struct {
	TotalQueries  int
	UniqueNames   int
	NXDomainCount int
	TopNames      []NameCount
}

// NameCount pairs a name with an occurrence count.
type NameCount struct {
	Name  string
	Count int
}

// TLSSummary condenses TLS handshake observations across all flows.
type TLSSummary struct {
	TotalHandshakes int
	VersionCounts   map[string]int
	WeakCount       int
	UniqueSNIs      []string
}

// Summary is the full derived-statistics bundle for one capture.
type Summary struct {
	TotalPackets int
	TotalBytes   uint64
	FirstPacket  time.Time
	LastPacket   time.Time
	Duration     time.Duration

	ProtocolMix []ProtoStat
	AppProtoMix []ProtoStat

	TopTalkers []TalkerStat
	TopPorts   []PortStat

	Timeline []TimelineBucket

	DNS DNSSummary
	TLS TLSSummary
}

// Compute builds a Summary from a flow.Result. topN bounds the length of the
// top-talkers/top-ports tables (0 = default of 20).
func Compute(res *flow.Result, topN int) *Summary {
	if topN <= 0 {
		topN = 20
	}
	s := &Summary{
		TotalPackets: res.Meta.TotalPackets,
		TotalBytes:   res.Meta.TotalBytes,
		FirstPacket:  res.Meta.FirstPacket,
		LastPacket:   res.Meta.LastPacket,
	}
	if !s.FirstPacket.IsZero() {
		s.Duration = s.LastPacket.Sub(s.FirstPacket)
	}

	s.ProtocolMix = protoMix(res.ProtoPackets, res.ProtoBytes, s.TotalBytes)
	s.AppProtoMix = appProtoMix(res.Flows, s.TotalBytes)
	s.TopTalkers = topTalkers(res.Hosts, topN)
	s.TopPorts = topPorts(res.Hosts, topN)
	s.Timeline = timeline(res)
	s.DNS = dnsSummary(res.DNSQueries, topN)
	s.TLS = tlsSummary(res.Flows)
	return s
}

func protoMix(pkts map[string]int, bytes map[string]uint64, total uint64) []ProtoStat {
	out := make([]ProtoStat, 0, len(pkts))
	for name, count := range pkts {
		b := bytes[name]
		pct := 0.0
		if total > 0 {
			pct = float64(b) / float64(total) * 100
		}
		out = append(out, ProtoStat{Protocol: name, Packets: count, Bytes: b, PctBytes: pct})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Bytes > out[j].Bytes })
	return out
}

func appProtoMix(flows map[string]*flow.Flow, total uint64) []ProtoStat {
	agg := map[string]*ProtoStat{}
	for _, fl := range flows {
		name := fl.AppProto
		if name == "" {
			name = "other/" + fl.Protocol
		}
		e, ok := agg[name]
		if !ok {
			e = &ProtoStat{Protocol: name}
			agg[name] = e
		}
		e.Packets += int(fl.PacketsAB + fl.PacketsBA)
		e.Bytes += fl.BytesAB + fl.BytesBA
	}
	out := make([]ProtoStat, 0, len(agg))
	for _, e := range agg {
		if total > 0 {
			e.PctBytes = float64(e.Bytes) / float64(total) * 100
		}
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Bytes > out[j].Bytes })
	return out
}

func topTalkers(hosts map[string]*flow.Host, topN int) []TalkerStat {
	out := make([]TalkerStat, 0, len(hosts))
	for _, h := range hosts {
		out = append(out, TalkerStat{
			IP: h.IP, Hostnames: h.Hostnames,
			BytesTotal: h.BytesOut + h.BytesIn, Packets: h.PacketsOut + h.PacketsIn,
			IsPrivate: h.IsPrivate,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].BytesTotal > out[j].BytesTotal })
	if len(out) > topN {
		out = out[:topN]
	}
	return out
}

func topPorts(hosts map[string]*flow.Host, topN int) []PortStat {
	counts := map[int]int{}
	for _, h := range hosts {
		for _, p := range h.PortsOpen {
			counts[p]++
		}
	}
	out := make([]PortStat, 0, len(counts))
	for p, c := range counts {
		out = append(out, PortStat{Port: p, Count: c})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	if len(out) > topN {
		out = out[:topN]
	}
	return out
}

func timeline(res *flow.Result) []TimelineBucket {
	if res.Meta.FirstPacket.IsZero() {
		return nil
	}
	dur := res.Meta.LastPacket.Sub(res.Meta.FirstPacket)
	bucketCount := 60
	bucketDur := dur / time.Duration(bucketCount)
	if bucketDur <= 0 {
		bucketDur = time.Second
	}
	buckets := map[int]*TimelineBucket{}
	assign := func(t time.Time, n int, b uint64) {
		idx := int(t.Sub(res.Meta.FirstPacket) / bucketDur)
		bk, ok := buckets[idx]
		if !ok {
			bk = &TimelineBucket{Start: res.Meta.FirstPacket.Add(time.Duration(idx) * bucketDur)}
			buckets[idx] = bk
		}
		bk.Packets += n
		bk.Bytes += b
	}
	for _, fl := range res.Flows {
		// Approximate: attribute the flow's totals to its last-seen bucket
		// isn't ideal, so instead spread evenly isn't available without
		// per-packet timestamps; use first/last seen as a coarse midpoint.
		mid := fl.FirstSeen.Add(fl.LastSeen.Sub(fl.FirstSeen) / 2)
		assign(mid, int(fl.PacketsAB+fl.PacketsBA), fl.BytesAB+fl.BytesBA)
	}
	out := make([]TimelineBucket, 0, len(buckets))
	for _, bk := range buckets {
		out = append(out, *bk)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Start.Before(out[j].Start) })
	return out
}

func dnsSummary(queries []flow.DNSQuery, topN int) DNSSummary {
	names := map[string]int{}
	nx := 0
	for _, q := range queries {
		names[q.Name]++
		if q.NXDomain {
			nx++
		}
	}
	top := make([]NameCount, 0, len(names))
	for n, c := range names {
		top = append(top, NameCount{Name: n, Count: c})
	}
	sort.Slice(top, func(i, j int) bool { return top[i].Count > top[j].Count })
	if len(top) > topN {
		top = top[:topN]
	}
	return DNSSummary{TotalQueries: len(queries), UniqueNames: len(names), NXDomainCount: nx, TopNames: top}
}

func tlsSummary(flows map[string]*flow.Flow) TLSSummary {
	s := TLSSummary{VersionCounts: map[string]int{}}
	sniSet := map[string]bool{}
	for _, fl := range flows {
		if fl.TLS == nil {
			continue
		}
		s.TotalHandshakes++
		if fl.TLS.Version != "" {
			s.VersionCounts[fl.TLS.Version]++
		}
		if fl.TLS.WeakCipher {
			s.WeakCount++
		}
		if fl.TLS.SNI != "" {
			sniSet[fl.TLS.SNI] = true
		}
	}
	for sni := range sniSet {
		s.UniqueSNIs = append(s.UniqueSNIs, sni)
	}
	sort.Strings(s.UniqueSNIs)
	return s
}
