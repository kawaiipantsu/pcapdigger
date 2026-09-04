// Package csv renders report views as one or more CSV tables per report,
// since CSV has no native support for nested structures.
package csv

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"pcapdigger/internal/report/model"
)

// WriteNetwork writes the network-engineering view as a set of CSV tables.
func WriteNetwork(r *model.Report, outDir, baseName string) ([]string, error) {
	v := r.Network()
	var paths []string

	p, err := writeTable(outDir, baseName, "network-hosts", []string{
		"ip", "hostnames", "is_private", "bytes_out", "bytes_in", "packets_out", "packets_in", "ports_open", "country", "as_org", "first_seen", "last_seen",
	}, hostRows(v.Hosts))
	if err != nil {
		return nil, err
	}
	paths = append(paths, p)

	p, err = writeTable(outDir, baseName, "network-flows", []string{
		"protocol", "app_protocol", "host_a", "port_a", "host_b", "port_b", "packets_a_to_b", "packets_b_to_a", "bytes_a_to_b", "bytes_b_to_a", "tls_version", "tls_sni", "tls_decrypted", "tls_key_source", "first_seen", "last_seen",
	}, flowRows(v.Flows))
	if err != nil {
		return nil, err
	}
	paths = append(paths, p)

	p, err = writeTable(outDir, baseName, "network-protocols", []string{"protocol", "packets", "bytes", "pct_bytes"}, protoRows(v.ProtocolMix))
	if err != nil {
		return nil, err
	}
	paths = append(paths, p)

	p, err = writeTable(outDir, baseName, "network-top-ports", []string{"port", "count"}, portRows(v.TopPorts))
	if err != nil {
		return nil, err
	}
	paths = append(paths, p)

	return paths, nil
}

// WriteSecurity writes the security-architect view as a set of CSV tables.
func WriteSecurity(r *model.Report, outDir, baseName string) ([]string, error) {
	v := r.Security()
	var paths []string

	rows := make([][]string, 0, len(v.Findings))
	for _, f := range v.Findings {
		rows = append(rows, []string{
			strconv.Itoa(f.ID), f.Severity, f.Category, f.Title, f.Description, f.Recommendation,
			strings.Join(f.Hosts, ";"), strings.Join(f.Evidence, " | "), fmtTime(f.FirstSeen), fmtTime(f.LastSeen),
		})
	}
	p, err := writeTable(outDir, baseName, "security-findings", []string{
		"id", "severity", "category", "title", "description", "recommendation", "hosts", "evidence", "first_seen", "last_seen",
	}, rows)
	if err != nil {
		return nil, err
	}
	paths = append(paths, p)

	p, err = writeTable(outDir, baseName, "security-flagged-hosts", []string{
		"ip", "hostnames", "is_private", "country", "as_org", "whois_org", "finding_ids",
	}, flaggedHostRows(v.FlaggedHosts))
	if err != nil {
		return nil, err
	}
	paths = append(paths, p)

	return paths, nil
}

// WriteExecutive writes the executive view as CSV (a key metrics table and
// a top-findings table).
func WriteExecutive(r *model.Report, outDir, baseName string) ([]string, error) {
	v := r.Executive()
	var paths []string

	summary := [][]string{
		{"source_file", v.SourceFile},
		{"generated_at", fmtTime(v.GeneratedAt)},
		{"duration_seconds", fmt.Sprintf("%.1f", v.DurationSecs)},
		{"total_packets", strconv.Itoa(v.TotalPackets)},
		{"total_bytes", strconv.FormatUint(v.TotalBytes, 10)},
		{"host_count", strconv.Itoa(v.HostCount)},
		{"external_host_count", strconv.Itoa(v.ExternalHostCount)},
		{"overall_risk", v.Risk.OverallRisk},
		{"risk_score", strconv.Itoa(v.Risk.Score)},
		{"critical_findings", strconv.Itoa(v.Risk.CriticalCount)},
		{"high_findings", strconv.Itoa(v.Risk.HighCount)},
		{"medium_findings", strconv.Itoa(v.Risk.MediumCount)},
		{"low_findings", strconv.Itoa(v.Risk.LowCount)},
	}
	p, err := writeTable(outDir, baseName, "executive-summary", []string{"metric", "value"}, summary)
	if err != nil {
		return nil, err
	}
	paths = append(paths, p)

	rows := make([][]string, 0, len(v.TopFindings))
	for _, f := range v.TopFindings {
		rows = append(rows, []string{f.Severity, f.Category, f.Title, f.Description})
	}
	p, err = writeTable(outDir, baseName, "executive-top-findings", []string{"severity", "category", "title", "description"}, rows)
	if err != nil {
		return nil, err
	}
	paths = append(paths, p)

	return paths, nil
}

func writeTable(outDir, baseName, table string, header []string, rows [][]string) (string, error) {
	path := filepath.Join(outDir, fmt.Sprintf("%s-%s.csv", baseName, table))
	f, err := os.Create(path)
	if err != nil {
		return "", fmt.Errorf("create %s: %w", path, err)
	}
	defer f.Close()
	w := csv.NewWriter(f)
	if err := w.Write(header); err != nil {
		return "", err
	}
	for _, row := range rows {
		if err := w.Write(row); err != nil {
			return "", err
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return "", err
	}
	return path, nil
}

func hostRows(hosts []model.Host) [][]string {
	rows := make([][]string, 0, len(hosts))
	for _, h := range hosts {
		country, asOrg := "", ""
		if h.Geo != nil {
			country, asOrg = h.Geo.Country, h.Geo.ASOrg
		}
		rows = append(rows, []string{
			h.IP, strings.Join(h.Hostnames, ";"), strconv.FormatBool(h.IsPrivate),
			strconv.FormatUint(h.BytesOut, 10), strconv.FormatUint(h.BytesIn, 10),
			strconv.FormatUint(h.PacketsOut, 10), strconv.FormatUint(h.PacketsIn, 10),
			joinInts(h.PortsOpen), country, asOrg, fmtTime(h.FirstSeen), fmtTime(h.LastSeen),
		})
	}
	return rows
}

func flaggedHostRows(hosts []model.Host) [][]string {
	rows := make([][]string, 0, len(hosts))
	for _, h := range hosts {
		country, asOrg, whoisOrg := "", "", ""
		if h.Geo != nil {
			country, asOrg = h.Geo.Country, h.Geo.ASOrg
		}
		if h.WHOIS != nil {
			whoisOrg = h.WHOIS.Organization
		}
		rows = append(rows, []string{
			h.IP, strings.Join(h.Hostnames, ";"), strconv.FormatBool(h.IsPrivate),
			country, asOrg, whoisOrg, joinInts(h.FindingIDs),
		})
	}
	return rows
}

func flowRows(flows []model.Flow) [][]string {
	rows := make([][]string, 0, len(flows))
	for _, f := range flows {
		rows = append(rows, []string{
			f.Protocol, f.AppProto, f.HostA, strconv.Itoa(f.PortA), f.HostB, strconv.Itoa(f.PortB),
			strconv.FormatUint(f.PacketsAB, 10), strconv.FormatUint(f.PacketsBA, 10),
			strconv.FormatUint(f.BytesAB, 10), strconv.FormatUint(f.BytesBA, 10),
			f.TLSVer, f.TLSSNI, strconv.FormatBool(f.TLSDecrypted), f.TLSKeySource, fmtTime(f.FirstSeen), fmtTime(f.LastSeen),
		})
	}
	return rows
}

func protoRows(stats []model.ProtoStat) [][]string {
	rows := make([][]string, 0, len(stats))
	for _, s := range stats {
		rows = append(rows, []string{s.Protocol, strconv.Itoa(s.Packets), strconv.FormatUint(s.Bytes, 10), fmt.Sprintf("%.2f", s.PctBytes)})
	}
	return rows
}

func portRows(ports []model.NameCountPort) [][]string {
	rows := make([][]string, 0, len(ports))
	for _, p := range ports {
		rows = append(rows, []string{strconv.Itoa(p.Port), strconv.Itoa(p.Count)})
	}
	return rows
}

func joinInts(vals []int) string {
	parts := make([]string, 0, len(vals))
	for _, v := range vals {
		parts = append(parts, strconv.Itoa(v))
	}
	return strings.Join(parts, ";")
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
