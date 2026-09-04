package diagram

import (
	"encoding/xml"
	"strings"
	"testing"

	"pcapdigger/internal/report/model"
)

func TestGenerateProducesValidSVG(t *testing.T) {
	r := &model.Report{
		Meta: model.Meta{SourceFile: "test.pcap"},
		Hosts: []model.Host{
			{IP: "10.0.0.1", IsPrivate: true},
			{IP: "1.2.3.4", IsPrivate: false, Geo: &model.GeoInfo{Country: "Testland"}},
		},
		Flows: []model.Flow{
			{HostA: "10.0.0.1", HostB: "1.2.3.4", BytesAB: 1000, BytesBA: 200},
		},
		Findings: []model.Finding{
			{Severity: "High", Hosts: []string{"10.0.0.1", "1.2.3.4"}},
		},
	}

	svg := Generate(r)
	if !strings.HasPrefix(svg, "<svg") {
		t.Fatalf("expected output to start with <svg, got: %.60s", svg)
	}
	if !strings.HasSuffix(strings.TrimSpace(svg), "</svg>") {
		t.Fatalf("expected output to end with </svg>")
	}

	var doc struct {
		XMLName xml.Name `xml:"svg"`
	}
	if err := xml.Unmarshal([]byte(svg), &doc); err != nil {
		t.Fatalf("generated SVG is not well-formed XML: %v", err)
	}

	if !strings.Contains(svg, "10.0.0.1") || !strings.Contains(svg, "1.2.3.4") {
		t.Errorf("expected both host IPs to appear in the diagram")
	}
	if !strings.Contains(svg, "flagged") {
		t.Errorf("expected the flow tied to a finding to use the 'flagged' style")
	}
}

func TestGenerateHandlesNoHosts(t *testing.T) {
	r := &model.Report{Meta: model.Meta{SourceFile: "empty.pcap"}}
	svg := Generate(r)
	if !strings.HasPrefix(svg, "<svg") {
		t.Fatalf("expected valid SVG even with no hosts/flows, got: %.60s", svg)
	}
}
