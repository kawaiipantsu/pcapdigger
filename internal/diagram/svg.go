// Package diagram renders a simple SVG network flow diagram: hosts as
// boxes (internal hosts in a left column, external hosts in a right
// column) connected by cubic-Bézier spline paths representing the busiest
// conversations, so a reader gets a visual overview of assets and flows
// without needing a GUI packet tool.
package diagram

import (
	"fmt"
	"html"
	"math"
	"sort"
	"strings"

	"pcapdigger/internal/report/model"
)

const (
	maxNodesPerSide = 25
	maxFlowsDrawn   = 60
	nodeWidth       = 220
	nodeHeight      = 36
	rowGap          = 54
	colGapFromEdge  = 60
	topMargin       = 80
)

// Generate builds the SVG document for r, limited to the busiest flows and
// their endpoint hosts.
func Generate(r *model.Report) string {
	topFlows := r.Flows
	if len(topFlows) > maxFlowsDrawn {
		topFlows = topFlows[:maxFlowsDrawn]
	}

	involved := map[string]bool{}
	for _, fl := range topFlows {
		involved[fl.HostA] = true
		involved[fl.HostB] = true
	}

	byIP := map[string]model.Host{}
	for _, h := range r.Hosts {
		byIP[h.IP] = h
	}
	sevByIP := map[string]string{}
	for _, f := range r.Findings {
		for _, h := range f.Hosts {
			if rank(f.Severity) > rank(sevByIP[h]) {
				sevByIP[h] = f.Severity
			}
		}
	}

	var left, right []model.Host
	for ip := range involved {
		h, ok := byIP[ip]
		if !ok {
			h = model.Host{IP: ip}
		}
		if h.IsPrivate {
			left = append(left, h)
		} else {
			right = append(right, h)
		}
	}
	sort.Slice(left, func(i, j int) bool { return left[i].IP < left[j].IP })
	sort.Slice(right, func(i, j int) bool { return right[i].IP < right[j].IP })
	splitFallback := false
	if len(right) == 0 && len(left) > 1 {
		// All-internal (or all-external) capture: fall back to splitting
		// hosts evenly across both columns so the diagram isn't wasted
		// on a single, empty-sided layout.
		mid := (len(left) + 1) / 2
		left, right = left[:mid], left[mid:]
		splitFallback = true
	} else if len(left) == 0 && len(right) > 1 {
		mid := (len(right) + 1) / 2
		left, right = right[:mid], right[mid:]
		splitFallback = true
	}
	truncNote := ""
	if len(left) > maxNodesPerSide || len(right) > maxNodesPerSide {
		truncNote = fmt.Sprintf("Showing top %d busiest flows; some hosts/flows are omitted for legibility.", maxFlowsDrawn)
	}
	if len(left) > maxNodesPerSide {
		left = left[:maxNodesPerSide]
	}
	if len(right) > maxNodesPerSide {
		right = right[:maxNodesPerSide]
	}

	rows := maxInt(len(left), len(right))
	width := colGapFromEdge*2 + nodeWidth*2 + 400
	height := topMargin + rows*rowGap + 80

	pos := map[string][2]int{}
	leftX := colGapFromEdge
	rightX := width - colGapFromEdge - nodeWidth
	for i, h := range left {
		pos[h.IP] = [2]int{leftX, topMargin + i*rowGap}
	}
	for i, h := range right {
		pos[h.IP] = [2]int{rightX, topMargin + i*rowGap}
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" font-family="Helvetica,Arial,sans-serif">`, width, height)
	sb.WriteString(`<style>
.node-box{fill:#f4f6f8;stroke:#4a5568;stroke-width:1.5;rx:6;}
.node-box.internal{fill:#eaf3ff;stroke:#2b6cb0;}
.node-box.external{fill:#fff5f0;stroke:#c05621;}
.node-box.sev-critical{stroke:#c53030;stroke-width:2.5;}
.node-box.sev-high{stroke:#dd6b20;stroke-width:2.5;}
.node-box.sev-medium{stroke:#d69e2e;stroke-width:2;}
.node-label{font-size:11px;fill:#1a202c;}
.node-sub{font-size:9px;fill:#4a5568;}
.flow-path{fill:none;stroke:#718096;opacity:0.6;}
.flow-path.flagged{stroke:#c53030;opacity:0.85;stroke-dasharray:5,3;}
.title{font-size:16px;font-weight:bold;fill:#1a202c;}
.legend{font-size:10px;fill:#4a5568;}
</style>`)
	fmt.Fprintf(&sb, `<text x="20" y="28" class="title">pcapdigger flow diagram — %s</text>`, html.EscapeString(r.Meta.SourceFile))
	legend := "Left: internal hosts · Right: external hosts · Line thickness ~ bytes transferred · Red dashed = flow tied to a security finding"
	if splitFallback {
		legend = "All hosts share the same internal/external classification, so they are split across columns for layout only · Line thickness ~ bytes transferred · Red dashed = flow tied to a security finding"
	}
	fmt.Fprintf(&sb, `<text x="20" y="46" class="legend">%s</text>`, html.EscapeString(legend))
	if truncNote != "" {
		fmt.Fprintf(&sb, `<text x="20" y="60" class="legend">%s</text>`, html.EscapeString(truncNote))
	}

	// Flow splines, drawn before nodes so boxes sit on top.
	maxBytes := uint64(1)
	for _, fl := range topFlows {
		if b := fl.BytesAB + fl.BytesBA; b > maxBytes {
			maxBytes = b
		}
	}
	flagged := map[string]bool{}
	for _, f := range r.Findings {
		if len(f.Hosts) >= 2 {
			flagged[f.Hosts[0]+"|"+f.Hosts[1]] = true
			flagged[f.Hosts[1]+"|"+f.Hosts[0]] = true
		}
	}
	for _, fl := range topFlows {
		pa, ok1 := pos[fl.HostA]
		pb, ok2 := pos[fl.HostB]
		if !ok1 || !ok2 {
			continue
		}
		x1, y1 := pa[0]+nodeWidth, pa[1]+nodeHeight/2
		x2, y2 := pb[0], pb[1]+nodeHeight/2
		if pa[0] > pb[0] {
			x1, y1 = pa[0], pa[1]+nodeHeight/2
			x2, y2 = pb[0]+nodeWidth, pb[1]+nodeHeight/2
		}
		midX := (x1 + x2) / 2
		sw := strokeWidth(fl.BytesAB+fl.BytesBA, maxBytes)
		cls := "flow-path"
		if flagged[fl.HostA+"|"+fl.HostB] {
			cls = "flow-path flagged"
		}
		fmt.Fprintf(&sb, `<path class="%s" stroke-width="%.1f" d="M %d,%d C %d,%d %d,%d %d,%d" />`,
			cls, sw, x1, y1, midX, y1, midX, y2, x2, y2)
	}

	drawColumn := func(hosts []model.Host, cls string) {
		for _, h := range hosts {
			p := pos[h.IP]
			boxCls := "node-box " + cls
			if sev := sevByIP[h.IP]; sev != "" {
				boxCls += " " + sevClass(sev)
			}
			fmt.Fprintf(&sb, `<rect class="%s" x="%d" y="%d" width="%d" height="%d" rx="6"/>`, boxCls, p[0], p[1], nodeWidth, nodeHeight)
			label := h.IP
			if len(h.Hostnames) > 0 {
				label = h.Hostnames[0]
			}
			fmt.Fprintf(&sb, `<text x="%d" y="%d" class="node-label">%s</text>`, p[0]+8, p[1]+15, html.EscapeString(truncate(label, 28)))
			sub := h.IP
			if h.Geo != nil && h.Geo.Country != "" {
				sub += " · " + h.Geo.Country
			}
			fmt.Fprintf(&sb, `<text x="%d" y="%d" class="node-sub">%s</text>`, p[0]+8, p[1]+29, html.EscapeString(truncate(sub, 34)))
		}
	}
	drawColumn(left, "internal")
	drawColumn(right, "external")

	sb.WriteString(`</svg>`)
	return sb.String()
}

func rank(sev string) int {
	switch sev {
	case "Critical":
		return 4
	case "High":
		return 3
	case "Medium":
		return 2
	case "Low":
		return 1
	default:
		return 0
	}
}

func sevClass(sev string) string {
	switch sev {
	case "Critical":
		return "sev-critical"
	case "High":
		return "sev-high"
	case "Medium":
		return "sev-medium"
	default:
		return ""
	}
}

func strokeWidth(bytes, maxBytes uint64) float64 {
	if bytes == 0 {
		return 1
	}
	ratio := math.Log1p(float64(bytes)) / math.Log1p(float64(maxBytes))
	w := 1 + ratio*7
	if w < 1 {
		w = 1
	}
	return w
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
