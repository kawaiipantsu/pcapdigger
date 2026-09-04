package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"pcapdigger/internal/analyze"
	"pcapdigger/internal/config"
	"pcapdigger/internal/diagram"
	"pcapdigger/internal/enrich/geoip"
	"pcapdigger/internal/enrich/whois"
	"pcapdigger/internal/flow"
	"pcapdigger/internal/pcapdata"
	csvreport "pcapdigger/internal/report/csv"
	jsonreport "pcapdigger/internal/report/json"
	mdreport "pcapdigger/internal/report/markdown"
	"pcapdigger/internal/report/model"
	"pcapdigger/internal/security"
	"pcapdigger/internal/tlskeys"
)

var allFormats = []string{"json", "csv", "markdown"}
var allReports = []string{"network", "security", "executive"}

type analyzeOptions struct {
	formats    []string
	reports    []string
	outputDir  string
	noEnrich   bool
	noWHOIS    bool
	whoisLimit int
	diagram    bool
	iocFile    string
	topN       int
	verbose    bool
	noDecrypt  bool
}

func newAnalyzeCmd() *cobra.Command {
	opts := &analyzeOptions{}
	var formatFlag, reportFlag string

	cmd := &cobra.Command{
		Use:   "analyze <capture.pcap|capture.pcapng>",
		Short: "Analyze a capture file and generate reports",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.formats = expandList(formatFlag, allFormats, map[string]string{"md": "markdown"})
			opts.reports = expandList(reportFlag, allReports, nil)
			return runAnalyze(args[0], opts)
		},
	}
	cmd.Flags().StringVar(&formatFlag, "format", "all", "output formats: json,csv,markdown (or \"all\")")
	cmd.Flags().StringVar(&reportFlag, "report", "all", "reports to generate: network,security,executive (or \"all\")")
	cmd.Flags().StringVarP(&opts.outputDir, "output", "o", "", "output directory (default: current directory)")
	cmd.Flags().BoolVar(&opts.noEnrich, "no-enrich", false, "disable all GeoIP/ASN/WHOIS enrichment")
	cmd.Flags().BoolVar(&opts.noWHOIS, "no-whois", false, "disable WHOIS lookups only")
	cmd.Flags().IntVar(&opts.whoisLimit, "whois-limit", 50, "max number of external hosts to WHOIS-lookup")
	cmd.Flags().BoolVar(&opts.diagram, "diagram", true, "generate an SVG flow diagram")
	cmd.Flags().StringVar(&opts.iocFile, "ioc-file", "", "optional IOC blocklist file (one IP or domain per line, optionally \"value,description\")")
	cmd.Flags().IntVar(&opts.topN, "top-n", 20, "row limit for top-talkers/top-ports/top-DNS tables")
	cmd.Flags().BoolVarP(&opts.verbose, "verbose", "v", false, "print progress to stderr")
	cmd.Flags().BoolVar(&opts.noDecrypt, "no-decrypt", false, "disable TLS decryption even if keys are available in ~/.config/pcapdigger/tls")
	return cmd
}

func runAnalyze(capturePath string, opts *analyzeOptions) error {
	logf := func(format string, args ...interface{}) {
		if opts.verbose {
			fmt.Fprintf(os.Stderr, format+"\n", args...)
		}
	}

	paths, err := resolvePaths()
	if err != nil {
		return err
	}
	cfg, err := config.Load(paths)
	if err != nil {
		return err
	}

	outDir := opts.outputDir
	if outDir == "" {
		outDir = cfg.Output.DefaultDir
	}
	if outDir == "" {
		outDir = "."
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}
	baseName := strings.TrimSuffix(filepath.Base(capturePath), filepath.Ext(capturePath))

	logf("opening %s ...", capturePath)
	reader, err := pcapdata.Open(capturePath)
	if err != nil {
		return err
	}
	defer reader.Close()

	builder := flow.New(filepath.Base(capturePath), reader.LinkType().String())
	tlsNote := ""
	if !opts.noDecrypt {
		keys, err := tlskeys.Load(paths.TLSKeysDir)
		if err != nil {
			return fmt.Errorf("load TLS keys: %w", err)
		}
		if keys.Empty() {
			tlsNote = "No TLS decryption secrets found in ~/.config/pcapdigger/tls (a keylog file, an RSA private key, or a PSK file) — encrypted flows were not decrypted."
		} else {
			builder.EnableTLSDecryption(keys)
			logf("loaded TLS decryption secrets: %d keylog sessions, %d RSA keys, %d PSKs", len(keys.Keylog), len(keys.RSAKeys), len(keys.PSKs))
		}
	} else {
		tlsNote = "TLS decryption was disabled for this run (--no-decrypt)."
	}

	packetCount := 0
	if err := reader.Walk(func(p pcapdata.Packet) error {
		builder.Add(p)
		packetCount++
		return nil
	}); err != nil {
		return fmt.Errorf("read capture: %w", err)
	}
	result := builder.Result()
	logf("processed %d packets, %d hosts, %d flows", packetCount, len(result.Hosts), len(result.Flows))
	if decrypted := countDecryptedFlows(result); decrypted > 0 {
		logf("decrypted %d TLS flow(s)", decrypted)
		tlsNote = fmt.Sprintf("%d TLS flow(s) were decrypted using locally-supplied keys.", decrypted)
	}

	summary := analyze.Compute(result, opts.topN)

	var iocs security.IOCSet
	if opts.iocFile != "" {
		iocs, err = loadIOCFile(opts.iocFile)
		if err != nil {
			return fmt.Errorf("load IOC file: %w", err)
		}
		logf("loaded %d IOC entries", len(iocs))
	}

	logf("running security detectors ...")
	findings := security.Run(&security.Context{Result: result, IOCs: iocs}, security.AllDetectors())
	logf("%d findings", len(findings))

	geoLookup, geoNote := setupGeoIP(paths, cfg, opts, logf)
	defer geoLookup.Close()

	whoisRecords, whoisNote := runWHOIS(paths, cfg, opts, summary, logf)

	report := model.Build(model.BuildInput{
		Result: result, Summary: summary, Findings: findings,
		Geo: geoLookup, WHOIS: whoisRecords, GeoIPNote: geoNote, WHOISNote: whoisNote, TLSNote: tlsNote,
	})

	if opts.diagram {
		svg := diagram.Generate(report)
		diagPath := filepath.Join(outDir, baseName+"-flow-diagram.svg")
		if err := os.WriteFile(diagPath, []byte(svg), 0o644); err != nil {
			return fmt.Errorf("write diagram: %w", err)
		}
		report.DiagramPath = diagPath
		logf("wrote flow diagram to %s", diagPath)
	}

	written, err := renderReports(report, opts, outDir, baseName)
	if err != nil {
		return err
	}

	fmt.Printf("Analysis complete: %s (%s risk, score %d/100)\n", capturePath, report.Risk.OverallRisk, report.Risk.Score)
	fmt.Printf("%d findings (%d critical, %d high, %d medium, %d low)\n",
		len(findings), report.Risk.CriticalCount, report.Risk.HighCount, report.Risk.MediumCount, report.Risk.LowCount)
	fmt.Println("Generated files:")
	sort.Strings(written)
	for _, f := range written {
		fmt.Printf("  %s\n", f)
	}
	return nil
}

func setupGeoIP(paths config.Paths, cfg config.Config, opts *analyzeOptions, logf func(string, ...interface{})) (*geoip.Lookup, string) {
	if opts.noEnrich || !cfg.Enrichment.GeoIP {
		return nil, ""
	}
	lookup, err := geoip.Open(paths.GeoCityDBPath(), paths.GeoASNDBPath())
	if err != nil {
		logf("geoip open failed: %v", err)
		return nil, "GeoIP lookup failed to initialize: " + err.Error()
	}
	if !lookup.Available() {
		return lookup, "No GeoIP database installed — run `pcapdigger update-db` (requires a MaxMind license key set via `pcapdigger config set maxmind.license_key ...`) to enable country/ASN enrichment."
	}
	return lookup, ""
}

func countDecryptedFlows(result *flow.Result) int {
	n := 0
	for _, fl := range result.Flows {
		if fl.TLS != nil && fl.TLS.Decrypted {
			n++
		}
	}
	return n
}

func runWHOIS(paths config.Paths, cfg config.Config, opts *analyzeOptions, summary *analyze.Summary, logf func(string, ...interface{})) (map[string]*whois.Record, string) {
	if opts.noEnrich || opts.noWHOIS || !cfg.Enrichment.WHOIS {
		return nil, "WHOIS enrichment was disabled for this run."
	}
	client := whois.NewClient(paths.WHOISDir, cfg.WHOISTTL())

	var targets []string
	for _, t := range summary.TopTalkers {
		if !t.IsPrivate {
			targets = append(targets, t.IP)
		}
	}
	limit := opts.whoisLimit
	if limit <= 0 {
		limit = 50
	}
	note := ""
	if len(targets) > limit {
		note = fmt.Sprintf("WHOIS was performed for the %d busiest external hosts only (out of %d); increase --whois-limit for full coverage.", limit, len(targets))
		targets = targets[:limit]
	}

	records := map[string]*whois.Record{}
	for _, ip := range targets {
		rec, err := client.Lookup(ip)
		if err != nil {
			logf("whois lookup failed for %s: %v", ip, err)
			continue
		}
		records[ip] = rec
	}
	logf("resolved WHOIS for %d/%d external hosts", len(records), len(targets))
	return records, note
}

type writerFunc func(r *model.Report, outDir, baseName string) ([]string, error)

func renderReports(report *model.Report, opts *analyzeOptions, outDir, baseName string) ([]string, error) {
	writers := map[string]map[string]writerFunc{
		"json": {
			"network": jsonreport.WriteNetwork, "security": jsonreport.WriteSecurity, "executive": jsonreport.WriteExecutive,
		},
		"csv": {
			"network": csvreport.WriteNetwork, "security": csvreport.WriteSecurity, "executive": csvreport.WriteExecutive,
		},
		"markdown": {
			"network": mdreport.WriteNetwork, "security": mdreport.WriteSecurity, "executive": mdreport.WriteExecutive,
		},
	}

	var written []string
	for _, format := range opts.formats {
		byReport, ok := writers[format]
		if !ok {
			return nil, fmt.Errorf("unknown format %q", format)
		}
		for _, rk := range opts.reports {
			fn, ok := byReport[rk]
			if !ok {
				return nil, fmt.Errorf("unknown report %q", rk)
			}
			paths, err := fn(report, outDir, baseName)
			if err != nil {
				return nil, fmt.Errorf("render %s/%s: %w", format, rk, err)
			}
			written = append(written, paths...)
		}
	}
	return written, nil
}

// expandList parses a comma-separated flag value, expanding "all" to the
// full option set and applying any aliases (e.g. "md" -> "markdown").
func expandList(value string, all []string, aliases map[string]string) []string {
	value = strings.TrimSpace(value)
	if value == "" || strings.EqualFold(value, "all") {
		out := make([]string, len(all))
		copy(out, all)
		return out
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.ToLower(strings.TrimSpace(p))
		if alias, ok := aliases[p]; ok {
			p = alias
		}
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// loadIOCFile reads a simple IOC blocklist: one entry per line, either
// "indicator" or "indicator,description". Blank lines and lines starting
// with # are ignored.
func loadIOCFile(path string) (security.IOCSet, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	set := security.IOCSet{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		indicator, desc, ok := strings.Cut(line, ",")
		indicator = strings.TrimSpace(indicator)
		if !ok {
			desc = "user-supplied indicator of compromise"
		}
		set[indicator] = strings.TrimSpace(desc)
	}
	return set, nil
}
