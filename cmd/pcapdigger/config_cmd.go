package main

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"pcapdigger/internal/config"
)

func newConfigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Manage pcapdigger configuration (~/.config/pcapdigger/config.yaml)",
	}
	cmd.AddCommand(newConfigInitCmd())
	cmd.AddCommand(newConfigShowCmd())
	cmd.AddCommand(newConfigSetCmd())
	return cmd
}

func newConfigInitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Create a default config file if one doesn't already exist",
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := resolvePaths()
			if err != nil {
				return err
			}
			if p.Exists() {
				fmt.Printf("config already exists at %s\n", p.ConfigFile)
				return nil
			}
			if err := config.Save(p, config.Default()); err != nil {
				return err
			}
			fmt.Printf("wrote default config to %s\n", p.ConfigFile)
			return nil
		},
	}
}

func newConfigShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "Print the effective configuration and data paths",
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := resolvePaths()
			if err != nil {
				return err
			}
			cfg, err := config.Load(p)
			if err != nil {
				return err
			}
			fmt.Printf("config file:   %s\n", p.ConfigFile)
			fmt.Printf("data dir:      %s\n", p.DataDir)
			fmt.Printf("cache dir:     %s\n", p.CacheDir)
			fmt.Printf("geo city db:   %s\n", p.GeoCityDBPath())
			fmt.Printf("geo asn db:    %s\n", p.GeoASNDBPath())
			fmt.Printf("tls keys dir:  %s (drop keylog/*.log, RSA *.pem|*.key, or *.psk files here)\n", p.TLSKeysDir)
			fmt.Println()
			fmt.Printf("maxmind.account_id:   %s\n", mask(cfg.MaxMind.AccountID))
			fmt.Printf("maxmind.license_key:  %s\n", mask(cfg.MaxMind.LicenseKey))
			fmt.Printf("enrichment.enabled:   %v\n", cfg.Enrichment.Enabled)
			fmt.Printf("enrichment.whois:     %v\n", cfg.Enrichment.WHOIS)
			fmt.Printf("enrichment.geoip:     %v\n", cfg.Enrichment.GeoIP)
			fmt.Printf("report.default_formats: %v\n", cfg.Report.DefaultFormats)
			fmt.Printf("report.default_reports: %v\n", cfg.Report.DefaultReports)
			fmt.Printf("output.default_dir:   %s\n", cfg.Output.DefaultDir)
			fmt.Printf("cache.whois_ttl_hours: %d\n", cfg.Cache.WHOISTTLHours)
			return nil
		},
	}
}

func newConfigSetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "set <key> <value>",
		Short: "Set a configuration value (e.g. maxmind.license_key, maxmind.account_id)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := resolvePaths()
			if err != nil {
				return err
			}
			cfg, err := config.Load(p)
			if err != nil {
				return err
			}
			if err := applySet(&cfg, args[0], args[1]); err != nil {
				return err
			}
			if err := config.Save(p, cfg); err != nil {
				return err
			}
			fmt.Printf("set %s\n", args[0])
			return nil
		},
	}
}

func applySet(cfg *config.Config, key, value string) error {
	switch key {
	case "maxmind.account_id":
		cfg.MaxMind.AccountID = value
	case "maxmind.license_key":
		cfg.MaxMind.LicenseKey = value
	case "enrichment.enabled":
		return setBool(&cfg.Enrichment.Enabled, value)
	case "enrichment.whois":
		return setBool(&cfg.Enrichment.WHOIS, value)
	case "enrichment.geoip":
		return setBool(&cfg.Enrichment.GeoIP, value)
	case "output.default_dir":
		cfg.Output.DefaultDir = value
	case "cache.whois_ttl_hours":
		n, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("invalid integer %q: %w", value, err)
		}
		cfg.Cache.WHOISTTLHours = n
	case "report.default_formats":
		cfg.Report.DefaultFormats = splitCSV(value)
	case "report.default_reports":
		cfg.Report.DefaultReports = splitCSV(value)
	default:
		return fmt.Errorf("unknown config key %q", key)
	}
	return nil
}

func setBool(dst *bool, value string) error {
	b, err := strconv.ParseBool(value)
	if err != nil {
		return fmt.Errorf("invalid boolean %q: %w", value, err)
	}
	*dst = b
	return nil
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func mask(s string) string {
	if s == "" {
		return "(not set)"
	}
	if len(s) <= 4 {
		return "****"
	}
	return s[:2] + strings.Repeat("*", len(s)-4) + s[len(s)-2:]
}
