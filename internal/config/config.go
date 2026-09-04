// Package config manages pcapdigger's on-disk configuration, data, and cache
// directories, which always live under the user's home directory
// (~/.config/pcapdigger by default, overridable via PCAPDIGGER_HOME).
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the persisted pcapdigger configuration.
type Config struct {
	MaxMind    MaxMindConfig    `yaml:"maxmind"`
	Enrichment EnrichmentConfig `yaml:"enrichment"`
	Report     ReportConfig     `yaml:"report"`
	Output     OutputConfig     `yaml:"output"`
	Cache      CacheConfig      `yaml:"cache"`
}

type MaxMindConfig struct {
	AccountID  string `yaml:"account_id"`
	LicenseKey string `yaml:"license_key"`
}

type EnrichmentConfig struct {
	Enabled bool `yaml:"enabled"`
	WHOIS   bool `yaml:"whois"`
	GeoIP   bool `yaml:"geoip"`
}

type ReportConfig struct {
	DefaultFormats []string `yaml:"default_formats"`
	DefaultReports []string `yaml:"default_reports"`
}

type OutputConfig struct {
	DefaultDir string `yaml:"default_dir"`
}

type CacheConfig struct {
	WHOISTTLHours int `yaml:"whois_ttl_hours"`
}

// Default returns a Config populated with sane defaults.
func Default() Config {
	return Config{
		Enrichment: EnrichmentConfig{Enabled: true, WHOIS: true, GeoIP: true},
		Report: ReportConfig{
			DefaultFormats: []string{"markdown"},
			DefaultReports: []string{"network", "security", "executive"},
		},
		Output: OutputConfig{DefaultDir: "."},
		Cache:  CacheConfig{WHOISTTLHours: 720},
	}
}

// WHOISTTL returns the configured WHOIS cache TTL as a duration.
func (c Config) WHOISTTL() time.Duration {
	h := c.Cache.WHOISTTLHours
	if h <= 0 {
		h = 720
	}
	return time.Duration(h) * time.Hour
}

// Paths resolves every on-disk location pcapdigger reads/writes.
type Paths struct {
	Home       string // ~/.config/pcapdigger (or PCAPDIGGER_HOME)
	ConfigFile string // Home/config.yaml
	DataDir    string // Home/data (mmdb files, manifest)
	CacheDir   string // Home/cache
	WHOISDir   string // Home/cache/whois
	TLSKeysDir string // Home/tls (keylog/RSA-key/PSK files for TLS decryption)
}

// ResolvePaths computes Paths, honoring PCAPDIGGER_HOME as an override for
// the whole config/data/cache root (used mainly by tests).
func ResolvePaths() (Paths, error) {
	root := os.Getenv("PCAPDIGGER_HOME")
	if root == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return Paths{}, fmt.Errorf("resolve home directory: %w", err)
		}
		root = filepath.Join(home, ".config", "pcapdigger")
	}
	return Paths{
		Home:       root,
		ConfigFile: filepath.Join(root, "config.yaml"),
		DataDir:    filepath.Join(root, "data"),
		CacheDir:   filepath.Join(root, "cache"),
		WHOISDir:   filepath.Join(root, "cache", "whois"),
		TLSKeysDir: filepath.Join(root, "tls"),
	}, nil
}

// EnsureDirs creates every directory pcapdigger needs, if missing.
func (p Paths) EnsureDirs() error {
	for _, d := range []string{p.Home, p.DataDir, p.CacheDir, p.WHOISDir, p.TLSKeysDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return fmt.Errorf("create %s: %w", d, err)
		}
	}
	return nil
}

// Load reads the config file at p.ConfigFile, returning defaults merged with
// nothing if the file does not exist yet.
func Load(p Paths) (Config, error) {
	cfg := Default()
	data, err := os.ReadFile(p.ConfigFile)
	if os.IsNotExist(err) {
		return cfg, nil
	}
	if err != nil {
		return cfg, fmt.Errorf("read config: %w", err)
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("parse config %s: %w", p.ConfigFile, err)
	}
	return cfg, nil
}

// Save writes cfg to p.ConfigFile, creating parent directories as needed.
func Save(p Paths, cfg Config) error {
	if err := p.EnsureDirs(); err != nil {
		return err
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	if err := os.WriteFile(p.ConfigFile, data, 0o600); err != nil {
		return fmt.Errorf("write config %s: %w", p.ConfigFile, err)
	}
	return nil
}

// Exists reports whether a config file has already been written.
func (p Paths) Exists() bool {
	_, err := os.Stat(p.ConfigFile)
	return err == nil
}

// GeoCityDBPath returns the expected on-disk path of the GeoLite2-City mmdb.
func (p Paths) GeoCityDBPath() string {
	return filepath.Join(p.DataDir, "GeoLite2-City.mmdb")
}

// GeoASNDBPath returns the expected on-disk path of the GeoLite2-ASN mmdb.
func (p Paths) GeoASNDBPath() string {
	return filepath.Join(p.DataDir, "GeoLite2-ASN.mmdb")
}

// ManifestPath returns the path of the small JSON manifest recording when
// the GeoIP databases were last updated.
func (p Paths) ManifestPath() string {
	return filepath.Join(p.DataDir, "manifest.json")
}

// WHOISCachePath returns the cache file path for a given lookup key (IP).
func (p Paths) WHOISCachePath(key string) string {
	return filepath.Join(p.WHOISDir, key+".json")
}
