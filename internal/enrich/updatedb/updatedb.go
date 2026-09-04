// Package updatedb downloads and installs the MaxMind GeoLite2-City and
// GeoLite2-ASN databases into the local pcapdigger data directory, using a
// license key supplied via config. No other network enrichment ever
// happens automatically outside of this explicit, user-triggered step.
package updatedb

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const baseURL = "https://download.maxmind.com/geoip/databases/"

// Manifest records when each database was last updated.
type Manifest struct {
	Editions map[string]EditionInfo `json:"editions"`
}

// EditionInfo is the manifest entry for one downloaded database edition.
type EditionInfo struct {
	UpdatedAt time.Time `json:"updated_at"`
	SHA256    string    `json:"sha256"`
}

// Credentials are the MaxMind account credentials required to download
// GeoLite2 databases.
type Credentials struct {
	AccountID  string
	LicenseKey string
}

// Options controls where databases are installed and how the manifest is
// tracked.
type Options struct {
	DataDir      string
	ManifestPath string
	Editions     []string // e.g. {"GeoLite2-City", "GeoLite2-ASN"}
	HTTPClient   *http.Client
}

// Update downloads every requested edition and installs it into DataDir,
// updating the manifest. Progress/status lines are written to log for each
// edition processed.
func Update(creds Credentials, opts Options, log func(string)) error {
	if creds.AccountID == "" || creds.LicenseKey == "" {
		return fmt.Errorf("MaxMind account_id and license_key must be set (pcapdigger config set maxmind.account_id / maxmind.license_key)")
	}
	if err := os.MkdirAll(opts.DataDir, 0o755); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}
	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Minute}
	}
	manifest, err := loadManifest(opts.ManifestPath)
	if err != nil {
		return err
	}

	for _, edition := range opts.Editions {
		if log != nil {
			log(fmt.Sprintf("downloading %s ...", edition))
		}
		data, sum, err := download(client, creds, edition)
		if err != nil {
			return fmt.Errorf("download %s: %w", edition, err)
		}
		mmdbName, err := extractMMDB(data, opts.DataDir, edition)
		if err != nil {
			return fmt.Errorf("extract %s: %w", edition, err)
		}
		manifest.Editions[edition] = EditionInfo{UpdatedAt: time.Now().UTC(), SHA256: sum}
		if log != nil {
			log(fmt.Sprintf("installed %s -> %s", edition, mmdbName))
		}
	}

	return saveManifest(opts.ManifestPath, manifest)
}

func download(client *http.Client, creds Credentials, edition string) (data []byte, sha256Hex string, err error) {
	url := fmt.Sprintf("%s%s/download?suffix=tar.gz", baseURL, edition)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, "", err
	}
	req.SetBasicAuth(creds.AccountID, creds.LicenseKey)

	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, "", fmt.Errorf("unexpected status %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	data, err = io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(data)
	return data, hex.EncodeToString(sum[:]), nil
}

// extractMMDB unpacks the .tar.gz archive in memory and writes the single
// .mmdb file it contains to dataDir/<edition>.mmdb.
func extractMMDB(archiveData []byte, dataDir, edition string) (string, error) {
	gz, err := gzip.NewReader(bytes.NewReader(archiveData))
	if err != nil {
		return "", fmt.Errorf("gunzip: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	destName := edition + ".mmdb"
	dest := filepath.Join(dataDir, destName)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return "", fmt.Errorf("archive did not contain a .mmdb file")
		}
		if err != nil {
			return "", err
		}
		if !strings.HasSuffix(hdr.Name, ".mmdb") {
			continue
		}
		tmp := dest + ".tmp"
		f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
		if err != nil {
			return "", err
		}
		if _, err := io.Copy(f, tr); err != nil {
			f.Close()
			os.Remove(tmp)
			return "", err
		}
		f.Close()
		if err := os.Rename(tmp, dest); err != nil {
			return "", err
		}
		return destName, nil
	}
}

func loadManifest(path string) (*Manifest, error) {
	m := &Manifest{Editions: map[string]EditionInfo{}}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return m, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	if err := json.Unmarshal(data, m); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	if m.Editions == nil {
		m.Editions = map[string]EditionInfo{}
	}
	return m, nil
}

func saveManifest(path string, m *Manifest) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// LoadManifest exposes the manifest reader for status/inspection commands.
func LoadManifest(path string) (*Manifest, error) {
	return loadManifest(path)
}
