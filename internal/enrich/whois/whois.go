// Package whois implements a minimal raw WHOIS (RFC 3912, TCP/43) client
// with IANA-to-RIR referral chasing and on-disk JSON caching. No API key is
// required. Only used for a capped number of top external hosts, since
// each lookup is a live network round-trip.
package whois

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Record is the best-effort parsed result of a WHOIS lookup.
type Record struct {
	Query        string    `json:"query"`
	Registry     string    `json:"registry"`
	Organization string    `json:"organization,omitempty"`
	NetRange     string    `json:"net_range,omitempty"`
	Country      string    `json:"country,omitempty"`
	AbuseContact string    `json:"abuse_contact,omitempty"`
	Raw          string    `json:"raw"`
	QueriedAt    time.Time `json:"queried_at"`
}

// Client performs cached WHOIS lookups.
type Client struct {
	CacheDir string
	TTL      time.Duration
	Dial     func(network, address string) (net.Conn, error)
	Timeout  time.Duration
}

// NewClient builds a Client with the given cache directory and TTL.
func NewClient(cacheDir string, ttl time.Duration) *Client {
	return &Client{CacheDir: cacheDir, TTL: ttl, Timeout: 10 * time.Second}
}

// Lookup returns WHOIS info for ip, using the on-disk cache when fresh.
func (c *Client) Lookup(ip string) (*Record, error) {
	if rec, ok := c.readCache(ip); ok {
		return rec, nil
	}
	rec, err := c.query(ip)
	if err != nil {
		return nil, err
	}
	c.writeCache(ip, rec)
	return rec, nil
}

func (c *Client) cachePath(key string) string {
	return filepath.Join(c.CacheDir, sanitize(key)+".json")
}

func (c *Client) readCache(key string) (*Record, bool) {
	if c.CacheDir == "" {
		return nil, false
	}
	data, err := os.ReadFile(c.cachePath(key))
	if err != nil {
		return nil, false
	}
	var rec Record
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, false
	}
	if c.TTL > 0 && time.Since(rec.QueriedAt) > c.TTL {
		return nil, false
	}
	return &rec, true
}

func (c *Client) writeCache(key string, rec *Record) {
	if c.CacheDir == "" {
		return
	}
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return
	}
	_ = os.MkdirAll(c.CacheDir, 0o755)
	_ = os.WriteFile(c.cachePath(key), data, 0o644)
}

const ianaWHOIS = "whois.iana.org:43"

func (c *Client) query(ip string) (*Record, error) {
	dial := c.Dial
	if dial == nil {
		dial = net.Dial
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	first, err := rawQuery(dial, ianaWHOIS, ip, timeout)
	if err != nil {
		return nil, fmt.Errorf("query IANA WHOIS: %w", err)
	}
	server := referral(first)
	raw, registry := first, "iana"
	if server != "" && server != "whois.iana.org" {
		second, err := rawQuery(dial, server+":43", ip, timeout)
		if err == nil && strings.TrimSpace(second) != "" {
			raw, registry = second, server
		}
	}

	rec := parse(raw)
	rec.Query = ip
	rec.Registry = registry
	rec.Raw = raw
	rec.QueriedAt = time.Now().UTC()
	return rec, nil
}

func rawQuery(dial func(network, address string) (net.Conn, error), addr, query string, timeout time.Duration) (string, error) {
	conn, err := dial("tcp", addr)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte(query + "\r\n")); err != nil {
		return "", err
	}
	var sb strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			sb.Write(buf[:n])
		}
		if err != nil {
			break
		}
	}
	return sb.String(), nil
}

// referral extracts the "refer:" server from an IANA WHOIS response.
func referral(resp string) string {
	for _, line := range strings.Split(resp, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(line), "refer:") {
			return strings.TrimSpace(line[len("refer:"):])
		}
	}
	return ""
}

// parse does a best-effort, registry-agnostic key/value extraction across
// the common ARIN/RIPE/APNIC/LACNIC/AFRINIC WHOIS text formats.
func parse(raw string) *Record {
	rec := &Record{}
	orgFields := []string{"orgname:", "org-name:", "organization:", "descr:", "owner:"}
	netFields := []string{"netrange:", "cidr:", "inetnum:", "inet6num:"}
	countryFields := []string{"country:"}
	abuseFields := []string{"abuse-mailbox:", "orgabuseemail:", "abuse-c:"}

	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") {
			continue
		}
		lower := strings.ToLower(line)
		switch {
		case rec.Organization == "" && matchAny(lower, orgFields):
			rec.Organization = valueAfterColon(line)
		case rec.NetRange == "" && matchAny(lower, netFields):
			rec.NetRange = valueAfterColon(line)
		case rec.Country == "" && matchAny(lower, countryFields):
			rec.Country = valueAfterColon(line)
		case rec.AbuseContact == "" && matchAny(lower, abuseFields):
			rec.AbuseContact = valueAfterColon(line)
		}
	}
	return rec
}

func matchAny(lower string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return false
}

func valueAfterColon(line string) string {
	idx := strings.Index(line, ":")
	if idx == -1 {
		return ""
	}
	return strings.TrimSpace(line[idx+1:])
}

func sanitize(key string) string {
	return strings.NewReplacer(":", "_", "/", "_").Replace(key)
}
