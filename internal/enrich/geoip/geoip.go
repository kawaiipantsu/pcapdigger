// Package geoip performs offline GeoIP/ASN lookups against locally
// downloaded MaxMind GeoLite2 .mmdb files (see internal/enrich/updatedb).
package geoip

import (
	"fmt"
	"net"
	"os"

	geoip2 "github.com/oschwald/geoip2-golang"
)

// Info is the enrichment result for a single IP address.
type Info struct {
	Country     string
	CountryCode string
	City        string
	Latitude    float64
	Longitude   float64
	ASN         uint
	ASOrg       string
}

// Lookup resolves Geo/ASN info against local mmdb files. Either db path may
// be missing (empty databases are handled gracefully by Available()).
type Lookup struct {
	city *geoip2.Reader
	asn  *geoip2.Reader
}

// Open opens the city and ASN databases at the given paths. A path that
// does not exist on disk is skipped without error (that portion of
// enrichment is simply unavailable), so the tool still runs without any
// GeoIP database installed.
func Open(cityPath, asnPath string) (*Lookup, error) {
	l := &Lookup{}
	if fileExists(cityPath) {
		r, err := geoip2.Open(cityPath)
		if err != nil {
			return nil, fmt.Errorf("open GeoIP city db %s: %w", cityPath, err)
		}
		l.city = r
	}
	if fileExists(asnPath) {
		r, err := geoip2.Open(asnPath)
		if err != nil {
			return nil, fmt.Errorf("open GeoIP ASN db %s: %w", asnPath, err)
		}
		l.asn = r
	}
	return l, nil
}

// Available reports whether at least one database was successfully opened.
func (l *Lookup) Available() bool {
	return l != nil && (l.city != nil || l.asn != nil)
}

// Close releases the underlying mmdb file handles.
func (l *Lookup) Close() {
	if l == nil {
		return
	}
	if l.city != nil {
		l.city.Close()
	}
	if l.asn != nil {
		l.asn.Close()
	}
}

// Lookup returns enrichment info for ip, or nil if no database covers it
// (private/reserved ranges are never present in GeoLite2, and lookups
// simply return an empty record in that case).
func (l *Lookup) Lookup(ip string) *Info {
	if l == nil || (l.city == nil && l.asn == nil) {
		return nil
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return nil
	}
	info := &Info{}
	found := false
	if l.city != nil {
		if rec, err := l.city.City(parsed); err == nil && rec != nil {
			info.Country = rec.Country.Names["en"]
			info.CountryCode = rec.Country.IsoCode
			info.City = rec.City.Names["en"]
			info.Latitude = rec.Location.Latitude
			info.Longitude = rec.Location.Longitude
			if info.Country != "" || info.City != "" {
				found = true
			}
		}
	}
	if l.asn != nil {
		if rec, err := l.asn.ASN(parsed); err == nil && rec != nil {
			info.ASN = rec.AutonomousSystemNumber
			info.ASOrg = rec.AutonomousSystemOrganization
			if info.ASN != 0 {
				found = true
			}
		}
	}
	if !found {
		return nil
	}
	return info
}

func fileExists(path string) bool {
	if path == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}
