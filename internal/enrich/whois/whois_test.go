package whois

import "testing"

func TestParseARINStyle(t *testing.T) {
	raw := `#
# ARIN WHOIS data
#
NetRange:       93.184.216.0 - 93.184.216.255
CIDR:           93.184.216.0/24
OrgName:        Edgecast Inc.
Country:        US
OrgAbuseEmail:  abuse@example.com

# end
`
	rec := parse(raw)
	if rec.Organization != "Edgecast Inc." {
		t.Errorf("Organization = %q, want %q", rec.Organization, "Edgecast Inc.")
	}
	if rec.NetRange != "93.184.216.0 - 93.184.216.255" {
		t.Errorf("NetRange = %q", rec.NetRange)
	}
	if rec.Country != "US" {
		t.Errorf("Country = %q, want %q", rec.Country, "US")
	}
	if rec.AbuseContact != "abuse@example.com" {
		t.Errorf("AbuseContact = %q", rec.AbuseContact)
	}
}

func TestParseRIPEStyle(t *testing.T) {
	raw := `% RIPE database
inetnum:        193.0.0.0 - 193.0.7.255
descr:          RIPE NCC
country:        NL
abuse-mailbox:  abuse@ripe.example
`
	rec := parse(raw)
	if rec.Organization != "RIPE NCC" {
		t.Errorf("Organization = %q, want %q", rec.Organization, "RIPE NCC")
	}
	if rec.Country != "NL" {
		t.Errorf("Country = %q", rec.Country)
	}
	if rec.AbuseContact != "abuse@ripe.example" {
		t.Errorf("AbuseContact = %q", rec.AbuseContact)
	}
}

func TestReferral(t *testing.T) {
	resp := "% IANA WHOIS\nrefer:        whois.arin.net\n\n"
	if got := referral(resp); got != "whois.arin.net" {
		t.Errorf("referral() = %q, want %q", got, "whois.arin.net")
	}
}
