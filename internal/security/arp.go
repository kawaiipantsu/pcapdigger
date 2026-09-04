package security

import (
	"fmt"
	"sort"
	"time"
)

const gratuitousBurstThreshold = 5
const gratuitousBurstWindow = 10 * time.Second

// ARPSpoofDetector flags conflicting IP->MAC claims and gratuitous ARP
// bursts, both classic indicators of ARP cache poisoning / spoofing.
type ARPSpoofDetector struct{}

func (d *ARPSpoofDetector) Name() string { return "arp-spoof" }

func (d *ARPSpoofDetector) Detect(ctx *Context) []Finding {
	var findings []Finding

	macsByIP := map[string]map[string]bool{}
	for _, ev := range ctx.Result.ARPEvents {
		if ev.SrcIP == "" || ev.SrcMAC == "" {
			continue
		}
		if macsByIP[ev.SrcIP] == nil {
			macsByIP[ev.SrcIP] = map[string]bool{}
		}
		macsByIP[ev.SrcIP][ev.SrcMAC] = true
	}
	for ip, macs := range macsByIP {
		if len(macs) < 2 {
			continue
		}
		list := make([]string, 0, len(macs))
		for m := range macs {
			list = append(list, m)
		}
		sort.Strings(list)
		findings = append(findings, Finding{
			Severity:       High,
			Category:       "Spoofing",
			Title:          fmt.Sprintf("Conflicting ARP mappings for %s", ip),
			Description:    fmt.Sprintf("IP %s was claimed by %d different MAC addresses over the capture window, which can indicate ARP cache poisoning/spoofing (or a misconfigured duplicate IP).", ip, len(macs)),
			Recommendation: "Verify which MAC legitimately owns this IP; enable dynamic ARP inspection / port security on switches.",
			Evidence:       []string{fmt.Sprintf("MACs observed: %v", list)},
			Hosts:          []string{ip},
		})
	}

	// gratuitous ARP bursts per source IP.
	grats := map[string][]time.Time{}
	for _, ev := range ctx.Result.ARPEvents {
		if ev.IsGratuitous {
			grats[ev.SrcIP] = append(grats[ev.SrcIP], ev.Timestamp)
		}
	}
	for ip, times := range grats {
		sort.Slice(times, func(i, j int) bool { return times[i].Before(times[j]) })
		if burst := maxBurst(times, gratuitousBurstWindow); burst >= gratuitousBurstThreshold {
			findings = append(findings, Finding{
				Severity:       Medium,
				Category:       "Spoofing",
				Title:          fmt.Sprintf("Gratuitous ARP burst from %s", ip),
				Description:    fmt.Sprintf("%s sent %d gratuitous ARP announcements within a %s window, which can be legitimate (failover/DHCP) or an ARP spoofing attempt.", ip, burst, gratuitousBurstWindow),
				Recommendation: "Correlate with known failover/HA events; investigate if unexpected.",
				Evidence:       []string{fmt.Sprintf("%d gratuitous ARP packets in burst", burst)},
				Hosts:          []string{ip},
			})
		}
	}

	return findings
}

// maxBurst returns the largest number of timestamps that fall within any
// sliding window of the given duration.
func maxBurst(sorted []time.Time, window time.Duration) int {
	best := 0
	i := 0
	for j := range sorted {
		for sorted[j].Sub(sorted[i]) > window {
			i++
		}
		if j-i+1 > best {
			best = j - i + 1
		}
	}
	return best
}
