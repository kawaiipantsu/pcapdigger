package security

import "fmt"

const (
	beaconMinSamples = 5
	beaconMaxCoV     = 0.15 // low coefficient of variation = highly regular timing
	beaconMinSeconds = 1.0
	beaconMaxSeconds = 3600.0
)

// BeaconingDetector flags flows with unusually regular periodicity in their
// A->B packet timing to an external host — a common C2 beacon indicator.
type BeaconingDetector struct{}

func (d *BeaconingDetector) Name() string { return "beaconing" }

func (d *BeaconingDetector) Detect(ctx *Context) []Finding {
	var findings []Finding
	for _, fl := range ctx.Result.Flows {
		hostA, hostB := ctx.Result.Hosts[fl.IPA], ctx.Result.Hosts[fl.IPB]
		if hostA == nil || hostB == nil || !hostA.IsPrivate || hostB.IsPrivate {
			continue // only flag internal host beaconing out to an external host
		}
		count, mean, cov := fl.IntervalStats()
		if count >= beaconMinSamples && cov <= beaconMaxCoV && mean >= beaconMinSeconds && mean <= beaconMaxSeconds {
			findings = append(findings, Finding{
				Severity:       Medium,
				Category:       "Command & Control",
				Title:          fmt.Sprintf("Regular periodic connections from %s to %s", fl.IPA, fl.IPB),
				Description:    fmt.Sprintf("%s contacted %s at a highly regular interval (~%.1fs, coefficient of variation %.2f, %d samples), a pattern consistent with C2 beaconing.", fl.IPA, fl.IPB, mean, cov, count),
				Recommendation: fmt.Sprintf("Investigate the destination host/domain reputation; inspect the process on %s making these connections.", fl.IPA),
				Evidence:       []string{fmt.Sprintf("interval: %.1fs, CoV: %.2f, samples: %d", mean, cov, count)},
				Hosts:          []string{fl.IPA, fl.IPB},
				FirstSeen:      fl.FirstSeen, LastSeen: fl.LastSeen,
			})
		}
	}
	return findings
}
