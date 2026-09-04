package proto

import "math"

// ShannonEntropy returns the Shannon entropy (bits per character) of s.
// High entropy relative to length is a common heuristic for DNS-tunneling /
// encoded-payload subdomains.
func ShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	n := float64(len(s))
	var h float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}
