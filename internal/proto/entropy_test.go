package proto

import "testing"

func TestShannonEntropy(t *testing.T) {
	cases := []struct {
		s       string
		wantLow bool // true if entropy should be clearly low
	}{
		{"aaaaaaaaaa", true},
		{"", true},
		{"x7fQ2pL9zR4mK1vN8cT6bH3jY0wD5s", false}, // high-entropy, tunneling-like label
	}
	for _, c := range cases {
		got := ShannonEntropy(c.s)
		if c.wantLow && got > 1.0 {
			t.Errorf("ShannonEntropy(%q) = %f, expected low entropy", c.s, got)
		}
		if !c.wantLow && got < 3.0 {
			t.Errorf("ShannonEntropy(%q) = %f, expected high entropy", c.s, got)
		}
	}
}
