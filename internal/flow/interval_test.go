package flow

import (
	"math"
	"testing"
	"time"
)

func TestIntervalStatsRegular(t *testing.T) {
	f := &Flow{}
	start := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	// Ten packets, exactly 10s apart: should read back as ~10s mean, ~0 CoV.
	for i := 0; i < 10; i++ {
		f.observeInterval(start.Add(time.Duration(i) * 10 * time.Second))
	}
	count, mean, cov := f.IntervalStats()
	if count != 9 {
		t.Fatalf("count = %d, want 9", count)
	}
	if math.Abs(mean-10) > 0.001 {
		t.Errorf("mean = %f, want ~10", mean)
	}
	if cov > 0.01 {
		t.Errorf("CoV = %f, want ~0 for perfectly regular intervals", cov)
	}
}

func TestIntervalStatsIrregular(t *testing.T) {
	f := &Flow{}
	start := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	offsets := []int{0, 1, 40, 41, 90, 300, 305}
	for _, o := range offsets {
		f.observeInterval(start.Add(time.Duration(o) * time.Second))
	}
	count, _, cov := f.IntervalStats()
	if count != len(offsets)-1 {
		t.Fatalf("count = %d, want %d", count, len(offsets)-1)
	}
	if cov < 0.5 {
		t.Errorf("CoV = %f, want high variance for bursty/irregular intervals", cov)
	}
}

func TestIntervalStatsInsufficientSamples(t *testing.T) {
	f := &Flow{}
	count, mean, cov := f.IntervalStats()
	if count != 0 || mean != 0 || cov != 0 {
		t.Errorf("expected zero stats with no samples, got count=%d mean=%f cov=%f", count, mean, cov)
	}
	f.observeInterval(time.Now())
	count, _, _ = f.IntervalStats()
	if count != 0 {
		t.Errorf("a single timestamp should produce zero intervals, got count=%d", count)
	}
}
