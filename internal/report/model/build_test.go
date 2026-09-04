package model

import (
	"testing"

	"pcapdigger/internal/security"
)

func mkFindings(severities ...security.Severity) []security.Finding {
	out := make([]security.Finding, 0, len(severities))
	for _, s := range severities {
		out = append(out, security.Finding{Severity: s})
	}
	return out
}

func TestRiskAssessmentNoFindings(t *testing.T) {
	ra := riskAssessment(nil)
	if ra.OverallRisk != "Minimal" || ra.Score != 0 {
		t.Errorf("expected Minimal/0 with no findings, got %+v", ra)
	}
}

func TestRiskAssessmentCriticalDominates(t *testing.T) {
	ra := riskAssessment(mkFindings(security.Critical, security.Low, security.Low))
	if ra.OverallRisk != "Critical" {
		t.Errorf("OverallRisk = %q, want Critical", ra.OverallRisk)
	}
	if ra.CriticalCount != 1 || ra.LowCount != 2 {
		t.Errorf("unexpected counts: %+v", ra)
	}
}

func TestRiskAssessmentScoreCapsAt100(t *testing.T) {
	ra := riskAssessment(mkFindings(security.Critical, security.Critical, security.Critical, security.Critical))
	if ra.Score != 100 {
		t.Errorf("Score = %d, want capped at 100", ra.Score)
	}
}

func TestRiskAssessmentMediumOnly(t *testing.T) {
	ra := riskAssessment(mkFindings(security.Medium, security.Medium))
	if ra.OverallRisk != "Medium" {
		t.Errorf("OverallRisk = %q, want Medium", ra.OverallRisk)
	}
}
