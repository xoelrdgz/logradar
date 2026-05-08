package app

import (
	"testing"

	"github.com/xoelrdgz/logradar/internal/domain"
)

func TestDefaultAlertScorerNormalizesDetectionResult(t *testing.T) {
	scored := (DefaultAlertScorer{}).Score(nil, domain.DetectionResult{
		Detected:   true,
		RiskScore:  99,
		Confidence: 2,
	})

	if scored.RiskScore != 10 {
		t.Fatalf("RiskScore = %d, want 10", scored.RiskScore)
	}
	if scored.Level != domain.AlertLevelCritical {
		t.Fatalf("Level = %s, want CRITICAL", scored.Level)
	}
	if scored.Confidence != 1 {
		t.Fatalf("Confidence = %f, want 1", scored.Confidence)
	}
}
