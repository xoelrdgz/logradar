package app

import (
	"github.com/xoelrdgz/logradar/internal/domain"
)

type AlertScorer interface {
	Score(entry *domain.LogEntry, result domain.DetectionResult) domain.DetectionResult
}

type DefaultAlertScorer struct{}

func (DefaultAlertScorer) Score(entry *domain.LogEntry, result domain.DetectionResult) domain.DetectionResult {
	if !result.Detected {
		return result
	}
	result.RiskScore = scoreRisk(result.RiskScore)
	result.Level = levelForRisk(result.RiskScore, result.Level)
	result.Confidence = scoreConfidence(result.Confidence, result.RiskScore)
	return result
}

func scoreRisk(risk int) int {
	if risk < 1 {
		return 1
	}
	if risk > 10 {
		return 10
	}
	return risk
}

func levelForRisk(risk int, current domain.AlertLevel) domain.AlertLevel {
	if current != "" {
		return current
	}
	switch {
	case risk >= 8:
		return domain.AlertLevelCritical
	case risk >= 5:
		return domain.AlertLevelWarning
	default:
		return domain.AlertLevelInfo
	}
}

func scoreConfidence(confidence float64, risk int) float64 {
	if confidence > 0 {
		if confidence > 1 {
			return 1
		}
		return confidence
	}
	switch {
	case risk >= 9:
		return 0.95
	case risk >= 7:
		return 0.85
	case risk >= 5:
		return 0.7
	default:
		return 0.55
	}
}
