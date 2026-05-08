package app

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestRuntimeConfigValidateAcceptsCoherentConfig(t *testing.T) {
	dir := t.TempDir()
	cfg := validRuntimeConfig(dir)

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestRuntimeConfigValidateReportsInvalidValues(t *testing.T) {
	cfg := validRuntimeConfig(t.TempDir())
	cfg.Workers.Count = 0
	cfg.Workers.BufferSize = -1
	cfg.Workers.SubmitTimeout = 0
	cfg.Output.Metrics.Port = "9090"
	cfg.Output.Metrics.Path = "metrics"
	cfg.Output.JSON.MaxAlertBytes = 0
	cfg.Detection.Behavioral.BruteForce.Threshold = 0

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() error = nil, want invalid configuration error")
	}
	message := err.Error()
	for _, want := range []string{
		"workers.count",
		"workers.buffer_size",
		"workers.submit_timeout_ms",
		"output.metrics.port",
		"output.metrics.path",
		"output.json.max_alert_bytes",
		"detection.behavioral.brute_force.threshold",
	} {
		if !strings.Contains(message, want) {
			t.Fatalf("Validate() error %q does not contain %q", message, want)
		}
	}
}

func TestRuntimeConfigValidateChecksWritableParents(t *testing.T) {
	cfg := validRuntimeConfig(t.TempDir())
	cfg.Output.JSON.Enabled = true
	cfg.Output.JSON.Path = filepath.Join(t.TempDir(), "missing", "alerts.jsonl")

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() error = nil, want missing parent directory error")
	}
	if !strings.Contains(err.Error(), "output.json.path parent directory") {
		t.Fatalf("Validate() error = %q, want output.json.path parent directory", err)
	}
}

func validRuntimeConfig(dir string) RuntimeConfig {
	return RuntimeConfig{
		Log: LogRuntimeConfig{
			Path:   filepath.Join(dir, "access.log"),
			Format: "combined",
			Checkpoint: CheckpointRuntimeConfig{
				Enabled: true,
				Path:    filepath.Join(dir, "checkpoint.json"),
			},
		},
		App: AppRuntimeConfig{
			ShutdownTimeoutSeconds: 5,
		},
		Workers: WorkerRuntimeConfig{
			Count:          2,
			BufferSize:     32,
			SubmitTimeout:  100,
			OverflowPath:   filepath.Join(dir, "overflow.jsonl"),
			QuarantinePath: filepath.Join(dir, "quarantine.jsonl"),
		},
		Detection: DetectionRuntimeConfig{
			Signatures: SignatureRuntimeConfig{Enabled: true},
			Behavioral: BehavioralRuntimeConfig{
				Enabled: true,
				BruteForce: BruteForceRuntimeConfig{
					Threshold:     5,
					WindowSeconds: 60,
					StatusCode:    401,
				},
				RateLimit: RateLimitRuntimeConfig{
					Threshold:     100,
					WindowSeconds: 10,
				},
			},
		},
		ThreatIntel: ThreatIntelRuntimeConfig{
			Enabled:                true,
			BloomFilterSize:        1000,
			BloomFalsePositiveRate: 0.01,
			DefaultTTLSeconds:      0,
		},
		Output: OutputRuntimeConfig{
			JSON: JSONOutputRuntimeConfig{
				Enabled:         true,
				Path:            filepath.Join(dir, "alerts.jsonl"),
				RedactSensitive: true,
				IncludeRawLog:   true,
				MaxAlertBytes:   65536,
			},
			Metrics: MetricsRuntimeConfig{
				Enabled: true,
				Port:    ":19090",
				Path:    "/metrics",
			},
			Dedup: DedupRuntimeConfig{
				Enabled:       true,
				WindowSeconds: 60,
			},
		},
		TUI: TUIRuntimeConfig{
			Enabled:            true,
			RefreshIntervalMS:  100,
			MaxAlertsDisplayed: 50,
		},
	}
}
