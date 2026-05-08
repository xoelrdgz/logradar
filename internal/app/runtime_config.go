package app

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"
)

type RuntimeConfig struct {
	Log         LogRuntimeConfig
	App         AppRuntimeConfig
	Workers     WorkerRuntimeConfig
	Detection   DetectionRuntimeConfig
	ThreatIntel ThreatIntelRuntimeConfig
	Output      OutputRuntimeConfig
	TUI         TUIRuntimeConfig
	Logging     LoggingRuntimeConfig
}

type AppRuntimeConfig struct {
	ShutdownTimeoutSeconds int
}

type LogRuntimeConfig struct {
	Path       string
	Format     string
	Checkpoint CheckpointRuntimeConfig
}

type CheckpointRuntimeConfig struct {
	Enabled bool
	Path    string
}

type WorkerRuntimeConfig struct {
	Count          int
	BufferSize     int
	SubmitTimeout  int
	OverflowPath   string
	QuarantinePath string
}

type DetectionRuntimeConfig struct {
	Signatures SignatureRuntimeConfig
	Behavioral BehavioralRuntimeConfig
	Allowlist  AllowlistRuntimeConfig
}

type AllowlistRuntimeConfig struct {
	IPs             []string
	CIDRs           []string
	PathPrefixes    []string
	UserAgentSubstr []string
}

type SignatureRuntimeConfig struct {
	Enabled   bool
	RulesFile string
	Patterns  map[string]string
}

type BehavioralRuntimeConfig struct {
	Enabled    bool
	BruteForce BruteForceRuntimeConfig
	RateLimit  RateLimitRuntimeConfig
}

type BruteForceRuntimeConfig struct {
	Threshold     int
	WindowSeconds int64
	StatusCode    int
}

type RateLimitRuntimeConfig struct {
	Threshold     int
	WindowSeconds int64
}

type ThreatIntelRuntimeConfig struct {
	Enabled                bool
	MaliciousIPsFile       string
	FeedFiles              []string
	BloomFilterSize        uint
	BloomFalsePositiveRate float64
	DefaultTTLSeconds      int
}

type OutputRuntimeConfig struct {
	JSON    JSONOutputRuntimeConfig
	Metrics MetricsRuntimeConfig
	Dedup   DedupRuntimeConfig
}

type DedupRuntimeConfig struct {
	Enabled       bool
	WindowSeconds int
}

type JSONOutputRuntimeConfig struct {
	Enabled         bool
	Path            string
	Stdout          bool
	RedactSensitive bool
	IncludeRawLog   bool
	MaxAlertBytes   int
}

type MetricsRuntimeConfig struct {
	Enabled bool
	Port    string
	Path    string
}

type TUIRuntimeConfig struct {
	Enabled            bool
	RefreshIntervalMS  int
	MaxAlertsDisplayed int
}

type LoggingRuntimeConfig struct {
	Level  string
	Format string
}

func LoadRuntimeConfig() RuntimeConfig {
	return RuntimeConfig{
		Log: LogRuntimeConfig{
			Path:   viper.GetString("log.path"),
			Format: viper.GetString("log.format"),
			Checkpoint: CheckpointRuntimeConfig{
				Enabled: viper.GetBool("log.checkpoint.enabled"),
				Path:    viper.GetString("log.checkpoint.path"),
			},
		},
		App: AppRuntimeConfig{
			ShutdownTimeoutSeconds: viper.GetInt("app.shutdown_timeout_seconds"),
		},
		Workers: WorkerRuntimeConfig{
			Count:          viper.GetInt("workers.count"),
			BufferSize:     viper.GetInt("workers.buffer_size"),
			SubmitTimeout:  viper.GetInt("workers.submit_timeout_ms"),
			OverflowPath:   viper.GetString("workers.overflow_path"),
			QuarantinePath: viper.GetString("workers.quarantine_path"),
		},
		Detection: DetectionRuntimeConfig{
			Signatures: SignatureRuntimeConfig{
				Enabled:   viper.GetBool("detection.signatures.enabled"),
				RulesFile: viper.GetString("detection.signatures.rules_file"),
				Patterns:  viper.GetStringMapString("detection.signatures.patterns"),
			},
			Behavioral: BehavioralRuntimeConfig{
				Enabled: viper.GetBool("detection.behavioral.enabled"),
				BruteForce: BruteForceRuntimeConfig{
					Threshold:     viper.GetInt("detection.behavioral.brute_force.threshold"),
					WindowSeconds: int64(viper.GetInt("detection.behavioral.brute_force.window_seconds")),
					StatusCode:    viper.GetInt("detection.behavioral.brute_force.status_code"),
				},
				RateLimit: RateLimitRuntimeConfig{
					Threshold:     viper.GetInt("detection.behavioral.rate_limit.threshold"),
					WindowSeconds: int64(viper.GetInt("detection.behavioral.rate_limit.window_seconds")),
				},
			},
			Allowlist: AllowlistRuntimeConfig{
				IPs:             viper.GetStringSlice("detection.allowlist.ips"),
				CIDRs:           viper.GetStringSlice("detection.allowlist.cidrs"),
				PathPrefixes:    viper.GetStringSlice("detection.allowlist.path_prefixes"),
				UserAgentSubstr: viper.GetStringSlice("detection.allowlist.user_agent_substrings"),
			},
		},
		ThreatIntel: ThreatIntelRuntimeConfig{
			Enabled:                viper.GetBool("threat_intel.enabled"),
			MaliciousIPsFile:       viper.GetString("threat_intel.malicious_ips_file"),
			FeedFiles:              viper.GetStringSlice("threat_intel.feed_files"),
			BloomFilterSize:        viper.GetUint("threat_intel.bloom_filter_size"),
			BloomFalsePositiveRate: viper.GetFloat64("threat_intel.bloom_false_positive_rate"),
			DefaultTTLSeconds:      viper.GetInt("threat_intel.default_ttl_seconds"),
		},
		Output: OutputRuntimeConfig{
			JSON: JSONOutputRuntimeConfig{
				Enabled:         viper.GetBool("output.json.enabled"),
				Path:            viper.GetString("output.json.path"),
				Stdout:          viper.GetBool("output.json.stdout"),
				RedactSensitive: viper.GetBool("output.json.redact_sensitive"),
				IncludeRawLog:   viper.GetBool("output.json.include_raw_log"),
				MaxAlertBytes:   viper.GetInt("output.json.max_alert_bytes"),
			},
			Metrics: MetricsRuntimeConfig{
				Enabled: viper.GetBool("output.metrics.enabled"),
				Port:    viper.GetString("output.metrics.port"),
				Path:    viper.GetString("output.metrics.path"),
			},
			Dedup: DedupRuntimeConfig{
				Enabled:       viper.GetBool("output.dedup.enabled"),
				WindowSeconds: viper.GetInt("output.dedup.window_seconds"),
			},
		},
		TUI: TUIRuntimeConfig{
			Enabled:            viper.GetBool("tui.enabled"),
			RefreshIntervalMS:  viper.GetInt("tui.refresh_interval_ms"),
			MaxAlertsDisplayed: viper.GetInt("tui.max_alerts_displayed"),
		},
		Logging: LoggingRuntimeConfig{
			Level:  viper.GetString("logging.level"),
			Format: viper.GetString("logging.format"),
		},
	}
}

func (cfg RuntimeConfig) Validate() error {
	var problems []string

	if cfg.Workers.Count <= 0 {
		problems = append(problems, "workers.count must be greater than 0")
	}
	if cfg.Workers.BufferSize <= 0 {
		problems = append(problems, "workers.buffer_size must be greater than 0")
	}
	const maxWorkerBufferSize = 1_000_000
	if cfg.Workers.BufferSize > maxWorkerBufferSize {
		problems = append(problems, fmt.Sprintf("workers.buffer_size must be <= %d", maxWorkerBufferSize))
	}
	if cfg.Workers.SubmitTimeout <= 0 {
		problems = append(problems, "workers.submit_timeout_ms must be greater than 0")
	}
	if cfg.App.ShutdownTimeoutSeconds <= 0 {
		problems = append(problems, "app.shutdown_timeout_seconds must be greater than 0")
	}

	if !isSupportedLogFormat(cfg.Log.Format) {
		problems = append(problems, fmt.Sprintf("log.format %q is not supported", cfg.Log.Format))
	}
	if cfg.Log.Checkpoint.Enabled {
		problems = appendWritablePathProblems(problems, "log.checkpoint.path", cfg.Log.Checkpoint.Path)
	}
	problems = appendWritablePathProblems(problems, "workers.overflow_path", cfg.Workers.OverflowPath)
	problems = appendWritablePathProblems(problems, "workers.quarantine_path", cfg.Workers.QuarantinePath)

	if cfg.Detection.Behavioral.Enabled {
		if cfg.Detection.Behavioral.BruteForce.Threshold <= 0 {
			problems = append(problems, "detection.behavioral.brute_force.threshold must be greater than 0")
		}
		if cfg.Detection.Behavioral.BruteForce.WindowSeconds <= 0 {
			problems = append(problems, "detection.behavioral.brute_force.window_seconds must be greater than 0")
		}
		if cfg.Detection.Behavioral.BruteForce.StatusCode < 0 || cfg.Detection.Behavioral.BruteForce.StatusCode > 599 {
			problems = append(problems, "detection.behavioral.brute_force.status_code must be between 0 and 599")
		}
		if cfg.Detection.Behavioral.RateLimit.Threshold <= 0 {
			problems = append(problems, "detection.behavioral.rate_limit.threshold must be greater than 0")
		}
		if cfg.Detection.Behavioral.RateLimit.WindowSeconds <= 0 {
			problems = append(problems, "detection.behavioral.rate_limit.window_seconds must be greater than 0")
		}
	}

	if cfg.ThreatIntel.Enabled {
		if cfg.ThreatIntel.BloomFilterSize == 0 {
			problems = append(problems, "threat_intel.bloom_filter_size must be greater than 0")
		}
		if cfg.ThreatIntel.BloomFalsePositiveRate <= 0 || cfg.ThreatIntel.BloomFalsePositiveRate >= 1 {
			problems = append(problems, "threat_intel.bloom_false_positive_rate must be greater than 0 and lower than 1")
		}
		if cfg.ThreatIntel.DefaultTTLSeconds < 0 {
			problems = append(problems, "threat_intel.default_ttl_seconds must be >= 0")
		}
	}

	if cfg.Output.JSON.Enabled {
		problems = appendWritablePathProblems(problems, "output.json.path", cfg.Output.JSON.Path)
	}
	if cfg.Output.JSON.MaxAlertBytes <= 0 {
		problems = append(problems, "output.json.max_alert_bytes must be greater than 0")
	}
	if cfg.Output.Dedup.Enabled && cfg.Output.Dedup.WindowSeconds <= 0 {
		problems = append(problems, "output.dedup.window_seconds must be greater than 0")
	}
	if cfg.Output.Metrics.Enabled {
		if err := validateListenAddress(cfg.Output.Metrics.Port); err != nil {
			problems = append(problems, "output.metrics.port "+err.Error())
		}
		if !strings.HasPrefix(cfg.Output.Metrics.Path, "/") {
			problems = append(problems, "output.metrics.path must start with /")
		}
	}

	if cfg.TUI.RefreshIntervalMS <= 0 {
		problems = append(problems, "tui.refresh_interval_ms must be greater than 0")
	}
	if cfg.TUI.MaxAlertsDisplayed <= 0 {
		problems = append(problems, "tui.max_alerts_displayed must be greater than 0")
	}

	if len(problems) > 0 {
		return fmt.Errorf("invalid configuration: %s", strings.Join(problems, "; "))
	}
	return nil
}

func isSupportedLogFormat(format string) bool {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "combined", "clf", "json", "auto", "autodetect", "auto-detect":
		return true
	default:
		return false
	}
}

func appendWritablePathProblems(problems []string, key, path string) []string {
	if path == "" {
		return problems
	}
	parent := filepath.Dir(path)
	info, err := os.Stat(parent)
	if err != nil {
		return append(problems, fmt.Sprintf("%s parent directory %q is not accessible: %v", key, parent, err))
	}
	if !info.IsDir() {
		return append(problems, fmt.Sprintf("%s parent path %q is not a directory", key, parent))
	}
	testFile, err := os.CreateTemp(parent, ".logradar-write-check-*")
	if err != nil {
		return append(problems, fmt.Sprintf("%s parent directory %q is not writable: %v", key, parent, err))
	}
	name := testFile.Name()
	if err := testFile.Close(); err != nil {
		return append(problems, fmt.Sprintf("%s write check close failed: %v", key, err))
	}
	_ = os.Remove(name)
	return problems
}

func validateListenAddress(addr string) error {
	if strings.TrimSpace(addr) == "" {
		return fmt.Errorf("must not be empty")
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("must be a valid listen address like :9090: %w", err)
	}
	if port == "" {
		return fmt.Errorf("must include a port")
	}
	if _, err := net.LookupPort("tcp", port); err != nil {
		return fmt.Errorf("has invalid port %q: %w", port, err)
	}
	if host != "" && net.ParseIP(host) == nil && host != "localhost" {
		return fmt.Errorf("has unsupported host %q", host)
	}
	return nil
}
