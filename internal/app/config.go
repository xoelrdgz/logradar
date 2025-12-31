package app

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"

	"github.com/xoelrdgz/logradar/internal/ports"
)

type HotReloadConfig struct {
	detectors atomic.Pointer[[]ports.ThreatDetector]

	detectorFactory DetectorFactory

	configPath string
	enabled    bool
	mu         sync.Mutex
	stopChan   chan struct{}
	stopOnce   sync.Once
}

type DetectorFactory func(ctx context.Context) ([]ports.ThreatDetector, error)

type DetectionConfig struct {
	SignaturesEnabled bool

	BehavioralEnabled   bool
	BruteForceThreshold int
	BruteForceWindow    int64
	RateLimitThreshold  int
	RateLimitWindow     int64

	ThreatIntelEnabled bool
	ThreatIntelFile    string
	BloomFilterSize    uint
	BloomFPRate        float64
}

type HotReloadOptions struct {
	ConfigPath      string
	DetectorFactory DetectorFactory
	DebounceDelay   time.Duration
}

func NewHotReloadConfig(opts HotReloadOptions) *HotReloadConfig {
	if opts.DebounceDelay == 0 {
		opts.DebounceDelay = 500 * time.Millisecond
	}

	return &HotReloadConfig{
		detectorFactory: opts.DetectorFactory,
		configPath:      opts.ConfigPath,
		enabled:         true,
		stopChan:        make(chan struct{}),
	}
}

func (h *HotReloadConfig) SetDetectors(detectors []ports.ThreatDetector) {
	h.detectors.Store(&detectors)
}

func (h *HotReloadConfig) GetDetectors() []ports.ThreatDetector {
	ptr := h.detectors.Load()
	if ptr == nil {
		return nil
	}
	return *ptr
}

func (h *HotReloadConfig) StartWatching(ctx context.Context) {
	viper.OnConfigChange(func(e fsnotify.Event) {
		log.Info().
			Str("file", e.Name).
			Str("op", e.Op.String()).
			Msg("Config file changed, reloading...")

		h.reload(ctx)
	})

	viper.WatchConfig()
	log.Info().Str("config", h.configPath).Msg("Hot-reload config watching started")
}

func (h *HotReloadConfig) reload(ctx context.Context) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := viper.ReadInConfig(); err != nil {
		log.Error().Err(err).Msg("Failed to re-read config, keeping current configuration")
		return
	}

	if err := h.validateConfig(); err != nil {
		log.Error().Err(err).Msg("Invalid configuration, rejecting reload")
		return
	}
	if h.detectorFactory != nil {
		newDetectors, err := h.detectorFactory(ctx)
		if err != nil {
			log.Error().Err(err).Msg("Failed to create new detectors, keeping current")
			return
		}

		oldDetectors := h.GetDetectors()
		h.SetDetectors(newDetectors)

		go h.cleanupOldDetectors(oldDetectors)

		log.Info().
			Int("detector_count", len(newDetectors)).
			Msg("Configuration hot-reloaded successfully")
	}
}

func (h *HotReloadConfig) validateConfig() error {
	workerCount := viper.GetInt("workers.count")
	if workerCount < 1 || workerCount > 1000 {
		return &ConfigValidationError{Field: "workers.count", Value: workerCount, Reason: "must be between 1 and 1000"}
	}

	bufferSize := viper.GetInt("workers.buffer_size")
	if bufferSize < 100 || bufferSize > 10000000 {
		return &ConfigValidationError{Field: "workers.buffer_size", Value: bufferSize, Reason: "must be between 100 and 10M"}
	}

	bfThreshold := viper.GetInt("detection.behavioral.brute_force.threshold")
	if bfThreshold < 1 {
		return &ConfigValidationError{Field: "detection.behavioral.brute_force.threshold", Value: bfThreshold, Reason: "must be positive"}
	}

	rlThreshold := viper.GetInt("detection.behavioral.rate_limit.threshold")
	if rlThreshold < 1 {
		return &ConfigValidationError{Field: "detection.behavioral.rate_limit.threshold", Value: rlThreshold, Reason: "must be positive"}
	}

	return nil
}

const drainPeriod = 2 * time.Second

func (h *HotReloadConfig) cleanupOldDetectors(detectors []ports.ThreatDetector) {
	if detectors == nil {
		return
	}

	time.Sleep(drainPeriod)

	for _, d := range detectors {
		if stopper, ok := d.(interface{ Stop() }); ok {
			stopper.Stop()
		}
	}

	log.Debug().Int("count", len(detectors)).Msg("Old detectors cleaned up after drain period")
}

func (h *HotReloadConfig) Stop() {
	h.stopOnce.Do(func() {
		close(h.stopChan)
		log.Info().Msg("Hot-reload config watcher stopped")
	})
}

func GetCurrentDetectionConfig() DetectionConfig {
	return DetectionConfig{
		SignaturesEnabled:   viper.GetBool("detection.signatures.enabled"),
		BehavioralEnabled:   viper.GetBool("detection.behavioral.enabled"),
		BruteForceThreshold: viper.GetInt("detection.behavioral.brute_force.threshold"),
		BruteForceWindow:    int64(viper.GetInt("detection.behavioral.brute_force.window_seconds")),
		RateLimitThreshold:  viper.GetInt("detection.behavioral.rate_limit.threshold"),
		RateLimitWindow:     int64(viper.GetInt("detection.behavioral.rate_limit.window_seconds")),
		ThreatIntelEnabled:  viper.GetBool("threat_intel.enabled"),
		ThreatIntelFile:     viper.GetString("threat_intel.malicious_ips_file"),
		BloomFilterSize:     uint(viper.GetInt("threat_intel.bloom_filter_size")),
		BloomFPRate:         viper.GetFloat64("threat_intel.bloom_false_positive_rate"),
	}
}

type ConfigValidationError struct {
	Field  string
	Value  interface{}
	Reason string
}

func (e *ConfigValidationError) Error() string {
	return "config validation error: " + e.Field + " = " +
		formatValue(e.Value) + " - " + e.Reason
}

func formatValue(v interface{}) string {
	switch val := v.(type) {
	case int:
		return string(rune(val + '0'))
	case string:
		return val
	default:
		return "?"
	}
}

type ReloadableAnalyzer struct {
	*Analyzer
	hotConfig *HotReloadConfig
}

func NewReloadableAnalyzer(
	reader ports.LogReader,
	detectors []ports.ThreatDetector,
	alerters []ports.Alerter,
	hotConfig *HotReloadConfig,
) *ReloadableAnalyzer {
	analyzer := NewAnalyzer(reader, detectors, alerters)

	if hotConfig != nil {
		hotConfig.SetDetectors(detectors)
	}

	return &ReloadableAnalyzer{
		Analyzer:  analyzer,
		hotConfig: hotConfig,
	}
}

func (a *ReloadableAnalyzer) StartWithHotReload(ctx context.Context) error {
	if a.hotConfig != nil {
		a.hotConfig.StartWatching(ctx)
	}
	return a.Start(ctx)
}

func (a *ReloadableAnalyzer) Stop() {
	if a.hotConfig != nil {
		a.hotConfig.Stop()
	}
	a.Analyzer.Stop()
}
