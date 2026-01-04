// Package app provides hot-reload configuration management for LogRadar.
//
// Hot-reload allows updating detection rules, thresholds, and threat intelligence
// without service restart. Changes to config files trigger atomic detector swap
// with graceful drain period for in-flight requests.
//
// Zero-Downtime Reload Architecture:
//
//	┌──────────────┐     ┌───────────────┐
//	│ Config File  │────▶│ Viper Watcher │
//	└──────────────┘     └───────────────┘
//	                            │
//	                            ▼
//	                     ┌──────────────┐
//	                     │ Validate     │
//	                     └──────────────┘
//	                            │
//	                            ▼
//	┌──────────────┐     ┌──────────────┐     ┌──────────────┐
//	│ Old Detectors│◀────│ Atomic Swap  │────▶│ New Detectors│
//	└──────────────┘     └──────────────┘     └──────────────┘
//	       │
//	       ▼ (after drain period)
//	┌──────────────┐
//	│ Stop/Cleanup │
//	└──────────────┘
package app

import (
	"context"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"

	"github.com/xoelrdgz/logradar/internal/ports"
)

// HotReloadConfig manages zero-downtime configuration updates.
//
// Features:
//   - Watches config file for changes (via fsnotify)
//   - Validates new configuration before applying
//   - Atomic detector swap using sync/atomic.Pointer
//   - Graceful drain period for old detectors
//
// Thread Safety: All methods are safe for concurrent access.
type HotReloadConfig struct {
	// detectors stores the current detector slice using atomic pointer
	// for lock-free read access in hot path
	detectors atomic.Pointer[[]ports.ThreatDetector]

	// detectorFactory creates new detector instances from configuration
	detectorFactory DetectorFactory

	configPath string        // Path to config file being watched
	enabled    bool          // Whether hot-reload is active
	mu         sync.Mutex    // Protects reload operation
	stopChan   chan struct{} // Shutdown signal
	stopOnce   sync.Once     // Ensures single close
}

// DetectorFactory is a function that creates detectors from current config.
// Called during hot-reload to instantiate new detector instances.
//
// Parameters:
//   - ctx: Context for cancellation during factory operation
//
// Returns:
//   - Slice of configured threat detectors
//   - Error if detector creation fails (reload aborted)
type DetectorFactory func(ctx context.Context) ([]ports.ThreatDetector, error)

// DetectionConfig aggregates all detection-related configuration options.
// Retrieved from Viper configuration for detector instantiation.
type DetectionConfig struct {
	// SignaturesEnabled controls signature-based detection
	SignaturesEnabled bool

	// BehavioralEnabled controls behavioral anomaly detection
	BehavioralEnabled   bool
	BruteForceThreshold int   // Failed auth count to trigger alert
	BruteForceWindow    int64 // Window in seconds
	RateLimitThreshold  int   // Requests per window to trigger alert
	RateLimitWindow     int64 // Window in seconds

	// ThreatIntelEnabled controls threat intelligence matching
	ThreatIntelEnabled bool
	ThreatIntelFile    string  // Path to malicious IP list
	BloomFilterSize    uint    // Bloom filter expected elements
	BloomFPRate        float64 // Bloom filter false positive rate
}

// HotReloadOptions configures hot-reload behavior.
type HotReloadOptions struct {
	ConfigPath      string          // Path to config file to watch
	DetectorFactory DetectorFactory // Factory for creating detectors
	DebounceDelay   time.Duration   // Delay before applying changes (default: 500ms)
}

// NewHotReloadConfig creates a hot-reload configuration manager.
//
// Parameters:
//   - opts: Configuration options including factory and paths
//
// Returns:
//   - Configured HotReloadConfig ready for StartWatching()
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

// SetDetectors atomically updates the detector slice.
// Called during initial setup and hot-reload operations.
//
// Parameters:
//   - detectors: New detector slice to activate
func (h *HotReloadConfig) SetDetectors(detectors []ports.ThreatDetector) {
	h.detectors.Store(&detectors)
}

// GetDetectors returns the currently active detector slice.
// Lock-free read via atomic pointer for hot-path performance.
//
// Returns:
//   - Current detector slice (may be nil before initialization)
func (h *HotReloadConfig) GetDetectors() []ports.ThreatDetector {
	ptr := h.detectors.Load()
	if ptr == nil {
		return nil
	}
	return *ptr
}

// StartWatching begins monitoring the config file for changes.
// Uses Viper's fsnotify integration for filesystem events.
//
// Parameters:
//   - ctx: Context for reload operations
//
// Behavior:
//   - Logs config changes
//   - Validates new configuration
//   - Atomically swaps detectors if valid
//   - Schedules old detector cleanup after drain period
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

// reload performs the actual configuration reload operation.
// Mutex-protected to prevent concurrent reloads.
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

// validateConfig checks configuration values are within acceptable ranges.
//
// Returns:
//   - nil if configuration is valid
//   - ConfigValidationError describing the invalid field
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

// drainPeriod is the time to wait before cleaning up old detectors.
// Allows in-flight requests using old detectors to complete.
const drainPeriod = 2 * time.Second

// cleanupOldDetectors stops old detectors after drain period.
// Runs in a separate goroutine to avoid blocking reload.
//
// Parameters:
//   - detectors: Old detector slice to clean up
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

// Stop terminates the hot-reload watcher.
// Idempotent via sync.Once protection.
func (h *HotReloadConfig) Stop() {
	h.stopOnce.Do(func() {
		close(h.stopChan)
		log.Info().Msg("Hot-reload config watcher stopped")
	})
}

// GetCurrentDetectionConfig reads detection settings from current Viper config.
//
// Returns:
//   - DetectionConfig populated from Viper values
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

// ConfigValidationError represents a configuration validation failure.
// Provides structured error information for logging and debugging.
type ConfigValidationError struct {
	Field  string      // Configuration key that failed validation
	Value  interface{} // The invalid value
	Reason string      // Human-readable explanation
}

// Error implements the error interface for ConfigValidationError.
func (e *ConfigValidationError) Error() string {
	return "config validation error: " + e.Field + " = " +
		formatValue(e.Value) + " - " + e.Reason
}

// formatValue converts a configuration value to string for error messages.
func formatValue(v interface{}) string {
	switch val := v.(type) {
	case int:
		return strconv.Itoa(val)
	case string:
		return val
	default:
		return "?"
	}
}

// ReloadableAnalyzer wraps Analyzer with hot-reload capability.
// Combines standard analysis with configuration watching.
type ReloadableAnalyzer struct {
	*Analyzer                  // Embedded base analyzer
	hotConfig *HotReloadConfig // Hot-reload manager
}

// NewReloadableAnalyzer creates an analyzer with hot-reload support.
//
// Parameters:
//   - reader: Log source
//   - detectors: Initial detector set
//   - alerters: Alert outputs
//   - hotConfig: Hot-reload manager (may be nil to disable)
//
// Returns:
//   - Configured ReloadableAnalyzer
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

// StartWithHotReload starts analysis and config watching.
//
// Parameters:
//   - ctx: Lifecycle context
//
// Returns:
//   - Error from Start() if startup fails
func (a *ReloadableAnalyzer) StartWithHotReload(ctx context.Context) error {
	if a.hotConfig != nil {
		a.hotConfig.StartWatching(ctx)
	}
	return a.Start(ctx)
}

// Stop terminates both analyzer and hot-reload watcher.
func (a *ReloadableAnalyzer) Stop() {
	if a.hotConfig != nil {
		a.hotConfig.Stop()
	}
	a.Analyzer.Stop()
}
