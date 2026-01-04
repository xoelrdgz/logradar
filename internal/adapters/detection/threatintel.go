// Package detection implements threat intelligence integration for LogRadar.
//
// This file provides IP reputation checking against threat intelligence feeds
// with Bloom filter pre-check for efficient negative lookups and atomic pointer
// swaps for zero-downtime updates.
//
// Architecture:
//   - Bloom filter: O(1) probabilistic membership test (fast negative)
//   - HashMap: Exact threat info lookup after Bloom positive
//   - Atomic pointer: Zero-downtime reload without locks in hot path
//
// File Format:
//   - One IP per line
//   - Optional comma-separated source: "1.2.3.4,abuseipdb"
//   - Lines starting with # are comments
//
// Thread Safety: All methods are safe for concurrent access via atomic pointer.
package detection

import (
	"bufio"
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/rs/zerolog/log"

	"github.com/xoelrdgz/logradar/internal/domain"
	"github.com/xoelrdgz/logradar/pkg/bloomfilter"
)

// ThreatIntelData holds the threat intelligence data structures.
// Replaced atomically during reload operations.
type ThreatIntelData struct {
	bloom   *bloomfilter.BloomFilter      // Fast probabilistic lookup
	threats map[string]*domain.ThreatInfo // Exact IP -> ThreatInfo mapping
}

// ThreatIntelligence provides IP reputation checking with zero-downtime reloads.
//
// Lookup Flow:
//  1. Check Bloom filter (O(1), probabilistic)
//  2. If Bloom positive, check exact hashmap
//  3. Return ThreatInfo if found
//
// This two-stage approach ensures:
//   - Fast rejection of non-malicious IPs (most traffic)
//   - Zero false negatives (Bloom filter property)
//   - Minimal false positives (confirmed by hashmap)
type ThreatIntelligence struct {
	data     atomic.Pointer[ThreatIntelData] // Current data (atomically swapped)
	filepath string                          // Path to threat intel file
	loadMu   sync.Mutex                      // Serializes Load() calls
}

// ThreatIntelConfig configures threat intelligence loading.
type ThreatIntelConfig struct {
	Filepath          string  // Path to malicious IP list
	BloomSize         uint    // Expected number of IPs (for Bloom sizing)
	FalsePositiveRate float64 // Bloom filter FP rate (e.g., 0.01 = 1%)
}

// DefaultThreatIntelConfig returns production defaults.
//
// Defaults:
//   - Bloom filter sized for 10K IPs with 1% false positive rate
//   - Looks for threat intel at ./testdata/malicious_ips.txt
func DefaultThreatIntelConfig() ThreatIntelConfig {
	return ThreatIntelConfig{
		Filepath:          "./testdata/malicious_ips.txt",
		BloomSize:         10000,
		FalsePositiveRate: 0.01,
	}
}

// NewThreatIntelligence creates a threat intelligence checker.
//
// Parameters:
//   - config: File path and Bloom filter configuration
//
// Returns:
//   - Configured ThreatIntelligence (call Load() to populate)
//
// Note: Initializes with empty data. Call Load() to populate from file.
func NewThreatIntelligence(config ThreatIntelConfig) *ThreatIntelligence {
	ti := &ThreatIntelligence{
		filepath: config.Filepath,
	}

	initialData := &ThreatIntelData{
		bloom:   bloomfilter.New(config.BloomSize, config.FalsePositiveRate),
		threats: make(map[string]*domain.ThreatInfo),
	}
	ti.data.Store(initialData)

	return ti
}

// Load reads threat intelligence from the configured file.
//
// Parameters:
//   - ctx: Context for cancellation during file reading
//
// Returns:
//   - nil on success (including file not found - starts with empty list)
//   - Error if file read fails or path is suspicious
//
// Security:
//   - Validates file path to prevent directory traversal attacks
//   - Uses atomic pointer swap for zero-downtime updates
//   - Mutex prevents concurrent Load() calls from corrupting state
//
// File Format:
//   - "IP" or "IP,source" per line
//   - Empty lines and # comments are ignored
func (t *ThreatIntelligence) Load(ctx context.Context) error {
	t.loadMu.Lock()
	defer t.loadMu.Unlock()

	// Path traversal protection
	cleanPath := filepath.Clean(t.filepath)
	if strings.Contains(cleanPath, "..") {
		return fmt.Errorf("path traversal detected in threat intel file path: %q", t.filepath)
	}

	file, err := os.Open(cleanPath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Warn().Str("file", t.filepath).Msg("Threat intelligence file not found, starting with empty list")
			return nil
		}
		return err
	}
	defer file.Close()

	// Create new data structures
	newBloom := bloomfilter.New(10000, 0.01)
	newThreats := make(map[string]*domain.ThreatInfo)

	scanner := bufio.NewScanner(file)
	loadedCount := 0

	for scanner.Scan() {
		// Check for cancellation during large file loads
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse "IP" or "IP,source" format
		parts := strings.Split(line, ",")
		ipStr := strings.TrimSpace(parts[0])

		addr, err := netip.ParseAddr(ipStr)
		if err != nil {
			log.Debug().Str("ip", ipStr).Msg("Invalid IP in threat intel file, skipping")
			continue
		}

		newBloom.Add([]byte(ipStr))

		info := &domain.ThreatInfo{
			IP:         addr,
			Source:     "local",
			Confidence: 1.0,
			Categories: []string{"known_malicious"},
		}

		if len(parts) >= 2 {
			info.Source = strings.TrimSpace(parts[1])
		}

		newThreats[ipStr] = info
		loadedCount++
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	// Atomic swap for zero-downtime update
	newData := &ThreatIntelData{
		bloom:   newBloom,
		threats: newThreats,
	}
	t.data.Store(newData)

	log.Info().Int("count", loadedCount).Str("file", t.filepath).Msg("Loaded threat intelligence (zero-downtime)")
	return nil
}

// IsKnownMalicious checks if an IP is in the threat intelligence database.
//
// Parameters:
//   - ip: IP address string to check
//
// Returns:
//   - true if IP is known malicious
//   - false if not in database
//
// Performance: O(1) for negative lookups via Bloom filter.
// Lock-free for hot path performance.
func (t *ThreatIntelligence) IsKnownMalicious(ip string) bool {
	data := t.data.Load()

	// Fast path: Bloom filter negative means definitely not malicious
	if !data.bloom.Contains([]byte(ip)) {
		return false
	}

	// Confirm Bloom positive with exact lookup
	_, exists := data.threats[ip]
	return exists
}

// GetThreatInfo retrieves detailed threat intelligence for an IP.
//
// Parameters:
//   - ip: IP address string to lookup
//
// Returns:
//   - ThreatInfo with source, confidence, categories
//   - bool indicating if info was found
//
// Note: Call after IsKnownMalicious() returns true for efficiency.
func (t *ThreatIntelligence) GetThreatInfo(ip string) (*domain.ThreatInfo, bool) {
	data := t.data.Load()
	info, exists := data.threats[ip]
	return info, exists
}

// Count returns the number of IPs in the threat intelligence database.
func (t *ThreatIntelligence) Count() int {
	data := t.data.Load()
	return len(data.threats)
}

// AddMaliciousIP adds an IP to the threat intelligence database at runtime.
//
// Parameters:
//   - ip: IP address string to add
//   - info: Threat information for the IP
//
// Thread Safety: Uses mutex to serialize with Load() operations.
//
// Note: Creates a new threats map (copy-on-write) to ensure atomic visibility.
// Bloom filter is updated in-place (safe for This use case).
func (t *ThreatIntelligence) AddMaliciousIP(ip string, info *domain.ThreatInfo) {
	t.loadMu.Lock()
	defer t.loadMu.Unlock()

	oldData := t.data.Load()

	// Copy-on-write for threat map
	newThreats := make(map[string]*domain.ThreatInfo, len(oldData.threats)+1)
	for k, v := range oldData.threats {
		newThreats[k] = v
	}
	newThreats[ip] = info

	// Bloom filter is write-friendly (always safe to add)
	oldData.bloom.Add([]byte(ip))

	newData := &ThreatIntelData{
		bloom:   oldData.bloom,
		threats: newThreats,
	}
	t.data.Store(newData)
}

// ThreatIntelDetector wraps ThreatIntelligence as a ports.ThreatDetector.
// Implements the detector interface for integration with the worker pool.
type ThreatIntelDetector struct {
	intel *ThreatIntelligence // Underlying threat intelligence store
}

// NewThreatIntelDetector creates a detector wrapping threat intelligence.
//
// Parameters:
//   - intel: Configured ThreatIntelligence (should have Load() called)
//
// Returns:
//   - ThreatIntelDetector ready for Detect() calls
func NewThreatIntelDetector(intel *ThreatIntelligence) *ThreatIntelDetector {
	return &ThreatIntelDetector{intel: intel}
}

// Detect checks if the source IP is known malicious.
//
// Parameters:
//   - ctx: Context for cancellation (not used in this detector)
//   - entry: Log entry to analyze
//
// Returns:
//   - DetectionResult with Detected=true if IP is in threat database
//   - Details include source and categories from threat intel
//
// Alert Level: Always CRITICAL for known malicious IPs (RiskScore=10)
func (d *ThreatIntelDetector) Detect(ctx context.Context, entry *domain.LogEntry) domain.DetectionResult {
	if entry == nil || !entry.IP.IsValid() {
		return domain.NoDetection()
	}

	ip := entry.IP.String()

	if d.intel.IsKnownMalicious(ip) {
		info, _ := d.intel.GetThreatInfo(ip)

		details := map[string]interface{}{
			"source": info.Source,
		}
		if len(info.Categories) > 0 {
			details["categories"] = info.Categories
		}

		return domain.DetectionResult{
			Detected:   true,
			ThreatType: domain.ThreatTypeMaliciousIP,
			Level:      domain.AlertLevelCritical,
			RiskScore:  10,
			Message:    "Connection from known malicious IP",
			Details:    details,
		}
	}

	return domain.NoDetection()
}

// Name returns the detector identifier for logging and metrics.
func (d *ThreatIntelDetector) Name() string {
	return "threat_intel"
}

// Type returns the primary threat type this detector handles.
func (d *ThreatIntelDetector) Type() domain.ThreatType {
	return domain.ThreatTypeMaliciousIP
}
