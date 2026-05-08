package detection

import (
	"bufio"
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/xoelrdgz/logradar/internal/domain"
	"github.com/xoelrdgz/logradar/pkg/bloomfilter"
)

type ThreatIntelData struct {
	bloom   *bloomfilter.BloomFilter
	threats map[string]*domain.ThreatInfo
}

type ThreatIntelligence struct {
	data       atomic.Pointer[ThreatIntelData]
	filepath   string
	feedFiles  []string
	defaultTTL time.Duration
	loadMu     sync.Mutex
}

type ThreatIntelConfig struct {
	Filepath          string
	FeedFiles         []string
	BloomSize         uint
	FalsePositiveRate float64
	DefaultTTL        time.Duration
}

func DefaultThreatIntelConfig() ThreatIntelConfig {
	return ThreatIntelConfig{
		Filepath:          "",
		BloomSize:         10000,
		FalsePositiveRate: 0.01,
		DefaultTTL:        0,
	}
}

func NewThreatIntelligence(config ThreatIntelConfig) *ThreatIntelligence {
	ti := &ThreatIntelligence{
		filepath:   config.Filepath,
		feedFiles:  config.FeedFiles,
		defaultTTL: config.DefaultTTL,
	}

	initialData := &ThreatIntelData{
		bloom:   bloomfilter.New(config.BloomSize, config.FalsePositiveRate),
		threats: make(map[string]*domain.ThreatInfo),
	}
	ti.data.Store(initialData)

	return ti
}

func (t *ThreatIntelligence) Load(ctx context.Context) error {
	t.loadMu.Lock()
	defer t.loadMu.Unlock()

	feedPaths := t.feedPaths()
	if len(feedPaths) == 0 {
		log.Info().Msg("Threat intelligence enabled without a feed path; starting with empty list")
		return nil
	}

	newBloom := bloomfilter.New(10000, 0.01)
	newThreats := make(map[string]*domain.ThreatInfo)
	loadedCount := 0

	for _, feedPath := range feedPaths {
		cleanPath := filepath.Clean(feedPath)
		if strings.Contains(cleanPath, "..") {
			return fmt.Errorf("path traversal detected in threat intel file path: %q", feedPath)
		}

		file, err := os.Open(cleanPath)
		if err != nil {
			if os.IsNotExist(err) {
				log.Warn().Str("file", feedPath).Msg("Threat intelligence file not found, skipping feed")
				continue
			}
			return err
		}

		count, err := t.loadFeed(ctx, file, newBloom, newThreats)
		_ = file.Close()
		if err != nil {
			return err
		}
		if count > 0 {
			log.Debug().Int("count", count).Str("file", feedPath).Msg("Loaded threat intelligence feed")
		}
		loadedCount += count
	}

	newData := &ThreatIntelData{
		bloom:   newBloom,
		threats: newThreats,
	}
	t.data.Store(newData)

	log.Info().Int("count", loadedCount).Int("feeds", len(feedPaths)).Msg("Loaded threat intelligence (zero-downtime)")
	return nil
}

func (t *ThreatIntelligence) feedPaths() []string {
	seen := make(map[string]struct{})
	var paths []string
	for _, path := range append([]string{t.filepath}, t.feedFiles...) {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		paths = append(paths, path)
	}
	return paths
}

func (t *ThreatIntelligence) loadFeed(ctx context.Context, file *os.File, bloom *bloomfilter.BloomFilter, threats map[string]*domain.ThreatInfo) (int, error) {
	scanner := bufio.NewScanner(file)
	loadedCount := 0

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return loadedCount, ctx.Err()
		default:
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		ipStr, info, expiresAt, err := parseThreatIntelLine(line, time.Now(), t.defaultTTL)
		if err != nil {
			log.Debug().Err(err).Str("line", line).Msg("Invalid threat intel line, skipping")
			continue
		}
		if !expiresAt.IsZero() && !expiresAt.After(time.Now()) {
			log.Debug().Str("ip", ipStr).Msg("Expired threat intel entry, skipping")
			continue
		}

		bloom.Add([]byte(ipStr))
		threats[ipStr] = info
		loadedCount++
	}

	if err := scanner.Err(); err != nil {
		return loadedCount, err
	}
	return loadedCount, nil
}

func (t *ThreatIntelligence) IsKnownMalicious(ip string) bool {
	data := t.data.Load()

	if !data.bloom.Contains([]byte(ip)) {
		return false
	}

	_, exists := data.threats[ip]
	return exists
}

func (t *ThreatIntelligence) GetThreatInfo(ip string) (*domain.ThreatInfo, bool) {
	data := t.data.Load()
	info, exists := data.threats[ip]
	return info, exists
}

func (t *ThreatIntelligence) Count() int {
	data := t.data.Load()
	return len(data.threats)
}

func (t *ThreatIntelligence) AddMaliciousIP(ip string, info *domain.ThreatInfo) {
	t.loadMu.Lock()
	defer t.loadMu.Unlock()

	oldData := t.data.Load()

	newThreats := make(map[string]*domain.ThreatInfo, len(oldData.threats)+1)
	for k, v := range oldData.threats {
		newThreats[k] = v
	}
	newThreats[ip] = info

	oldData.bloom.Add([]byte(ip))

	newData := &ThreatIntelData{
		bloom:   oldData.bloom,
		threats: newThreats,
	}
	t.data.Store(newData)
}

func parseThreatIntelLine(line string, now time.Time, defaultTTL time.Duration) (string, *domain.ThreatInfo, time.Time, error) {
	parts := strings.Split(line, ",")
	ipStr := strings.TrimSpace(parts[0])
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return "", nil, time.Time{}, err
	}

	info := &domain.ThreatInfo{
		IP:          addr,
		Source:      "local",
		Confidence:  1.0,
		Categories:  []string{"known_malicious"},
		LastUpdated: now.UTC(),
	}
	var expiresAt time.Time

	if len(parts) >= 2 && strings.TrimSpace(parts[1]) != "" {
		info.Source = strings.TrimSpace(parts[1])
	}
	if len(parts) >= 3 && strings.TrimSpace(parts[2]) != "" {
		confidence, err := strconv.ParseFloat(strings.TrimSpace(parts[2]), 64)
		if err != nil {
			return "", nil, time.Time{}, err
		}
		if confidence < 0 {
			confidence = 0
		}
		if confidence > 1 {
			confidence = 1
		}
		info.Confidence = confidence
	}
	if len(parts) >= 4 && strings.TrimSpace(parts[3]) != "" {
		categories := strings.FieldsFunc(parts[3], func(r rune) bool {
			return r == '|' || r == ';'
		})
		info.Categories = info.Categories[:0]
		for _, category := range categories {
			category = strings.TrimSpace(category)
			if category != "" {
				info.Categories = append(info.Categories, category)
			}
		}
		if len(info.Categories) == 0 {
			info.Categories = []string{"known_malicious"}
		}
	}
	if len(parts) >= 5 && strings.TrimSpace(parts[4]) != "" {
		expiresAt, err = parseExpiry(strings.TrimSpace(parts[4]), now)
		if err != nil {
			return "", nil, time.Time{}, err
		}
	} else if defaultTTL > 0 {
		expiresAt = now.Add(defaultTTL).UTC()
	}

	return ipStr, info, expiresAt, nil
}

func parseExpiry(raw string, now time.Time) (time.Time, error) {
	if ttl, err := time.ParseDuration(raw); err == nil {
		return now.Add(ttl).UTC(), nil
	}
	expiresAt, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, err
	}
	return expiresAt.UTC(), nil
}

type ThreatIntelDetector struct {
	intel *ThreatIntelligence
}

func NewThreatIntelDetector(intel *ThreatIntelligence) *ThreatIntelDetector {
	return &ThreatIntelDetector{intel: intel}
}

func (d *ThreatIntelDetector) Detect(ctx context.Context, entry *domain.LogEntry) domain.DetectionResult {
	if entry == nil || !entry.IP.IsValid() {
		return domain.NoDetection()
	}

	ip := entry.IP.String()

	if d.intel.IsKnownMalicious(ip) {
		info, _ := d.intel.GetThreatInfo(ip)

		details := map[string]interface{}{
			"source":     info.Source,
			"confidence": fmt.Sprintf("%.2f", info.Confidence),
		}
		if len(info.Categories) > 0 {
			details["categories"] = info.Categories
		}
		if !info.LastUpdated.IsZero() {
			details["last_updated"] = info.LastUpdated.Format(time.RFC3339)
		}

		return domain.DetectionResult{
			Detected:    true,
			ThreatType:  domain.ThreatTypeMaliciousIP,
			Level:       domain.AlertLevelCritical,
			RiskScore:   10,
			Message:     "Connection from known malicious IP",
			RuleID:      "threat_intel.malicious_ip",
			RuleVersion: "1",
			Confidence:  info.Confidence,
			Evidence: domain.Evidence{
				Field:    "source_ip",
				Fragment: ip,
			},
			Details: details,
		}
	}

	return domain.NoDetection()
}

func (d *ThreatIntelDetector) Name() string {
	return "threat_intel"
}

func (d *ThreatIntelDetector) Type() domain.ThreatType {
	return domain.ThreatTypeMaliciousIP
}
