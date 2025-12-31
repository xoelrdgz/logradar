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

type ThreatIntelData struct {
	bloom   *bloomfilter.BloomFilter
	threats map[string]*domain.ThreatInfo
}

type ThreatIntelligence struct {
	data     atomic.Pointer[ThreatIntelData]
	filepath string
	loadMu   sync.Mutex
}

type ThreatIntelConfig struct {
	Filepath          string
	BloomSize         uint
	FalsePositiveRate float64
}

func DefaultThreatIntelConfig() ThreatIntelConfig {
	return ThreatIntelConfig{
		Filepath:          "./testdata/malicious_ips.txt",
		BloomSize:         10000,
		FalsePositiveRate: 0.01,
	}
}

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

func (t *ThreatIntelligence) Load(ctx context.Context) error {
	t.loadMu.Lock()
	defer t.loadMu.Unlock()
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

	newBloom := bloomfilter.New(10000, 0.01)
	newThreats := make(map[string]*domain.ThreatInfo)

	scanner := bufio.NewScanner(file)
	loadedCount := 0

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

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

	newData := &ThreatIntelData{
		bloom:   newBloom,
		threats: newThreats,
	}
	t.data.Store(newData)

	log.Info().Int("count", loadedCount).Str("file", t.filepath).Msg("Loaded threat intelligence (zero-downtime)")
	return nil
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

func (d *ThreatIntelDetector) Name() string {
	return "threat_intel"
}

func (d *ThreatIntelDetector) Type() domain.ThreatType {
	return domain.ThreatTypeMaliciousIP
}
