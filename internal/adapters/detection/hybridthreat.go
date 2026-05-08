package detection

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/rs/zerolog/log"
	bolt "go.etcd.io/bbolt"

	"github.com/xoelrdgz/logradar/internal/domain"
	"github.com/xoelrdgz/logradar/pkg/bloomfilter"
)

type HybridThreatStore struct {
	bloom      *bloomfilter.BloomFilter
	db         *bolt.DB
	dbPath     string
	count      atomic.Int64
	mu         sync.RWMutex
	bloomMu    sync.RWMutex
	hotCache   map[string]*domain.ThreatInfo
	hotCacheMu sync.RWMutex
}

var ThreatBucket = []byte("threats")

type HybridThreatConfig struct {
	DBPath            string
	ExpectedItems     uint
	FalsePositiveRate float64
	HotCacheSize      int
}

func DefaultHybridThreatConfig() HybridThreatConfig {
	return HybridThreatConfig{
		DBPath:            "./data/threatintel.db",
		ExpectedItems:     1000000,
		FalsePositiveRate: 0.01,
		HotCacheSize:      1000,
	}
}

func NewHybridThreatStore(config HybridThreatConfig) (*HybridThreatStore, error) {
	dir := filepath.Dir(config.DBPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create db directory: %w", err)
	}

	db, err := bolt.Open(config.DBPath, 0600, &bolt.Options{
		NoSync:     false,
		NoGrowSync: true,
		ReadOnly:   false,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to open bolt db: %w", err)
	}

	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(ThreatBucket)
		return err
	})
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create bucket: %w", err)
	}

	var count int64
	db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(ThreatBucket)
		if b != nil {
			count = int64(b.Stats().KeyN)
		}
		return nil
	})

	store := &HybridThreatStore{
		bloom:    bloomfilter.New(config.ExpectedItems, config.FalsePositiveRate),
		db:       db,
		dbPath:   config.DBPath,
		hotCache: make(map[string]*domain.ThreatInfo, config.HotCacheSize),
	}
	store.count.Store(count)

	if count > 0 {
		store.rebuildBloom()
	}

	log.Info().
		Str("db_path", config.DBPath).
		Int64("entries", count).
		Uint("bloom_size", config.ExpectedItems).
		Msg("Hybrid threat store initialized")

	return store, nil
}

func (s *HybridThreatStore) rebuildBloom() error {
	return s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(ThreatBucket)
		if b == nil {
			return nil
		}

		s.bloomMu.Lock()
		defer s.bloomMu.Unlock()

		return b.ForEach(func(k, _ []byte) error {
			s.bloom.Add(k)
			return nil
		})
	})
}

func (s *HybridThreatStore) LoadFromFile(ctx context.Context, filepath string) error {
	file, err := os.Open(filepath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Warn().Str("file", filepath).Msg("Threat file not found")
			return nil
		}
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	batch := make([]struct {
		key  string
		info *domain.ThreatInfo
	}, 0, 10000)

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
			continue
		}

		info := &domain.ThreatInfo{
			IP:         addr,
			Source:     "local",
			Confidence: 1.0,
			Categories: []string{"known_malicious"},
		}

		if len(parts) >= 2 {
			info.Source = strings.TrimSpace(parts[1])
		}

		batch = append(batch, struct {
			key  string
			info *domain.ThreatInfo
		}{key: ipStr, info: info})

		if len(batch) >= 10000 {
			if err := s.writeBatch(batch); err != nil {
				return err
			}
			batch = batch[:0]
		}
	}

	if len(batch) > 0 {
		if err := s.writeBatch(batch); err != nil {
			return err
		}
	}

	log.Info().Int64("count", s.count.Load()).Str("file", filepath).Msg("Loaded threat intel from file")
	return scanner.Err()
}

func (s *HybridThreatStore) writeBatch(batch []struct {
	key  string
	info *domain.ThreatInfo
}) error {
	s.bloomMu.Lock()
	defer s.bloomMu.Unlock()

	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(ThreatBucket)
		if b == nil {
			return fmt.Errorf("bucket not found")
		}

		for _, item := range batch {
			data, err := json.Marshal(item.info)
			if err != nil {
				continue
			}

			if err := b.Put([]byte(item.key), data); err != nil {
				return err
			}

			s.bloom.Add([]byte(item.key))
			s.count.Add(1)
		}

		return nil
	})
}

func (s *HybridThreatStore) IsKnownMalicious(ip string) bool {
	s.bloomMu.RLock()
	inBloom := s.bloom.Contains([]byte(ip))
	s.bloomMu.RUnlock()

	if !inBloom {
		return false
	}

	s.hotCacheMu.RLock()
	_, cached := s.hotCache[ip]
	s.hotCacheMu.RUnlock()
	if cached {
		return true
	}

	var exists bool
	s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(ThreatBucket)
		if b == nil {
			return nil
		}
		exists = b.Get([]byte(ip)) != nil
		return nil
	})

	return exists
}

func (s *HybridThreatStore) GetThreatInfo(ip string) (*domain.ThreatInfo, bool) {
	s.hotCacheMu.RLock()
	info, cached := s.hotCache[ip]
	s.hotCacheMu.RUnlock()
	if cached {
		return info, true
	}

	var result *domain.ThreatInfo
	s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(ThreatBucket)
		if b == nil {
			return nil
		}

		data := b.Get([]byte(ip))
		if data == nil {
			return nil
		}

		dataCopy := make([]byte, len(data))
		copy(dataCopy, data)

		result = &domain.ThreatInfo{}
		if err := json.Unmarshal(dataCopy, result); err != nil {
			result = nil
		}
		return nil
	})

	if result != nil {
		s.hotCacheMu.Lock()
		if len(s.hotCache) < 1000 {
			s.hotCache[ip] = result
		}
		s.hotCacheMu.Unlock()
	}

	return result, result != nil
}

func (s *HybridThreatStore) Add(ip string, info *domain.ThreatInfo) error {
	data, err := json.Marshal(info)
	if err != nil {
		return err
	}

	s.bloomMu.Lock()
	s.bloom.Add([]byte(ip))
	s.bloomMu.Unlock()

	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(ThreatBucket)
		if b == nil {
			return fmt.Errorf("bucket not found")
		}
		s.count.Add(1)
		return b.Put([]byte(ip), data)
	})
}

func (s *HybridThreatStore) Count() int64 {
	return s.count.Load()
}
func (s *HybridThreatStore) Close() error {
	if s.db != nil {
		log.Info().Int64("entries", s.count.Load()).Msg("Closing hybrid threat store")
		return s.db.Close()
	}
	return nil
}

func (s *HybridThreatStore) BloomFillRatio() float64 {
	s.bloomMu.RLock()
	defer s.bloomMu.RUnlock()
	return s.bloom.FillRatio()
}

func (s *HybridThreatStore) ClearHotCache() {
	s.hotCacheMu.Lock()
	s.hotCache = make(map[string]*domain.ThreatInfo)
	s.hotCacheMu.Unlock()
}
