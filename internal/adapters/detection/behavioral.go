package detection

import (
	"container/list"
	"context"
	"hash/maphash"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xoelrdgz/logradar/internal/domain"
)

var hashSeed = maphash.MakeSeed()

type RingBufferEvent struct {
	Timestamp     int64
	StatusCode    int16
	UserAgentHash uint32
}

type EventRingBuffer struct {
	data  []RingBufferEvent
	head  int
	count int
	cap   int
}

func NewEventRingBuffer(capacity int) *EventRingBuffer {
	if capacity <= 0 {
		capacity = 512
	}
	return &EventRingBuffer{
		data: make([]RingBufferEvent, capacity),
		cap:  capacity,
	}
}

func (r *EventRingBuffer) Push(event RingBufferEvent) {
	r.data[r.head] = event
	r.head = (r.head + 1) % r.cap
	if r.count < r.cap {
		r.count++
	}
}

func (r *EventRingBuffer) CountSince(cutoff int64) int {
	count := 0
	for i := 0; i < r.count; i++ {
		idx := (r.head - r.count + i + r.cap) % r.cap
		if r.data[idx].Timestamp >= cutoff {
			count++
		}
	}
	return count
}

func (r *EventRingBuffer) CountStatusSince(statusCode int, cutoff int64) int {
	count := 0
	sc := int16(statusCode)
	for i := 0; i < r.count; i++ {
		idx := (r.head - r.count + i + r.cap) % r.cap
		if r.data[idx].Timestamp >= cutoff && r.data[idx].StatusCode == sc {
			count++
		}
	}
	return count
}

func (r *EventRingBuffer) Count() int {
	return r.count
}

func (r *EventRingBuffer) Clear() {
	r.head = 0
	r.count = 0
}

const timeBucketCount = 120

type TimeBuckets struct {
	buckets      [timeBucketCount]int32
	statusCounts [timeBucketCount]int32
	lastSecond   int64
}

func (tb *TimeBuckets) RecordEvent(timestamp int64, isStatusMatch bool) {
	second := timestamp
	bucket := int(second % timeBucketCount)

	if second != tb.lastSecond {
		tb.clearStaleBuckets(second)
		tb.lastSecond = second
	}

	atomic.AddInt32(&tb.buckets[bucket], 1)
	if isStatusMatch {
		atomic.AddInt32(&tb.statusCounts[bucket], 1)
	}
}

func (tb *TimeBuckets) clearStaleBuckets(currentSecond int64) {
	if tb.lastSecond == 0 {
		for i := range tb.buckets {
			tb.buckets[i] = 0
			tb.statusCounts[i] = 0
		}
		return
	}

	gap := currentSecond - tb.lastSecond
	if gap >= timeBucketCount {
		for i := range tb.buckets {
			tb.buckets[i] = 0
			tb.statusCounts[i] = 0
		}
		return
	}

	for s := tb.lastSecond + 1; s <= currentSecond; s++ {
		bucket := int(s % timeBucketCount)
		tb.buckets[bucket] = 0
		tb.statusCounts[bucket] = 0
	}
}

func (tb *TimeBuckets) CountSince(currentSecond int64, windowSeconds int64) int64 {
	var total int64
	startSecond := currentSecond - windowSeconds + 1
	for s := startSecond; s <= currentSecond; s++ {
		bucket := int(s % timeBucketCount)
		total += int64(atomic.LoadInt32(&tb.buckets[bucket]))
	}
	return total
}

func (tb *TimeBuckets) CountStatusSince(currentSecond int64, windowSeconds int64) int64 {
	var total int64
	startSecond := currentSecond - windowSeconds + 1
	for s := startSecond; s <= currentSecond; s++ {
		bucket := int(s % timeBucketCount)
		total += int64(atomic.LoadInt32(&tb.statusCounts[bucket]))
	}
	return total
}

type IPEventWindow struct {
	Events           *EventRingBuffer
	Buckets          *TimeBuckets
	UniqueUserAgents map[uint32]struct{}
	mu               sync.RWMutex
}

type BehavioralDetector struct {
	shards     []*ipShard
	shardCount int

	bruteForceThreshold int
	bruteForceWindow    int64
	bruteForceStatus    int

	rateLimitThreshold int
	rateLimitWindow    int64

	cleanupInterval time.Duration
	stopCleanup     chan struct{}
	stopOnce        sync.Once
}

const maxIPsPerShard = 10000

type ipShard struct {
	windows map[string]*IPEventWindow
	mu      sync.RWMutex
	lruList *list.List
	lruMap  map[string]*list.Element
}

type BehavioralConfig struct {
	ShardCount          int
	BruteForceThreshold int
	BruteForceWindow    int64
	BruteForceStatus    int
	RateLimitThreshold  int
	RateLimitWindow     int64
	CleanupInterval     time.Duration
}

func DefaultBehavioralConfig() BehavioralConfig {
	return BehavioralConfig{
		ShardCount:          16,
		BruteForceThreshold: 10,
		BruteForceWindow:    60,
		BruteForceStatus:    401,
		RateLimitThreshold:  100,
		RateLimitWindow:     10,
		CleanupInterval:     30 * time.Second,
	}
}

const UARotationThreshold = 5

func NewBehavioralDetector(config BehavioralConfig) *BehavioralDetector {
	if config.ShardCount <= 0 {
		config.ShardCount = 16
	}

	shards := make([]*ipShard, config.ShardCount)
	for i := 0; i < config.ShardCount; i++ {
		shards[i] = &ipShard{
			windows: make(map[string]*IPEventWindow),
			lruList: list.New(),
			lruMap:  make(map[string]*list.Element),
		}
	}

	return &BehavioralDetector{
		shards:              shards,
		shardCount:          config.ShardCount,
		bruteForceThreshold: config.BruteForceThreshold,
		bruteForceWindow:    config.BruteForceWindow,
		bruteForceStatus:    config.BruteForceStatus,
		rateLimitThreshold:  config.RateLimitThreshold,
		rateLimitWindow:     config.RateLimitWindow,
		cleanupInterval:     config.CleanupInterval,
		stopCleanup:         make(chan struct{}),
	}
}

func (d *BehavioralDetector) getShard(ip string) *ipShard {
	return d.shards[secureHash(ip)%uint64(d.shardCount)]
}

func secureHash(s string) uint64 {
	var h maphash.Hash
	h.SetSeed(hashSeed)
	h.WriteString(s)
	return h.Sum64()
}

func (d *BehavioralDetector) RecordEvent(ip string, statusCode int, userAgent string, timestamp int64) {
	shard := d.getShard(ip)
	uaHash := hashUserAgent(userAgent)
	isStatusMatch := statusCode == d.bruteForceStatus

	shard.mu.Lock()
	defer shard.mu.Unlock()

	window, exists := shard.windows[ip]
	if !exists {
		if len(shard.windows) >= maxIPsPerShard {
			oldest := shard.lruList.Back()
			if oldest != nil {
				oldIP := oldest.Value.(string)
				delete(shard.windows, oldIP)
				delete(shard.lruMap, oldIP)
				shard.lruList.Remove(oldest)
			}
		}
		window = &IPEventWindow{
			Events:           NewEventRingBuffer(512),
			Buckets:          &TimeBuckets{},
			UniqueUserAgents: make(map[uint32]struct{}),
		}
		shard.windows[ip] = window
		elem := shard.lruList.PushFront(ip)
		shard.lruMap[ip] = elem
	} else {
		if elem, ok := shard.lruMap[ip]; ok {
			shard.lruList.MoveToFront(elem)
		}
	}

	window.mu.Lock()
	defer window.mu.Unlock()

	window.UniqueUserAgents[uaHash] = struct{}{}

	window.Buckets.RecordEvent(timestamp, isStatusMatch)

	window.Events.Push(RingBufferEvent{
		Timestamp:     timestamp,
		StatusCode:    int16(statusCode),
		UserAgentHash: uaHash,
	})
}

func hashUserAgent(ua string) uint32 {
	if ua == "" {
		return 0
	}
	var h maphash.Hash
	h.SetSeed(hashSeed)
	h.WriteString(ua)
	return uint32(h.Sum64())
}

func (d *BehavioralDetector) GetEventCount(ip string, windowSeconds int64) int64 {
	shard := d.getShard(ip)
	shard.mu.RLock()
	window, exists := shard.windows[ip]
	shard.mu.RUnlock()

	if !exists {
		return 0
	}

	currentSecond := time.Now().Unix()

	window.mu.RLock()
	defer window.mu.RUnlock()

	return window.Buckets.CountSince(currentSecond, windowSeconds)
}

func (d *BehavioralDetector) GetUserAgentDiversity(ip string) int {
	shard := d.getShard(ip)
	shard.mu.RLock()
	window, exists := shard.windows[ip]
	shard.mu.RUnlock()

	if !exists {
		return 0
	}

	window.mu.RLock()
	defer window.mu.RUnlock()

	return len(window.UniqueUserAgents)
}

func (d *BehavioralDetector) GetStatusCodeCount(ip string, statusCode int, windowSeconds int64) int64 {
	shard := d.getShard(ip)
	shard.mu.RLock()
	window, exists := shard.windows[ip]
	shard.mu.RUnlock()

	if !exists {
		return 0
	}

	currentSecond := time.Now().Unix()

	window.mu.RLock()
	defer window.mu.RUnlock()

	if statusCode == d.bruteForceStatus {
		return window.Buckets.CountStatusSince(currentSecond, windowSeconds)
	}
	cutoff := currentSecond - windowSeconds
	return int64(window.Events.CountStatusSince(statusCode, cutoff))
}

func (d *BehavioralDetector) Detect(ctx context.Context, entry *domain.LogEntry) domain.DetectionResult {
	if entry == nil || !entry.IP.IsValid() {
		return domain.NoDetection()
	}

	ip := entry.IP.String()
	timestamp := entry.Timestamp.Unix()

	d.RecordEvent(ip, entry.StatusCode, entry.UserAgent, timestamp)

	if entry.StatusCode == d.bruteForceStatus {
		count := d.GetStatusCodeCount(ip, d.bruteForceStatus, d.bruteForceWindow)
		if count > int64(d.bruteForceThreshold) {
			return domain.DetectionResult{
				Detected:   true,
				ThreatType: domain.ThreatTypeBruteForce,
				Level:      domain.AlertLevelCritical,
				RiskScore:  8,
				Message:    "Brute force attack detected",
				Details: map[string]interface{}{
					"failed_attempts": count,
					"window_seconds":  d.bruteForceWindow,
					"threshold":       d.bruteForceThreshold,
				},
			}
		}
	}

	uaDiversity := d.GetUserAgentDiversity(ip)
	if uaDiversity > UARotationThreshold {
		return domain.DetectionResult{
			Detected:   true,
			ThreatType: domain.ThreatTypeBotDetection,
			Level:      domain.AlertLevelWarning,
			RiskScore:  7,
			Message:    "Automated scanner/bot detected (UA rotation)",
			Details: map[string]interface{}{
				"unique_user_agents": uaDiversity,
				"threshold":          UARotationThreshold,
				"indicator":          "User-Agent rotation is characteristic of attack tools",
			},
		}
	}

	totalCount := d.GetEventCount(ip, d.rateLimitWindow)

	adjustedThreshold := int64(d.rateLimitThreshold)
	if uaDiversity > 2 {
		adjustedThreshold = adjustedThreshold / 2
		if adjustedThreshold < 20 {
			adjustedThreshold = 20
		}
	}

	if totalCount > adjustedThreshold {
		return domain.DetectionResult{
			Detected:   true,
			ThreatType: domain.ThreatTypeRateLimitDoS,
			Level:      domain.AlertLevelCritical,
			RiskScore:  9,
			Message:    "Potential Layer 7 DoS attack detected",
			Details: map[string]interface{}{
				"request_count":      totalCount,
				"window_seconds":     d.rateLimitWindow,
				"threshold":          d.rateLimitThreshold,
				"adjusted_threshold": adjustedThreshold,
				"ua_diversity":       uaDiversity,
			},
		}
	}

	return domain.NoDetection()
}

func (d *BehavioralDetector) Name() string {
	return "behavioral"
}
func (d *BehavioralDetector) Type() domain.ThreatType {
	return domain.ThreatTypeBruteForce
}

func (d *BehavioralDetector) Stop() {
	d.StopCleanup()
}

func (d *BehavioralDetector) StartCleanup(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(d.cleanupInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-d.stopCleanup:
				return
			case <-ticker.C:
				d.Cleanup()
			}
		}
	}()
}

func (d *BehavioralDetector) StopCleanup() {
	d.stopOnce.Do(func() {
		close(d.stopCleanup)
	})
}

func (d *BehavioralDetector) Cleanup() {
	cutoff := time.Now().Unix() - d.bruteForceWindow*2

	var wg sync.WaitGroup
	for _, shard := range d.shards {
		wg.Add(1)
		go func(s *ipShard) {
			defer wg.Done()
			d.cleanupShard(s, cutoff)
		}(shard)
	}
	wg.Wait()
}

func (d *BehavioralDetector) cleanupShard(shard *ipShard, cutoff int64) {
	shard.mu.Lock()
	defer shard.mu.Unlock()
	for ip, window := range shard.windows {
		window.mu.RLock()
		count := window.Events.CountSince(cutoff)
		window.mu.RUnlock()

		if count == 0 {
			delete(shard.windows, ip)
		}
	}
}
