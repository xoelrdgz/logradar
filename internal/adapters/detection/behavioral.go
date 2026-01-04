// Package detection implements behavioral anomaly detection for LogRadar.
//
// This file provides stateful detection of attack patterns based on IP behavior
// over time. Uses sharded data structures for reduced lock contention.
//
// Detection Capabilities:
//   - Brute Force: Repeated 401/403 responses within time window
//   - Rate Limiting: Excessive requests per second per IP
//   - UA Rotation: Detects automated tools rotating User-Agents
//
// Thread Safety: Uses 16-way sharding for concurrent access with minimal contention.
//
// Memory Management:
//   - LRU eviction per shard (max 10K IPs per shard)
//   - Time-bucketed counters for efficient aggregation
//   - Ring buffers for event history with fixed memory footprint
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

// hashSeed is the global seed for maphash operations.
// Initialized once at package load for consistent hashing across the process lifetime.
var hashSeed = maphash.MakeSeed()

// RingBufferEvent represents a single request event stored in the ring buffer.
// Uses compact types to minimize memory footprint (16 bytes per event).
type RingBufferEvent struct {
	Timestamp     int64  // Unix timestamp of the request
	StatusCode    int16  // HTTP status code (int16 saves 2 bytes vs int)
	UserAgentHash uint32 // FNV hash of User-Agent for diversity tracking
}

// EventRingBuffer provides O(1) push and O(n) scan for time-windowed events.
// Fixed-size circular buffer prevents unbounded memory growth per IP.
//
// Thread Safety: NOT thread-safe. Caller must hold lock on containing IPEventWindow.
type EventRingBuffer struct {
	data  []RingBufferEvent // Circular buffer storage
	head  int               // Next write position
	count int               // Current number of events (up to cap)
	cap   int               // Buffer capacity
}

// NewEventRingBuffer creates a ring buffer with the specified capacity.
//
// Parameters:
//   - capacity: Maximum events to store (default: 512 if <=0)
//
// Returns:
//   - Initialized EventRingBuffer ready for Push operations
func NewEventRingBuffer(capacity int) *EventRingBuffer {
	if capacity <= 0 {
		capacity = 512
	}
	return &EventRingBuffer{
		data: make([]RingBufferEvent, capacity),
		cap:  capacity,
	}
}

// Push adds an event to the buffer, overwriting oldest if at capacity.
//
// Parameters:
//   - event: The event to store
//
// Complexity: O(1)
func (r *EventRingBuffer) Push(event RingBufferEvent) {
	r.data[r.head] = event
	r.head = (r.head + 1) % r.cap
	if r.count < r.cap {
		r.count++
	}
}

// CountSince returns the number of events with timestamp >= cutoff.
//
// Parameters:
//   - cutoff: Unix timestamp threshold
//
// Returns:
//   - Count of events since cutoff
//
// Complexity: O(n) where n is buffer count
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

// CountStatusSince returns events matching status code since cutoff.
//
// Parameters:
//   - statusCode: HTTP status to filter by
//   - cutoff: Unix timestamp threshold
//
// Returns:
//   - Count of matching events
//
// Complexity: O(n)
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

// Count returns the current number of events in the buffer.
func (r *EventRingBuffer) Count() int {
	return r.count
}

// Clear resets the buffer to empty state.
func (r *EventRingBuffer) Clear() {
	r.head = 0
	r.count = 0
}

// timeBucketCount is the number of second-granularity buckets for O(1) counting.
// 120 buckets = 2 minutes of history, sufficient for typical detection windows.
const timeBucketCount = 120

// TimeBuckets provides O(1) event counting using second-granularity buckets.
// Each bucket holds aggregate counts for one second, enabling O(window) range queries.
//
// Thread Safety: Uses atomic operations for counter updates.
type TimeBuckets struct {
	buckets      [timeBucketCount]int32 // Total events per second
	statusCounts [timeBucketCount]int32 // Status-matching events per second
	lastSecond   int64                  // Last recorded second (for stale bucket clearing)
}

// RecordEvent increments counters for the given timestamp.
//
// Parameters:
//   - timestamp: Unix timestamp of the event
//   - isStatusMatch: True if event matches brute-force status code
//
// Behavior:
//   - Clears stale buckets when time advances
//   - Uses atomic add for thread-safe counter updates
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

// clearStaleBuckets resets buckets that are outside the current window.
// Called when time advances to ensure accurate counts.
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

// CountSince returns total events in the time window.
//
// Parameters:
//   - currentSecond: Current Unix timestamp (seconds)
//   - windowSeconds: Time window size
//
// Returns:
//   - Sum of events in [currentSecond-windowSeconds+1, currentSecond]
//
// Complexity: O(windowSeconds)
func (tb *TimeBuckets) CountSince(currentSecond int64, windowSeconds int64) int64 {
	var total int64
	startSecond := currentSecond - windowSeconds + 1
	for s := startSecond; s <= currentSecond; s++ {
		bucket := int(s % timeBucketCount)
		total += int64(atomic.LoadInt32(&tb.buckets[bucket]))
	}
	return total
}

// CountStatusSince returns status-matching events in the time window.
//
// Parameters:
//   - currentSecond: Current Unix timestamp (seconds)
//   - windowSeconds: Time window size
//
// Returns:
//   - Sum of status-matching events in the window
func (tb *TimeBuckets) CountStatusSince(currentSecond int64, windowSeconds int64) int64 {
	var total int64
	startSecond := currentSecond - windowSeconds + 1
	for s := startSecond; s <= currentSecond; s++ {
		bucket := int(s % timeBucketCount)
		total += int64(atomic.LoadInt32(&tb.statusCounts[bucket]))
	}
	return total
}

// IPEventWindow holds all behavioral tracking data for a single IP address.
//
// Contains:
//   - Ring buffer for detailed event history
//   - Time buckets for fast aggregate counting
//   - Set of unique User-Agent hashes for diversity tracking
type IPEventWindow struct {
	Events           *EventRingBuffer    // Detailed event history
	Buckets          *TimeBuckets        // Aggregate counters
	UniqueUserAgents map[uint32]struct{} // UA hash set for diversity
	mu               sync.RWMutex        // Protects all fields
}

// BehavioralDetector detects brute force, rate limit, and bot attacks.
//
// Detection Strategy:
//  1. Track all requests per IP with timestamps and status codes
//  2. Check for excessive failed auth attempts (brute force)
//  3. Check for User-Agent rotation (automated tools)
//  4. Check for excessive request rate (DoS)
//
// Thread Safety: All methods are safe for concurrent access.
// Uses sharding to distribute lock contention across N shards.
type BehavioralDetector struct {
	shards     []*ipShard // Sharded IP tracking maps
	shardCount int        // Number of shards (default: 16)

	bruteForceThreshold int   // Failed auth count to trigger alert
	bruteForceWindow    int64 // Time window in seconds
	bruteForceStatus    int   // Status code for failed auth (401/403)

	rateLimitThreshold int   // Request count to trigger alert
	rateLimitWindow    int64 // Time window in seconds

	cleanupInterval time.Duration // Interval for expired entry cleanup
	stopCleanup     chan struct{} // Signal to stop cleanup goroutine
	stopOnce        sync.Once     // Ensures single stop
}

// maxIPsPerShard limits memory usage per shard via LRU eviction.
const maxIPsPerShard = 10000

// ipShard holds the IP tracking map for one shard.
// Uses LRU eviction when at capacity.
type ipShard struct {
	windows map[string]*IPEventWindow // IP -> tracking data
	mu      sync.RWMutex              // Protects map access
	lruList *list.List                // LRU order tracking
	lruMap  map[string]*list.Element  // IP -> LRU list element
}

// BehavioralConfig configures the behavioral detector.
type BehavioralConfig struct {
	ShardCount          int           // Number of shards (default: 16)
	BruteForceThreshold int           // Failed auths to trigger (default: 10)
	BruteForceWindow    int64         // Window in seconds (default: 60)
	BruteForceStatus    int           // Failed auth status (default: 401)
	RateLimitThreshold  int           // Requests to trigger (default: 100)
	RateLimitWindow     int64         // Window in seconds (default: 10)
	CleanupInterval     time.Duration // Cleanup interval (default: 30s)
}

// DefaultBehavioralConfig returns production-ready defaults.
//
// Defaults:
//   - 16 shards for concurrent access
//   - 10 failed auths in 60s triggers brute force alert
//   - 100 requests in 10s triggers rate limit alert
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

// UARotationThreshold is the unique UA count indicating automated tool usage.
const UARotationThreshold = 5

// NewBehavioralDetector creates a configured behavioral detector.
//
// Parameters:
//   - config: Detection thresholds and settings
//
// Returns:
//   - Configured BehavioralDetector ready for Detect()
//
// Note: Call StartCleanup() to enable background expired entry cleanup.
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

// getShard returns the shard for an IP using consistent hashing.
func (d *BehavioralDetector) getShard(ip string) *ipShard {
	return d.shards[secureHash(ip)%uint64(d.shardCount)]
}

// secureHash computes a consistent hash for IP sharding using maphash.
func secureHash(s string) uint64 {
	var h maphash.Hash
	h.SetSeed(hashSeed)
	h.WriteString(s)
	return h.Sum64()
}

// RecordEvent records a request event for behavioral analysis.
//
// Parameters:
//   - ip: Client IP address string
//   - statusCode: HTTP response status code
//   - userAgent: User-Agent header value
//   - timestamp: Unix timestamp of request
//
// Behavior:
//   - Creates IP window if not exists (with LRU eviction if at capacity)
//   - Updates LRU order on access
//   - Records event in both ring buffer and time buckets
//   - Tracks unique User-Agent hashes
//
// Thread Safety: Safe for concurrent calls.
func (d *BehavioralDetector) RecordEvent(ip string, statusCode int, userAgent string, timestamp int64) {
	shard := d.getShard(ip)
	uaHash := hashUserAgent(userAgent)
	isStatusMatch := statusCode == d.bruteForceStatus

	shard.mu.Lock()
	defer shard.mu.Unlock()

	window, exists := shard.windows[ip]
	if !exists {
		// LRU eviction if at capacity
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
		// Move to front on access
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

// hashUserAgent computes a compact hash of the User-Agent string.
func hashUserAgent(ua string) uint32 {
	if ua == "" {
		return 0
	}
	var h maphash.Hash
	h.SetSeed(hashSeed)
	h.WriteString(ua)
	return uint32(h.Sum64())
}

// GetEventCount returns total request count for IP in time window.
//
// Parameters:
//   - ip: Client IP address
//   - windowSeconds: Time window size
//
// Returns:
//   - Number of requests in window (0 if IP not tracked)
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

// GetUserAgentDiversity returns unique User-Agent count for IP.
//
// Parameters:
//   - ip: Client IP address
//
// Returns:
//   - Number of unique UAs seen (0 if IP not tracked)
//
// Security Note: High diversity indicates automated rotation (bot/scanner behavior).
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

// GetStatusCodeCount returns count of specific status code for IP.
//
// Parameters:
//   - ip: Client IP address
//   - statusCode: HTTP status to count
//   - windowSeconds: Time window size
//
// Returns:
//   - Number of matching status codes in window
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

// Detect analyzes a log entry for behavioral anomalies.
//
// Parameters:
//   - ctx: Context for cancellation
//   - entry: Parsed log entry to analyze
//
// Returns:
//   - DetectionResult with Detected=true if anomaly found
//
// Detection Order:
//  1. Record the event for tracking
//  2. Check brute force (failed auth threshold exceeded)
//  3. Check UA rotation (automated tool signature)
//  4. Check rate limit (adjusted based on UA diversity)
//
// Security Considerations:
//   - Adjusts rate limit threshold down for suspicious UAs
//   - Combines multiple signals for higher confidence
func (d *BehavioralDetector) Detect(ctx context.Context, entry *domain.LogEntry) domain.DetectionResult {
	if entry == nil || !entry.IP.IsValid() {
		return domain.NoDetection()
	}

	ip := entry.IP.String()
	timestamp := entry.Timestamp.Unix()

	d.RecordEvent(ip, entry.StatusCode, entry.UserAgent, timestamp)

	// Check brute force
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

	// Check UA rotation (bot detection)
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

	// Check rate limit with adjusted threshold for suspicious UAs
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

// Name returns the detector identifier for logging and metrics.
func (d *BehavioralDetector) Name() string {
	return "behavioral"
}

// Type returns the primary threat type this detector handles.
func (d *BehavioralDetector) Type() domain.ThreatType {
	return domain.ThreatTypeBruteForce
}

// Stop gracefully shuts down the detector's cleanup goroutine.
func (d *BehavioralDetector) Stop() {
	d.StopCleanup()
}

// StartCleanup launches background goroutine to remove expired entries.
//
// Parameters:
//   - ctx: Context for lifecycle management
//
// Behavior:
//   - Runs at CleanupInterval (default: 30s)
//   - Removes IPs with no recent events
//   - Stops on context cancellation or Stop() call
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

// StopCleanup stops the background cleanup goroutine.
// Idempotent via sync.Once protection.
func (d *BehavioralDetector) StopCleanup() {
	d.stopOnce.Do(func() {
		close(d.stopCleanup)
	})
}

// Cleanup removes expired IP entries from all shards.
// Runs in parallel across shards for efficiency.
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

// cleanupShard removes IPs with no events since cutoff from a single shard.
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
