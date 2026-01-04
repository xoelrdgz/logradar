// Package bloomfilter implements a probabilistic Bloom filter data structure.
//
// A Bloom filter is a space-efficient probabilistic data structure that can
// definitively say "definitely not in set" but only "probably in set".
// Used by LogRadar for fast threat intelligence IP lookups.
//
// Properties:
//   - No false negatives: if Contains returns false, the item is definitely not in the set
//   - Possible false positives: if Contains returns true, the item might be in the set
//   - Space efficient: much smaller than storing the actual elements
//
// Thread Safety: All methods are safe for concurrent access via RWMutex.
package bloomfilter

import (
	"hash/maphash"
	"math"
	"sync"
)

// hashSeed is the global seed for maphash operations.
var hashSeed = maphash.MakeSeed()

// BloomFilter is a probabilistic set membership data structure.
//
// Optimal sizing formula:
//   - m = -n*ln(p) / (ln(2)^2)  (bit array size)
//   - k = m/n * ln(2)           (number of hash functions)
//
// Where n = expected items, p = false positive rate.
type BloomFilter struct {
	bits      []uint64     // Bit array (packed as uint64)
	size      uint         // Number of bits (m)
	hashCount uint         // Number of hash functions (k)
	count     uint         // Number of items added
	mu        sync.RWMutex // Protects all fields
}

// New creates a Bloom filter with optimal size for expected items and FP rate.
//
// Parameters:
//   - expectedItems: Number of items to store (default: 1000 if 0)
//   - fpRate: Desired false positive rate, e.g., 0.01 for 1% (default: 0.01 if invalid)
//
// Returns:
//   - Configured BloomFilter ready for Add/Contains
//
// Example:
//
//	bf := bloomfilter.New(10000, 0.01)  // 10K items, 1% FP rate
//	bf.Add([]byte("malicious-ip"))
//	if bf.Contains([]byte("suspicious-ip")) { ... }
func New(expectedItems uint, fpRate float64) *BloomFilter {
	if expectedItems == 0 {
		expectedItems = 1000
	}
	if fpRate <= 0 || fpRate >= 1 {
		fpRate = 0.01
	}

	// Optimal bit array size
	m := uint(math.Ceil(-float64(expectedItems) * math.Log(fpRate) / (math.Ln2 * math.Ln2)))
	// Optimal hash function count
	k := uint(math.Ceil(float64(m) / float64(expectedItems) * math.Ln2))

	// Round up to uint64 boundary
	size := (m + 63) / 64

	return &BloomFilter{
		bits:      make([]uint64, size),
		size:      m,
		hashCount: k,
	}
}

// Add inserts an item into the Bloom filter.
//
// Parameters:
//   - data: Byte representation of item to add
//
// Thread Safety: Safe for concurrent calls.
func (bf *BloomFilter) Add(data []byte) {
	bf.mu.Lock()
	defer bf.mu.Unlock()

	h1, h2 := bf.hash(data)

	// Set k bits using double hashing
	for i := uint(0); i < bf.hashCount; i++ {
		pos := (h1 + h2*uint64(i)) % uint64(bf.size)
		bf.setBit(pos)
	}

	bf.count++
}

// Contains checks if an item might be in the set.
//
// Parameters:
//   - data: Byte representation of item to check
//
// Returns:
//   - false: Definitely NOT in set (no false negatives)
//   - true: PROBABLY in set (possible false positive)
//
// Thread Safety: Safe for concurrent calls.
func (bf *BloomFilter) Contains(data []byte) bool {
	bf.mu.RLock()
	defer bf.mu.RUnlock()

	h1, h2 := bf.hash(data)

	// Check all k bits
	for i := uint(0); i < bf.hashCount; i++ {
		pos := (h1 + h2*uint64(i)) % uint64(bf.size)
		if !bf.getBit(pos) {
			return false
		}
	}

	return true
}

// Count returns the number of items added.
func (bf *BloomFilter) Count() uint {
	bf.mu.RLock()
	defer bf.mu.RUnlock()
	return bf.count
}

// FillRatio returns the fraction of bits set (saturation).
//
// Returns:
//   - Ratio between 0.0 (empty) and 1.0 (full)
//
// A high fill ratio (> 0.5) indicates the filter is becoming saturated
// and false positive rate is increasing.
func (bf *BloomFilter) FillRatio() float64 {
	bf.mu.RLock()
	defer bf.mu.RUnlock()

	var setBits uint
	for _, word := range bf.bits {
		setBits += uint(popcount(word))
	}

	return float64(setBits) / float64(bf.size)
}

// EstimatedFPRate returns the current estimated false positive rate.
//
// Returns:
//   - Current FP rate based on fill ratio
//
// Formula: FP = (fill_ratio)^k
func (bf *BloomFilter) EstimatedFPRate() float64 {
	fillRatio := bf.FillRatio()
	return math.Pow(fillRatio, float64(bf.hashCount))
}

// Clear resets the Bloom filter to empty state.
func (bf *BloomFilter) Clear() {
	bf.mu.Lock()
	defer bf.mu.Unlock()

	for i := range bf.bits {
		bf.bits[i] = 0
	}
	bf.count = 0
}

// hash computes two independent hash values using double hashing.
// Uses maphash for fast, high-quality hashing.
func (bf *BloomFilter) hash(data []byte) (uint64, uint64) {
	var h maphash.Hash
	h.SetSeed(hashSeed)
	h.Write(data)
	sum := h.Sum64()

	// Split into two hashes using rotation
	h1 := sum
	h2 := (sum >> 32) | (sum << 32)

	return h1, h2
}

// setBit sets the bit at position pos.
func (bf *BloomFilter) setBit(pos uint64) {
	idx := pos / 64
	bit := pos % 64
	bf.bits[idx] |= 1 << bit
}

// getBit returns true if the bit at position pos is set.
func (bf *BloomFilter) getBit(pos uint64) bool {
	idx := pos / 64
	bit := pos % 64
	return (bf.bits[idx] & (1 << bit)) != 0
}

// popcount counts the number of set bits (population count / Hamming weight).
func popcount(x uint64) int {
	count := 0
	for x != 0 {
		x &= x - 1
		count++
	}
	return count
}
