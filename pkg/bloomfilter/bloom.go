package bloomfilter

import (
	"hash/maphash"
	"math"
	"sync"
)

var hashSeed = maphash.MakeSeed()

type BloomFilter struct {
	bits      []uint64
	size      uint
	hashCount uint
	count     uint
	mu        sync.RWMutex
}

func New(expectedItems uint, fpRate float64) *BloomFilter {
	if expectedItems == 0 {
		expectedItems = 1000
	}
	if fpRate <= 0 || fpRate >= 1 {
		fpRate = 0.01
	}

	m := uint(math.Ceil(-float64(expectedItems) * math.Log(fpRate) / (math.Ln2 * math.Ln2)))
	k := uint(math.Ceil(float64(m) / float64(expectedItems) * math.Ln2))

	size := (m + 63) / 64

	return &BloomFilter{
		bits:      make([]uint64, size),
		size:      m,
		hashCount: k,
	}
}

func (bf *BloomFilter) Add(data []byte) {
	bf.mu.Lock()
	defer bf.mu.Unlock()

	h1, h2 := bf.hash(data)

	for i := uint(0); i < bf.hashCount; i++ {
		pos := (h1 + h2*uint64(i)) % uint64(bf.size)
		bf.setBit(pos)
	}

	bf.count++
}

func (bf *BloomFilter) Contains(data []byte) bool {
	bf.mu.RLock()
	defer bf.mu.RUnlock()

	h1, h2 := bf.hash(data)

	for i := uint(0); i < bf.hashCount; i++ {
		pos := (h1 + h2*uint64(i)) % uint64(bf.size)
		if !bf.getBit(pos) {
			return false
		}
	}

	return true
}

func (bf *BloomFilter) Count() uint {
	bf.mu.RLock()
	defer bf.mu.RUnlock()
	return bf.count
}

func (bf *BloomFilter) FillRatio() float64 {
	bf.mu.RLock()
	defer bf.mu.RUnlock()

	var setBits uint
	for _, word := range bf.bits {
		setBits += uint(popcount(word))
	}

	return float64(setBits) / float64(bf.size)
}

func (bf *BloomFilter) EstimatedFPRate() float64 {
	fillRatio := bf.FillRatio()
	return math.Pow(fillRatio, float64(bf.hashCount))
}

func (bf *BloomFilter) Clear() {
	bf.mu.Lock()
	defer bf.mu.Unlock()

	for i := range bf.bits {
		bf.bits[i] = 0
	}
	bf.count = 0
}

func (bf *BloomFilter) hash(data []byte) (uint64, uint64) {
	var h maphash.Hash
	h.SetSeed(hashSeed)
	h.Write(data)
	sum := h.Sum64()

	h1 := sum
	h2 := (sum >> 32) | (sum << 32)

	return h1, h2
}

func (bf *BloomFilter) setBit(pos uint64) {
	idx := pos / 64
	bit := pos % 64
	bf.bits[idx] |= 1 << bit
}

func (bf *BloomFilter) getBit(pos uint64) bool {
	idx := pos / 64
	bit := pos % 64
	return (bf.bits[idx] & (1 << bit)) != 0
}

func popcount(x uint64) int {
	count := 0
	for x != 0 {
		x &= x - 1
		count++
	}
	return count
}
