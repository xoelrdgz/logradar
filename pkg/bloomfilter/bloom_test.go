package bloomfilter

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBloomFilter_AddAndContains(t *testing.T) {
	bf := New(1000, 0.01)

	items := []string{"apple", "banana", "cherry", "date", "elderberry"}

	for _, item := range items {
		bf.Add([]byte(item))
	}

	for _, item := range items {
		assert.True(t, bf.Contains([]byte(item)), "Item %s should be found", item)
	}
	notAdded := []string{"fig", "grape", "honeydew"}
	falsePositives := 0
	for _, item := range notAdded {
		if bf.Contains([]byte(item)) {
			falsePositives++
		}
	}

	t.Logf("False positives: %d out of %d (expected ~%.2f)", falsePositives, len(notAdded), 0.01*float64(len(notAdded)))
}

func TestBloomFilter_Count(t *testing.T) {
	bf := New(1000, 0.01)

	assert.Equal(t, uint(0), bf.Count())

	bf.Add([]byte("item1"))
	assert.Equal(t, uint(1), bf.Count())

	bf.Add([]byte("item2"))
	bf.Add([]byte("item3"))
	assert.Equal(t, uint(3), bf.Count())
}

func TestBloomFilter_Clear(t *testing.T) {
	bf := New(100, 0.01)

	bf.Add([]byte("item1"))
	bf.Add([]byte("item2"))

	assert.True(t, bf.Contains([]byte("item1")))
	assert.Equal(t, uint(2), bf.Count())

	bf.Clear()

	assert.False(t, bf.Contains([]byte("item1")))
	assert.False(t, bf.Contains([]byte("item2")))
	assert.Equal(t, uint(0), bf.Count())
}

func TestBloomFilter_FillRatio(t *testing.T) {
	bf := New(100, 0.01)

	initialRatio := bf.FillRatio()
	assert.Equal(t, 0.0, initialRatio)

	for i := 0; i < 50; i++ {
		bf.Add([]byte(fmt.Sprintf("item%d", i)))
	}

	newRatio := bf.FillRatio()
	assert.True(t, newRatio > 0, "Fill ratio should be > 0")
}

func TestBloomFilter_EstimatedFPRate(t *testing.T) {
	bf := New(1000, 0.01)

	assert.Equal(t, 0.0, bf.EstimatedFPRate())

	for i := 0; i < 100; i++ {
		bf.Add([]byte(fmt.Sprintf("item%d", i)))
	}

	fpRate := bf.EstimatedFPRate()
	assert.True(t, fpRate > 0, "FP rate should be > 0")
	assert.True(t, fpRate < 0.1, "FP rate should be < 10%%")

	t.Logf("Estimated FP rate: %.4f", fpRate)
}

func TestBloomFilter_DefaultValues(t *testing.T) {
	bf1 := New(0, 0.01)
	assert.NotNil(t, bf1)

	bf2 := New(1000, 0)
	assert.NotNil(t, bf2)

	bf3 := New(1000, 1.5)
	assert.NotNil(t, bf3)
}

func TestBloomFilter_IPAddresses(t *testing.T) {
	bf := New(10000, 0.01)

	maliciousIPs := []string{
		"10.0.0.1", "10.0.0.2", "10.0.0.3",
		"192.168.1.100", "192.168.1.101",
		"172.16.0.50",
	}

	for _, ip := range maliciousIPs {
		bf.Add([]byte(ip))
	}

	for _, ip := range maliciousIPs {
		assert.True(t, bf.Contains([]byte(ip)), "IP %s should be found", ip)
	}
	legitimateIPs := []string{
		"192.168.1.1", "192.168.1.2", "192.168.1.3",
		"8.8.8.8", "1.1.1.1", "208.67.222.222",
	}

	falsePositives := 0
	for _, ip := range legitimateIPs {
		if bf.Contains([]byte(ip)) {
			falsePositives++
		}
	}

	t.Logf("IP false positives: %d out of %d", falsePositives, len(legitimateIPs))
}

func BenchmarkBloomFilter_Add(b *testing.B) {
	bf := New(100000, 0.01)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bf.Add([]byte(fmt.Sprintf("item%d", i)))
	}
}

func BenchmarkBloomFilter_Contains(b *testing.B) {
	bf := New(100000, 0.01)

	for i := 0; i < 10000; i++ {
		bf.Add([]byte(fmt.Sprintf("item%d", i)))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bf.Contains([]byte(fmt.Sprintf("item%d", i%10000)))
	}
}

func BenchmarkBloomFilter_ContainsNotPresent(b *testing.B) {
	bf := New(100000, 0.01)

	for i := 0; i < 10000; i++ {
		bf.Add([]byte(fmt.Sprintf("existing%d", i)))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bf.Contains([]byte(fmt.Sprintf("notexisting%d", i)))
	}
}
