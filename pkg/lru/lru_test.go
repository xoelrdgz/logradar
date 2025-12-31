package lru

import (
	"sync"
	"testing"
)

func TestCache_Basic(t *testing.T) {
	cache := New[string, int](10)

	cache.Put("a", 1)
	cache.Put("b", 2)
	cache.Put("c", 3)

	if val, ok := cache.Get("a"); !ok || val != 1 {
		t.Errorf("Expected 1, got %d (ok=%v)", val, ok)
	}
	if val, ok := cache.Get("b"); !ok || val != 2 {
		t.Errorf("Expected 2, got %d (ok=%v)", val, ok)
	}
	if val, ok := cache.Get("c"); !ok || val != 3 {
		t.Errorf("Expected 3, got %d (ok=%v)", val, ok)
	}
}

func TestCache_NotFound(t *testing.T) {
	cache := New[string, int](10)

	if _, ok := cache.Get("nonexistent"); ok {
		t.Error("Expected not found")
	}
}

func TestCache_Eviction(t *testing.T) {
	cache := New[string, int](3)

	cache.Put("a", 1)
	cache.Put("b", 2)
	cache.Put("c", 3)
	cache.Put("d", 4)

	if _, ok := cache.Get("a"); ok {
		t.Error("Expected 'a' to be evicted")
	}
	if _, ok := cache.Get("b"); !ok {
		t.Error("Expected 'b' to exist")
	}
	if _, ok := cache.Get("c"); !ok {
		t.Error("Expected 'c' to exist")
	}
	if _, ok := cache.Get("d"); !ok {
		t.Error("Expected 'd' to exist")
	}
}

func TestCache_LRUOrder(t *testing.T) {
	cache := New[string, int](3)

	cache.Put("a", 1)
	cache.Put("b", 2)
	cache.Put("c", 3)

	cache.Get("a")

	cache.Put("d", 4)

	if _, ok := cache.Get("a"); !ok {
		t.Error("Expected 'a' to exist (was accessed recently)")
	}
	if _, ok := cache.Get("b"); ok {
		t.Error("Expected 'b' to be evicted (LRU)")
	}
	if _, ok := cache.Get("c"); !ok {
		t.Error("Expected 'c' to exist")
	}
	if _, ok := cache.Get("d"); !ok {
		t.Error("Expected 'd' to exist")
	}
}

func TestCache_Update(t *testing.T) {
	cache := New[string, int](10)

	cache.Put("a", 1)
	cache.Put("a", 2)

	if val, ok := cache.Get("a"); !ok || val != 2 {
		t.Errorf("Expected 2, got %d", val)
	}
	if cache.Len() != 1 {
		t.Errorf("Expected length 1, got %d", cache.Len())
	}
}

func TestCache_Sticky(t *testing.T) {
	cache := New[string, int](3)

	cache.Put("a", 1)
	cache.SetSticky("a", true)
	cache.Put("b", 2)
	cache.Put("c", 3)
	cache.Put("d", 4)

	if _, ok := cache.Get("a"); !ok {
		t.Error("Expected sticky 'a' to NOT be evicted")
	}
	if _, ok := cache.Get("b"); ok {
		t.Error("Expected 'b' to be evicted (oldest non-sticky)")
	}

	if !cache.IsSticky("a") {
		t.Error("Expected 'a' to be sticky")
	}
	if cache.IsSticky("c") {
		t.Error("Expected 'c' to NOT be sticky")
	}
}

func TestCache_StickyCount(t *testing.T) {
	cache := New[string, int](10)

	cache.Put("a", 1)
	cache.Put("b", 2)
	cache.Put("c", 3)

	cache.SetSticky("a", true)
	cache.SetSticky("b", true)

	if cache.StickyCount() != 2 {
		t.Errorf("Expected 2 sticky, got %d", cache.StickyCount())
	}

	cache.SetSticky("a", false)

	if cache.StickyCount() != 1 {
		t.Errorf("Expected 1 sticky, got %d", cache.StickyCount())
	}
}

func TestCache_Delete(t *testing.T) {
	cache := New[string, int](10)

	cache.Put("a", 1)
	cache.Put("b", 2)
	cache.SetSticky("a", true)

	cache.Delete("a")

	if _, ok := cache.Get("a"); ok {
		t.Error("Expected 'a' to be deleted")
	}
	if cache.IsSticky("a") {
		t.Error("Expected sticky status to be removed")
	}
	if cache.Len() != 1 {
		t.Errorf("Expected length 1, got %d", cache.Len())
	}
}

func TestCache_Clear(t *testing.T) {
	cache := New[string, int](10)

	cache.Put("a", 1)
	cache.Put("b", 2)
	cache.SetSticky("a", true)

	cache.Clear()

	if cache.Len() != 0 {
		t.Errorf("Expected length 0, got %d", cache.Len())
	}
	if cache.StickyCount() != 0 {
		t.Errorf("Expected 0 sticky, got %d", cache.StickyCount())
	}
}

func TestCache_Keys(t *testing.T) {
	cache := New[string, int](10)

	cache.Put("a", 1)
	cache.Put("b", 2)
	cache.Put("c", 3)

	keys := cache.Keys()
	if len(keys) != 3 {
		t.Errorf("Expected 3 keys, got %d", len(keys))
	}

	if keys[0] != "c" {
		t.Errorf("Expected 'c' first (most recent), got %s", keys[0])
	}
}

func TestCache_GetOrCreate(t *testing.T) {
	cache := New[string, int](10)

	val := cache.GetOrCreate("a", func() int { return 42 })
	if val != 42 {
		t.Errorf("Expected 42, got %d", val)
	}
	val = cache.GetOrCreate("a", func() int { return 100 })
	if val != 42 {
		t.Errorf("Expected 42 (cached), got %d", val)
	}
}

func TestCache_ConcurrentAccess(t *testing.T) {
	cache := New[int, int](1000)

	var wg sync.WaitGroup
	goroutines := 10
	operations := 1000

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < operations; i++ {
				key := (id * operations) + i
				cache.Put(key, key*2)
				cache.Get(key)
				cache.GetOrCreate(key, func() int { return key * 3 })
			}
		}(g)
	}

	wg.Wait()

	if cache.Len() > 1000 {
		t.Errorf("Cache exceeded capacity: %d", cache.Len())
	}
}

func TestCache_Capacity(t *testing.T) {
	cache := New[string, int](50)

	if cache.Capacity() != 50 {
		t.Errorf("Expected capacity 50, got %d", cache.Capacity())
	}
}

func TestCache_DefaultCapacity(t *testing.T) {
	cache := New[string, int](0)

	if cache.Capacity() != 1000 {
		t.Errorf("Expected default capacity 1000, got %d", cache.Capacity())
	}
}
