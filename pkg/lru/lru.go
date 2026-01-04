// Package lru implements a Least Recently Used (LRU) cache with sticky entries.
//
// An LRU cache evicts the least recently accessed item when at capacity.
// This implementation adds "sticky" entries that are never evicted, useful
// for pinning important data.
//
// Features:
//   - O(1) Get and Put operations (amortized)
//   - Generic types for key and value
//   - Sticky entries that bypass eviction
//   - Thread-safe via RWMutex
//
// Thread Safety: All methods are safe for concurrent access.
package lru

import (
	"container/list"
	"sync"
)

// Cache is a generic LRU cache with optional sticky entries.
//
// Type Parameters:
//   - K: Key type (must be comparable)
//   - V: Value type (any)
type Cache[K comparable, V any] struct {
	capacity int                 // Maximum items before eviction
	mu       sync.RWMutex        // Protects all fields
	list     *list.List          // LRU order (front = most recent)
	items    map[K]*list.Element // Key -> list element lookup
	sticky   map[K]bool          // Keys that cannot be evicted
}

// entry stores key-value pair in list elements.
type entry[K comparable, V any] struct {
	key   K
	value V
}

// New creates an LRU cache with the given capacity.
//
// Parameters:
//   - capacity: Maximum items before eviction (default: 1000 if <= 0)
//
// Returns:
//   - Configured Cache ready for Get/Put
func New[K comparable, V any](capacity int) *Cache[K, V] {
	if capacity <= 0 {
		capacity = 1000
	}
	return &Cache[K, V]{
		capacity: capacity,
		list:     list.New(),
		items:    make(map[K]*list.Element),
		sticky:   make(map[K]bool),
	}
}

// Get retrieves a value by key and moves it to most recently used.
//
// Parameters:
//   - key: Key to look up
//
// Returns:
//   - Value and true if found
//   - Zero value and false if not found
//
// Thread Safety: Safe for concurrent calls.
func (c *Cache[K, V]) Get(key K) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.items[key]; ok {
		c.list.MoveToFront(elem)
		return elem.Value.(*entry[K, V]).value, true
	}

	var zero V
	return zero, false
}

// Put stores a key-value pair, evicting LRU item if at capacity.
//
// Parameters:
//   - key: Key to store
//   - value: Value to store
//
// Behavior:
//   - Updates existing key and moves to front
//   - Adds new key at front
//   - Evicts LRU non-sticky item if at capacity
//
// Thread Safety: Safe for concurrent calls.
func (c *Cache[K, V]) Put(key K, value V) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.items[key]; ok {
		c.list.MoveToFront(elem)
		elem.Value.(*entry[K, V]).value = value
		return
	}

	elem := c.list.PushFront(&entry[K, V]{key: key, value: value})
	c.items[key] = elem

	c.evictIfNeeded()
}

// GetOrCreate gets existing value or creates new one using factory.
//
// Parameters:
//   - key: Key to look up or create
//   - factory: Function to create value if not exists
//
// Returns:
//   - Existing or newly created value
//
// Thread Safety: Factory is called under lock - keep it fast.
func (c *Cache[K, V]) GetOrCreate(key K, factory func() V) V {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.items[key]; ok {
		c.list.MoveToFront(elem)
		return elem.Value.(*entry[K, V]).value
	}

	value := factory()
	elem := c.list.PushFront(&entry[K, V]{key: key, value: value})
	c.items[key] = elem
	c.evictIfNeeded()

	return value
}

// evictIfNeeded removes LRU non-sticky items until under capacity.
func (c *Cache[K, V]) evictIfNeeded() {
	for c.list.Len() > c.capacity {
		evicted := false
		// Search from back (LRU) for non-sticky item
		for elem := c.list.Back(); elem != nil; elem = elem.Prev() {
			e := elem.Value.(*entry[K, V])
			if !c.sticky[e.key] {
				c.list.Remove(elem)
				delete(c.items, e.key)
				evicted = true
				break
			}
		}

		// All items are sticky - can't evict
		if !evicted {
			break
		}
	}
}

// SetSticky marks a key as sticky (non-evictable) or removes sticky status.
//
// Parameters:
//   - key: Key to modify
//   - sticky: true to pin, false to unpin
func (c *Cache[K, V]) SetSticky(key K, sticky bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if sticky {
		c.sticky[key] = true
	} else {
		delete(c.sticky, key)
	}
}

// IsSticky returns whether a key is marked as sticky.
func (c *Cache[K, V]) IsSticky(key K) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.sticky[key]
}

// Delete removes a key from the cache.
//
// Parameters:
//   - key: Key to remove
//
// Note: Also removes sticky status if set.
func (c *Cache[K, V]) Delete(key K) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.items[key]; ok {
		c.list.Remove(elem)
		delete(c.items, key)
		delete(c.sticky, key)
	}
}

// Len returns the current number of items in the cache.
func (c *Cache[K, V]) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.list.Len()
}

// Clear removes all items from the cache.
func (c *Cache[K, V]) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.list.Init()
	c.items = make(map[K]*list.Element)
	c.sticky = make(map[K]bool)
}

// Keys returns all keys in LRU order (most recent first).
func (c *Cache[K, V]) Keys() []K {
	c.mu.RLock()
	defer c.mu.RUnlock()

	keys := make([]K, 0, c.list.Len())
	for elem := c.list.Front(); elem != nil; elem = elem.Next() {
		keys = append(keys, elem.Value.(*entry[K, V]).key)
	}
	return keys
}

// Capacity returns the maximum cache size.
func (c *Cache[K, V]) Capacity() int {
	return c.capacity
}

// StickyCount returns the number of sticky entries.
func (c *Cache[K, V]) StickyCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.sticky)
}
