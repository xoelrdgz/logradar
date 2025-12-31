package lru

import (
	"container/list"
	"sync"
)

type Cache[K comparable, V any] struct {
	capacity int
	mu       sync.RWMutex

	list  *list.List
	items map[K]*list.Element

	sticky map[K]bool
}

type entry[K comparable, V any] struct {
	key   K
	value V
}

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

func (c *Cache[K, V]) evictIfNeeded() {
	for c.list.Len() > c.capacity {
		evicted := false
		for elem := c.list.Back(); elem != nil; elem = elem.Prev() {
			e := elem.Value.(*entry[K, V])
			if !c.sticky[e.key] {
				c.list.Remove(elem)
				delete(c.items, e.key)
				evicted = true
				break
			}
		}

		if !evicted {
			break
		}
	}
}

func (c *Cache[K, V]) SetSticky(key K, sticky bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if sticky {
		c.sticky[key] = true
	} else {
		delete(c.sticky, key)
	}
}

func (c *Cache[K, V]) IsSticky(key K) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.sticky[key]
}

func (c *Cache[K, V]) Delete(key K) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.items[key]; ok {
		c.list.Remove(elem)
		delete(c.items, key)
		delete(c.sticky, key)
	}
}

func (c *Cache[K, V]) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.list.Len()
}

func (c *Cache[K, V]) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.list.Init()
	c.items = make(map[K]*list.Element)
	c.sticky = make(map[K]bool)
}

func (c *Cache[K, V]) Keys() []K {
	c.mu.RLock()
	defer c.mu.RUnlock()

	keys := make([]K, 0, c.list.Len())
	for elem := c.list.Front(); elem != nil; elem = elem.Next() {
		keys = append(keys, elem.Value.(*entry[K, V]).key)
	}
	return keys
}

func (c *Cache[K, V]) Capacity() int {
	return c.capacity
}

func (c *Cache[K, V]) StickyCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.sticky)
}
