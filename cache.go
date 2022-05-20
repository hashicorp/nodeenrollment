package nodeenrollment

import (
	"sync"

	"github.com/patrickmn/go-cache"
)

type RegistrationCache interface {
	Get(string) (any, bool)
	Set(string, any)
	ItemCount() int
	Flush()
}

var _ RegistrationCache = (*wrappingCache)(nil)

// TestCache can be used to get a wrappingCache to override caches for tests.
// Use via new(TestCache).
type TestCache = wrappingCache

type wrappingCache struct {
	cache *cache.Cache
	init  sync.Once
}

func (w *wrappingCache) initCache() {
	w.cache = cache.New(DefaultRegistrationCacheLifetime, DefaultRegistrationCacheCleanupInterval)
}

func (w *wrappingCache) Get(k string) (any, bool) {
	w.init.Do(w.initCache)
	return w.cache.Get(k)
}

func (w *wrappingCache) Set(k string, x any) {
	w.init.Do(w.initCache)
	w.cache.SetDefault(k, x)
}

func (w *wrappingCache) ItemCount() int {
	w.init.Do(w.initCache)
	return w.cache.ItemCount()
}

func (w *wrappingCache) Flush() {
	w.init.Do(w.initCache)
	w.cache.Flush()
}
