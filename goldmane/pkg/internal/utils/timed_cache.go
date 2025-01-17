package utils

import (
	"sync"
	"time"

	"github.com/projectcalico/calico/goldmane/pkg/internal/types"
	"github.com/projectcalico/calico/goldmane/proto"
)

// cacheKey wraps the canonical FlowKey type with a start and end time, as well as a scope (typically
// set to be the the originating node) since this cache stores flows across multiple
// sources and aggregation intervals.
type cacheKey struct {
	fk        types.FlowKey
	startTime int64
	endTime   int64
	scope     string
}

type expiringCacheEntry struct {
	Flow     *proto.Flow
	ExpireAt time.Time
}

// ExpiringFlowCache implements a cache of flow entries that expire after a configurable duration.
type ExpiringFlowCache struct {
	sync.Mutex
	flows    map[cacheKey]*expiringCacheEntry
	duration time.Duration
}

func NewExpiringFlowCache(d time.Duration) *ExpiringFlowCache {
	return &ExpiringFlowCache{
		flows:    make(map[cacheKey]*expiringCacheEntry),
		duration: d,
	}
}

func (c *ExpiringFlowCache) Add(f *proto.Flow, scope string) {
	key := cacheKey{
		startTime: f.StartTime,
		endTime:   f.EndTime,
		fk:        *types.ProtoToFlowKey(f.Key),
		scope:     scope,
	}
	c.Lock()
	defer c.Unlock()
	c.flows[key] = &expiringCacheEntry{
		Flow:     f,
		ExpireAt: time.Now().Add(c.duration),
	}
}

func (c *ExpiringFlowCache) Has(f *proto.Flow, scope string) bool {
	key := cacheKey{
		startTime: f.StartTime,
		endTime:   f.EndTime,
		fk:        *types.ProtoToFlowKey(f.Key),
		scope:     scope,
	}
	c.Lock()
	defer c.Unlock()
	_, ok := c.flows[key]
	return ok
}

func (c *ExpiringFlowCache) Iter(f func(f *proto.Flow) error) error {
	c.Lock()
	defer c.Unlock()
	for _, v := range c.flows {
		if err := f(v.Flow); err != nil {
			return err
		}
	}
	return nil
}

func (c *ExpiringFlowCache) Run(interval time.Duration) {
	for {
		<-time.After(interval)
		c.DeleteExpired()
	}
}

func (c *ExpiringFlowCache) DeleteExpired() {
	c.Lock()
	defer c.Unlock()

	now := time.Now()
	for k, v := range c.flows {
		if v.ExpireAt.Before(now) {
			delete(c.flows, k)
		}
	}
}
