package intdataplane

import (
	"maps"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/proto"
)

type HostMetadataCache struct {
	updates     map[string]*proto.HostMetadataV4V6Update
	updatesLock sync.Mutex
	inSync      bool

	onHostUpdateCB func(map[string]*proto.HostMetadataV4V6Update)
	cbLock         sync.Mutex

	updateRequest    chan signal
	throttleInterval time.Duration
	newTimerFn       NewResettableTimerFunc
}

type signal struct{}

type HostMetadataCacheOption func(*HostMetadataCache)

// OptWithThrottleInterval sets the throttling interval for update flushes.
func OptWithThrottleInterval(d time.Duration) func(t *HostMetadataCache) {
	return func(t *HostMetadataCache) { t.throttleInterval = d }
}

// OptWithNewTimerFn sets the ResettableTimer in the HostMetadataCache.
func OptWithNewTimerFn(f NewResettableTimerFunc) func(t *HostMetadataCache) {
	return func(t *HostMetadataCache) { t.newTimerFn = f }
}

func NewHostMetadataCache(opts ...HostMetadataCacheOption) *HostMetadataCache {
	c := &HostMetadataCache{
		updates:          make(map[string]*proto.HostMetadataV4V6Update),
		updateRequest:    make(chan signal, 1),
		throttleInterval: time.Second,
		newTimerFn:       NewRealTimer,
	}

	for _, o := range opts {
		o(c)
	}

	return c
}

func (c *HostMetadataCache) CompleteDeferredWork() error {
	if !c.inSync {
		logrus.Debug("Now in sync")
	}
	c.inSync = true
	c.requestFlush()
	return nil
}

func (c *HostMetadataCache) OnUpdate(u any) {
	switch upd := u.(type) {
	case *proto.HostMetadataV4V6Update:
		logrus.WithField("update", upd).Debug("Received HostMetadataV4V6Update message")
		c.onHostMetadataV4V6Update(upd)

	case *proto.HostMetadataV4V6Remove:
		logrus.WithField("update", upd).Debug("Received HostMetadataV4V6Remove message")
		c.onHostMetadataV4V6Remove(upd)
	default:
		return
	}

	if c.inSync {
		c.requestFlush()
	}
}

func (c *HostMetadataCache) onHostMetadataV4V6Update(u *proto.HostMetadataV4V6Update) {
	c.updatesLock.Lock()
	defer c.updatesLock.Unlock()
	c.updates[u.Hostname] = u
}

func (c *HostMetadataCache) onHostMetadataV4V6Remove(u *proto.HostMetadataV4V6Remove) {
	c.updatesLock.Lock()
	defer c.updatesLock.Unlock()
	delete(c.updates, u.Hostname)
}

func (c *HostMetadataCache) requestFlush() {
	select {
	case c.updateRequest <- signal{}:
	default:
	}
}

// Start spawns a new goroutine for the cache to flush updates.
func (c *HostMetadataCache) Start() {
	go c.loopFlushingUpdates()
}

// loopFlushingUpdates flushes updates indefinitely at most once every c.throttleInterval.
// Intended to be run on its own goroutine.
func (c *HostMetadataCache) loopFlushingUpdates() {
	timer := c.newTimerFn(c.throttleInterval)
	for {
		// One update should get through immediately before timers can delay things.
		<-c.updateRequest
		logrus.Debug("Flushing host metadata cached updates")
		c.sendAllUpdates()
		_ = timer.Reset(c.throttleInterval)
		<-timer.Chan()
	}
}

func (c *HostMetadataCache) sendAllUpdates() {
	c.cbLock.Lock()
	defer c.cbLock.Unlock()
	c.updatesLock.Lock()
	defer c.updatesLock.Lock()

	if c.onHostUpdateCB != nil {
		upds := make(map[string]*proto.HostMetadataV4V6Update)
		maps.Copy(upds, c.updates)
		c.onHostUpdateCB(upds)
	}
}

func (c *HostMetadataCache) SetOnHostUpdateCB(cb func(map[string]*proto.HostMetadataV4V6Update)) {
	c.cbLock.Lock()
	defer c.cbLock.Unlock()

	c.onHostUpdateCB = cb
}

// wrappedRealTimer implements the ResettableTimer interface.
// time.Timer requires a method Chan to return timer.C when wrapped in an interface.
type wrappedRealTimer struct {
	*time.Timer
}

// Chan implements the ResettableTimer interface.
func (t wrappedRealTimer) Chan() <-chan time.Time {
	return t.C
}

// NewRealTimer returns a time.Timer, wrapped to implement the ResettableTimer interface.
func NewRealTimer(d time.Duration) ResettableTimer {
	return wrappedRealTimer{time.NewTimer(d)}
}

type ResettableTimer interface {
	Reset(time.Duration) bool
	Chan() <-chan time.Time
}

type NewResettableTimerFunc func(time.Duration) ResettableTimer
