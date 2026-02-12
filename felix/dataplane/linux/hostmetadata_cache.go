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

	queue            chan signal
	throttleInterval time.Duration
}

type signal struct{}

type HostMetadataCacheOption func(*HostMetadataCache)

func NewHostMetadataCache(opts ...HostMetadataCacheOption) *HostMetadataCache {
	c := &HostMetadataCache{
		updates:          make(map[string]*proto.HostMetadataV4V6Update),
		queue:            make(chan signal, 1),
		throttleInterval: time.Second,
	}

	for _, o := range opts {
		o(c)
	}

	go c.loopFlushingUpdates()
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
	c.updates[u.Hostname] = u
}

func (c *HostMetadataCache) onHostMetadataV4V6Remove(u *proto.HostMetadataV4V6Remove) {
	delete(c.updates, u.Hostname)
}

func (c *HostMetadataCache) requestFlush() {
	select {
	case c.queue <- signal{}:
	default:
	}
}

func (c *HostMetadataCache) loopFlushingUpdates() {
	var timer *time.Timer
	for {
		<-c.queue
		logrus.Debug("Flushing throttled updates")
		c.sendAllUpdates()

		if timer == nil {
			timer = time.NewTimer(c.throttleInterval)
		} else {
			_ = timer.Reset(c.throttleInterval)
		}
		<-timer.C
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

// SetThrottle implements the Throttled interface.
func (c *HostMetadataCache) SetThrottle(d time.Duration) {
	c.throttleInterval = d
}

// Throttled allows any module to use the 'with throttle interval' option.
// This felt prudent since dataplane manager options share scope with the whole dataplane pkg.
type Throttled interface {
	SetThrottle(time.Duration)
}

// OptWithThrottleInterval sets the throttling interval for any module
// that must regulate the period of an operation.
func OptWithThrottleInterval(d time.Duration) func(t Throttled) {
	return func(t Throttled) { t.SetThrottle(d) }
}
