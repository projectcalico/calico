package intdataplane

import (
	"maps"
	"sync"
	"time"

	"github.com/projectcalico/calico/felix/proto"
	"github.com/sirupsen/logrus"
)

type HostMetadataCache struct {
	updates     map[string]*proto.HostMetadataV4V6Update
	updatesLock sync.Mutex
	inSync      bool

	onHostUpdateCB func(map[string]*proto.HostMetadataV4V6Update)
	cbLock         sync.Mutex

	queue chan signal
}

type signal struct{}

func NewHostMetadataCache() *HostMetadataCache {
	c := &HostMetadataCache{
		updates: make(map[string]*proto.HostMetadataV4V6Update),
		queue:   make(chan signal, 1),
	}

	go c.loopFlushingUpdates()
	return c
}

func (c *HostMetadataCache) CompleteDeferredWork() error {
	c.inSync = true
	logrus.Debug("Now in sync")
	c.requestUpdate()
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
		c.requestUpdate()
	}
}

func (c *HostMetadataCache) onHostMetadataV4V6Update(u *proto.HostMetadataV4V6Update) {
	c.updates[u.Hostname] = u
}

func (c *HostMetadataCache) onHostMetadataV4V6Remove(u *proto.HostMetadataV4V6Remove) {
	delete(c.updates, u.Hostname)
}

func (c *HostMetadataCache) requestUpdate() {
	select {
	case c.queue <- signal{}:
	default:
	}
}

func (c *HostMetadataCache) loopFlushingUpdates() {
	var timer *time.Timer
	for {
		<-c.queue
		c.sendAllUpdates()

		if timer == nil {
			timer = time.NewTimer(time.Second)
		} else {
			_ = timer.Reset(time.Second)
		}
		<-timer.C
	}
}

func (c *HostMetadataCache) sendAllUpdates() error {
	c.cbLock.Lock()
	defer c.cbLock.Unlock()
	c.updatesLock.Lock()
	defer c.updatesLock.Lock()

	if c.onHostUpdateCB != nil {
		upds := make(map[string]*proto.HostMetadataV4V6Update)
		maps.Copy(upds, c.updates)
		c.onHostUpdateCB(upds)
	}

	return nil
}

func (c *HostMetadataCache) SetOnHostUpdateCB(cb func(map[string]*proto.HostMetadataV4V6Update)) {
	c.cbLock.Lock()
	defer c.cbLock.Unlock()

	c.onHostUpdateCB = cb
}
