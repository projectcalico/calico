package intdataplane

import (
	"maps"
	"sync"

	"github.com/projectcalico/calico/felix/proto"
)

type HostMetadataCache struct {
	updates map[string]*proto.HostMetadataV4V6Update
	inSync  bool

	onHostUpdateCB func(map[string]*proto.HostMetadataV4V6Update)
	cbLock         sync.Mutex
}

func NewHostMetadataCache() *HostMetadataCache {
	return &HostMetadataCache{
		updates: make(map[string]*proto.HostMetadataV4V6Update),
	}
}

func (c *HostMetadataCache) CompleteDeferredWork() error {
	c.inSync = true
	c.sendAllUpdates()
	return nil
}

func (c *HostMetadataCache) OnUpdate(u any) {
	switch upd := u.(type) {
	case *proto.HostMetadataV4V6Update:
		c.onHostMetadataV4V6Update(upd)
	case *proto.HostMetadataV4V6Remove:
		c.onHostMetadataV4V6Remove(upd)
	default:
		return
	}

	if c.inSync {
		c.sendAllUpdates()
	}
}

func (c *HostMetadataCache) sendAllUpdates() {
	c.cbLock.Lock()
	defer c.cbLock.Unlock()
	if c.onHostUpdateCB != nil {
		upds := make(map[string]*proto.HostMetadataV4V6Update)
		maps.Copy(upds, c.updates)
		c.onHostUpdateCB(upds)
	}
}

func (c *HostMetadataCache) onHostMetadataV4V6Update(u *proto.HostMetadataV4V6Update) {
	c.updates[u.Hostname] = u
}

func (c *HostMetadataCache) onHostMetadataV4V6Remove(u *proto.HostMetadataV4V6Remove) {
	delete(c.updates, u.Hostname)
}

func (c *HostMetadataCache) SetOnHostUpdateCB(cb func(map[string]*proto.HostMetadataV4V6Update)) {
	c.cbLock.Lock()
	defer c.cbLock.Unlock()

	c.onHostUpdateCB = cb
}
