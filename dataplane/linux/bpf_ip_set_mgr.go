// Copyright (c) 2019 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package intdataplane

import (
	"encoding/binary"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/felix/bpf"
	"github.com/projectcalico/felix/ip"
	"github.com/projectcalico/felix/proto"
	"github.com/projectcalico/libcalico-go/lib/set"
)

type mapManager struct {
	// Caches.  Updated immediately for now.
	desiredKeysByIPSetID map[uint64]set.Set

	keysToAddByIPSetID    map[uint64]set.Set
	keysToRemoveByIPSetID map[uint64]set.Set

	ipSetMap bpf.Map

	dirtyIPSetIDs   set.Set
	resyncScheduled bool
}

// uint32 prefixLen HE  4
// uint64 set_id BE     +8 = 12
// uint32 addr BE       +4 = 16
// uint16 port HE       +2 = 18
// uint8 proto          +1 = 19
// uint8 pad            +1 = 20
const ipSetEntrySize = 20

type IPSetEntry [ipSetEntrySize]byte

func newBPFMapManager() *mapManager {
	return &mapManager{
		desiredKeysByIPSetID:  map[uint64]set.Set{},
		keysToAddByIPSetID:    map[uint64]set.Set{},
		keysToRemoveByIPSetID: map[uint64]set.Set{},
		dirtyIPSetIDs:         set.New(),
		ipSetMap:              IPSetsMap(),
		resyncScheduled:       true,
	}
}

func IPSetsMap() bpf.Map {
	return bpf.NewPinnedMap(
		"calico_ip_sets",
		"/sys/fs/bpf/tc/globals/calico_ip_sets",
		"lpm_trie",
		ipSetEntrySize,
		4,
		1024*1024,
		unix.BPF_F_NO_PREALLOC)
}

func (e IPSetEntry) SetID() uint64 {
	return binary.BigEndian.Uint64(e[4:12])
}

func (e IPSetEntry) Addr() net.IP {
	return e[12:16]
}

func (e IPSetEntry) PrefixLen() uint32 {
	return binary.LittleEndian.Uint32(e[:4])
}

func (e IPSetEntry) Protocol() uint8 {
	return e[18]
}

func (e IPSetEntry) Port() uint32 {
	return binary.LittleEndian.Uint32(e[16:18])
}

func makeBPFIPSetEntry(setID uint64, cidr ip.V4CIDR, port uint16, proto uint8) IPSetEntry {
	var entry IPSetEntry
	// TODO Detect endianness
	if proto == 0 {
		// Normal CIDR-based lookup.
		binary.LittleEndian.PutUint32(entry[0:4], uint32(64 /* ID */ +cidr.Prefix()))
	} else {
		// Named port lookup, use full length of key.
		binary.LittleEndian.PutUint32(entry[0:4], 64 /* ID */ +32 /* IP */ +16 /* Port */ +8 /* protocol */)
	}
	binary.BigEndian.PutUint64(entry[4:12], setID)
	binary.BigEndian.PutUint32(entry[12:16], cidr.Addr().(ip.V4Addr).AsUint32())
	binary.LittleEndian.PutUint16(entry[16:18], port)
	entry[18] = proto
	return entry
}

func (m *mapManager) OnUpdate(msg interface{}) {
	switch msg := msg.(type) {
	// IP set-related messages, these are extremely common.
	case *proto.IPSetUpdate:
		log.WithField("id", msg.Id).Info("IP set added")
		id := bpf.IPSetIDToU64(msg.Id)

		oldMembers := m.desiredKeysByIPSetID[id]
		if oldMembers == nil {
			oldMembers = set.Empty()
		}
		newMembers := set.New()
		m.desiredKeysByIPSetID[id] = newMembers

		if m.keysToAddByIPSetID[id] == nil {
			m.keysToAddByIPSetID[id] = set.New()
		}
		if m.keysToRemoveByIPSetID[id] == nil {
			m.keysToRemoveByIPSetID[id] = set.New()
		}
		for _, member := range msg.Members {
			entry := parseIPSetMember(id, member)
			newMembers.Add(entry)
			if !oldMembers.Contains(entry) {
				m.keysToAddByIPSetID[id].Add(entry)
			}
			oldMembers.Discard(entry)
			m.keysToRemoveByIPSetID[id].Discard(entry)
		}
		oldMembers.Iter(func(item interface{}) error {
			entry := item.(IPSetEntry)
			m.keysToRemoveByIPSetID[id].Add(entry)
			return nil
		})

		m.dirtyIPSetIDs.Add(id)
	case *proto.IPSetRemove:
		log.WithField("id", msg.Id).Info("IP set removed")
		id := bpf.IPSetIDToU64(msg.Id)

		oldMembers := m.desiredKeysByIPSetID[id]
		if oldMembers == nil {
			oldMembers = set.Empty()
		}

		if m.keysToRemoveByIPSetID[id] == nil {
			m.keysToRemoveByIPSetID[id] = set.New()
		}
		oldMembers.Iter(func(item interface{}) error {
			entry := item.(IPSetEntry)
			m.keysToRemoveByIPSetID[id].Add(entry)
			return nil
		})

		delete(m.desiredKeysByIPSetID, id)
		delete(m.keysToAddByIPSetID, id)

		m.dirtyIPSetIDs.Add(id)
	case *proto.IPSetDeltaUpdate:
		log.WithField("id", msg.Id).WithField("added", len(msg.AddedMembers)).WithField("removed", len(msg.RemovedMembers)).Info("IP delta")
		id := bpf.IPSetIDToU64(msg.Id)

		for _, member := range msg.RemovedMembers {
			entry := parseIPSetMember(id, member)
			m.desiredKeysByIPSetID[id].Discard(entry)
			m.keysToAddByIPSetID[id].Discard(entry)
			m.keysToRemoveByIPSetID[id].Add(entry)
		}
		for _, member := range msg.AddedMembers {
			entry := parseIPSetMember(id, member)
			m.desiredKeysByIPSetID[id].Add(entry)
			m.keysToAddByIPSetID[id].Add(entry)
			m.keysToRemoveByIPSetID[id].Discard(entry)
		}

		m.dirtyIPSetIDs.Add(id)
	}
}

func parseIPSetMember(id uint64, member string) IPSetEntry {
	var cidrStr string
	var port uint16
	var protocol uint8
	if strings.Contains(member, ",") {
		// Named port
		parts := strings.Split(member, ",")
		cidrStr = parts[0]
		parts = strings.Split(parts[1], ":")
		switch parts[0] {
		case "tcp":
			protocol = 6
		case "udp":
			protocol = 17
		default:
			log.WithField("member", member).Panic("Unknown protocol in named port member")
		}
		port64, err := strconv.ParseUint(parts[1], 10, 16)
		if err != nil {
			log.WithField("member", member).WithError(err).Panic("Failed to parse port")
		}
		port = uint16(port64)
	} else {
		cidrStr = member
	}
	cidr := ip.MustParseCIDROrIP(cidrStr).(ip.V4CIDR)
	entry := makeBPFIPSetEntry(id, cidr, port, protocol)
	return entry
}

var dummyValue = []byte{1, 0, 0, 0}

func (m *mapManager) CompleteDeferredWork() error {
	var numAdds, numDels uint
	startTime := time.Now()

	err := m.ipSetMap.EnsureExists()
	if err != nil {
		log.WithError(err).Panic("Failed to create IP set map")
	}

	debug := log.GetLevel() >= log.DebugLevel
	if m.resyncScheduled {
		log.Info("Doing full resync of BPF IP sets map")
		m.keysToAddByIPSetID = map[uint64]set.Set{}
		m.keysToRemoveByIPSetID = map[uint64]set.Set{}

		for setID, desiredEntries := range m.desiredKeysByIPSetID {
			if debug {
				log.WithField("setID", setID).Debug("Copying entries from desired->add")
			}
			m.keysToAddByIPSetID[setID] = set.New()
			m.keysToRemoveByIPSetID[setID] = set.New()
			desiredEntries.Iter(func(item interface{}) error {
				m.keysToAddByIPSetID[setID].Add(item)
				return nil
			})
			m.dirtyIPSetIDs.Add(setID)
		}

		err := m.ipSetMap.Iter(func(k, v []byte) {
			var entry IPSetEntry
			copy(entry[:], k)
			setID := entry.SetID()
			if debug {
				log.WithFields(log.Fields{"setID": setID,
					"addr":      entry.Addr(),
					"prefixLen": entry.PrefixLen()}).Debug("Found entry in dataplane")
			}
			kta := m.keysToAddByIPSetID[setID]
			if kta == nil {
				kta = set.Empty()
			}
			if kta.Contains(entry) {
				if debug {
					log.Debug("Entry was expected")
				}
				kta.Discard(entry)
			} else {
				if debug {
					log.Debug("Entry wasn't expected, marking for deletion")
				}
				ktr := m.keysToRemoveByIPSetID[setID]
				if ktr == nil {
					ktr = set.New()
					m.keysToRemoveByIPSetID[setID] = ktr
				}
				ktr.Add(entry)
				m.dirtyIPSetIDs.Add(setID)
			}
		})
		if err != nil {
			log.WithError(err).Panic("Failed to scan BPF map.")
		}

		m.dirtyIPSetIDs.Iter(func(item interface{}) error {
			setID := item.(uint64)

			kta := m.keysToAddByIPSetID[setID]
			if kta == nil {
				kta = set.Empty()
			}
			if kta.Len() > 0 {
				return nil
			}
			ktr := m.keysToRemoveByIPSetID[setID]
			if ktr == nil {
				ktr = set.Empty()
			}
			if ktr.Len() > 0 {
				return nil
			}

			log.WithField("setID", setID).Debug("IP set is now clean")
			return set.RemoveItem
		})

		m.resyncScheduled = false
	}

	m.dirtyIPSetIDs.Iter(func(item interface{}) error {
		leaveDirty := false

		setID := item.(uint64)
		m.keysToRemoveByIPSetID[setID].Iter(func(item interface{}) error {
			entry := item.(IPSetEntry)
			if debug {
				log.WithFields(log.Fields{"setID": setID, "entry": entry}).Debug("Removing entry from IP set")
			}
			err := m.ipSetMap.Delete(entry[:])
			if err != nil {
				log.WithError(err).Error("Failed to remove IP set entry")
				leaveDirty = true
				return nil
			}
			numDels++
			return set.RemoveItem
		})

		if m.desiredKeysByIPSetID[setID] == nil {
			delete(m.keysToAddByIPSetID, setID)
			delete(m.keysToRemoveByIPSetID, setID)
		} else {
			m.keysToAddByIPSetID[setID].Iter(func(item interface{}) error {
				entry := item.(IPSetEntry)
				if debug {
					log.WithFields(log.Fields{"setID": setID, "entry": entry}).Debug("Adding entry to IP set")
				}
				err := m.ipSetMap.Update(entry[:], dummyValue)
				if err != nil {
					log.WithError(err).Error("Failed to add IP set entry")
					leaveDirty = true
					return nil
				}
				numAdds++
				return set.RemoveItem
			})
		}

		if leaveDirty {
			log.WithField("setID", setID).Debug("IP set still dirty, queueing resync")
			m.resyncScheduled = true
			return nil
		}

		log.WithField("setID", setID).Debug("IP set is now clean")
		return set.RemoveItem
	})

	duration := time.Since(startTime)
	if numDels > 0 || numAdds > 0 {
		log.WithFields(log.Fields{
			"timeTaken": duration,
			"numAdds":   numAdds,
			"numDels":   numDels,
		}).Info("Completed updates to BPF IP sets.")
	}

	return nil
}
