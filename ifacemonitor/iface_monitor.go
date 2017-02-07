// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.
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

package ifacemonitor

import (
	"syscall"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/projectcalico/felix/set"
)

type netlinkStub interface {
	Subscribe(
		linkUpdates chan netlink.LinkUpdate,
		addrUpdates chan netlink.AddrUpdate,
	) error
	LinkList() ([]netlink.Link, error)
	AddrList(link netlink.Link, family int) ([]netlink.Addr, error)
}

type State string

const (
	StateUp   = "up"
	StateDown = "down"
)

type InterfaceStateCallback func(ifaceName string, ifaceState State)
type AddrStateCallback func(ifaceName string, addrs set.Set)

type InterfaceMonitor struct {
	netlinkStub  netlinkStub
	resyncC      <-chan time.Time
	upIfaces     set.Set
	Callback     InterfaceStateCallback
	AddrCallback AddrStateCallback
	ifaceName    map[int]string
	ifaceAddrs   map[int]set.Set
}

func New() *InterfaceMonitor {
	// Interface monitor using the real netlink, and resyncing every 10 seconds.
	resyncTicker := time.NewTicker(10 * time.Second)
	return NewWithStubs(&netlinkReal{}, resyncTicker.C)
}

func NewWithStubs(netlinkStub netlinkStub, resyncC <-chan time.Time) *InterfaceMonitor {
	return &InterfaceMonitor{
		netlinkStub: netlinkStub,
		resyncC:     resyncC,
		upIfaces:    set.New(),
		ifaceName:   map[int]string{},
		ifaceAddrs:  map[int]set.Set{},
	}
}

func (m *InterfaceMonitor) MonitorInterfaces() {
	log.Info("Interface monitoring thread started.")

	updates := make(chan netlink.LinkUpdate)
	addrUpdates := make(chan netlink.AddrUpdate)
	if err := m.netlinkStub.Subscribe(updates, addrUpdates); err != nil {
		log.WithError(err).Fatal("Failed to subscribe to netlink stub")
	}
	log.Info("Subscribed to netlink updates.")

	// Start of day, do a resync to notify all our existing interfaces.  We also do periodic
	// resyncs because it's not clear what the ordering guarantees are for our netlink
	// subscription vs a list operation as used by resync().
	err := m.resync()
	if err != nil {
		log.WithError(err).Fatal("Failed to read link states from netlink.")
	}

readLoop:
	for {
		log.WithFields(log.Fields{
			"updates":     updates,
			"addrUpdates": addrUpdates,
			"resyncC":     m.resyncC,
		}).Debug("About to select on possible triggers")
		select {
		case update, ok := <-updates:
			log.WithField("update", update).Debug("Link update")
			if !ok {
				log.Warn("Failed to read a link update")
				break readLoop
			}
			m.handleNetlinkUpdate(update)
		case addrUpdate, ok := <-addrUpdates:
			log.WithField("addrUpdate", addrUpdate).Debug("Address update")
			if !ok {
				log.Warn("Failed to read an address update")
				break readLoop
			}
			m.handleNetlinkAddrUpdate(addrUpdate)
		case <-m.resyncC:
			log.Debug("Resync trigger")
			err := m.resync()
			if err != nil {
				log.WithError(err).Fatal("Failed to read link states from netlink.")
			}
		}
	}
	log.Fatal("Failed to read events from Netlink.")
}

func (m *InterfaceMonitor) handleNetlinkUpdate(update netlink.LinkUpdate) {
	attrs := update.Attrs()
	if attrs == nil {
		// Defensive, some sort of interface that the netlink lib doesn't understand?
		log.WithField("update", update).Warn("Missing attributes on netlink update.")
		return
	}
	msgType := update.Header.Type
	ifaceExists := msgType == syscall.RTM_NEWLINK // Alternative is an RTM_DELLINK
	m.storeAndNotifyLink(ifaceExists, update.Link)
}

func (m *InterfaceMonitor) handleNetlinkAddrUpdate(update netlink.AddrUpdate) {
	addr := update.LinkAddress.IP.String()
	ifIndex := update.LinkIndex
	exists := update.NewAddr
	log.WithFields(log.Fields{
		"addr":    addr,
		"ifIndex": ifIndex,
		"exists":  exists,
	}).Info("Netlink address update.")

	// notifyIfaceAddrs needs m.ifaceName[ifIndex] - because we can only notify when we know the
	// interface name - so check that we have that.
	if _, known := m.ifaceName[ifIndex]; !known {
		// We think this interface does not exist - indicates a race between the link and
		// address update channels.  Addresses will be notified when we process the link
		// update.
		log.WithField("ifIndex", ifIndex).Debug("Link not notified yet.")
		return
	}
	if _, known := m.ifaceAddrs[ifIndex]; !known {
		// m.ifaceAddrs[ifIndex] has exactly the same lifetime as m.ifaceName[ifIndex], so
		// it should be impossible for m.ifaceAddrs[ifIndex] not to exist if
		// m.ifaceName[ifIndex] does exist.  However we check anyway and warn in case there
		// is some possible scenario...
		log.WithField("ifIndex", ifIndex).Warn("Race for new interface.")
		return
	}

	if exists {
		if !m.ifaceAddrs[ifIndex].Contains(addr) {
			m.ifaceAddrs[ifIndex].Add(addr)
			m.notifyIfaceAddrs(ifIndex)
		}
	} else {
		if m.ifaceAddrs[ifIndex].Contains(addr) {
			m.ifaceAddrs[ifIndex].Discard(addr)
			m.notifyIfaceAddrs(ifIndex)
		}
	}
}

func (m *InterfaceMonitor) notifyIfaceAddrs(ifIndex int) {
	log.WithField("ifIndex", ifIndex).Debug("notifyIfaceAddrs")
	if name, known := m.ifaceName[ifIndex]; known {
		log.WithField("ifIndex", ifIndex).Debug("Known interface")
		addrs := m.ifaceAddrs[ifIndex]
		if addrs != nil {
			// Take a copy, so that the dataplane's set of addresses is independent of
			// ours.
			addrs = addrs.Copy()
		}
		m.AddrCallback(name, addrs)
	}
}

func (m *InterfaceMonitor) storeAndNotifyLink(ifaceExists bool, link netlink.Link) {
	log.WithFields(log.Fields{
		"ifaceExists": ifaceExists,
		"link":        link,
	}).Debug("storeAndNotifyLink called")

	attrs := link.Attrs()
	ifIndex := attrs.Index
	oldName := m.ifaceName[ifIndex]
	newName := attrs.Name
	if oldName != "" && oldName != newName {
		log.WithFields(log.Fields{
			"oldName": oldName,
			"newName": newName,
		}).Info("Interface renamed, simulating deletion of old copy.")
		m.storeAndNotifyLinkInner(false, oldName, link)
	}

	m.storeAndNotifyLinkInner(ifaceExists, newName, link)
}

func (m *InterfaceMonitor) storeAndNotifyLinkInner(ifaceExists bool, ifaceName string, link netlink.Link) {
	log.WithFields(log.Fields{
		"ifaceExists": ifaceExists,
		"ifaceName":   ifaceName,
		"link":        link,
	}).Debug("storeAndNotifyLinkInner called")

	// Store or remove mapping between this interface's index and name.
	attrs := link.Attrs()
	ifIndex := attrs.Index
	if ifaceExists {
		m.ifaceName[ifIndex] = ifaceName
	} else {
		log.Debug("Notify link non-existence to address callback consumers")
		delete(m.ifaceAddrs, ifIndex)
		m.notifyIfaceAddrs(ifIndex)
		delete(m.ifaceName, ifIndex)
	}

	// We need the operstate of the interface; this is carried in the IFF_RUNNING flag.  The
	// IFF_UP flag contains the admin state, which doesn't tell us whether we can program routes
	// etc.
	rawFlags := attrs.RawFlags
	ifaceIsUp := ifaceExists && rawFlags&syscall.IFF_RUNNING != 0
	ifaceWasUp := m.upIfaces.Contains(ifaceName)
	logCxt := log.WithField("ifaceName", ifaceName)
	if ifaceIsUp && !ifaceWasUp {
		logCxt.Debug("Interface now up")
		m.upIfaces.Add(ifaceName)
		m.Callback(ifaceName, StateUp)
	} else if ifaceWasUp && !ifaceIsUp {
		logCxt.Debug("Interface now down")
		m.upIfaces.Discard(ifaceName)
		m.Callback(ifaceName, StateDown)
	} else {
		logCxt.WithField("ifaceIsUp", ifaceIsUp).Debug("Nothing to notify")
	}

	// If the link now exists, get addresses for the link and store and notify those too; then
	// we don't have to worry about a possible race between the link and address update
	// channels.  We deliberately do this regardless of the link state, as in some cases this
	// will allow us to secure a Host Endpoint interface _before_ it comes up, and so eliminate
	// a small window of insecurity.
	if ifaceExists {
		newAddrs := set.New()
		for _, family := range [2]int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
			addrs, err := m.netlinkStub.AddrList(link, family)
			if err != nil {
				log.WithError(err).Warn("Netlink addr list operation failed.")
			}
			for _, addr := range addrs {
				newAddrs.Add(addr.IPNet.IP.String())
			}
		}
		if (m.ifaceAddrs[ifIndex] == nil) || !m.ifaceAddrs[ifIndex].Equals(newAddrs) {
			m.ifaceAddrs[ifIndex] = newAddrs
			m.notifyIfaceAddrs(ifIndex)
		}
	}
}

func (m *InterfaceMonitor) resync() error {
	log.Debug("Resyncing interface state.")
	links, err := m.netlinkStub.LinkList()
	if err != nil {
		log.WithError(err).Warn("Netlink list operation failed.")
		return err
	}
	currentIfaces := set.New()
	for _, link := range links {
		attrs := link.Attrs()
		if attrs == nil {
			// Defensive, some sort of interface that the netlink lib doesn't
			// understand?
			log.WithField("link", link).Warn("Missing attributes on netlink update.")
			continue
		}
		currentIfaces.Add(attrs.Name)
		m.storeAndNotifyLink(true, link)
	}
	m.upIfaces.Iter(func(name interface{}) error {
		if currentIfaces.Contains(name) {
			return nil
		}
		log.WithField("ifaceName", name).Info("Spotted interface removal on resync.")
		m.Callback(name.(string), StateDown)
		m.AddrCallback(name.(string), nil)
		return set.RemoveItem
	})
	log.Debug("Resync complete")
	return nil
}
