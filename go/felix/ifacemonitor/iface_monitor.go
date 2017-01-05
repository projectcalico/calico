// Copyright (c) 2016 Tigera, Inc. All rights reserved.
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
	log "github.com/Sirupsen/logrus"
	"github.com/projectcalico/felix/go/felix/set"
	"github.com/vishvananda/netlink"
	"syscall"
	"time"
)

type State string

const (
	StateUp   = "up"
	StateDown = "down"
)

type InterfaceStateCallback func(ifaceName string, ifaceState State)
type AddrStateCallback func(ifaceName string, addrs set.Set)

type InterfaceMonitor struct {
	upIfaces set.Set
	Callback InterfaceStateCallback

	AddrCallback AddrStateCallback
	ifaceName    map[int]string
	ifaceAddrs   map[int]set.Set
}

func New() *InterfaceMonitor {
	return &InterfaceMonitor{
		upIfaces: set.New(),

		ifaceName:  map[int]string{},
		ifaceAddrs: map[int]set.Set{},
	}
}

func (m *InterfaceMonitor) MonitorInterfaces() {
	log.Info("Interface monitoring thread started.")
	updates := make(chan netlink.LinkUpdate)
	addrUpdates := make(chan netlink.AddrUpdate)
	cancel := make(chan struct{})

	if err := netlink.LinkSubscribe(updates, cancel); err != nil {
		log.WithError(err).Fatal("Failed to subscribe to link updates")
	}
	if err := netlink.AddrSubscribe(addrUpdates, cancel); err != nil {
		log.WithError(err).Fatal("Failed to subscribe to addr updates")
	}
	log.Info("Subscribed to netlink updates.")

	// Start of day, do a resync to notify all our existing interfaces.  We also do periodic
	// resyncs because it's not clear what the ordering guarantees are for our netlink
	// subscription vs a list operation as used by resync().
	err := m.resync()
	if err != nil {
		log.WithError(err).Fatal("Failed to read link states from netlink.")
	}

	// Schedule periodic resyncs after that.
	resyncTicker := time.NewTicker(10 * time.Second)
readLoop:
	for {
		select {
		case update, ok := <-updates:
			if !ok {
				log.Warn("Failed to read a link update")
				break readLoop
			}
			m.handleNetlinkUpdate(update)
		case addrUpdate, ok := <-addrUpdates:
			if !ok {
				log.Warn("Failed to read an address update")
				break readLoop
			}
			m.handleNetlinkAddrUpdate(addrUpdate)
		case <-resyncTicker.C:
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

	if _, known := m.ifaceName[ifIndex]; !known {
		log.WithField("ifIndex", ifIndex).Warn("No known iface with this index.")
		return
	}
	if _, known := m.ifaceAddrs[ifIndex]; !known {
		// We think this interface does not exist - indicates a race between the
		// link and address update channels.  Addresses will be notified when we
		// process the link update.
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
	if m.ifaceAddrs[ifIndex] != nil {
		m.AddrCallback(m.ifaceName[ifIndex], m.ifaceAddrs[ifIndex].Copy())
	} else {
		m.AddrCallback(m.ifaceName[ifIndex], m.ifaceAddrs[ifIndex])
	}
}

func (m *InterfaceMonitor) storeAndNotifyLink(ifaceExists bool, link netlink.Link) {
	// Store or remove mapping between this interface's index and name.
	attrs := link.Attrs()
	ifIndex := attrs.Index
	ifaceName := attrs.Name
	if ifaceExists {
		m.ifaceName[ifIndex] = ifaceName
	} else {
		// Notify link non-existence to address callback consumers.
		delete(m.ifaceAddrs, ifIndex)
		m.notifyIfaceAddrs(ifIndex)
		delete(m.ifaceName, ifIndex)
	}

	// We need the operstate of the interface; this is carried in the IFF_RUNNING flag.
	// The IFF_UP flag contains the admin state, which doesn't tell us whether we can
	// program routes etc.
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

	// If the link now exists, get addresses for the link and store and notify those
	// too; then we don't have to worry about a possible race between the link and
	// address update channels.  We deliberately do this regardless of the link state,
	// as in some cases this will allow us to secure a Host Endpoint interface
	// _before_ it comes up, and so eliminate a small window of insecurity.
	if ifaceExists {
		newAddrs := set.New()
		for _, family := range [2]int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
			addrs, err := netlink.AddrList(link, family)
			if err != nil {
				log.WithError(err).Warn("Netlink addr list operation failed.")
			}
			for _, addr := range addrs {
				newAddrs.Add(addr.IPNet.IP.String())
			}
		}
		m.ifaceAddrs[ifIndex] = newAddrs
		m.notifyIfaceAddrs(ifIndex)
	}
}

func (m *InterfaceMonitor) resync() error {
	log.Debug("Resyncing interface state.")
	links, err := netlink.LinkList()
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
		return set.RemoveItem
	})
	return nil
}
