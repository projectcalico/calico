// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.
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
	"context"
	"fmt"
	"regexp"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

type netlinkStub interface {
	Subscribe(
		linkUpdates chan netlink.LinkUpdate,
		routeUpdates chan netlink.RouteUpdate,
	) (cancel chan struct{}, err error)
	LinkList() ([]netlink.Link, error)
	ListLocalRoutes(link netlink.Link, family int) ([]netlink.Route, error)
}

type State string

const (
	StateUnknown = ""
	StateUp      = "up"
	StateDown    = "down"
)

type InterfaceStateCallback func(ifaceName string, ifaceState State, ifIndex int)
type AddrStateCallback func(ifaceName string, addrs set.Set)

type Config struct {
	// InterfaceExcludes is a list of interface names that we don't want callbacks for.
	InterfaceExcludes []*regexp.Regexp
	// ResyncInterval is the interval at which we rescan all the interfaces.  If <0 rescan is disabled.
	ResyncInterval time.Duration
}
type InterfaceMonitor struct {
	Config

	netlinkStub      netlinkStub
	resyncC          <-chan time.Time
	upIfaces         map[string]int // Map from interface name to index.
	StateCallback    InterfaceStateCallback
	AddrCallback     AddrStateCallback
	ifaceName        map[int]string
	ifaceAddrs       map[int]set.Set
	fatalErrCallback func(error)
}

func New(config Config, fatalErrCallback func(error)) *InterfaceMonitor {
	// Interface monitor using the real netlink, and resyncing every 10 seconds.
	var resyncC <-chan time.Time
	if config.ResyncInterval > 0 {
		log.WithField("interval", config.ResyncInterval).Info(
			"configured to periodically rescan interfaces.")
		resyncTicker := time.NewTicker(config.ResyncInterval)
		resyncC = resyncTicker.C
	}
	return NewWithStubs(config, &netlinkReal{}, resyncC, fatalErrCallback)
}

func NewWithStubs(config Config, netlinkStub netlinkStub, resyncC <-chan time.Time, fatalErrCallback func(error)) *InterfaceMonitor {
	return &InterfaceMonitor{
		Config:           config,
		netlinkStub:      netlinkStub,
		resyncC:          resyncC,
		upIfaces:         map[string]int{},
		ifaceName:        map[int]string{},
		ifaceAddrs:       map[int]set.Set{},
		fatalErrCallback: fatalErrCallback,
	}
}

func IsInterfacePresent(name string) bool {
	link, _ := netlink.LinkByName(name)
	return link != nil
}

func (m *InterfaceMonitor) MonitorInterfaces() {
	log.Info("Interface monitoring thread started.")

	// Reconnection loop.
	for {
		var nlCancelC chan struct{}
		filterUpdatesCtx, filterUpdatesCancel := context.WithCancel(context.Background())
		filteredUpdates := make(chan netlink.LinkUpdate, 10)
		filteredRouteUpdates := make(chan netlink.RouteUpdate, 10)
		{
			updates := make(chan netlink.LinkUpdate, 10)
			routeUpdates := make(chan netlink.RouteUpdate, 10)
			var err error
			if nlCancelC, err = m.netlinkStub.Subscribe(updates, routeUpdates); err != nil {
				// If we can't even subscribe, something must have gone very wrong.  Bail.
				m.fatalErrCallback(fmt.Errorf("failed to subscribe to netlink: %w", err))
			}
			go FilterUpdates(filterUpdatesCtx, filteredRouteUpdates, routeUpdates, filteredUpdates, updates)
		}
		log.Info("Subscribed to netlink updates.")

		// Do a resync to notify all our existing interfaces.  We also do periodic
		// resyncs because it's not clear what the ordering guarantees are for our netlink
		// subscription vs a list operation as used by resync().
		err := m.resync()
		if err != nil {
			m.fatalErrCallback(fmt.Errorf("failed to read from netlink (initial resync): %w", err))
		}

	readLoop:
		for {
			log.WithFields(log.Fields{
				"updates":      filteredUpdates,
				"routeUpdates": filteredRouteUpdates,
				"resyncC":      m.resyncC,
			}).Debug("About to select on possible triggers")
			select {
			case update, ok := <-filteredUpdates:
				log.WithField("update", update).Debug("Link update")
				if !ok {
					log.Warn("Failed to read a link update")
					break readLoop
				}
				m.handleNetlinkUpdate(update)
			case routeUpdate, ok := <-filteredRouteUpdates:
				log.WithField("addrUpdate", routeUpdate).Debug("Address update")
				if !ok {
					log.Warn("Failed to read an address update")
					break readLoop
				}
				m.handleNetlinkRouteUpdate(routeUpdate)
			case <-m.resyncC:
				log.Debug("Resync trigger")
				err := m.resync()
				if err != nil {
					m.fatalErrCallback(fmt.Errorf("failed to read from netlink (resync): %w", err))
				}
			}
		}
		close(nlCancelC)
		filterUpdatesCancel()
		log.Warn("Reconnecting to netlink after a failure...")
	}
}

func (m *InterfaceMonitor) isExcludedInterface(ifName string) bool {
	for _, nameExp := range m.InterfaceExcludes {
		if nameExp.Match([]byte(ifName)) {
			return true
		}
	}
	return false
}

func (m *InterfaceMonitor) handleNetlinkUpdate(update netlink.LinkUpdate) {
	attrs := update.Attrs()
	linkAttrs := update.Link.Attrs()
	if attrs == nil || linkAttrs == nil {
		// Defensive, some sort of interface that the netlink lib doesn't understand?
		log.WithField("update", update).Warn("Missing attributes on netlink update.")
		return
	}

	msgType := update.Header.Type
	ifaceExists := msgType == syscall.RTM_NEWLINK // Alternative is an RTM_DELLINK
	m.storeAndNotifyLink(ifaceExists, update.Link)
}

func (m *InterfaceMonitor) handleNetlinkRouteUpdate(update netlink.RouteUpdate) {
	ifIndex := update.LinkIndex
	if ifName, known := m.ifaceName[ifIndex]; known {
		if m.isExcludedInterface(ifName) {
			return
		}
	}

	addr := update.Dst.IP.String()
	exists := update.Type == unix.RTM_NEWROUTE
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
	attrs := link.Attrs()
	ifIndex := attrs.Index
	newName := attrs.Name
	log.WithFields(log.Fields{
		"ifaceExists": ifaceExists,
		"link":        link,
	}).Debug("storeAndNotifyLink called")

	oldName := m.ifaceName[ifIndex]
	if oldName != "" && oldName != newName {
		log.WithFields(log.Fields{
			"oldName": oldName,
			"newName": newName,
		}).Info("Interface renamed, simulating deletion of old copy.")
		m.storeAndNotifyLinkInner(false, oldName, link)
	}

	m.storeAndNotifyLinkInner(ifaceExists, newName, link)
}

func linkIsOperUp(link netlink.Link) bool {
	// We need the operstate of the interface; this is carried in the IFF_RUNNING flag.  The
	// IFF_UP flag contains the admin state, which doesn't tell us whether we can program routes
	// etc.
	attrs := link.Attrs()
	if attrs == nil {
		return false
	}
	rawFlags := attrs.RawFlags
	ifaceIsUp := rawFlags&syscall.IFF_RUNNING != 0
	return ifaceIsUp
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
		if !m.isExcludedInterface(ifaceName) {
			// for excluded interfaces, e.g. kube-ipvs0, we ignore all ip address changes.
			log.Debug("Notify link non-existence to address callback consumers")
			delete(m.ifaceAddrs, ifIndex)
			m.notifyIfaceAddrs(ifIndex)
		}
		delete(m.ifaceName, ifIndex)
	}

	// We need the operstate of the interface; this is carried in the IFF_RUNNING flag.  The
	// IFF_UP flag contains the admin state, which doesn't tell us whether we can program routes
	// etc.
	ifaceIsUp := ifaceExists && linkIsOperUp(link)
	oldIfIndex, ifaceWasUp := m.upIfaces[ifaceName]
	logCxt := log.WithField("ifaceName", ifaceName)
	if ifaceIsUp && !ifaceWasUp {
		logCxt.Debug("Interface now up")
		m.upIfaces[ifaceName] = ifIndex
		m.StateCallback(ifaceName, StateUp, ifIndex)
	} else if ifaceWasUp && !ifaceIsUp {
		logCxt.Debug("Interface now down")
		delete(m.upIfaces, ifaceName)
		m.StateCallback(ifaceName, StateDown, oldIfIndex)
	} else {
		logCxt.WithField("ifaceIsUp", ifaceIsUp).Debug("Nothing to notify")
	}

	// If the link now exists, get addresses for the link and store and notify those too; then
	// we don't have to worry about a possible race between the link and address update
	// channels.  We deliberately do this regardless of the link state, as in some cases this
	// will allow us to secure a Host Endpoint interface _before_ it comes up, and so eliminate
	// a small window of insecurity.
	if ifaceExists && !m.isExcludedInterface(ifaceName) {
		// Notify address changes for non excluded interfaces.
		newAddrs := set.New()
		for _, family := range [2]int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
			routes, err := m.netlinkStub.ListLocalRoutes(link, family)
			if err != nil {
				log.WithError(err).Warn("Netlink route list operation failed.")
			}
			for _, route := range routes {
				if !routeIsLocalUnicast(route) {
					log.WithField("route", route).Debug("Ignoring non-local route.")
					continue
				}
				newAddrs.Add(route.Dst.IP.String())
			}
		}
		if (m.ifaceAddrs[ifIndex] == nil) || !m.ifaceAddrs[ifIndex].Equals(newAddrs) {
			log.WithFields(log.Fields{
				"old": m.ifaceAddrs[ifIndex],
				"new": newAddrs,
			}).Debug("Detected interface address change while notifying link")
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
	for name, ifIndex := range m.upIfaces {
		if currentIfaces.Contains(name) {
			continue
		}
		log.WithField("ifaceName", name).Info("Spotted interface removal on resync.")
		m.StateCallback(name, StateDown, ifIndex)
		m.AddrCallback(name, nil)
		delete(m.upIfaces, name)
		delete(m.ifaceAddrs, ifIndex)
		delete(m.ifaceName, ifIndex)
	}
	log.Debug("Resync complete")
	return nil
}
