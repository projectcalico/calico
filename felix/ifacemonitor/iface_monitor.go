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
	StateNotPresent State = ""
	StateUp         State = "up"
	StateDown       State = "down"
)

type InterfaceStateCallback func(ifaceName string, ifaceState State, ifIndex int)
type AddrStateCallback func(ifaceName string, addrs set.Set[string])

type Config struct {
	// InterfaceExcludes is a list of interface names that we don't want callbacks for.
	InterfaceExcludes []*regexp.Regexp
	// ResyncInterval is the interval at which we rescan all the interfaces.  If <0 rescan is disabled.
	ResyncInterval time.Duration
}

type InterfaceMonitor struct {
	Config

	netlinkStub netlinkStub
	resyncC     <-chan time.Time

	ifaceNameToIdx map[string]int
	ifaceIdxToInfo map[int]*ifaceInfo

	StateCallback    InterfaceStateCallback
	AddrCallback     AddrStateCallback
	fatalErrCallback func(error)
}

type ifaceInfo struct {
	Idx        int
	Name       string
	State      State
	TrackAddrs bool
	Addrs      set.Set[string]
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
		ifaceNameToIdx:   map[string]int{},
		ifaceIdxToInfo:   map[int]*ifaceInfo{},
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
	info := m.ifaceIdxToInfo[ifIndex]

	// Early check: avoid logging anything for excluded interfaces.
	if info != nil && !info.TrackAddrs {
		return
	}

	addr := update.Dst.IP.String()
	exists := update.Type == unix.RTM_NEWROUTE
	logCtx := log.WithFields(log.Fields{
		"addr":    addr,
		"ifIndex": ifIndex,
		"exists":  exists,
	})

	if info == nil {
		logCtx.Info("Netlink address update but interface isn't yet known.  Will handle when interface is signalled.")
		return
	} else {
		logCtx.Info("Netlink address update for known interface. ")
	}

	if exists {
		if !info.Addrs.Contains(addr) {
			info.Addrs.Add(addr)
			m.notifyIfaceAddrs(info)
		}
	} else {
		if info.Addrs.Contains(addr) {
			info.Addrs.Discard(addr)
			m.notifyIfaceAddrs(info)
		}
	}
}

func (m *InterfaceMonitor) notifyIfaceAddrs(info *ifaceInfo) {
	logCtx := log.WithFields(log.Fields{
		"ifIndex": info.Idx,
		"name":    info.Name,
	})
	if !info.TrackAddrs {
		logCtx.Debug("Skipping notifying addresses for ignored interface")
		return
	}
	logCtx.Debug("Notifying addresses for interface")
	m.AddrCallback(info.Name, info.Addrs.Copy())
}

func (m *InterfaceMonitor) storeAndNotifyLink(ifaceExists bool, link netlink.Link) {
	attrs := link.Attrs()
	ifIndex := attrs.Index
	newName := attrs.Name
	log.WithFields(log.Fields{
		"ifaceExists": ifaceExists,
		"ifIndex":     ifIndex,
		"name":        newName,
	}).Debug("storeAndNotifyLink called")

	if info := m.ifaceIdxToInfo[ifIndex]; info != nil && info.Name != newName {
		log.WithFields(log.Fields{
			"oldName": info.Name,
			"newName": newName,
		}).Info("Interface renamed, simulating deletion of old copy.")
		m.storeAndNotifyLinkInner(false, info.Name, link)
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
	attrs := link.Attrs()
	ifIndex := attrs.Index
	log.WithFields(log.Fields{
		"ifaceExists": ifaceExists,
		"ifaceName":   ifaceName,
		"link":        link,
		"ifIndex":     ifIndex,
	}).Debug("storeAndNotifyLinkInner called")

	// Calculate the old and new states of the interface.
	oldState := StateNotPresent
	if info := m.ifaceIdxToInfo[ifIndex]; info != nil {
		oldState = info.State
	}
	newState := StateNotPresent
	if ifaceExists {
		if linkIsOperUp(link) {
			newState = StateUp
		} else {
			newState = StateDown
		}
	}

	// Store or remove the information.
	trackAddrs := !m.isExcludedInterface(ifaceName)
	if ifaceExists {
		if m.ifaceIdxToInfo[ifIndex] == nil {
			m.ifaceIdxToInfo[ifIndex] = &ifaceInfo{
				Idx:        ifIndex,
				Name:       ifaceName,
				TrackAddrs: trackAddrs,
				Addrs:      set.New[string](),
			}
		}
		m.ifaceNameToIdx[ifaceName] = ifIndex
		m.ifaceIdxToInfo[ifIndex].State = newState
	} else {
		delete(m.ifaceIdxToInfo, ifIndex)
		delete(m.ifaceNameToIdx, ifaceName)
	}

	logCxt := log.WithFields(log.Fields{
		"ifaceName": ifaceName,
		"ifIndex":   ifIndex,
		"oldState":  oldState,
		"newState":  newState,
	})
	if oldState != newState {
		logCxt.Debug("Interface changed state")
		m.StateCallback(ifaceName, newState, ifIndex)
	} else {
		logCxt.Debug("Interface state hasn't changed, nothing to notify.")
	}

	if !trackAddrs {
		return
	}

	if newState == StateNotPresent {
		if oldState != StateNotPresent {
			// We were tracking addresses for this interface before but now it's gone.  Signal that.
			log.Debug("Notify link non-existence to address callback consumers")
			m.AddrCallback(ifaceName, nil)
		}
		return
	}

	// The link now exists; get addresses for the link and store and notify those too; then
	// we don't have to worry about a possible race between the link and address update
	// channels.  We deliberately do this regardless of the link state, as in some cases this
	// will allow us to secure a Host Endpoint interface _before_ it comes up, and so eliminate
	// a small window of insecurity.
	newAddrs := set.New[string]()
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
	info := m.ifaceIdxToInfo[ifIndex]
	if oldState == StateNotPresent || !info.Addrs.Equals(newAddrs) {
		log.WithFields(log.Fields{
			"old": info.Addrs,
			"new": newAddrs,
		}).Debug("Detected interface address change while notifying link")
		info.Addrs = newAddrs

		m.notifyIfaceAddrs(info)
	}
}

func (m *InterfaceMonitor) resync() error {
	log.Debug("Resyncing interface state.")
	links, err := m.netlinkStub.LinkList()
	if err != nil {
		log.WithError(err).Warn("Netlink list operation failed.")
		return err
	}
	currentIfaces := set.New[string]()
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
	for ifIndex, info := range m.ifaceIdxToInfo {
		name := info.Name
		if currentIfaces.Contains(name) {
			continue
		}
		log.WithField("ifaceName", name).Info("Spotted interface removal on resync.")
		m.StateCallback(name, StateNotPresent, ifIndex)
		if info.TrackAddrs {
			// We were tracking addresses for this interface before but now it's gone.  Signal that.
			m.AddrCallback(name, nil)
		}
		delete(m.ifaceNameToIdx, name)
		delete(m.ifaceIdxToInfo, ifIndex)
	}
	log.Debug("Resync complete")
	return nil
}
