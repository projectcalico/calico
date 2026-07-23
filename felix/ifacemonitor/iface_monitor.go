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
	"errors"
	"fmt"
	"regexp"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/projectcalico/calico/felix/environment"
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

type (
	InterfaceStateCallback func(ifaceName string, ifaceState State, ifIndex int)
	AddrStateCallback      func(ifaceName string, addrs set.Set[string])
	InSyncCallback         func()
)

type Config struct {
	// InterfaceExcludes is a list of interface names that we don't want callbacks for.
	InterfaceExcludes []*regexp.Regexp
	// ResyncInterval is the interval at which we rescan all the interfaces.  If <0 rescan is disabled.
	ResyncInterval time.Duration
	NetlinkTimeout time.Duration
}

type InterfaceMonitor struct {
	Config

	netlinkStub netlinkStub
	resyncC     <-chan time.Time

	ifaceNameToIdx map[string]set.Adaptive[int]
	ifaceIdxToInfo map[int]*ifaceInfo

	StateCallback    InterfaceStateCallback
	AddrCallback     AddrStateCallback
	InSyncCallback   InSyncCallback
	fatalErrCallback func(error)
}

type ifaceInfo struct {
	Idx        int
	Name       string
	State      State
	TrackAddrs bool
	Addrs      set.Set[string]
}

func New(config Config,
	featureDetector environment.FeatureDetectorIface,
	fatalErrCallback func(error),
) *InterfaceMonitor {
	// Interface monitor using the real netlink.
	var resyncC <-chan time.Time
	if config.ResyncInterval > 0 {
		log.WithField("interval", config.ResyncInterval).Info(
			"configured to periodically rescan interfaces.")
		resyncTicker := time.NewTicker(config.ResyncInterval)
		resyncC = resyncTicker.C
	}
	return NewWithStubs(config, newRealNetlink(featureDetector, config.NetlinkTimeout), resyncC, fatalErrCallback)
}

func NewWithStubs(config Config, netlinkStub netlinkStub, resyncC <-chan time.Time, fatalErrCallback func(error)) *InterfaceMonitor {
	return &InterfaceMonitor{
		Config:           config,
		netlinkStub:      netlinkStub,
		resyncC:          resyncC,
		ifaceNameToIdx:   map[string]set.Adaptive[int]{},
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
				filterUpdatesCancel()
				return
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
			filterUpdatesCancel()
			return
		}

		// Let the main goroutine know that we're in sync in order to unblock dataplane programming.
		m.InSyncCallback()
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
					close(nlCancelC)
					filterUpdatesCancel()
					return
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
		if nameExp.MatchString(ifName) {
			return true
		}
	}
	return false
}

func (m *InterfaceMonitor) handleNetlinkUpdate(update netlink.LinkUpdate) {
	attrs := update.Attrs()
	linkAttrs := update.Attrs()
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

	if update.Dst == nil {
		return
	}
	if update.Dst.IP.IsUnspecified() {
		if ones, _ := update.Dst.Mask.Size(); ones == 0 {
			// Default route, ignore.  These used to be filtered out by the
			// nil check above, but the netlink library was changed to return
			// an explicit unspecified CIDR in that case.
			return
		}
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

// lookupLocalAddrs returns the set of local unicast addresses for the given link.
func (m *InterfaceMonitor) lookupLocalAddrs(link netlink.Link) set.Set[string] {
	newAddrs := set.New[string]()
	for _, family := range [2]int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		routes, err := m.netlinkStub.ListLocalRoutes(link, family)
		if err != nil {
			if errors.Is(err, unix.ENODEV) {
				log.Debug("Tried to list routes for interface but it is gone, ignoring...")
				continue
			}
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
	return newAddrs
}

// unmaskInterface notifies the state and addresses of the given interface,
// which was previously deferred because multiple indices shared the same
// name. Now that the conflict is resolved, we can send the notification.
func (m *InterfaceMonitor) unmaskInterface(ifaceName string, remainingIdx int, link netlink.Link) {
	remainingInfo := m.ifaceIdxToInfo[remainingIdx]
	if remainingInfo == nil {
		log.WithFields(log.Fields{
			"ifaceName": ifaceName,
			"ifIndex":   remainingIdx,
		}).Warn("No info for remaining interface index; skipping unmask.")
		return
	}
	log.WithFields(log.Fields{
		"ifaceName": ifaceName,
		"ifIndex":   remainingIdx,
		"state":     remainingInfo.State,
	}).Debug("Notifying previously-deferred interface after conflict resolved.")
	m.StateCallback(ifaceName, remainingInfo.State, remainingIdx)
	if remainingInfo.TrackAddrs {
		remainingInfo.Addrs = m.lookupLocalAddrs(link)
		m.notifyIfaceAddrs(remainingInfo)
	}
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

func LinkIsOperUp(link netlink.Link) bool {
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
		if LinkIsOperUp(link) {
			newState = StateUp
		} else {
			newState = StateDown
		}
	}

	// Store or remove the information.
	ids := m.ifaceNameToIdx[ifaceName]
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
		ids.Add(ifIndex)
		m.ifaceIdxToInfo[ifIndex].State = newState
	} else {
		delete(m.ifaceIdxToInfo, ifIndex)
		ids.Discard(ifIndex)
	}
	if ids.Len() == 0 {
		delete(m.ifaceNameToIdx, ifaceName)
	} else {
		m.ifaceNameToIdx[ifaceName] = ids
	}

	// In some cases, we can receive a notification for a new link of the same name before
	// receiving the deletion notification for the old link.  In that case, we want to avoid
	// notifying of changes until the final state is known. Defer notification if there are
	// now multiple interface indices associated with the same name.
	if ids.Len() > 1 {
		log.WithFields(log.Fields{
			"ifaceName": ifaceName,
			"ifIndex":   ifIndex,
			"numIfaces": ids.Len(),
		}).Debug("Multiple interfaces with same name exist, deferring notification.")
		return
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

	notifyAddrs := true
	if newState == StateNotPresent {
		if oldState != StateNotPresent && trackAddrs {
			// We were tracking addresses for this interface before but now it's gone.  Signal that.
			logCxt.Debug("Notify link non-existence to address callback consumers")
			m.AddrCallback(ifaceName, nil)
		}

		// If the interface does not exist, we don't have to notify addresses.
		notifyAddrs = false
	}

	// If we just deleted an index and there's exactly one remaining interface
	// with this name, we "unmask" it — notify its actual state now that the
	// conflict is resolved.
	if newState == StateNotPresent && ids.Len() == 1 {
		var remainingIdx int
		for idx := range ids.All() {
			remainingIdx = idx
		}
		// Construct a link with the remaining index for the addr lookup.
		// We can't use the original `link` parameter here because it
		// carries the deleted interface's index, and ListLocalRoutes
		// filters by index.
		remainingLink := &netlink.Dummy{
			LinkAttrs: netlink.LinkAttrs{
				Index: remainingIdx,
				Name:  ifaceName,
			},
		}
		m.unmaskInterface(ifaceName, remainingIdx, remainingLink)
		return
	}

	if !trackAddrs || !notifyAddrs {
		return
	}

	// The link now exists; get addresses for the link and store and notify those too; then
	// we don't have to worry about a possible race between the link and address update
	// channels.  We deliberately do this regardless of the link state, as in some cases this
	// will allow us to secure a Host Endpoint interface _before_ it comes up, and so eliminate
	// a small window of insecurity.
	newAddrs := m.lookupLocalAddrs(link)
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
	var links []netlink.Link
	var err error
	retries := 3
	for {
		links, err = m.netlinkStub.LinkList()
		if err != nil {
			// EINTR means the dump was inconsistent and we should retry.
			if errors.Is(err, syscall.EINTR) && retries > 0 {
				log.WithError(err).Warn("Netlink list operation failed. Retrying")
				retries--
				continue
			}
			log.WithError(err).Warn("Netlink list operation failed.")
			return err
		}
		break
	}
	currentIdxs := set.New[int]()
	linksByIdx := map[int]netlink.Link{}
	for _, link := range links {
		attrs := link.Attrs()
		if attrs == nil {
			// Defensive, some sort of interface that the netlink lib doesn't
			// understand?
			log.WithField("link", link).Warn("Missing attributes on netlink update.")
			continue
		}
		currentIdxs.Add(attrs.Index)
		linksByIdx[attrs.Index] = link
		m.storeAndNotifyLink(true, link)
	}
	for ifIndex, info := range m.ifaceIdxToInfo {
		name := info.Name
		if currentIdxs.Contains(ifIndex) {
			continue
		}
		log.WithField("ifaceName", name).Info("Spotted interface removal on resync.")
		m.StateCallback(name, StateNotPresent, ifIndex)
		if info.TrackAddrs {
			// We were tracking addresses for this interface before but now it's gone.  Signal that.
			m.AddrCallback(name, nil)
		}
		ids := m.ifaceNameToIdx[name]
		ids.Discard(ifIndex)
		m.ifaceNameToIdx[name] = ids
		if ids.Len() == 0 {
			delete(m.ifaceNameToIdx, name)
		} else if ids.Len() == 1 {
			// We just removed a stale index and there's exactly one
			// remaining index with this name. Its notification was
			// deferred (because ids.Len() was >1), so notify it now.
			var remainingIdx int
			for idx := range ids.All() {
				remainingIdx = idx
			}
			link, ok := linksByIdx[remainingIdx]
			if !ok {
				log.WithFields(log.Fields{
					"ifaceName": name,
					"ifIndex":   remainingIdx,
				}).Warn("Remaining interface index not found in link list; skipping unmask.")
				continue
			}
			m.unmaskInterface(name, remainingIdx, link)
		}
		delete(m.ifaceIdxToInfo, ifIndex)
	}
	log.Debug("Resync complete")
	return nil
}
