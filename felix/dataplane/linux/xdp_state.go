// Copyright (c) 2019-2021 Tigera, Inc. All rights reserved.
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
	"fmt"
	"net"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/dataplane/common"
	"github.com/projectcalico/calico/felix/ipsets"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

// XDP state manages XDP programs installed on network interfaces and
// the BPF maps those programs use. Each network interface that has an
// XDP program installed has its own corresponding BPF map. The "map"
// part in "BPF map" suggests a key-value store. And indeed keys are
// CIDRs, and values are implementation specific stuff (for now, just
// a reference counter). If a CIDR is in a map then it means that
// traffic coming from the IP addresses that match this CIDR is
// blocked.
//
// To set up the XDP program and the map we need two things: a list of
// network interface names and the list of blocked CIDRs for each
// network interface. The list of blocked CIDRs can be different for
// each network interface.
//
// To get the required data we need to track a chain of information we
// get from the data store. From the datastore we can receive
// information about network interfaces, host endpoints, policies, and
// ipsets. Network interfaces are associated with host endpoints. Host
// endpoints have information about policies that are applied to the
// network interface associated with a particular host endpoint. The
// policy can contain information about IDs of ipsets. Ipsets are
// basically a sets of members. And these members are put into BPF
// maps.
//
// XDP state does not receive the information about all the above
// directly from the datastore, but indirectly through various
// managers using callbacks. The network interface and host endpoint
// stuff comes from the endpoint manager, policies come from the
// policy manager, and ipsets come from the ipsets manager. Callbacks
// are set in the PopulateCallbacks function.
//
// XDP state gathers information during the first phase of the
// internal dataplane event loop, where the internal dataplane routes
// messages from the data store to each manager, which in turn may
// invoke some callbacks. Those callbacks are also invoked at the
// beginning of the second phase of the internal dataplane event loop,
// where the internal dataplane tells each manager to complete its
// deferred work.
//
// XDP state contains an IP state which is a representation of an XDP
// state for a specific IP family. Currently it only contains such a
// thing for IPv4. Among other data the IP state has a field called
// system state which is a view of the information from the data store
// that is relevant to XDP. That is: network interface names, host
// endpoints, policies, and ipset IDs. Note the lack of ipset contents
// - this is to preserve memory. Such a form of a system state
// requires us to perform updates of the XDP state in two steps:
// processing pending diff state together with applying BPF actions,
// and processing member updates.
//
// After the information gathering is done, it is processed to figure
// out the next system state of XDP and generate BPF actions to go to
// the desired state from the current one. This part is done in the
// ProcessPendingDiffState function.
//
// Next step is to apply the actions. This happens in the
// ApplyBPFActions function.
//
// Then we need to process member updates. This consumes the
// information we get from the ipset manager about changes within
// ipsets. This happens in the ProcessMemberUpdates function.
//
// There is a special step for resynchronization - it modifies BPF
// actions based on the actual state of XDP on the system and the
// desired state. See the ResyncIfNeeded function.

type xdpState struct {
	ipV4State *xdpIPState
	common    xdpStateCommon
}

func NewXDPState(allowGenericXDP bool) (*xdpState, error) {
	lib, err := bpf.NewBPFLib("/usr/lib/calico/bpf/")
	if err != nil {
		return nil, err
	}
	return NewXDPStateWithBPFLibrary(lib, allowGenericXDP), nil
}

func NewXDPStateWithBPFLibrary(library bpf.BPFDataplane, allowGenericXDP bool) *xdpState {
	log.Debug("Created new xdpState.")
	return &xdpState{
		ipV4State: newXDPIPState(4),
		common: xdpStateCommon{
			programTag: "",
			needResync: true,
			bpfLib:     library,
			xdpModes:   getXDPModes(allowGenericXDP),
		},
	}
}

func membersToSet(members []string) set.Set[string] {
	membersSet := set.New[string]()
	for _, m := range members {
		membersSet.Add(m)
	}

	return membersSet
}

func (x *xdpState) OnUpdate(protoBufMsg interface{}) {
	log.WithField("msg", protoBufMsg).Debug("Received message")
	switch msg := protoBufMsg.(type) {
	case *proto.IPSetDeltaUpdate:
		log.WithField("ipSetId", msg.Id).Debug("IP set delta update")
		x.ipV4State.addMembersIPSet(msg.Id, membersToSet(msg.AddedMembers))
		x.ipV4State.removeMembersIPSet(msg.Id, membersToSet(msg.RemovedMembers))
	case *proto.IPSetUpdate:
		log.WithField("ipSetId", msg.Id).Debug("IP set update")
		x.ipV4State.replaceIPSet(msg.Id, membersToSet(msg.Members))
	case *proto.IPSetRemove:
		log.WithField("ipSetId", msg.Id).Debug("IP set remove")
		x.ipV4State.removeIPSet(msg.Id)
	case *proto.ActivePolicyUpdate:
		log.WithField("id", msg.Id).Debug("Updating policy chains")
		x.ipV4State.updatePolicy(*msg.Id, msg.Policy)
	case *proto.ActivePolicyRemove:
		log.WithField("id", msg.Id).Debug("Removing policy chains")
		x.ipV4State.removePolicy(*msg.Id)
	}
}

func (x *xdpState) CompleteDeferredWork() error {
	return nil
}

func (x *xdpState) PopulateCallbacks(cbs *common.Callbacks) {
	if x.ipV4State != nil {
		cbIDs := []*common.CbID{
			cbs.AddInterfaceV4.Append(x.ipV4State.addInterface),
			cbs.RemoveInterfaceV4.Append(x.ipV4State.removeInterface),
			cbs.UpdateInterfaceV4.Append(x.ipV4State.updateInterface),
			cbs.UpdateHostEndpointV4.Append(x.ipV4State.updateHostEndpoint),
			cbs.RemoveHostEndpointV4.Append(x.ipV4State.removeHostEndpoint),
		}
		x.ipV4State.cbIDs = append(x.ipV4State.cbIDs, cbIDs...)
	}
}

func (x *xdpState) DepopulateCallbacks(cbs *common.Callbacks) {
	if x.ipV4State != nil {
		for _, id := range x.ipV4State.cbIDs {
			cbs.Drop(id)
		}
		x.ipV4State.cbIDs = nil
	}
}

func (x *xdpState) QueueResync() {
	x.common.needResync = true
}

func (x *xdpState) ProcessPendingDiffState(epSourceV4 endpointsSource) {
	if x.ipV4State != nil {
		x.ipV4State.processPendingDiffState(epSourceV4)
	}
}

func (x *xdpState) ResyncIfNeeded(ipsSourceV4 ipsetsSource) error {
	var err error
	if !x.common.needResync {
		return nil
	}

	success := false
	for i := 0; i < 10; i++ {
		if i > 0 {
			log.Info("Retrying after an XDP update failure...")
		}
		log.Debug("Resyncing XDP state with dataplane.")
		err = x.tryResync(newConvertingIPSetsSource(ipsSourceV4))
		if err == nil {
			success = true
			break
		}
	}
	if !success {
		return fmt.Errorf("failed to resync: %v", err)
	}
	x.common.needResync = false
	return nil
}

func (x *xdpState) ApplyBPFActions(ipsSource ipsetsSource) error {
	if x.ipV4State != nil {
		memberCacheV4 := newXDPMemberCache(x.ipV4State.getBpfIPFamily(), x.common.bpfLib)
		err := x.ipV4State.bpfActions.apply(memberCacheV4, x.ipV4State.ipsetIDsToMembers, newConvertingIPSetsSource(ipsSource), x.common.xdpModes)
		x.ipV4State.bpfActions = newXDPBPFActions()
		if err != nil {
			log.WithError(err).Info("Applying BPF actions did not succeed. Queueing XDP resync.")
			x.QueueResync()
			return err
		}
	}
	return nil
}

func (x *xdpState) ProcessMemberUpdates() error {
	if x.ipV4State != nil {
		memberCacheV4 := newXDPMemberCache(x.ipV4State.getBpfIPFamily(), x.common.bpfLib)
		err := x.ipV4State.processMemberUpdates(memberCacheV4)
		if err != nil {
			log.WithError(err).Info("Processing member updates did not succeed. Queueing XDP resync.")
			x.QueueResync()
			return err
		}
	}
	return nil
}

func (x *xdpState) DropPendingDiffState() {
	if x.ipV4State != nil {
		x.ipV4State.pendingDiffState = newXDPPendingDiffState()
	}
}

func (x *xdpState) UpdateState() {
	if x.ipV4State != nil {
		x.ipV4State.currentState, x.ipV4State.newCurrentState = x.ipV4State.newCurrentState, nil
		x.ipV4State.cleanupCache()
	}
}

// WipeXDP clears any previously set XDP state, returning an error if synchronization fails.
func (x *xdpState) WipeXDP() error {
	savedIPV4State := x.ipV4State
	x.ipV4State = newXDPIPState(4)
	x.ipV4State.newCurrentState = newXDPSystemState()
	defer func() {
		x.ipV4State = savedIPV4State
	}()
	// Nil source, we are not going to use it anyway,
	// because we are about to drop everything, and when
	// we only drop stuff, the code does not call
	// ipsetsSource functions at all.
	ipsSource := &nilIPSetsSource{}
	if err := x.tryResync(ipsSource); err != nil {
		return err
	}
	if err := x.ApplyBPFActions(ipsSource); err != nil {
		return err
	}
	x.QueueResync()
	return nil
}

func (x *xdpState) tryResync(ipsSourceV4 ipsetsSource) error {
	if x.common.programTag == "" {
		tag, err := x.common.bpfLib.GetXDPObjTagAuto()
		if err != nil {
			return err
		}
		x.common.programTag = tag
	}
	if x.ipV4State != nil {
		if err := x.ipV4State.tryResync(&x.common, ipsSourceV4); err != nil {
			return err
		}
	}
	return nil
}

// xdpIPState holds the XDP state specific to an IP family.
type xdpIPState struct {
	ipFamily          int
	ipsetIDsToMembers *ipsetIDsToMembers
	currentState      *xdpSystemState
	pendingDiffState  *xdpPendingDiffState
	newCurrentState   *xdpSystemState
	bpfActions        *xdpBPFActions
	cbIDs             []*common.CbID
	logCxt            *log.Entry
}

type ipsetIDsToMembers struct {
	cache            map[string]set.Set[string] // ipSetID -> members
	pendingReplaces  map[string]set.Set[string] // ipSetID -> members
	pendingAdds      map[string]set.Set[string] // ipSetID -> members
	pendingDeletions map[string]set.Set[string] // ipSetID -> members
}

func newIPSetIDsToMembers() *ipsetIDsToMembers {
	i := &ipsetIDsToMembers{}
	i.Clear()
	return i
}

func (i *ipsetIDsToMembers) Clear() {
	i.cache = make(map[string]set.Set[string])
	i.pendingReplaces = make(map[string]set.Set[string])
	i.pendingAdds = make(map[string]set.Set[string])
	i.pendingDeletions = make(map[string]set.Set[string])
}

func (i *ipsetIDsToMembers) GetCached(setID string) (s set.Set[string], ok bool) {
	s, ok = i.cache[setID]
	return
}

func safeAdd[T comparable](m map[string]set.Set[T], setID string, member T) {
	if m[setID] == nil {
		m[setID] = set.New[T]()
	}
	m[setID].Add(member)
}

func (i *ipsetIDsToMembers) AddMembers(setID string, members set.Set[string]) {
	if _, ok := i.cache[setID]; !ok {
		// not tracked by XDP
		return
	}
	if rs, ok := i.pendingReplaces[setID]; ok {
		members.Iter(func(member string) error {
			rs.Add(member)
			return nil
		})
	} else {
		members.Iter(func(member string) error {
			safeAdd(i.pendingAdds, setID, member)
			return nil
		})
	}
}

func (i *ipsetIDsToMembers) RemoveMembers(setID string, members set.Set[string]) {
	if _, ok := i.cache[setID]; !ok {
		// not tracked by XDP
		return
	}
	if rs, ok := i.pendingReplaces[setID]; ok {
		members.Iter(func(member string) error {
			rs.Discard(member)
			return nil
		})
	} else {
		members.Iter(func(member string) error {
			safeAdd(i.pendingDeletions, setID, member)
			return nil
		})
	}
}

func (i *ipsetIDsToMembers) Delete(setID string) {
	if _, ok := i.cache[setID]; !ok {
		// not tracked by XDP
		return
	}
	i.pendingReplaces[setID] = set.New[string]()
	delete(i.pendingAdds, setID)
	delete(i.pendingDeletions, setID)
}

func (i *ipsetIDsToMembers) Replace(setID string, members set.Set[string]) {
	if _, ok := i.cache[setID]; !ok {
		// not tracked by XDP
		return
	}
	i.pendingReplaces[setID] = members
	delete(i.pendingAdds, setID)
	delete(i.pendingDeletions, setID)
}

func (i *ipsetIDsToMembers) UpdateCache() {
	cachedSetIDs := set.New[string]()
	for setID := range i.cache {
		cachedSetIDs.Add(setID)
	}

	cachedSetIDs.Iter(func(setID string) error {
		if m, ok := i.pendingReplaces[setID]; ok {
			i.cache[setID] = m
		} else {
			if m, ok := i.pendingDeletions[setID]; ok {
				m.Iter(func(member string) error {
					i.cache[setID].Discard(member)
					return nil
				})
			}
			if m, ok := i.pendingAdds[setID]; ok {
				m.Iter(func(member string) error {
					i.cache[setID].Add(member)
					return nil
				})
			}
		}
		return nil
	})

	// flush everything
	i.pendingReplaces = make(map[string]set.Set[string])
	i.pendingAdds = make(map[string]set.Set[string])
	i.pendingDeletions = make(map[string]set.Set[string])
}

func (i *ipsetIDsToMembers) SetCache(setID string, members set.Set[string]) {
	i.cache[setID] = members
}

func newXDPIPState(ipFamily int) *xdpIPState {
	return &xdpIPState{
		ipFamily:          ipFamily,
		ipsetIDsToMembers: newIPSetIDsToMembers(),
		currentState:      newXDPSystemState(),
		pendingDiffState:  newXDPPendingDiffState(),
		bpfActions:        newXDPBPFActions(),
		cbIDs:             nil,
		logCxt:            log.WithField("family", ipFamily),
	}
}

func (s *xdpIPState) getBpfIPFamily() bpf.IPFamily {
	if s.ipFamily == 4 {
		return bpf.IPFamilyV4
	}

	s.logCxt.WithField("ipFamily", s.ipFamily).Panic("Invalid ip family.")

	return bpf.IPFamilyUnknown
}

// newXDPResyncState creates the xdpResyncState object, returning an error on failure.
func (s *xdpIPState) newXDPResyncState(bpfLib bpf.BPFDataplane, ipsSource ipsetsSource, programTag string, xdpModes []bpf.XDPMode) (*xdpResyncState, error) {
	xdpIfaces, err := bpfLib.GetXDPIfaces()
	if err != nil {
		return nil, err
	}
	s.logCxt.WithField("ifaces", xdpIfaces).Debug("Interfaces with XDP program installed.")
	ifacesWithProgs := make(map[string]progInfo, len(xdpIfaces))
	for _, iface := range xdpIfaces {
		tag, tagErr := bpfLib.GetXDPTag(iface)
		mode, modeErr := bpfLib.GetXDPMode(iface)

		var bogosityReasons []string
		if tagErr != nil {
			bogosityReasons = append(bogosityReasons, fmt.Sprintf("error getting tag: %s", tagErr.Error()))
		} else if tag != programTag {
			bogosityReasons = append(bogosityReasons, fmt.Sprintf("loaded program's tag (%s) doesn't match expected tag (%s)",
				tag, programTag))
		}
		if modeErr != nil {
			bogosityReasons = append(bogosityReasons, fmt.Sprintf("error getting mode: %s", modeErr.Error()))
		} else if !isValidMode(mode, xdpModes) {
			bogosityReasons = append(bogosityReasons, fmt.Sprintf("installed program uses disallowed mode: %v", mode))
		}
		if len(bogosityReasons) > 0 {
			log.WithFields(log.Fields{
				"reasons": bogosityReasons,
				"iface":   iface,
			}).Info("Program on interface is bogus in some way.  Will need to reapply it.")
		}

		ifacesWithProgs[iface] = progInfo{
			bogus: len(bogosityReasons) > 0,
		}
	}
	ifacesWithPinnedMaps, err := bpfLib.ListCIDRMaps(s.getBpfIPFamily())
	if err != nil {
		return nil, err
	}
	s.logCxt.WithField("ifaces", ifacesWithPinnedMaps).Debug("Interfaces with BPF blacklist maps.")
	ifacesWithMaps := make(map[string]mapInfo, len(ifacesWithPinnedMaps))
	for _, iface := range ifacesWithPinnedMaps {
		mapOk, err := bpfLib.IsValidMap(iface, s.getBpfIPFamily())
		if err != nil {
			return nil, err
		}
		mapBogus := !mapOk
		mapMismatch, err := func() (bool, error) {
			if _, ok := ifacesWithProgs[iface]; !ok {
				return false, nil
			}
			mapID, err := bpfLib.GetCIDRMapID(iface, s.getBpfIPFamily())
			if err != nil {
				return false, err
			}
			mapIDs, err := bpfLib.GetMapsFromXDP(iface)
			if err != nil {
				return false, err
			}
			matched := false
			for _, id := range mapIDs {
				if mapID == id {
					matched = true
					break
				}
			}
			return !matched, nil
		}()
		if err != nil {
			return nil, err
		}
		var mapContents map[bpf.CIDRMapKey]uint32
		if !mapBogus {
			dump, err := bpfLib.DumpCIDRMap(iface, s.getBpfIPFamily())
			if err != nil {
				return nil, err
			}
			mapContents = dump
		}
		ifacesWithMaps[iface] = mapInfo{
			bogus:      mapBogus,
			mismatched: mapMismatch,
			contents:   mapContents,
		}
		s.logCxt.WithFields(log.Fields{
			"iface": iface,
			"info":  ifacesWithMaps[iface],
		}).Debug("Information about BPF blacklist map.")
	}
	visited := set.New[string]()
	ipsetMembers := make(map[string]set.Set[string])
	for _, data := range s.newCurrentState.IfaceNameToData {
		for _, setIDs := range data.PoliciesToSetIDs {
			var opErr error
			setIDs.Iter(func(setID string) error {
				if visited.Contains(setID) {
					return nil
				}
				members, err := s.getIPSetMembers(setID, ipsSource)
				if err != nil {
					opErr = err
					return set.StopIteration
				}
				s.logCxt.WithFields(log.Fields{
					"setID":       setID,
					"memberCount": members.Len(),
				}).Debug("Information about ipset members.")
				ipsetMembers[setID] = members
				visited.Add(setID)
				return nil
			})
			if opErr != nil {
				return nil, opErr
			}
		}
	}
	return &xdpResyncState{
		ifacesWithProgs: ifacesWithProgs,
		ifacesWithMaps:  ifacesWithMaps,
		ipsetMembers:    ipsetMembers,
	}, nil
}

func isValidMode(mode bpf.XDPMode, xdpModes []bpf.XDPMode) bool {
	for _, xdpMode := range xdpModes {
		if xdpMode == mode {
			return true
		}
	}
	return false
}

func (s *xdpIPState) getIPSetMembers(setID string, ipsSource ipsetsSource) (set.Set[string], error) {
	return getIPSetMembers(s.ipsetIDsToMembers, setID, ipsSource)
}

// tryResync reconciles the system's XDP state (derived from xdpStateCommon)
// with desired state (see ipsSource and the IpSetsManager for implementation details).
// It modifies the BPF actions based on the state of XDP on the system
// and on the desired state. It also repopulates the members cache.
//
// This function ensures that after applying the BPF actions, the XDP
// state will be consistent. Which means making sure that XDP programs
// are installed in desired interfaces, that they are referencing
// correct maps, and that maps contain the desired ipsets.
func (s *xdpIPState) tryResync(common *xdpStateCommon, ipsSource ipsetsSource) error {
	resyncStart := time.Now()
	defer func() {
		s.logCxt.WithField("resyncDuration", time.Since(resyncStart)).Debug("Finished XDP resync.")
	}()
	s.ipsetIDsToMembers.Clear()
	resyncState, err := s.newXDPResyncState(common.bpfLib, ipsSource, common.programTag, common.xdpModes)
	if err != nil {
		return err
	}
	s.fixupXDPProgramAndMapConsistency(resyncState)
	s.fixupBlacklistContents(resyncState)
	return nil
}

// fixupXDPProgramAndMapConsistency ensures that XDP programs are
// installed on the proper network interfaces, are valid, and
// reference the correct maps.
//
// There are several concepts related to programs and maps:
//
// A program can be installed or not. If the program is installed, it
// can be valid or not. A valid XDP program is a program that has an
// expected tag. Tag is basically a checksum of the program's
// bytecode. We figure out the desired program tag on the first
// resync. The tag is computed by the kernel, so it is not something
// we can know in advance.
//
// A map can exist or not. If it exists then it can be valid or
// not. If it is valid then it can be mismatched or not. A valid map
// is a map of an expected type with an expected key and value size
// (for the kernel, keys and values are purely array of bytes, and the
// length of those arrays needs to be defined at map creation time
// along with the map type). A mismatched map means that it is not
// used by the program. Which in reality means that the program is
// invalid and needs to be replaced.
//
// Since an XDP program references a BPF map and not the other way
// around, it means that if a map is invalid and needs to be replaced,
// then the program that references the map needs to be replaced too.
// In case of mismatched maps, only the program gets replaced.
func (s *xdpIPState) fixupXDPProgramAndMapConsistency(resyncState *xdpResyncState) {
	ifaces := s.getIfaces(resyncState, giNS|giWX|giIX|giUX|giWM|giCM|giRM)
	ifaces.Iter(func(iface string) error {
		shouldHaveXDP := func() bool {
			if data, ok := s.newCurrentState.IfaceNameToData[iface]; ok {
				return data.NeedsXDP()
			}
			return false
		}()
		hasXDP, hasBogusXDP := func() (bool, bool) {
			if progInfo, ok := resyncState.ifacesWithProgs[iface]; ok {
				return true, progInfo.bogus
			}
			return false, false
		}()
		mapExists, mapBogus, mapMismatch := func() (bool, bool, bool) {
			if mapInfo, ok := resyncState.ifacesWithMaps[iface]; ok {
				return true, mapInfo.bogus, mapInfo.mismatched
			}
			return false, false, false
		}()

		s.logCxt.WithFields(log.Fields{
			"iface":          iface,
			"hasProgram":     hasXDP,
			"isProgramBogus": hasBogusXDP,
			"wantsProgram":   shouldHaveXDP,
			"mapExists":      mapExists,
			"mapBogus":       mapBogus,
			"mapMismatched":  mapMismatch,
		}).Debug("Resync - fixing XDP program and map consistency.")
		func() {
			if !hasXDP && !shouldHaveXDP {
				s.bpfActions.InstallXDP.Discard(iface)
				s.bpfActions.UninstallXDP.Discard(iface)
				if !mapExists {
					s.bpfActions.CreateMap.Discard(iface)
					s.bpfActions.RemoveMap.Discard(iface)
				} else {
					s.bpfActions.CreateMap.Discard(iface)
					s.bpfActions.RemoveMap.Add(iface)
				}
				return
			}

			if !hasXDP && shouldHaveXDP {
				s.bpfActions.InstallXDP.Add(iface)
				s.bpfActions.UninstallXDP.Discard(iface)
				if !mapExists {
					s.bpfActions.CreateMap.Add(iface)
					s.bpfActions.RemoveMap.Discard(iface)
				} else if mapBogus {
					s.bpfActions.CreateMap.Add(iface)
					s.bpfActions.RemoveMap.Add(iface)
				} else {
					// mismatch is not possible, so it's a
					// good map
					s.bpfActions.CreateMap.Discard(iface)
					s.bpfActions.RemoveMap.Discard(iface)
				}
				return
			}

			if hasXDP && !shouldHaveXDP {
				s.bpfActions.InstallXDP.Discard(iface)
				s.bpfActions.UninstallXDP.Add(iface)
				if !mapExists {
					s.bpfActions.CreateMap.Discard(iface)
					s.bpfActions.RemoveMap.Discard(iface)
				} else {
					s.bpfActions.CreateMap.Discard(iface)
					s.bpfActions.RemoveMap.Add(iface)
				}
				return
			}

			if hasXDP && !hasBogusXDP && shouldHaveXDP {
				if !mapExists {
					// Good program, but no map? Means the
					// program needs to be replaced, so it
					// reads from the correct maps. The
					// map needs to be created.
					s.bpfActions.InstallXDP.Add(iface)
					s.bpfActions.UninstallXDP.Add(iface)
					s.bpfActions.CreateMap.Add(iface)
					s.bpfActions.RemoveMap.Discard(iface)
				} else if mapBogus {
					// Good program, but bogus map? Means
					// the program needs to be replaced,
					// so it reads from the correct
					// maps. The map needs to be replaced.
					s.bpfActions.InstallXDP.Add(iface)
					s.bpfActions.UninstallXDP.Add(iface)
					s.bpfActions.CreateMap.Add(iface)
					s.bpfActions.RemoveMap.Add(iface)
				} else if mapMismatch {
					// Good program, but mismatched map?
					// Means the program needs to be
					// replaced, so it reads from the
					// correct maps. The map itself is
					// fine.
					s.bpfActions.InstallXDP.Add(iface)
					s.bpfActions.UninstallXDP.Add(iface)
					s.bpfActions.CreateMap.Discard(iface)
					s.bpfActions.RemoveMap.Discard(iface)
				} else {
					// Good program reading from correct
					// maps. Nothing to do.
					s.bpfActions.InstallXDP.Discard(iface)
					s.bpfActions.UninstallXDP.Discard(iface)
					s.bpfActions.CreateMap.Discard(iface)
					s.bpfActions.RemoveMap.Discard(iface)
				}
				return
			}

			if hasXDP && hasBogusXDP && shouldHaveXDP {
				s.bpfActions.InstallXDP.Add(iface)
				s.bpfActions.UninstallXDP.Add(iface)
				if !mapExists {
					s.bpfActions.CreateMap.Add(iface)
					s.bpfActions.RemoveMap.Discard(iface)
				} else if mapBogus {
					s.bpfActions.CreateMap.Add(iface)
					s.bpfActions.RemoveMap.Add(iface)
				} else {
					// Mismatched or not, the map itself
					// is ok, so nothing to do here. The
					// replaced program will make use of
					// it.
					s.bpfActions.CreateMap.Discard(iface)
					s.bpfActions.RemoveMap.Discard(iface)
				}
				return
			}
		}()

		s.logCxt.WithFields(log.Fields{
			"iface":        iface,
			"installXDP":   s.bpfActions.InstallXDP.Contains(iface),
			"uninstallXDP": s.bpfActions.UninstallXDP.Contains(iface),
			"createMap":    s.bpfActions.CreateMap.Contains(iface),
			"removeMap":    s.bpfActions.RemoveMap.Contains(iface),
		}).Debug("Resync - finished fixing XDP program and map consistency.")
		return nil
	})
}

// fixupBlacklistContents ensures that contents of the BPF maps are in
// sync with ipsets those maps should contain.
//
// There are two cases - the BPF map is going to be created/replaced,
// and the BPF map already exists. When BPF map is about to be
// created/replaced, we just need to set up BPF actions that are about
// inserting whole ipsets into the BPF map. But if the map already
// exists, then we need to dump the contents of the map, compute the
// desired contents of the map, figure out the missing or superfluous
// members and update the BPF actions that are about modifying the BPF
// maps on a member level.
func (s *xdpIPState) fixupBlacklistContents(resyncState *xdpResyncState) {
	ifaces := s.getIfaces(resyncState, giNS)
	ifaces.Iter(func(iface string) error {
		createMap := s.bpfActions.CreateMap.Contains(iface)
		s.logCxt.WithFields(log.Fields{
			"iface":     iface,
			"mapCreate": createMap,
		}).Debug("Resync - fixing map contents.")
		if createMap {
			s.fixupBlacklistContentsFreshMap(iface)
		} else {
			if _, ok := resyncState.ifacesWithMaps[iface]; !ok {
				s.logCxt.WithField("iface", iface).Panic("Resync - iface missing from ifaces with maps in resync state!")
			}
			s.fixupBlacklistContentsExistingMap(resyncState, iface)
		}
		s.logCxt.WithFields(log.Fields{
			"iface":         iface,
			"addToMap":      s.bpfActions.AddToMap[iface],
			"removeFromMap": s.bpfActions.RemoveFromMap[iface],
			"membersToAdd":  s.bpfActions.MembersToAdd[iface],
			"membersToDrop": s.bpfActions.MembersToDrop[iface],
		}).Debug("Resync - finished fixing map contents.")
		return nil
	})
	for _, m := range []map[string]map[string]uint32{s.bpfActions.AddToMap, s.bpfActions.RemoveFromMap} {
		for iface := range m {
			if !ifaces.Contains(iface) {
				delete(m, iface)
			}
		}
	}
}

func (s *xdpIPState) fixupBlacklistContentsFreshMap(iface string) {
	setIDToRefCount := s.getSetIDToRefCountFromNewState(iface)
	s.bpfActions.AddToMap[iface] = setIDToRefCount
	delete(s.bpfActions.RemoveFromMap, iface)
}

func (s *xdpIPState) fixupBlacklistContentsExistingMap(resyncState *xdpResyncState, iface string) {
	membersInBpfMap := resyncState.ifacesWithMaps[iface].contents
	setIDsInNS := s.getSetIDToRefCountFromNewState(iface)
	membersInNS := make(map[string]uint32)
	for setID, refCount := range setIDsInNS {
		if _, ok := resyncState.ipsetMembers[setID]; !ok {
			s.logCxt.WithFields(log.Fields{
				"iface":          iface,
				"setID":          setID,
				"wantedRefCount": refCount,
			}).Panic("Resync - set id missing from ip set members in resync state!")
		}
		resyncState.ipsetMembers[setID].Iter(func(member string) error {
			membersInNS[member] += refCount
			return nil
		})
	}
	for mapKey, actualRefCount := range membersInBpfMap {
		member := mapKey.ToIPNet().String()
		expectedRefCount := membersInNS[member]
		s.logCxt.WithFields(log.Fields{
			"iface":            iface,
			"member":           member,
			"actualRefCount":   actualRefCount,
			"expectedRefCount": expectedRefCount,
		}).Debug("Resync - syncing member.")
		if expectedRefCount > actualRefCount {
			s.updateMembersToChange(s.bpfActions.MembersToAdd, iface, member, expectedRefCount-actualRefCount)
		} else if expectedRefCount < actualRefCount {
			s.updateMembersToChange(s.bpfActions.MembersToDrop, iface, member, actualRefCount-expectedRefCount)
		}
		delete(membersInNS, member)
	}
	for member, expectedRefCount := range membersInNS {
		s.logCxt.WithFields(log.Fields{
			"iface":            iface,
			"member":           member,
			"expectedRefCount": expectedRefCount,
		}).Debug("Resync - missing member.")
		s.updateMembersToChange(s.bpfActions.MembersToAdd, iface, member, expectedRefCount)
	}
	delete(s.bpfActions.AddToMap, iface)
	delete(s.bpfActions.RemoveFromMap, iface)
}

func (s *xdpIPState) updateMembersToChange(membersToChangeMap map[string]map[string]uint32, iface, member string, refCount uint32) {
	memberToRefCountMap := func() map[string]uint32 {
		m := membersToChangeMap[iface]
		if m == nil {
			m = make(map[string]uint32)
			membersToChangeMap[iface] = m
		}
		return m
	}()
	memberToRefCountMap[member] += refCount
}

func (s *xdpIPState) getSetIDToRefCountFromNewState(iface string) map[string]uint32 {
	setIDToRefCount := make(map[string]uint32)
	if data, ok := s.newCurrentState.IfaceNameToData[iface]; ok {
		for _, setIDs := range data.PoliciesToSetIDs {
			setIDs.Iter(func(setID string) error {
				setIDToRefCount[setID] += 1
				return nil
			})
		}
	}
	return setIDToRefCount
}

type IfaceFlags uint8

const (
	// from new state
	giNS = 1 << iota
	// from installXDP
	giIX
	// from uninstall XDP
	giUX
	// from ifacesWithProgs
	giWX
	// from createMaps
	giCM
	// from removeMaps
	giRM
	// from ifacesWithMaps
	giWM
)

func (s *xdpIPState) getIfaces(resyncState *xdpResyncState, flags IfaceFlags) set.Set[string] {
	ifaces := set.New[string]()
	addFromSet := func(item string) error {
		ifaces.Add(item)
		return nil
	}
	if flags&giNS == giNS {
		for iface, data := range s.newCurrentState.IfaceNameToData {
			if data.NeedsXDP() {
				ifaces.Add(iface)
			}
		}
	}
	if flags&giIX == giIX {
		s.bpfActions.InstallXDP.Iter(addFromSet)
	}
	if flags&giUX == giUX {
		s.bpfActions.UninstallXDP.Iter(addFromSet)
	}
	if flags&giWX == giWX {
		for iface := range resyncState.ifacesWithProgs {
			ifaces.Add(iface)
		}
	}
	if flags&giCM == giCM {
		s.bpfActions.CreateMap.Iter(addFromSet)
	}
	if flags&giRM == giRM {
		s.bpfActions.RemoveMap.Iter(addFromSet)
	}
	if flags&giWM == giWM {
		for iface := range resyncState.ifacesWithMaps {
			ifaces.Add(iface)
		}
	}
	return ifaces
}

// PROCESS MEMBER UPDATES

func (s *xdpIPState) processMemberUpdates(memberCache *xdpMemberCache) error {
	s.logCxt.Debug("Processing member updates.")

	// process member changes
	changes := s.getMemberChanges()

	for setID, change := range changes {
		ifacesToRefCounts := s.getAffectedIfaces(setID)
		s.logCxt.WithFields(log.Fields{
			"setID":          setID,
			"affectedIfaces": ifacesToRefCounts,
		}).Debug("Processing member changes.")
		for iface, refCount := range ifacesToRefCounts {
			s.logCxt.WithFields(log.Fields{
				"setID":    setID,
				"iface":    iface,
				"refCount": refCount,
				"toAdd":    change.toAdd,
				"toDrop":   change.toDrop,
			}).Debug("Processing BPF map changes.")

			miDelete := &memberIterSet{
				members:  change.toDrop,
				refCount: refCount,
			}
			if err := processMemberDeletions(memberCache, iface, miDelete); err != nil {
				return err
			}
			miAdd := &memberIterSet{
				members:  change.toAdd,
				refCount: refCount,
			}
			if err := processMemberAdds(memberCache, iface, miAdd); err != nil {
				return err
			}
		}
	}
	s.logCxt.Debug("Updating ipsetIDsToMembers cache.")

	s.ipsetIDsToMembers.UpdateCache()

	return nil
}

// processPendingDiffState processes the information the state has
// gathered from callbacks and generates the new desired state and the
// actions that, when executed, will get the current state into the
// new desired state.
//
// The aim is to get a list of IP addresses/CIDRs to be blocked on
// network interfaces. We can get addresses/CIDRs from ipsets. We can
// get ipsets from policies. We can get policies from host endpoints.
// Host endpoints are associated with network interfaces. All this
// creates a chain from interface to addresses/CIDRs: network
// interface -> host endpoint -> policies -> ipsets ->
// addresses/CIDRs.
//
// In this function we process the information in the same order as it
// is in the chain, so first we process the changes wrt. network
// interfaces, then changes in host endpoints, then changes in
// policies. Note that changes in ipsets themselves are processed
// elsewhere (see the processMemberUpdates function), because members
// of ipsets are not stored in the current state/new desired state.
// Current state has a granularity up to the ipset ID level.
//
// The function is careful to process each interface at most once - so
// if the network interface's host endpoint has changed and some
// policy associated with the host endpoint has changed, then the
// interface is only processed in the part of the code that handles
// updates of the host endpoint and it is skipped in the code that
// handles policy updates.
func (s *xdpIPState) processPendingDiffState(epSource endpointsSource) {
	cs := s.currentState
	s.newCurrentState = cs.Copy()

	newCs := s.newCurrentState
	s.logCxt.WithField("cs", cs).Debug("Processing pending diff state.")

	pds := s.pendingDiffState
	ba := s.bpfActions
	rawHep := epSource.GetRawHostEndpoints()

	processedIfaces := set.New[string]()

	// keys are interface names, values are maps with keys being
	// set IDs, and values being ref count delta (can be less or
	// greater than zero)
	changeInMaps := make(map[string]map[string]int)

	// CHANGES IN INTERFACES

	// new ifaces
	for ifaceName, hepID := range pds.NewIfaceNameToHostEpID {
		s.logCxt.WithFields(log.Fields{
			"iface":    ifaceName,
			"hostEpId": hepID.String(),
		}).Debug("New iface with host endpoint.")
		s.processHostEndpointChange(ifaceName, &xdpIfaceData{}, hepID, rawHep[hepID], changeInMaps)
		processedIfaces.Add(ifaceName)
	}

	// dropped ifaces
	pds.IfaceNamesToDrop.Iter(func(ifName string) error {
		s.logCxt.WithField("iface", ifName).Debug("Iface is gone.")

		dropXDP := false
		if data, ok := cs.IfaceNameToData[ifName]; ok {
			dropXDP = data.NeedsXDP()
		}
		if dropXDP {
			ba.UninstallXDP.Add(ifName)
			ba.RemoveMap.Add(ifName)
		}

		delete(newCs.IfaceNameToData, ifName)
		processedIfaces.Add(ifName)

		return nil
	})

	// Host Endpoints that changed
	for ifaceName, newEpID := range pds.IfaceEpIDChange {
		data := cs.IfaceNameToData[ifaceName]
		s.logCxt.WithFields(log.Fields{
			"iface":     ifaceName,
			"oldHostEp": data.EpID.String(),
			"newHostEp": newEpID.String(),
		}).Debug("Iface has a different host endpoint.")
		s.processHostEndpointChange(ifaceName, &data, newEpID, rawHep[newEpID], changeInMaps)
		processedIfaces.Add(ifaceName)
	}

	// CHANGES IN HOST ENDPOINTS

	// Host Endpoints that were updated
	pds.UpdatedHostEndpoints.Iter(func(hepID proto.HostEndpointID) error {
		s.logCxt.WithField("hostEpId", hepID.String()).Debug("Host endpoint has changed.")
		for ifaceName, data := range cs.IfaceNameToData {
			if processedIfaces.Contains(ifaceName) {
				s.logCxt.WithField("iface", ifaceName).Debug("Iface already processed, ignoring.")
				// ignore
				continue
			}
			if data.EpID != hepID {
				s.logCxt.WithFields(log.Fields{
					"iface":    ifaceName,
					"hostEpId": data.EpID.String(),
				}).Debug("Iface has different host endpoint, ignoring.")
				continue
			}
			s.logCxt.WithField("iface", ifaceName).Debug("Processing iface.")
			s.processHostEndpointChange(ifaceName, &data, hepID, rawHep[hepID], changeInMaps)
			processedIfaces.Add(ifaceName)
		}

		return nil
	})

	// Host Endpoints that were removed
	pds.RemovedHostEndpoints.Iter(func(hepID proto.HostEndpointID) error {
		// XXX do nothing
		return nil
	})

	// CHANGES IN POLICIES

	// Policies that should be removed
	pds.PoliciesToRemove.Iter(func(policyID proto.PolicyID) error {
		delete(newCs.XDPEligiblePolicies, policyID)
		return nil
	})

	// Policies that should be updated
	ifacesWithUpdatedPolicies := set.New[string]()
	for policyID, rules := range pds.PoliciesToUpdate {
		s.logCxt.WithFields(log.Fields{
			"policyID":  policyID.String(),
			"optimized": rules != nil,
		}).Debug("Policy updated.")
		for ifaceName, data := range cs.IfaceNameToData {
			if processedIfaces.Contains(ifaceName) {
				s.logCxt.WithField("iface", ifaceName).Debug("Iface already processed, ignoring.")
				continue
			}
			hep := rawHep[data.EpID]
			foundPolicyID := false
			for _, hepPolicyID := range getPolicyIDs(hep) {
				if hepPolicyID == policyID {
					foundPolicyID = true
					break
				}
			}
			if !foundPolicyID {
				s.logCxt.WithFields(log.Fields{
					"policyID": policyID,
					"iface":    ifaceName,
				}).Debug("Policy doesn't apply to iface, skipping iface.")
				continue
			}
			ifacesWithUpdatedPolicies.Add(ifaceName)

			m, ok := changeInMaps[ifaceName]
			if !ok {
				m = make(map[string]int)
				changeInMaps[ifaceName] = m
			}

			oldSetIDs := data.PoliciesToSetIDs[policyID]
			s.logCxt.WithFields(log.Fields{
				"policyID": policyID.String(),
				"setIDs":   dumpSetToString(oldSetIDs),
			}).Debug("Considering old set ID of policy.")
			if oldSetIDs != nil {
				// it means that the old version of the policy was optimized
				oldSetIDs.Iter(func(setID string) error {
					m[setID] -= 1
					return nil
				})
			}
			if rules != nil {
				// this means that new policy can be optimized
				newSetIDs := getSetIDs(rules)
				s.logCxt.WithFields(log.Fields{
					"iface":      ifaceName,
					"endpointID": data.EpID,
					"policyID":   policyID.String(),
					"oldSetIDs":  dumpSetToString(oldSetIDs),
					"newSetIDs":  dumpSetToString(newSetIDs),
				}).Debug("Replacing old ipsets with new ones for optimizable policy")
				s.logCxt.WithFields(log.Fields{
					"iface":      ifaceName,
					"endpointID": data.EpID,
					"policyID":   policyID.String(),
				}).Info("Policy will be optimized.")

				newSetIDs.Iter(func(setID string) error {
					m[setID] += 1
					return nil
				})
				newCs.IfaceNameToData[ifaceName].PoliciesToSetIDs[policyID] = newSetIDs
			} else {
				s.logCxt.WithFields(log.Fields{
					"iface":      ifaceName,
					"endpointID": data.EpID,
					"policyID":   policyID.String(),
					"oldSetIDs":  dumpSetToString(oldSetIDs),
				}).Debug("Dropping old ipsets for unoptimizable policy")
				s.logCxt.WithFields(log.Fields{
					"iface":      ifaceName,
					"endpointID": data.EpID,
					"policyID":   policyID.String(),
				}).Info("Policy can not be optimized.")
				// this means that new policy can't be optimized
				delete(newCs.IfaceNameToData[ifaceName].PoliciesToSetIDs, policyID)
			}
		}
		if rules != nil {
			newCs.XDPEligiblePolicies[policyID] = *rules
		} else {
			delete(newCs.XDPEligiblePolicies, policyID)
		}
	}

	ifacesWithUpdatedPolicies.Iter(func(ifaceName string) error {
		oldData := cs.IfaceNameToData[ifaceName]
		newData := newCs.IfaceNameToData[ifaceName]
		oldNeedsXDP := oldData.NeedsXDP()
		newNeedsXDP := newData.NeedsXDP()
		if oldNeedsXDP && !newNeedsXDP {
			ba.UninstallXDP.Add(ifaceName)
			ba.RemoveMap.Add(ifaceName)
		} else if !oldNeedsXDP && newNeedsXDP {
			ba.InstallXDP.Add(ifaceName)
			ba.CreateMap.Add(ifaceName)
		}
		return nil
	})

	// populate map changes
	for ifaceName, ips := range changeInMaps {
		if !ba.RemoveMap.Contains(ifaceName) {
			addIPSets := make(map[string]uint32)
			deleteIPSets := make(map[string]uint32)
			for setID, refCount := range ips {
				switch {
				case refCount > 0:
					addIPSets[setID] = uint32(refCount)
				case refCount < 0:
					deleteIPSets[setID] = uint32(-refCount)
				}
			}
			if len(addIPSets) > 0 {
				ba.AddToMap[ifaceName] = addIPSets
			}
			if len(deleteIPSets) > 0 {
				ba.RemoveFromMap[ifaceName] = deleteIPSets
			}
		}
	}

	s.logCxt.WithFields(log.Fields{
		"newCS":      newCs,
		"bpfActions": *ba,
	}).Debug("Finished processing pending diff state.")
}

func dumpSetToString(s set.Set[string]) string {
	if s == nil {
		return "<empty>"
	}
	strs := make([]string, 0, s.Len())
	s.Iter(func(item string) error {
		strs = append(strs, fmt.Sprintf("%v", item))
		return nil
	})
	return strings.Join(strs, ", ")
}

func (s *xdpIPState) processHostEndpointChange(ifaceName string, oldData *xdpIfaceData, newHepID proto.HostEndpointID, newEP *proto.HostEndpoint, changeInMaps map[string]map[string]int) {
	policiesToSetIDs := make(map[proto.PolicyID]set.Set[string] /*<string>*/)
	oldSetIDs := make(map[string]int)
	for _, setIDs := range oldData.PoliciesToSetIDs {
		setIDs.Iter(func(setID string) error {
			oldSetIDs[setID] += 1
			return nil
		})
	}

	newPolicyIDs := getPolicyIDs(newEP)
	newSetIDs := make(map[string]int)

	for _, policyID := range newPolicyIDs {
		rules := s.getLatestRulesForPolicyID(policyID)
		if rules == nil {
			s.logCxt.WithFields(log.Fields{
				"iface":      ifaceName,
				"endpointID": newHepID,
				"policyID":   policyID.String(),
			}).Info("Policy can not be optimized.")
			continue
		}
		s.logCxt.WithFields(log.Fields{
			"iface":      ifaceName,
			"endpointID": newHepID,
			"policyID":   policyID.String(),
		}).Info("Policy will be optimized.")

		rulesSetIDs := getSetIDs(rules)
		policiesToSetIDs[policyID] = rulesSetIDs

		rulesSetIDs.Iter(func(setID string) error {
			newSetIDs[setID] += 1
			return nil
		})
	}

	s.logCxt.WithFields(log.Fields{
		"oldSetIDs": oldSetIDs,
		"newSetIDs": newSetIDs,
	}).Debug("Processing host endpoint change.")

	newData := xdpIfaceData{
		EpID:             newHepID,
		PoliciesToSetIDs: policiesToSetIDs,
	}
	s.newCurrentState.IfaceNameToData[ifaceName] = newData
	oldNeedsXDP := oldData.NeedsXDP()
	newNeedsXDP := newData.NeedsXDP()
	if oldNeedsXDP && !newNeedsXDP {
		s.bpfActions.UninstallXDP.Add(ifaceName)
		s.bpfActions.RemoveMap.Add(ifaceName)
	} else if !oldNeedsXDP && newNeedsXDP {
		s.bpfActions.InstallXDP.Add(ifaceName)
		s.bpfActions.CreateMap.Add(ifaceName)
	}
	m, ok := changeInMaps[ifaceName]
	if !ok {
		m = make(map[string]int)
		changeInMaps[ifaceName] = m
	}

	for setID, refCount := range newSetIDs {
		m[setID] += refCount
	}
	for setID, refCount := range oldSetIDs {
		m[setID] -= refCount
	}
}

func getPolicyIDs(hep *proto.HostEndpoint) []proto.PolicyID {
	var policyIDs []proto.PolicyID
	// we handle Untracked policy only
	for _, tier := range hep.GetUntrackedTiers() {
		for _, policyName := range tier.IngressPolicies {
			policyID := proto.PolicyID{
				Tier: tier.Name,
				Name: policyName,
			}

			policyIDs = append(policyIDs, policyID)
			// TODO: For now we only support XDP
			// optimization of only the first untracked
			// policy, later we will want to support an
			// optimization of many rules as long as their
			// inbound rules form a sequence of
			// optimizable rules.
			break
		}
	}
	return policyIDs
}

func getSetIDs(rules *xdpRules) set.Set[string] /*<string>*/ {
	setIDs := set.New[string]()
	for _, rule := range rules.Rules {
		for _, setID := range rule.SetIDs {
			setIDs.Add(setID)
		}
	}
	return setIDs
}

func (s *xdpIPState) getLatestRulesForPolicyID(policyID proto.PolicyID) *xdpRules {
	logCxt := s.logCxt.WithField("policyID", policyID.String())
	rules, ok := s.pendingDiffState.PoliciesToUpdate[policyID]
	if ok {
		logCxt.Debug("Policy is updated.")
		if rules == nil {
			s.logCxt.Debug("Policy can't be optimized.")
		}
		return rules
	} else {
		logCxt.Debug("Policy is not updated.")
		xdpRules, ok := s.newCurrentState.XDPEligiblePolicies[policyID]
		if ok {
			return &xdpRules
		} else {
			logCxt.Debug("Policy can't be optimized.")
			return nil
		}
	}
}

func (s *xdpIPState) updatePolicy(policyID proto.PolicyID, policy *proto.Policy) {
	s.logCxt.WithFields(log.Fields{
		"policyID": policyID,
		"policy":   policy,
	}).Debug("updatePolicy callback called.")
	s.pendingDiffState.PoliciesToRemove.Discard(policyID)
	if xdpRules, ok := xdpRulesFromProtoRules(policy.InboundRules, policy.OutboundRules); ok {
		s.logCxt.WithField("policyID", policyID).Debug("Policy can be optimized.")
		s.pendingDiffState.PoliciesToUpdate[policyID] = &xdpRules
	} else {
		s.logCxt.WithField("policyID", policyID).Debug("Policy can not be optimized.")
		s.pendingDiffState.PoliciesToUpdate[policyID] = nil
	}
}

func (s *xdpIPState) removePolicy(policyID proto.PolicyID) {
	s.logCxt.WithField("policyID", policyID).Debug("removePolicy callback called.")
	delete(s.pendingDiffState.PoliciesToUpdate, policyID)
	s.pendingDiffState.PoliciesToRemove.Add(policyID)
}

func xdpRulesFromProtoRules(inboundRules, outboundRules []*proto.Rule) (xdpRules, bool) {
	xdpRules := xdpRules{}
	isValid := len(inboundRules) > 0 &&
		// TODO: Maybe we should take all the initial rules
		// that have deny action? So in case of policy that
		// has 4 inbound rules with actions "deny", "deny",
		// "allow" and "deny, respectively, we would take
		// first two rules into account.
		isValidRuleForXDP(inboundRules[0])
	if isValid {
		xdpRules.Rules = []xdpRule{
			{
				SetIDs: inboundRules[0].SrcIpSetIds,
			},
		}
	}
	return xdpRules, isValid
}

func isValidRuleForXDP(rule *proto.Rule) bool {
	return rule != nil &&
		rule.Action == "deny" &&
		// accept ipv4 traffic (or any, which matches ipv4
		// too)
		//
		// TODO: drop the ip version check when we add support
		// for ipv6
		(rule.IpVersion == proto.IPVersion_ANY ||
			rule.IpVersion == proto.IPVersion_IPV4) &&
		// accept only rules that don't specify a protocol,
		// which means blocking all the traffic
		rule.Protocol == nil &&
		len(rule.SrcNet) == 0 &&
		len(rule.SrcPorts) == 0 &&
		len(rule.SrcNamedPortIpSetIds) == 0 &&
		// have only a single ip-only selector
		len(rule.SrcIpSetIds) == 1 &&
		rule.NotProtocol == nil &&
		len(rule.NotSrcNet) == 0 &&
		len(rule.NotSrcPorts) == 0 &&
		len(rule.NotSrcIpSetIds) == 0 &&
		len(rule.NotSrcNamedPortIpSetIds) == 0 &&
		// have no icmp stuff
		rule.Icmp == nil &&
		rule.NotIcmp == nil &&
		// have no destination stuff
		len(rule.DstNet) == 0 &&
		len(rule.DstPorts) == 0 &&
		len(rule.DstNamedPortIpSetIds) == 0 &&
		len(rule.DstIpSetIds) == 0 &&
		len(rule.DstIpPortSetIds) == 0 &&
		len(rule.NotDstNet) == 0 &&
		len(rule.NotDstPorts) == 0 &&
		len(rule.NotDstIpSetIds) == 0 &&
		len(rule.NotDstNamedPortIpSetIds) == 0 &&
		// have no application layer policy stuff
		rule.HttpMatch == nil &&
		rule.SrcServiceAccountMatch == nil &&
		rule.DstServiceAccountMatch == nil

	// Note that XDP doesn't support writing rule.Metadata to the dataplane
	// (as we do using -m comment in iptables), but the rule still can be
	// rendered in XDP, so we place no constraints on rule.Metadata here.
}

func (s *xdpIPState) removeMembersIPSet(setID string, members set.Set[string]) {
	s.logCxt.WithFields(log.Fields{
		"setID":   setID,
		"members": members,
	}).Debug("removeMembersIPSet callback called.")
	s.ipsetIDsToMembers.RemoveMembers(setID, members)
}

func (s *xdpIPState) addMembersIPSet(setID string, members set.Set[string]) {
	s.logCxt.WithFields(log.Fields{
		"setID":   setID,
		"members": members,
	}).Debug("addMembersIPSet callback called.")
	s.ipsetIDsToMembers.AddMembers(setID, members)
}

func (s *xdpIPState) replaceIPSet(setID string, members set.Set[string]) {
	s.logCxt.WithFields(log.Fields{
		"setID":   setID,
		"members": members,
	}).Debug("ReplaceIPSet callback called.")
	s.ipsetIDsToMembers.Replace(setID, members)
}

func (s *xdpIPState) removeIPSet(setID string) {
	s.logCxt.WithField("setID", setID).Debug("removeIPSet callback called.")
	s.ipsetIDsToMembers.Delete(setID)
}

func (s *xdpIPState) cleanupCache() {
	setIDs := set.New[string]()
	for setID := range s.ipsetIDsToMembers.cache {
		setIDs.Add(setID)
	}
	for setID := range s.ipsetIDsToMembers.pendingReplaces {
		setIDs.Add(setID)
	}
	for setID := range s.ipsetIDsToMembers.pendingAdds {
		setIDs.Add(setID)
	}
	for setID := range s.ipsetIDsToMembers.pendingDeletions {
		setIDs.Add(setID)
	}
	setIDs.Iter(func(setID string) error {
		if !s.isSetIDInCurrentState(setID) {
			delete(s.ipsetIDsToMembers.cache, setID)
			delete(s.ipsetIDsToMembers.pendingReplaces, setID)
			delete(s.ipsetIDsToMembers.pendingAdds, setID)
			delete(s.ipsetIDsToMembers.pendingDeletions, setID)
		}
		return nil
	})
}

func (s *xdpIPState) isSetIDInCurrentState(setID string) bool {
	for _, data := range s.currentState.IfaceNameToData {
		for _, setIDs := range data.PoliciesToSetIDs {
			if setIDs.Contains(setID) {
				return true
			}
		}
	}
	return false
}

func (s *xdpIPState) addInterface(ifaceName string, hostEPID proto.HostEndpointID) {
	s.logCxt.WithFields(log.Fields{
		"ifaceName": ifaceName,
		"hostEPID":  hostEPID,
	}).Debug("addInterface callback called.")

	s.pendingDiffState.NewIfaceNameToHostEpID[ifaceName] = hostEPID
}

func (s *xdpIPState) removeInterface(ifaceName string) {
	s.logCxt.WithField("ifaceName", ifaceName).Debug("removeInterface callback called.")

	s.pendingDiffState.IfaceNamesToDrop.Add(ifaceName)
}

func (s *xdpIPState) updateInterface(ifaceName string, newHostEPID proto.HostEndpointID) {
	s.logCxt.WithFields(log.Fields{
		"ifaceName":   ifaceName,
		"newHostEPID": newHostEPID,
	}).Debug("updateInterface callback called.")

	s.pendingDiffState.IfaceEpIDChange[ifaceName] = newHostEPID
}

func (s *xdpIPState) updateHostEndpoint(hostEPID proto.HostEndpointID) {
	s.logCxt.WithField("hostEPID", hostEPID).Debug("updateHostEndpoint callback called.")

	s.pendingDiffState.RemovedHostEndpoints.Discard(hostEPID)
	if !s.isHostEndpointIDInCurrentState(hostEPID) {
		s.logCxt.WithField("hostEpId", hostEPID.EndpointId).Debug("Host endpoint not in current state, ignoring.")
		return
	}
	s.pendingDiffState.UpdatedHostEndpoints.Add(hostEPID)
}

type memberChanges struct {
	toAdd  set.Set[string]
	toDrop set.Set[string]
}

func (s *xdpIPState) getMemberChanges() map[string]memberChanges {
	changes := make(map[string]memberChanges)
	s.logCxt.WithFields(log.Fields{
		"oldMembers": s.ipsetIDsToMembers.cache,
	}).Debug("Getting member changes.")

	for setID, oldMembers := range s.ipsetIDsToMembers.cache {
		s.logCxt.WithFields(log.Fields{
			"setID":            setID,
			"pendingReplaces":  s.ipsetIDsToMembers.pendingReplaces[setID],
			"pendingAdds":      s.ipsetIDsToMembers.pendingAdds[setID],
			"pendingDeletions": s.ipsetIDsToMembers.pendingDeletions[setID],
		}).Debug("Processing setID.")

		mc := memberChanges{
			toAdd:  set.New[string](),
			toDrop: set.New[string](),
		}
		if pr, ok := s.ipsetIDsToMembers.pendingReplaces[setID]; ok {
			mc.toAdd = setDifference[string](pr, oldMembers)
			mc.toDrop = setDifference[string](oldMembers, pr)
		} else {
			if pa, ok := s.ipsetIDsToMembers.pendingAdds[setID]; ok {
				mc.toAdd = pa
			}
			if pd, ok := s.ipsetIDsToMembers.pendingDeletions[setID]; ok {
				mc.toDrop = pd
			}
		}

		s.logCxt.WithFields(log.Fields{
			"toAdd":  mc.toAdd,
			"toDrop": mc.toDrop,
		}).Debug("Generating toAdd and toDrop.")
		changes[setID] = mc
	}

	return changes
}

func setDifference[T comparable](a, b set.Set[T]) set.Set[T] {
	result := set.New[T]()
	a.Iter(func(item T) error {
		if !b.Contains(item) {
			result.Add(item)
		}
		return nil
	})
	return result
}

func (s *xdpIPState) getAffectedIfaces(setID string) map[string]uint32 {
	ifacesToRefCounts := make(map[string]uint32)
	for iface, data := range s.newCurrentState.IfaceNameToData {
		for _, setIDs := range data.PoliciesToSetIDs {
			if setIDs.Contains(setID) {
				ifacesToRefCounts[iface] += 1
			}
		}
	}
	return ifacesToRefCounts
}

func (s *xdpIPState) isHostEndpointIDInCurrentState(hep proto.HostEndpointID) bool {
	for _, data := range s.currentState.IfaceNameToData {
		if data.EpID == hep {
			return true
		}
	}
	return false
}

func (s *xdpIPState) removeHostEndpoint(hostEPID proto.HostEndpointID) {
	s.logCxt.WithField("hostEPID", hostEPID).Debug("removeHostEndpoint callback called.")

	s.pendingDiffState.RemovedHostEndpoints.Add(hostEPID)
	s.pendingDiffState.UpdatedHostEndpoints.Discard(hostEPID)
}

type xdpStateCommon struct {
	programTag string
	needResync bool
	bpfLib     bpf.BPFDataplane
	xdpModes   []bpf.XDPMode
}

type xdpSystemState struct {
	IfaceNameToData map[string]xdpIfaceData
	// a cache of all the policies that could be implemented with
	// XDP, even those that currently are not
	XDPEligiblePolicies map[proto.PolicyID]xdpRules
}

func newXDPSystemState() *xdpSystemState {
	return &xdpSystemState{
		IfaceNameToData:     make(map[string]xdpIfaceData),
		XDPEligiblePolicies: make(map[proto.PolicyID]xdpRules),
	}
}

func (s *xdpSystemState) Copy() *xdpSystemState {
	newState := xdpSystemState{
		IfaceNameToData:     make(map[string]xdpIfaceData),
		XDPEligiblePolicies: make(map[proto.PolicyID]xdpRules),
	}

	for k, v := range s.IfaceNameToData {
		newState.IfaceNameToData[k] = v.Copy()
	}

	for k, v := range s.XDPEligiblePolicies {
		newState.XDPEligiblePolicies[k] = v.Copy()
	}

	return &newState
}

type xdpPendingDiffState struct {
	NewIfaceNameToHostEpID map[string]proto.HostEndpointID
	IfaceNamesToDrop       set.Set[string] // <string>
	IfaceEpIDChange        map[string]proto.HostEndpointID
	UpdatedHostEndpoints   set.Set[proto.HostEndpointID] // <proto.HostEndpointID>
	RemovedHostEndpoints   set.Set[proto.HostEndpointID] // <proto.HostEndpointID>
	PoliciesToRemove       set.Set[proto.PolicyID]       // <PolicyID>
	PoliciesToUpdate       map[proto.PolicyID]*xdpRules
}

func newXDPPendingDiffState() *xdpPendingDiffState {
	return &xdpPendingDiffState{
		NewIfaceNameToHostEpID: make(map[string]proto.HostEndpointID),
		IfaceNamesToDrop:       set.New[string](),
		IfaceEpIDChange:        make(map[string]proto.HostEndpointID),
		UpdatedHostEndpoints:   set.New[proto.HostEndpointID](),
		RemovedHostEndpoints:   set.New[proto.HostEndpointID](),
		PoliciesToRemove:       set.New[proto.PolicyID](),
		PoliciesToUpdate:       make(map[proto.PolicyID]*xdpRules),
	}
}

type xdpBPFActions struct {
	// sets of interface names, for which a bpf map should be
	// created
	CreateMap set.Set[string]
	// sets of interface names, for which a bpf map should be
	// dropped (or emptied in some cases)
	RemoveMap set.Set[string]

	// The fields below are normalized, so for a given interface a
	// set ID will appear either in AddToMap or RemoveFromMap,
	// never in both at the same time
	//
	// Keys are interface names, values are maps where keys are
	// set IDs and values are ref counts to add/drop (positive
	// values)
	AddToMap      map[string]map[string]uint32
	RemoveFromMap map[string]map[string]uint32

	// sets of interface names, where XDP program should be
	// loaded/attached
	InstallXDP set.Set[string]
	// sets of interface names, where XDP program should be
	// unloaded/detached
	UninstallXDP set.Set[string]

	// Resync fallout
	// keys are interface names, values are maps, where keys are
	// members and values are ref counts
	MembersToDrop map[string]map[string]uint32
	MembersToAdd  map[string]map[string]uint32
}

func newXDPBPFActions() *xdpBPFActions {
	return &xdpBPFActions{
		CreateMap:     set.New[string](),
		RemoveMap:     set.New[string](),
		AddToMap:      make(map[string]map[string]uint32),
		RemoveFromMap: make(map[string]map[string]uint32),
		InstallXDP:    set.New[string](),
		UninstallXDP:  set.New[string](),
		MembersToDrop: make(map[string]map[string]uint32),
		MembersToAdd:  make(map[string]map[string]uint32),
	}
}

// apply processes the contents of BPF actions - uninstalls and
// installs XDP programs, creates and removes BPF maps, adds and
// removes whole ipsets into/from the BPF maps, adds and removes
// certain members to/from BPF maps.
func (a *xdpBPFActions) apply(memberCache *xdpMemberCache, ipsetIDsToMembers *ipsetIDsToMembers, ipsSource ipsetsSource, xdpModes []bpf.XDPMode) error {
	var opErr error
	logCxt := log.WithField("family", memberCache.GetFamily().String())

	// used for dropping programs, to handle the case when generic
	// xdp is currently disabled and we need to drop a program
	// installed in generic mode by previous felix instance which
	// had generic xdp enabled.
	allXDPModes := getXDPModes(true)
	logCxt.Debug("Processing BPF actions.")
	a.UninstallXDP.Iter(func(iface string) error {
		var removeErrs []error
		logCxt.WithField("iface", iface).Debug("Removing XDP programs.")
		for _, mode := range allXDPModes {
			if err := memberCache.bpfLib.RemoveXDP(iface, mode); err != nil {
				removeErrs = append(removeErrs, err)
			}
			// Note: keep trying to remove remaining possible modes, even if that one
			// appeared to succeed.  With current kernel and iproute2, RemoveXDP reports
			// success if there _wasn't_ any XDP program attached in the specified mode.
			// So, if we stop after the first mode that reports success, we won't remove
			// the XDP program in the mode that is actually in use!
		}
		// Only report an error if _all_ of the mode-specific removals failed.
		if len(removeErrs) == len(allXDPModes) {
			opErr = fmt.Errorf("failed to remove XDP program from %s: %v", iface, removeErrs)
			return set.StopIteration
		}
		return nil
	})
	if opErr != nil {
		return opErr
	}

	a.RemoveMap.Iter(func(iface string) error {
		logCxt.WithField("iface", iface).Debug("Removing BPF blacklist map.")
		if err := memberCache.bpfLib.RemoveCIDRMap(iface, memberCache.GetFamily()); err != nil {
			opErr = err
			return set.StopIteration
		}
		return nil
	})
	if opErr != nil {
		return opErr
	}

	a.CreateMap.Iter(func(iface string) error {
		logCxt.WithField("iface", iface).Debug("Creating a BPF blacklist map.")
		if _, err := memberCache.bpfLib.NewCIDRMap(iface, memberCache.GetFamily()); err != nil {
			opErr = err
			return set.StopIteration
		}
		return nil
	})
	if opErr != nil {
		return opErr
	}

	for iface, memberMap := range a.MembersToAdd {
		mi := &memberIterMap{
			memberMap: memberMap,
		}
		if err := processMemberAdds(memberCache, iface, mi); err != nil {
			return err
		}
	}

	for iface, setIDMap := range a.AddToMap {
		for setID, refCount := range setIDMap {
			logCxt.WithFields(log.Fields{
				"iface":    iface,
				"setID":    setID,
				"refCount": refCount,
			}).Debug("Adding members of ipset to BPF blacklist map.")
			members, err := getIPSetMembers(ipsetIDsToMembers, setID, ipsSource)
			if err != nil {
				return err
			}
			mi := &memberIterSet{
				members:  members,
				refCount: refCount,
			}
			if err := processMemberAdds(memberCache, iface, mi); err != nil {
				return err
			}
		}
	}

	// drop stuff from maps
	for iface, memberMap := range a.MembersToDrop {
		mi := &memberIterMap{
			memberMap: memberMap,
		}
		if err := processMemberDeletions(memberCache, iface, mi); err != nil {
			return err
		}
	}

	for iface, setIDMap := range a.RemoveFromMap {
		for setID, refCount := range setIDMap {
			logCxt.WithFields(log.Fields{
				"iface":    iface,
				"setID":    setID,
				"refCount": refCount,
			}).Debug("Dropping members of ipset from BPF blacklist map.")
			members, ok := ipsetIDsToMembers.GetCached(setID)
			if !ok {
				return fmt.Errorf("failed to remove members of %s program from %s: ipset not in cache", setID, iface)
			}
			mi := &memberIterSet{
				members:  members,
				refCount: refCount,
			}
			if err := processMemberDeletions(memberCache, iface, mi); err != nil {
				return err
			}
		}
	}

	a.InstallXDP.Iter(func(iface string) error {
		logCxt.WithField("iface", iface).Debug("Loading XDP program.")
		var loadErrs []error
		for _, mode := range xdpModes {
			if err := memberCache.bpfLib.LoadXDPAuto(iface, mode); err != nil {
				loadErrs = append(loadErrs, err)
			} else {
				logCxt.WithFields(log.Fields{
					"iface": iface,
					"mode":  mode,
				}).Debug("Loading XDP program succeeded.")
				loadErrs = nil
				break
			}
		}
		if loadErrs != nil {
			opErr = fmt.Errorf("failed to load XDP program from %s: %v", iface, loadErrs)
			return set.StopIteration
		}
		return nil
	})
	if opErr != nil {
		return opErr
	}
	logCxt.Debug("Finished processing BPF actions.")

	return nil
}

func getXDPModes(allowGenericXDP bool) []bpf.XDPMode {
	modes := []bpf.XDPMode{
		bpf.XDPOffload,
		bpf.XDPDriver,
	}
	if allowGenericXDP {
		modes = append(modes, bpf.XDPGeneric)
	}
	return modes
}

func getIPSetMembers(ipsetIDsToMembers *ipsetIDsToMembers, setID string, ipsSource ipsetsSource) (set.Set[string], error) {
	members, ok := ipsetIDsToMembers.GetCached(setID)
	if ok {
		return members, nil
	}

	members, err := ipsSource.GetIPSetMembers(setID)
	if err != nil {
		return nil, err
	}
	ipsetIDsToMembers.SetCache(setID, members)
	return members, nil
}

type convertingIPSetsSource struct {
	realSource ipsetsSource
}

func newConvertingIPSetsSource(realSource ipsetsSource) ipsetsSource {
	return &convertingIPSetsSource{
		realSource: realSource,
	}
}

var _ ipsetsSource = &convertingIPSetsSource{}

func (s *convertingIPSetsSource) GetIPSetType(setID string) (ipsets.IPSetType, error) {
	return s.realSource.GetIPSetType(setID)
}

func (s *convertingIPSetsSource) GetIPSetMembers(setID string) (set.Set[string], error) {
	members, err := s.realSource.GetIPSetMembers(setID)
	if err != nil {
		return nil, err
	}
	return s.tryConvert(setID, members)
}

func (s *convertingIPSetsSource) tryConvert(setID string, members set.Set[string] /*<string>*/) (set.Set[string], error) {
	setType, err := s.GetIPSetType(setID)
	if err != nil {
		return nil, err
	}
	convertedMembers := convertMembersToMasked(members, setType)
	return convertedMembers, nil
}

func convertMembersToMasked(members set.Set[string], setType ipsets.IPSetType) set.Set[string] {
	if members == nil {
		return nil
	}
	switch setType {
	case ipsets.IPSetTypeHashIP:
		newMembers := set.New[string]()
		members.Iter(func(member string) error {
			newMembers.Add(member + "/32")
			return nil
		})
		return newMembers
	case ipsets.IPSetTypeHashNet:
		return members
	default:
		return set.New[string]()
	}
}

func processMemberAdds(memberCache *xdpMemberCache, iface string, mi memberIter) error {
	if mi.Len() == 0 {
		return nil
	}
	logCxt := log.WithField("family", memberCache.GetFamily().String())
	bpfMembers, err := memberCache.GetMembers(iface)
	if err != nil {
		return err
	}
	return mi.Iter(func(member string, refCount uint32) error {
		ip, mask, err := bpf.MemberToIPMask(member)
		if err != nil {
			return err
		}
		mapKey, err := memberCache.GetCIDRMapKeyForMember(member)
		if err != nil {
			return err
		}
		if bpfRefCount, ok := bpfMembers[mapKey]; ok {
			logCxt.WithFields(log.Fields{
				"iface":    iface,
				"oldCount": bpfRefCount,
				"newCount": bpfRefCount + refCount,
				"member":   member,
			}).Debug("Updating refcount in BPF blacklist map.")
			bpfMembers[mapKey] = bpfRefCount + refCount
			if err := memberCache.bpfLib.UpdateCIDRMap(iface, memberCache.GetFamily(), *ip, mask, bpfRefCount+refCount); err != nil {
				return err
			}
		} else {
			logCxt.WithFields(log.Fields{
				"iface":    iface,
				"refCount": refCount,
				"member":   member,
			}).Debug("Adding a member in BPF blacklist map.")
			bpfMembers[mapKey] = refCount
			if err := memberCache.bpfLib.UpdateCIDRMap(iface, memberCache.GetFamily(), *ip, mask, refCount); err != nil {
				return err
			}
		}
		return nil
	})
}

func processMemberDeletions(memberCache *xdpMemberCache, iface string, mi memberIter) error {
	if mi.Len() == 0 {
		return nil
	}
	logCxt := log.WithField("family", memberCache.GetFamily().String())
	bpfMembers, err := memberCache.GetMembers(iface)
	if err != nil {
		return err
	}
	return mi.Iter(func(member string, refCount uint32) error {
		ip, mask, err := bpf.MemberToIPMask(member)
		if err != nil {
			return err
		}
		mapKey, err := memberCache.GetCIDRMapKeyForMember(member)
		if err != nil {
			return err
		}
		if bpfRefCount, ok := bpfMembers[mapKey]; ok {
			if bpfRefCount < refCount {
				logCxt.WithFields(log.Fields{
					"iface":    iface,
					"oldCount": bpfRefCount,
					"newCount": bpfRefCount - refCount,
					"member":   member,
				}).Debug("Can't update refcount in BPF blacklist map.")
				return fmt.Errorf("wanted to drop refcount of %s (%d) by %d, which would lead to negative refcount", member, bpfRefCount, refCount)
			} else if bpfRefCount == refCount {
				logCxt.WithFields(log.Fields{
					"iface":  iface,
					"member": member,
				}).Debug("Dropping a member from BPF blacklist map.")
				delete(bpfMembers, mapKey)
				if err := memberCache.bpfLib.RemoveItemCIDRMap(iface, memberCache.GetFamily(), *ip, mask); err != nil {
					return err
				}
			} else {
				logCxt.WithFields(log.Fields{
					"iface":    iface,
					"oldCount": bpfRefCount,
					"newCount": bpfRefCount - refCount,
					"member":   member,
				}).Debug("Updating refcount of a member in BPF blacklist map.")
				bpfMembers[mapKey] = bpfRefCount - refCount
				if err := memberCache.bpfLib.UpdateCIDRMap(iface, memberCache.GetFamily(), *ip, mask, bpfRefCount-refCount); err != nil {
					return err
				}
			}
		} else {
			return fmt.Errorf("expected to have member %s in map for %s %s", member, iface, memberCache.GetFamily().String())
		}
		return nil
	})
}

type xdpIfaceData struct {
	EpID             proto.HostEndpointID
	PoliciesToSetIDs map[proto.PolicyID]set.Set[string]
}

func (data xdpIfaceData) Copy() xdpIfaceData {
	new := data
	new.PoliciesToSetIDs = make(map[proto.PolicyID]set.Set[string], len(data.PoliciesToSetIDs))
	for k, v := range data.PoliciesToSetIDs {
		// this makes shallow copy, but fortunately these are
		// just strings
		new.PoliciesToSetIDs[k] = v.Copy()
	}
	return new
}

func (d *xdpIfaceData) NeedsXDP() bool {
	for _, setIDs := range d.PoliciesToSetIDs {
		if setIDs.Len() > 0 {
			return true
		}
	}
	return false
}

type xdpRules struct {
	Rules []xdpRule
}

func (rs xdpRules) Copy() xdpRules {
	var newRules []xdpRule
	for _, r := range rs.Rules {
		newSetIDs := make([]string, len(r.SetIDs))
		copy(newSetIDs, r.SetIDs)
		newRules = append(newRules, xdpRule{SetIDs: newSetIDs})
	}

	return xdpRules{Rules: newRules}
}

type xdpRule struct {
	SetIDs []string
}

type endpointsSource interface {
	GetRawHostEndpoints() map[proto.HostEndpointID]*proto.HostEndpoint
}

var _ endpointsSource = &endpointManager{}

type nilIPSetsSource struct{}

func (n *nilIPSetsSource) GetIPSetType(setID string) (ipsets.IPSetType, error) {
	return "", nil
}

func (n *nilIPSetsSource) GetIPSetMembers(setID string) (set.Set[string], error) {
	return set.New[string](), nil
}

type ipsetsSource interface {
	GetIPSetType(setID string) (ipsets.IPSetType, error)
	GetIPSetMembers(setID string) (set.Set[string], error)
}

var _ ipsetsSource = &common.IPSetsManager{}
var _ ipsetsSource = &nilIPSetsSource{}

type xdpMemberCache struct {
	family                 bpf.IPFamily
	cache                  map[string]map[bpf.CIDRMapKey]uint32
	memberToCIDRMapKeyFunc func(member string) (bpf.CIDRMapKey, error)
	bpfLib                 bpf.BPFDataplane
}

func newXDPMemberCache(family bpf.IPFamily, bpfLib bpf.BPFDataplane) *xdpMemberCache {
	return &xdpMemberCache{
		family:                 family,
		cache:                  make(map[string]map[bpf.CIDRMapKey]uint32),
		memberToCIDRMapKeyFunc: getMemberToCIDRMapKeyFunc(family),
		bpfLib:                 bpfLib,
	}
}

func getMemberToCIDRMapKeyFunc(family bpf.IPFamily) func(member string) (bpf.CIDRMapKey, error) {
	maskSizeInBits := func() int {
		if family == bpf.IPFamilyV4 {
			return 32
		}
		return 128
	}()
	return func(member string) (bpf.CIDRMapKey, error) {
		ip, maskLen, err := bpf.MemberToIPMask(member)
		if err != nil {
			return bpf.CIDRMapKey{}, err
		}
		mask := net.CIDRMask(maskLen, maskSizeInBits)
		ipnet := &net.IPNet{
			IP:   *ip,
			Mask: mask,
		}
		return bpf.NewCIDRMapKey(ipnet), nil
	}
}

func (c *xdpMemberCache) GetMembers(iface string) (map[bpf.CIDRMapKey]uint32, error) {
	if members, ok := c.cache[iface]; ok {
		return members, nil
	}
	members, err := c.bpfLib.DumpCIDRMap(iface, c.family)
	if err != nil {
		return nil, err
	}
	c.cache[iface] = members
	return members, nil
}

func (c *xdpMemberCache) GetFamily() bpf.IPFamily {
	return c.family
}

func (c *xdpMemberCache) GetCIDRMapKeyForMember(member string) (bpf.CIDRMapKey, error) {
	return c.memberToCIDRMapKeyFunc(member)
}

type xdpResyncState struct {
	ifacesWithProgs map[string]progInfo
	ifacesWithMaps  map[string]mapInfo
	ipsetMembers    map[string]set.Set[string]
}

type progInfo struct {
	bogus bool
}

type mapInfo struct {
	bogus      bool
	mismatched bool
	contents   map[bpf.CIDRMapKey]uint32
}

type memberIterMap struct {
	memberMap map[string]uint32
}

func (m *memberIterMap) Iter(f func(member string, refCount uint32) error) error {
	for member, refCount := range m.memberMap {
		if err := f(member, refCount); err != nil {
			return err
		}
	}
	return nil
}

func (m *memberIterMap) Len() int {
	return len(m.memberMap)
}

type memberIterSet struct {
	members  set.Set[string]
	refCount uint32
}

func (m *memberIterSet) Iter(f func(member string, refCount uint32) error) error {
	var opErr error
	m.members.Iter(func(member string) error {
		if err := f(member, m.refCount); err != nil {
			opErr = err
			return set.StopIteration
		}
		return nil
	})
	return opErr
}

func (m *memberIterSet) Len() int {
	return m.members.Len()
}

type memberIter interface {
	Iter(func(member string, refCount uint32) error) error
	Len() int
}

var _ memberIter = &memberIterSet{}
var _ memberIter = &memberIterMap{}
