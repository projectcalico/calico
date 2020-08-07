// Copyright (c) 2020 Tigera, Inc. All rights reserved.
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
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/projectcalico/felix/bpf"
	"github.com/projectcalico/felix/bpf/polprog"
	"github.com/projectcalico/felix/bpf/tc"
	"github.com/projectcalico/felix/idalloc"
	"github.com/projectcalico/felix/ifacemonitor"
	"github.com/projectcalico/felix/iptables"
	"github.com/projectcalico/felix/proto"
	"github.com/projectcalico/felix/ratelimited"
	"github.com/projectcalico/libcalico-go/lib/set"
)

const jumpMapCleanupInterval = 10 * time.Second

type bpfInterface struct {
	// info contains the information about the interface sent to us from external sources. For example,
	// the ID of the controlling workload interface and our current expectation of its "oper state".
	// When the info changes, we mark the interface dirty and refresh its dataplane state.
	info bpfInterfaceInfo
	// dpState contains the dataplane state that we've derived locally.  It caches the result of updating
	// the interface (so changes to dpState don't cause the interface to be marked dirty).
	dpState bpfInterfaceState
}

type bpfInterfaceInfo struct {
	operState  ifacemonitor.State
	endpointID *proto.WorkloadEndpointID
}

type bpfInterfaceState struct {
	jumpMapFDs [2]bpf.MapFD
}

type bpfEndpointManager struct {
	// Main store of information about interfaces; indexed on interface name.
	ifacesLock  sync.Mutex
	nameToIface map[string]bpfInterface

	allWEPs        map[proto.WorkloadEndpointID]*proto.WorkloadEndpoint
	happyWEPs      map[proto.WorkloadEndpointID]*proto.WorkloadEndpoint
	happyWEPsDirty bool
	policies       map[proto.PolicyID]*proto.Policy
	profiles       map[proto.ProfileID]*proto.Profile

	// Indexes
	policiesToWorkloads map[proto.PolicyID]set.Set  /*proto.WorkloadEndpointID*/
	profilesToWorkloads map[proto.ProfileID]set.Set /*proto.WorkloadEndpointID*/

	dirtyIfaceNames set.Set

	bpfLogLevel        string
	hostname           string
	hostIP             net.IP
	fibLookupEnabled   bool
	dataIfaceRegex     *regexp.Regexp
	workloadIfaceRegex *regexp.Regexp
	ipSetIDAlloc       *idalloc.IDAllocator
	epToHostDrop       bool
	vxlanMTU           int
	dsrEnabled         bool

	ipSetMap            bpf.Map
	stateMap            bpf.Map
	ruleRenderer        bpfAllowChainRenderer
	iptablesFilterTable *iptables.Table

	startupOnce      sync.Once
	mapCleanupRunner *ratelimited.Runner
}

type bpfAllowChainRenderer interface {
	WorkloadInterfaceAllowChains(endpoints map[proto.WorkloadEndpointID]*proto.WorkloadEndpoint) []*iptables.Chain
}

func newBPFEndpointManager(
	bpfLogLevel string,
	hostname string,
	fibLookupEnabled bool,
	epToHostDrop bool,
	dataIfaceRegex *regexp.Regexp,
	workloadIfaceRegex *regexp.Regexp,
	ipSetIDAlloc *idalloc.IDAllocator,
	vxlanMTU int,
	dsrEnabled bool,
	ipSetMap bpf.Map,
	stateMap bpf.Map,
	iptablesRuleRenderer bpfAllowChainRenderer,
	iptablesFilterTable *iptables.Table,
) *bpfEndpointManager {
	return &bpfEndpointManager{
		allWEPs:             map[proto.WorkloadEndpointID]*proto.WorkloadEndpoint{},
		happyWEPs:           map[proto.WorkloadEndpointID]*proto.WorkloadEndpoint{},
		happyWEPsDirty:      true,
		policies:            map[proto.PolicyID]*proto.Policy{},
		profiles:            map[proto.ProfileID]*proto.Profile{},
		nameToIface:         map[string]bpfInterface{},
		policiesToWorkloads: map[proto.PolicyID]set.Set{},
		profilesToWorkloads: map[proto.ProfileID]set.Set{},
		dirtyIfaceNames:     set.New(),
		bpfLogLevel:         bpfLogLevel,
		hostname:            hostname,
		fibLookupEnabled:    fibLookupEnabled,
		dataIfaceRegex:      dataIfaceRegex,
		workloadIfaceRegex:  workloadIfaceRegex,
		ipSetIDAlloc:        ipSetIDAlloc,
		epToHostDrop:        epToHostDrop,
		vxlanMTU:            vxlanMTU,
		dsrEnabled:          dsrEnabled,
		ipSetMap:            ipSetMap,
		stateMap:            stateMap,
		ruleRenderer:        iptablesRuleRenderer,
		iptablesFilterTable: iptablesFilterTable,
		mapCleanupRunner: ratelimited.NewRunner(jumpMapCleanupInterval, func(ctx context.Context) {
			log.Debug("Jump map cleanup triggered.")
			tc.CleanUpJumpMaps()
		}),
	}
}

// withIface handles the bookkeeping for working with a particular bpfInterface value.  It
// * creates the value if needed
// * calls the giving callback with the value so it can be edited
// * if the bpfInterface's info field changes, it marks it as dirty
// * if the bpfInterface is now empty (no info or state), it cleans it up.
func (m *bpfEndpointManager) withIface(ifaceName string, fn func(iface *bpfInterface) (forceDirty bool)) {
	iface := m.nameToIface[ifaceName]
	ifaceCopy := iface
	dirty := fn(&iface)
	logCtx := log.WithField("name", ifaceName)

	var zeroIface bpfInterface
	if iface == zeroIface {
		logCtx.Debug("Interface info is now empty.")
		delete(m.nameToIface, ifaceName)
	}

	dirty = dirty || iface.info != ifaceCopy.info

	if !dirty {
		return
	}

	logCtx.Debug("Marking iface dirty.")
	m.dirtyIfaceNames.Add(ifaceName)
	m.nameToIface[ifaceName] = iface
}

func (m *bpfEndpointManager) OnUpdate(msg interface{}) {
	switch msg := msg.(type) {
	// Updates from the dataplane:

	// Interface updates.
	case *ifaceUpdate:
		m.onInterfaceUpdate(msg)

	// Updates from the datamodel:

	// Workloads.
	case *proto.WorkloadEndpointUpdate:
		m.onWorkloadEndpointUpdate(msg)
	case *proto.WorkloadEndpointRemove:
		m.onWorkloadEnpdointRemove(msg)
	// Policies.
	case *proto.ActivePolicyUpdate:
		m.onPolicyUpdate(msg)
	case *proto.ActivePolicyRemove:
		m.onPolicyRemove(msg)
	// Profiles.
	case *proto.ActiveProfileUpdate:
		m.onProfileUpdate(msg)
	case *proto.ActiveProfileRemove:
		m.onProfileRemove(msg)

	case *proto.HostMetadataUpdate:
		if msg.Hostname == m.hostname {
			log.WithField("HostMetadataUpdate", msg).Info("Host IP changed")
			ip := net.ParseIP(msg.Ipv4Addr)
			if ip != nil {
				m.hostIP = ip
				// Should be safe without the lock since there shouldn't be any active background threads
				// but taking it now makes us robust to refactoring.
				m.ifacesLock.Lock()
				for ifaceName := range m.nameToIface {
					m.dirtyIfaceNames.Add(ifaceName)
				}
				m.ifacesLock.Unlock()
			} else {
				log.WithField("HostMetadataUpdate", msg).Warn("Cannot parse IP, no change applied")
			}
		}
	}
}

func (m *bpfEndpointManager) onInterfaceUpdate(update *ifaceUpdate) {
	// Should be safe without the lock since there shouldn't be any active background threads
	// but taking it now makes us robust to refactoring.
	m.ifacesLock.Lock()
	defer m.ifacesLock.Unlock()

	if !m.isDataIface(update.Name) && !m.isWorkloadIface(update.Name) {
		log.WithField("update", update).Debug("Ignoring interface that's neither data nor workload.")
		return
	}

	m.withIface(update.Name, func(iface *bpfInterface) bool {
		iface.info.operState = update.State
		return false
	})
}

// onWorkloadEndpointUpdate adds/updates the workload in the cache along with the index from active policy to
// workloads using that policy.
func (m *bpfEndpointManager) onWorkloadEndpointUpdate(msg *proto.WorkloadEndpointUpdate) {
	log.WithField("wep", msg.Endpoint).Debug("Workload endpoint update")
	wlID := *msg.Id
	oldWEP := m.allWEPs[wlID]
	wl := msg.Endpoint
	if oldWEP != nil {
		for _, t := range oldWEP.Tiers {
			for _, pol := range t.IngressPolicies {
				polSet := m.policiesToWorkloads[proto.PolicyID{
					Tier: t.Name,
					Name: pol,
				}]
				if polSet == nil {
					continue
				}
				polSet.Discard(wlID)
			}
			for _, pol := range t.EgressPolicies {
				polSet := m.policiesToWorkloads[proto.PolicyID{
					Tier: t.Name,
					Name: pol,
				}]
				if polSet == nil {
					continue
				}
				polSet.Discard(wlID)
			}
		}

		for _, profName := range oldWEP.ProfileIds {
			profID := proto.ProfileID{Name: profName}
			profSet := m.profilesToWorkloads[profID]
			if profSet == nil {
				continue
			}
			profSet.Discard(wlID)
		}

		m.withIface(oldWEP.Name, func(iface *bpfInterface) bool {
			iface.info.endpointID = nil
			return false
		})
	}
	m.allWEPs[wlID] = msg.Endpoint
	for _, t := range wl.Tiers {
		for _, pol := range t.IngressPolicies {
			polID := proto.PolicyID{
				Tier: t.Name,
				Name: pol,
			}
			if m.policiesToWorkloads[polID] == nil {
				m.policiesToWorkloads[polID] = set.New()
			}
			m.policiesToWorkloads[polID].Add(wlID)
		}
		for _, pol := range t.EgressPolicies {
			polID := proto.PolicyID{
				Tier: t.Name,
				Name: pol,
			}
			if m.policiesToWorkloads[polID] == nil {
				m.policiesToWorkloads[polID] = set.New()
			}
			m.policiesToWorkloads[polID].Add(wlID)
		}
		for _, profName := range wl.ProfileIds {
			profID := proto.ProfileID{Name: profName}
			profSet := m.profilesToWorkloads[profID]
			if profSet == nil {
				profSet = set.New()
				m.profilesToWorkloads[profID] = profSet
			}
			profSet.Add(wlID)
		}
	}
	m.withIface(wl.Name, func(iface *bpfInterface) bool {
		iface.info.endpointID = &wlID
		return true // Force interface to be marked dirty in case policies changed.
	})
}

// onWorkloadEndpointRemove removes the workload from the cache and the index, which maps from policy to workload.
func (m *bpfEndpointManager) onWorkloadEnpdointRemove(msg *proto.WorkloadEndpointRemove) {
	wlID := *msg.Id
	log.WithField("id", wlID).Debug("Workload endpoint removed")
	oldWEP := m.allWEPs[wlID]
	for _, t := range oldWEP.Tiers {
		for _, pol := range t.IngressPolicies {
			polSet := m.policiesToWorkloads[proto.PolicyID{
				Tier: t.Name,
				Name: pol,
			}]
			if polSet == nil {
				continue
			}
			polSet.Discard(wlID)
		}
		for _, pol := range t.EgressPolicies {
			polSet := m.policiesToWorkloads[proto.PolicyID{
				Tier: t.Name,
				Name: pol,
			}]
			if polSet == nil {
				continue
			}
			polSet.Discard(wlID)
		}
	}
	delete(m.allWEPs, wlID)
	if m.happyWEPs[wlID] != nil {
		delete(m.happyWEPs, wlID)
		m.happyWEPsDirty = true
	}

	m.withIface(oldWEP.Name, func(iface *bpfInterface) bool {
		iface.info.endpointID = nil
		return false
	})
}

// onPolicyUpdate stores the policy in the cache and marks any endpoints using it dirty.
func (m *bpfEndpointManager) onPolicyUpdate(msg *proto.ActivePolicyUpdate) {
	polID := *msg.Id
	log.WithField("id", polID).Debug("Policy update")
	m.policies[polID] = msg.Policy
	m.markPolicyUsersDirty(polID)
}

// onPolicyRemove removes the policy from the cache and marks any endpoints using it dirty.
// The latter should be a no-op due to the ordering guarantees of the calc graph.
func (m *bpfEndpointManager) onPolicyRemove(msg *proto.ActivePolicyRemove) {
	polID := *msg.Id
	log.WithField("id", polID).Debug("Policy removed")
	m.markPolicyUsersDirty(polID)
	delete(m.policies, polID)
	delete(m.policiesToWorkloads, polID)
}

// onProfileUpdate stores the profile in the cache and marks any endpoints that use it as dirty.
func (m *bpfEndpointManager) onProfileUpdate(msg *proto.ActiveProfileUpdate) {
	profID := *msg.Id
	log.WithField("id", profID).Debug("Profile update")
	m.profiles[profID] = msg.Profile
	m.markProfileUsersDirty(profID)
}

// onProfileRemove removes the profile from the cache and marks any endpoints that were using it as dirty.
// The latter should be a no-op due to the ordering guarantees of the calc graph.
func (m *bpfEndpointManager) onProfileRemove(msg *proto.ActiveProfileRemove) {
	profID := *msg.Id
	log.WithField("id", profID).Debug("Profile removed")
	m.markProfileUsersDirty(profID)
	delete(m.profiles, profID)
	delete(m.profilesToWorkloads, profID)
}

func (m *bpfEndpointManager) markPolicyUsersDirty(id proto.PolicyID) {
	wls := m.policiesToWorkloads[id]
	if wls == nil {
		// Hear about the policy before the endpoint.
		return
	}
	wls.Iter(func(item interface{}) error {
		wlID := item.(proto.WorkloadEndpointID)
		m.markExistingWEPDirty(wlID)
		return nil
	})
}

func (m *bpfEndpointManager) markProfileUsersDirty(id proto.ProfileID) {
	wls := m.profilesToWorkloads[id]
	if wls == nil {
		// Hear about the policy before the endpoint.
		return
	}
	wls.Iter(func(item interface{}) error {
		wlID := item.(proto.WorkloadEndpointID)
		m.markExistingWEPDirty(wlID)
		return nil
	})
}

func (m *bpfEndpointManager) markExistingWEPDirty(wlID proto.WorkloadEndpointID) {
	wep := m.allWEPs[wlID]
	if wep == nil {
		log.WithField("wlID", wlID).Panic(
			"BUG: policiesToWorkloads mapping points to unknown workload.")
	} else {
		m.dirtyIfaceNames.Add(wep.Name)
	}
}

func (m *bpfEndpointManager) CompleteDeferredWork() error {
	// Do one-off initialisation.
	m.ensureStarted()

	m.applyProgramsToDirtyDataInterfaces()
	m.updateWEPsInDataplane()

	if m.happyWEPsDirty {
		chains := m.ruleRenderer.WorkloadInterfaceAllowChains(m.happyWEPs)
		m.iptablesFilterTable.UpdateChains(chains)
		m.happyWEPsDirty = false
	}

	return nil
}

func (m *bpfEndpointManager) setAcceptLocal(iface string, val bool) error {
	numval := "0"
	if val {
		numval = "1"
	}

	path := fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/accept_local", iface)
	err := writeProcSys(path, numval)
	if err != nil {
		log.WithField("err", err).Errorf("Failed to  set %s to %s", path, numval)
		return err
	}

	log.Infof("%s set to %s", path, numval)
	return nil
}

func (m *bpfEndpointManager) ensureStarted() {
	m.startupOnce.Do(func() {
		log.Info("Starting map cleanup runner.")
		m.mapCleanupRunner.Start(context.Background())
	})
}

func (m *bpfEndpointManager) applyProgramsToDirtyDataInterfaces() {
	var mutex sync.Mutex
	errs := map[string]error{}
	var wg sync.WaitGroup
	m.dirtyIfaceNames.Iter(func(item interface{}) error {
		iface := item.(string)
		if !m.isDataIface(iface) {
			log.WithField("iface", iface).Debug(
				"Ignoring interface that doesn't match the host data interface regex")
			return nil
		}
		if m.getIfaceState(iface) != ifacemonitor.StateUp {
			log.WithField("iface", iface).Debug("Ignoring interface that is down")
			return set.RemoveItem
		}

		wg.Add(1)
		go func() {
			defer wg.Done()

			var ingressWG sync.WaitGroup
			var ingressErr error
			ingressWG.Add(1)
			go func() {
				defer ingressWG.Done()
				ingressErr = m.attachDataIfaceProgram(iface, PolDirnIngress)
			}()
			err := m.attachDataIfaceProgram(iface, PolDirnEgress)
			ingressWG.Wait()
			if err == nil {
				err = ingressErr
			}
			if err == nil {
				// This is required to allow NodePort forwarding with
				// encapsulation with the host's IP as the source address
				err = m.setAcceptLocal(iface, true)
			}
			mutex.Lock()
			errs[iface] = err
			mutex.Unlock()
		}()
		return nil
	})
	wg.Wait()
	m.dirtyIfaceNames.Iter(func(item interface{}) error {
		iface := item.(string)
		if !m.isDataIface(iface) {
			log.WithField("iface", iface).Debug(
				"Ignoring interface that doesn't match the host data interface regex")
			return nil
		}
		err := errs[iface]
		if err == nil {
			log.WithField("id", iface).Info("Applied program to host interface")
			return set.RemoveItem
		}
		if errors.Is(err, tc.ErrDeviceNotFound) {
			log.WithField("iface", iface).Debug(
				"Tried to apply BPF program to interface but the interface wasn't present.  " +
					"Will retry if it shows up.")
		}
		log.WithError(err).Warn("Failed to apply policy to interface")
		return nil
	})
}

func (m *bpfEndpointManager) updateWEPsInDataplane() {
	var mutex sync.Mutex
	errs := map[string]error{}
	var wg sync.WaitGroup

	m.dirtyIfaceNames.Iter(func(item interface{}) error {
		ifaceName := item.(string)

		if !m.isWorkloadIface(ifaceName) {
			return nil
		}

		wg.Add(1)
		go func(ifaceName string) {
			defer wg.Done()
			err := m.applyPolicy(ifaceName)
			mutex.Lock()
			errs[ifaceName] = err
			mutex.Unlock()
		}(ifaceName)
		return nil
	})
	wg.Wait()

	if m.dirtyIfaceNames.Len() > 0 {
		// Clean up any left-over jump maps in the background...
		m.mapCleanupRunner.Trigger()
	}

	m.dirtyIfaceNames.Iter(func(item interface{}) error {
		ifaceName := item.(string)

		if !m.isWorkloadIface(ifaceName) {
			return nil
		}

		err := errs[ifaceName]
		wlID := m.nameToIface[ifaceName].info.endpointID
		if err == nil {
			log.WithField("iface", ifaceName).Info("Updated workload interface.")
			if wlID != nil && m.allWEPs[*wlID] != nil {
				if m.happyWEPs[*wlID] == nil {
					log.WithField("id", wlID).Info("Adding workload interface to iptables allow list.")
					m.happyWEPsDirty = true
				}
				m.happyWEPs[*wlID] = m.allWEPs[*wlID]
			}
			return set.RemoveItem
		} else {
			if wlID != nil && m.happyWEPs[*wlID] != nil {
				if !errors.Is(err, tc.ErrDeviceNotFound) {
					log.WithField("id", *wlID).WithError(err).Error(
						"Failed to add policy to workload, removing from iptables allow list")
				}
				delete(m.happyWEPs, *wlID)
				m.happyWEPsDirty = true
			}
		}
		if errors.Is(err, tc.ErrDeviceNotFound) {
			log.WithField("wep", wlID).Debug(
				"Tried to apply BPF program to interface but the interface wasn't present.  " +
					"Will retry if it shows up.")
			return nil
		}
		log.WithError(err).WithFields(log.Fields{
			"wepID": wlID,
			"name":  ifaceName,
		}).Warn("Failed to apply policy to endpoint")
		return nil
	})
}

// applyPolicy actually applies the policy to the given workload.
func (m *bpfEndpointManager) applyPolicy(ifaceName string) error {
	startTime := time.Now()

	// Other threads might be filling in jump map FDs in the map so take the lock.
	m.ifacesLock.Lock()
	var endpointID *proto.WorkloadEndpointID
	var endpointStatus ifacemonitor.State
	m.withIface(ifaceName, func(iface *bpfInterface) (forceDirty bool) {
		endpointStatus = iface.info.operState
		endpointID = iface.info.endpointID
		if endpointID == nil {
			for i := range iface.dpState.jumpMapFDs {
				if iface.dpState.jumpMapFDs[i] > 0 {
					err := iface.dpState.jumpMapFDs[i].Close()
					if err != nil {
						log.WithError(err).Error("Failed to close jump map.")
					}
					iface.dpState.jumpMapFDs[i] = 0
				}
			}
		}
		return false
	})
	m.ifacesLock.Unlock()

	if endpointStatus == ifacemonitor.StateUnknown {
		// Interface is gone, nothing to do.
		log.WithField("ifaceName", ifaceName).Debug(
			"Ignoring request to program interface that is not present.")
		return nil
	}

	if endpointID == nil {
		// We think this endpoint exists but it is not known in the datastore.  It may be being removed;
		// clean it up.
		log.Debug("Interface has no matching endpoint, cleaning up")
		err := tc.RemoveQdisc(ifaceName)
		if errors.Is(err, tc.ErrDeviceNotFound) {
			log.WithField("name", ifaceName).Debug("Interface already gone.")
		} else if err != nil {
			log.WithField("name", ifaceName).WithError(err).Warn(
				"Failed to remove BPF from interface; ignoring.")
		}
		return nil
	}

	wep := m.allWEPs[*endpointID]

	var ingressErr, egressErr error
	var wg sync.WaitGroup

	wg.Add(2)
	go func() {
		defer wg.Done()
		ingressErr = m.attachWorkloadProgram(wep, PolDirnIngress)
	}()
	go func() {
		defer wg.Done()
		egressErr = m.attachWorkloadProgram(wep, PolDirnEgress)
	}()
	wg.Wait()

	if ingressErr != nil {
		return ingressErr
	}
	if egressErr != nil {
		return egressErr
	}

	applyTime := time.Since(startTime)
	log.WithField("timeTaken", applyTime).Info("Finished applying BPF programs for workload")
	return nil
}

var calicoRouterIP = net.IPv4(169, 254, 1, 1).To4()

func (m *bpfEndpointManager) attachWorkloadProgram(endpoint *proto.WorkloadEndpoint, polDirection PolDirection) error {
	ap := m.calculateTCAttachPoint(tc.EpTypeWorkload, polDirection, endpoint.Name)
	// Host side of the veth is always configured as 169.254.1.1.
	ap.HostIP = calicoRouterIP
	// * VXLAN MTU should be the host ifaces MTU -50, in order to allow space for VXLAN.
	// * We also expect that to be the MTU used on veths.
	// * We do encap on the veths, and there's a bogus kernel MTU check in the BPF helper
	//   for resizing the packet, so we have to reduce the apparent MTU by another 50 bytes
	//   when we cannot encap the packet - non-GSO & too close to veth MTU
	ap.TunnelMTU = uint16(m.vxlanMTU - 50)

	var tier *proto.TierInfo
	if len(endpoint.Tiers) != 0 {
		tier = endpoint.Tiers[0]
	}
	rules := m.extractRules(tier, endpoint.ProfileIds, polDirection)

	jumpMapFD := m.getJumpMapFD(endpoint.Name, polDirection)
	if jumpMapFD != 0 {
		if attached, err := ap.IsAttached(); err != nil {
			return fmt.Errorf("failed to check if interface %s had BPF program; %w", endpoint.Name, err)
		} else if !attached {
			// BPF program is missing; maybe we missed a notification of the interface being recreated?
			// Close the now-defunct jump map.
			log.WithField("iface", endpoint.Name).Warn(
				"Detected that BPF program no longer attached to interface.")
			err := jumpMapFD.Close()
			if err != nil {
				log.WithError(err).Warn("Failed to close jump map FD. Ignoring.")
			}
			m.setJumpMapFD(endpoint.Name, polDirection, 0)
			jumpMapFD = 0 // Trigger program to be re-added below.
		}
	}

	if jumpMapFD == 0 {
		// We don't have a program attached to this interface yet, attach one now.
		err := ap.AttachProgram()
		if err != nil {
			return err
		}

		jumpMapFD, err = FindJumpMap(ap)
		if err != nil {
			return fmt.Errorf("failed to look up jump map: %w", err)
		}
		m.setJumpMapFD(endpoint.Name, polDirection, jumpMapFD)
	}

	return m.updatePolicyProgram(jumpMapFD, rules)
}

func (m *bpfEndpointManager) getJumpMapFD(ifaceName string, direction PolDirection) (fd bpf.MapFD) {
	m.ifacesLock.Lock()
	defer m.ifacesLock.Unlock()
	m.withIface(ifaceName, func(iface *bpfInterface) bool {
		fd = iface.dpState.jumpMapFDs[direction]
		return false
	})
	return
}

func (m *bpfEndpointManager) setJumpMapFD(name string, direction PolDirection, fd bpf.MapFD) {
	m.ifacesLock.Lock()
	defer m.ifacesLock.Unlock()

	m.withIface(name, func(iface *bpfInterface) bool {
		iface.dpState.jumpMapFDs[direction] = fd
		return false
	})
}

func (m *bpfEndpointManager) getIfaceState(ifaceName string) (state ifacemonitor.State) {
	m.ifacesLock.Lock()
	defer m.ifacesLock.Unlock()
	m.withIface(ifaceName, func(iface *bpfInterface) bool {
		state = iface.info.operState
		return false
	})
	return
}

func (m *bpfEndpointManager) updatePolicyProgram(jumpMapFD bpf.MapFD, rules [][][]*proto.Rule) error {
	pg := polprog.NewBuilder(m.ipSetIDAlloc, m.ipSetMap.MapFD(), m.stateMap.MapFD(), jumpMapFD)
	insns, err := pg.Instructions(rules)
	if err != nil {
		return fmt.Errorf("failed to generate policy bytecode: %w", err)
	}
	progFD, err := bpf.LoadBPFProgramFromInsns(insns, "Apache-2.0")
	if err != nil {
		return fmt.Errorf("failed to load BPF policy program: %w", err)
	}
	k := make([]byte, 4)
	v := make([]byte, 4)
	binary.LittleEndian.PutUint32(v, uint32(progFD))
	err = bpf.UpdateMapEntry(jumpMapFD, k, v)
	if err != nil {
		return fmt.Errorf("failed to update jump map: %w", err)
	}
	return nil
}

func FindJumpMap(ap tc.AttachPoint) (bpf.MapFD, error) {
	tcCmd := exec.Command("tc", "filter", "show", "dev", ap.Iface, string(ap.Hook))
	out, err := tcCmd.Output()
	if err != nil {
		return 0, fmt.Errorf("failed to find TC filter for interface %v: %w", ap.Iface, err)
	}

	progName := ap.ProgramName()
	for _, line := range bytes.Split(out, []byte("\n")) {
		line := string(line)
		if strings.Contains(line, progName) {
			re := regexp.MustCompile(`id (\d+)`)
			m := re.FindStringSubmatch(line)
			if len(m) > 0 {
				progIDStr := m[1]
				bpftool := exec.Command("bpftool", "prog", "show", "id", progIDStr, "--json")
				output, err := bpftool.Output()
				if err != nil {
					return 0, fmt.Errorf("failed to get map metadata: %w", err)
				}
				var prog struct {
					MapIDs []int `json:"map_ids"`
				}
				err = json.Unmarshal(output, &prog)
				if err != nil {
					return 0, fmt.Errorf("failed to parse bpftool output: %w", err)
				}

				for _, mapID := range prog.MapIDs {
					mapFD, err := bpf.GetMapFDByID(mapID)
					if err != nil {
						return 0, fmt.Errorf("failed to get map FD from ID: %w", err)
					}
					mapInfo, err := bpf.GetMapInfo(mapFD)
					if err != nil {
						err = mapFD.Close()
						if err != nil {
							log.WithError(err).Panic("Failed to close FD.")
						}
						return 0, fmt.Errorf("failed to get map info: %w", err)
					}
					if mapInfo.Type == unix.BPF_MAP_TYPE_PROG_ARRAY {
						return mapFD, nil
					}
				}
			}

			return 0, errors.New("failed to find map")
		}
	}
	return 0, errors.New("failed to find TC program")
}

func (m *bpfEndpointManager) attachDataIfaceProgram(ifaceName string, polDirection PolDirection) error {
	epType := tc.EpTypeHost
	if ifaceName == "tunl0" {
		epType = tc.EpTypeTunnel
	} else if ifaceName == "wireguard.cali" {
		epType = tc.EpTypeWireguard
	}
	ap := m.calculateTCAttachPoint(epType, polDirection, ifaceName)
	ap.HostIP = m.hostIP
	ap.TunnelMTU = uint16(m.vxlanMTU)
	return ap.AttachProgram()
}

// PolDirection is the Calico datamodel direction of policy.  On a host endpoint, ingress is towards the host.
// On a workload endpoint, ingress is towards the workload.
type PolDirection int

const (
	PolDirnIngress PolDirection = iota
	PolDirnEgress
)

func (m *bpfEndpointManager) calculateTCAttachPoint(endpointType tc.EndpointType, policyDirection PolDirection, ifaceName string) tc.AttachPoint {
	var ap tc.AttachPoint

	if endpointType == tc.EpTypeWorkload {
		// Policy direction is relative to the workload so, from the host namespace it's flipped.
		if policyDirection == PolDirnIngress {
			ap.Hook = tc.HookEgress
		} else {
			ap.Hook = tc.HookIngress
		}
	} else {
		// Host endpoints have the natural relationship between policy direction and hook.
		if policyDirection == PolDirnIngress {
			ap.Hook = tc.HookIngress
		} else {
			ap.Hook = tc.HookEgress
		}
	}

	var toOrFrom tc.ToOrFromEp
	if ap.Hook == tc.HookIngress {
		toOrFrom = tc.FromEp
	} else {
		toOrFrom = tc.ToEp
	}

	ap.Iface = ifaceName
	ap.Type = endpointType
	ap.ToOrFrom = toOrFrom
	ap.ToHostDrop = m.epToHostDrop
	ap.FIB = m.fibLookupEnabled
	ap.DSR = m.dsrEnabled
	ap.LogLevel = m.bpfLogLevel

	return ap
}

func (m *bpfEndpointManager) extractRules(tier *proto.TierInfo, profileNames []string, direction PolDirection) [][][]*proto.Rule {
	var allRules [][][]*proto.Rule
	if tier != nil {
		var pols [][]*proto.Rule

		directionalPols := tier.IngressPolicies
		if direction == PolDirnEgress {
			directionalPols = tier.EgressPolicies
		}

		if len(directionalPols) > 0 {
			for _, polName := range directionalPols {
				pol := m.policies[proto.PolicyID{Tier: tier.Name, Name: polName}]
				if direction == PolDirnIngress {
					pols = append(pols, pol.InboundRules)
				} else {
					pols = append(pols, pol.OutboundRules)
				}
			}
			allRules = append(allRules, pols)
		}
	}
	var profs [][]*proto.Rule
	for _, profName := range profileNames {
		prof := m.profiles[proto.ProfileID{Name: profName}]
		if direction == PolDirnIngress {
			profs = append(profs, prof.InboundRules)
		} else {
			profs = append(profs, prof.OutboundRules)
		}
	}
	allRules = append(allRules, profs)
	return allRules
}

func (m *bpfEndpointManager) isWorkloadIface(iface string) bool {
	return m.workloadIfaceRegex.MatchString(iface)
}

func (m *bpfEndpointManager) isDataIface(iface string) bool {
	return m.dataIfaceRegex.MatchString(iface)
}
