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
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"

	"github.com/projectcalico/felix/bpf"
	"github.com/projectcalico/felix/bpf/polprog"

	"github.com/projectcalico/felix/bpf/tc"

	"github.com/projectcalico/felix/idalloc"

	"github.com/projectcalico/felix/ifacemonitor"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/felix/proto"
	"github.com/projectcalico/libcalico-go/lib/set"
)

type epIface struct {
	ifacemonitor.State
	addrs []net.IP
}

type bpfEndpointManager struct {
	// Caches.  Updated immediately for now.
	wlEps    map[proto.WorkloadEndpointID]*proto.WorkloadEndpoint
	policies map[proto.PolicyID]*proto.Policy
	profiles map[proto.ProfileID]*proto.Profile
	ifaces   map[string]epIface

	// Indexes
	policiesToWorkloads map[proto.PolicyID]set.Set  /*proto.WorkloadEndpointID*/
	profilesToWorkloads map[proto.ProfileID]set.Set /*proto.WorkloadEndpointID*/

	dirtyWorkloads set.Set
	dirtyIfaces    set.Set

	bpfLogLevel      string
	fibLookupEnabled bool
	dataIfaceRegex   *regexp.Regexp
	ipSetIDAlloc     *idalloc.IDAllocator
	epToHostDrop     bool
	natTunnelMTU     int
	dsrEnabled       bool

	ipSetMap bpf.Map
	stateMap bpf.Map
}

func newBPFEndpointManager(
	bpfLogLevel string,
	fibLookupEnabled bool,
	epToHostDrop bool,
	dataIfaceRegex *regexp.Regexp,
	ipSetIDAlloc *idalloc.IDAllocator,
	natTunnelMTU int,
	dsrEnabled bool,
	ipSetMap bpf.Map,
	stateMap bpf.Map,
) *bpfEndpointManager {
	return &bpfEndpointManager{
		wlEps:               map[proto.WorkloadEndpointID]*proto.WorkloadEndpoint{},
		policies:            map[proto.PolicyID]*proto.Policy{},
		profiles:            map[proto.ProfileID]*proto.Profile{},
		ifaces:              map[string]epIface{},
		policiesToWorkloads: map[proto.PolicyID]set.Set{},
		profilesToWorkloads: map[proto.ProfileID]set.Set{},
		dirtyWorkloads:      set.New(),
		dirtyIfaces:         set.New(),
		bpfLogLevel:         bpfLogLevel,
		fibLookupEnabled:    fibLookupEnabled,
		dataIfaceRegex:      dataIfaceRegex,
		ipSetIDAlloc:        ipSetIDAlloc,
		epToHostDrop:        epToHostDrop,
		natTunnelMTU:        natTunnelMTU,
		dsrEnabled:          dsrEnabled,
		ipSetMap:            ipSetMap,
		stateMap:            stateMap,
	}
}

func (m *bpfEndpointManager) OnUpdate(msg interface{}) {
	switch msg := msg.(type) {
	// Updates from the dataplane:

	// Interface updates.
	case *ifaceUpdate:
		m.onInterfaceUpdate(msg)
	case *ifaceAddrsUpdate:
		m.onInterfaceAddrsUpdate(msg)

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
	}
}

func (m *bpfEndpointManager) onInterfaceUpdate(update *ifaceUpdate) {
	if update.State == ifacemonitor.StateUnknown {
		delete(m.ifaces, update.Name)
	} else {
		iface := m.ifaces[update.Name]
		iface.State = update.State
		m.ifaces[update.Name] = iface
	}
	m.dirtyIfaces.Add(update.Name)
}

func (m *bpfEndpointManager) onInterfaceAddrsUpdate(update *ifaceAddrsUpdate) {
	var addrs []net.IP

	if update == nil || update.Addrs == nil {
		return
	}

	update.Addrs.Iter(func(s interface{}) error {
		str, ok := s.(string)
		if !ok {
			log.WithField("addr", s).Errorf("wrong type %T", s)
			return nil
		}
		ip := net.ParseIP(str)
		if ip == nil {
			return nil
		}
		ip = ip.To4()
		if ip == nil {
			return nil
		}
		addrs = append(addrs, ip)
		return nil
	})

	iface := m.ifaces[update.Name]
	iface.addrs = addrs
	m.ifaces[update.Name] = iface
	m.dirtyIfaces.Add(update.Name)
	log.WithField("iface", update.Name).WithField("addrs", addrs).WithField("State", iface.State).
		Debugf("onInterfaceAddrsUpdate")
}

// onWorkloadEndpointUpdate adds/updates the workload in the cache along with the index from active policy to
// workloads using that policy.
func (m *bpfEndpointManager) onWorkloadEndpointUpdate(msg *proto.WorkloadEndpointUpdate) {
	log.WithField("wep", msg.Endpoint).Debug("Workload endpoint update")
	wlID := *msg.Id
	oldWL := m.wlEps[wlID]
	wl := msg.Endpoint
	if oldWL != nil {
		for _, t := range oldWL.Tiers {
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

		for _, profName := range oldWL.ProfileIds {
			profID := proto.ProfileID{Name: profName}
			profSet := m.profilesToWorkloads[profID]
			if profSet == nil {
				continue
			}
			profSet.Discard(wlID)
		}
	}
	m.wlEps[wlID] = msg.Endpoint
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
	m.dirtyWorkloads.Add(wlID)
}

// onWorkloadEndpointRemove removes the workload from the cache and the index, which maps from policy to workload.
func (m *bpfEndpointManager) onWorkloadEnpdointRemove(msg *proto.WorkloadEndpointRemove) {
	wlID := *msg.Id
	log.WithField("id", wlID).Debug("Workload endpoint removed")
	wl := m.wlEps[wlID]
	for _, t := range wl.Tiers {
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
	delete(m.wlEps, wlID)
	m.dirtyWorkloads.Add(wlID)
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
		m.dirtyWorkloads.Add(item)
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
		m.dirtyWorkloads.Add(item)
		return nil
	})
}

func (m *bpfEndpointManager) CompleteDeferredWork() error {
	m.applyProgramsToDirtyDataInterfaces()
	m.applyProgramsToDirtyWorkloadEndpoints()

	// TODO: handle cali interfaces with no WEP
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

func (m *bpfEndpointManager) applyProgramsToDirtyDataInterfaces() {
	var mutex sync.Mutex
	errs := map[string]error{}
	var wg sync.WaitGroup
	m.dirtyIfaces.Iter(func(item interface{}) error {
		iface := item.(string)
		if !m.dataIfaceRegex.MatchString(iface) {
			log.WithField("iface", iface).Debug(
				"Ignoring interface that doesn't match the host data interface regex")
			return set.RemoveItem
		}
		if m.ifaces[iface].State != ifacemonitor.StateUp {
			log.WithField("iface", iface).Debug("Ignoring interface that is down")
			return set.RemoveItem
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			m.ensureQdisc(iface)
			err := m.attachDataIfaceProgram(iface, PolDirnIngress)
			if err == nil {
				err = m.attachDataIfaceProgram(iface, PolDirnEgress)
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
	m.dirtyIfaces.Iter(func(item interface{}) error {
		iface := item.(string)
		err := errs[iface]
		if err == nil {
			log.WithField("id", iface).Info("Applied program to host interface")
			return set.RemoveItem
		}
		log.WithError(err).Warn("Failed to apply policy to interface")
		return nil
	})
}

func (m *bpfEndpointManager) applyProgramsToDirtyWorkloadEndpoints() {
	var mutex sync.Mutex
	errs := map[proto.WorkloadEndpointID]error{}
	var wg sync.WaitGroup
	m.dirtyWorkloads.Iter(func(item interface{}) error {
		wg.Add(1)
		go func() {
			defer wg.Done()
			wlID := item.(proto.WorkloadEndpointID)
			err := m.applyPolicy(wlID)
			mutex.Lock()
			errs[wlID] = err
			mutex.Unlock()
		}()
		return nil
	})
	wg.Wait()

	if m.dirtyWorkloads.Len() > 0 {
		// Clean up any left-over jump maps in the background...
		go tc.CleanUpJumpMaps()
	}

	m.dirtyWorkloads.Iter(func(item interface{}) error {
		wlID := item.(proto.WorkloadEndpointID)
		err := errs[wlID]
		if err == nil {
			log.WithField("id", wlID).Info("Applied policy to workload")
			return set.RemoveItem
		}
		log.WithError(err).Warn("Failed to apply policy to endpoint")
		return nil
	})
}

// applyPolicy actually applies the policy to the given workload.
func (m *bpfEndpointManager) applyPolicy(wlID proto.WorkloadEndpointID) error {
	startTime := time.Now()
	wep := m.wlEps[wlID]
	if wep == nil {
		// TODO clean up old workloads
		return nil
	}
	ifaceName := wep.Name

	m.ensureQdisc(ifaceName)

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

func (m *bpfEndpointManager) ensureQdisc(ifaceName string) {
	tc.EnsureQdisc(ifaceName)
}

func (m *bpfEndpointManager) attachWorkloadProgram(endpoint *proto.WorkloadEndpoint, polDirection PolDirection) error {
	ap := m.calculateTCAttachPoint(tc.EpTypeWorkload, polDirection, endpoint.Name)
	// Host side of the veth is always configured as 169.254.1.1.
	hostIP := net.IPv4(169, 254, 1, 1)
	err := tc.AttachProgram(ap, hostIP)
	if err != nil {
		return err
	}

	var tier *proto.TierInfo
	if len(endpoint.Tiers) != 0 {
		tier = endpoint.Tiers[0]
	}
	rules := m.extractRules(tier, endpoint.ProfileIds, polDirection)

	jumpMapFD, err := FindJumpMap(ap)
	if err != nil {
		return errors.Wrap(err, "failed to look up jump map")
	}
	defer func() {
		err := jumpMapFD.Close()
		if err != nil {
			log.WithError(err).Panic("Failed to close jump map FD")
		}
	}()

	pg := polprog.NewBuilder(m.ipSetIDAlloc, m.ipSetMap.MapFD(), m.stateMap.MapFD(), jumpMapFD)
	insns, err := pg.Instructions(rules)
	if err != nil {
		return errors.Wrap(err, "failed to generate policy bytecode")
	}
	progFD, err := bpf.LoadBPFProgramFromInsns(insns, "Apache-2.0")
	if err != nil {
		return errors.Wrap(err, "failed to load BPF policy program")
	}
	k := make([]byte, 4)
	v := make([]byte, 4)
	binary.LittleEndian.PutUint32(v, uint32(progFD))
	err = bpf.UpdateMapEntry(jumpMapFD, k, v)
	if err != nil {
		return errors.Wrap(err, "failed to update jump map")
	}
	return nil
}

func FindJumpMap(ap tc.AttachPoint) (bpf.MapFD, error) {
	tcCmd := exec.Command("tc", "filter", "show", "dev", ap.Iface, string(ap.Hook))
	out, err := tcCmd.Output()
	if err != nil {
		return 0, errors.Wrap(err, "failed to find TC filter for interface "+ap.Iface)
	}
	for _, line := range bytes.Split(out, []byte("\n")) {
		line := string(line)
		if strings.Contains(line, ap.Section) {
			re := regexp.MustCompile(`id (\d+)`)
			m := re.FindStringSubmatch(line)
			if len(m) > 0 {
				progIDStr := m[1]
				bpftool := exec.Command("bpftool", "prog", "show", "id", progIDStr, "--json")
				output, err := bpftool.Output()
				if err != nil {
					return 0, errors.Wrap(err, "failed to get map metadata")
				}
				var prog struct {
					MapIDs []int `json:"map_ids"`
				}
				err = json.Unmarshal(output, &prog)
				if err != nil {
					return 0, errors.Wrap(err, "failed to parse bpftool output")
				}

				for _, mapID := range prog.MapIDs {
					mapFD, err := bpf.GetMapFDByID(mapID)
					if err != nil {
						return 0, errors.Wrap(err, "failed to get map FD from ID")
					}
					mapInfo, err := bpf.GetMapInfo(mapFD)
					if err != nil {
						err = mapFD.Close()
						if err != nil {
							log.WithError(err).Panic("Failed to close FD.")
						}
						return 0, errors.Wrap(err, "failed to get map info")
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
	}
	ap := m.calculateTCAttachPoint(epType, polDirection, ifaceName)
	iface := m.ifaces[ifaceName]
	var addr net.IP
	if len(iface.addrs) > 0 {
		addr = iface.addrs[0]
	}
	return tc.AttachProgram(ap, addr)
}

// PolDirection is the Calico datamodel direction of policy.  On a host endpoint, ingress is towards the host.
// On a workload endpoint, ingress is towards the workload.
type PolDirection string

const (
	PolDirnIngress PolDirection = "ingress"
	PolDirnEgress  PolDirection = "egress"
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

	ap.Section = tc.SectionName(endpointType, toOrFrom)
	ap.Iface = ifaceName
	ap.Filename = tc.ProgFilename(endpointType, toOrFrom, m.epToHostDrop, m.fibLookupEnabled,
		m.dsrEnabled, m.bpfLogLevel)

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
