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
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/projectcalico/felix/ifacemonitor"

	"github.com/projectcalico/felix/bpf"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/felix/ip"
	"github.com/projectcalico/felix/proto"
	"github.com/projectcalico/libcalico-go/lib/set"
)

type bpfEndpointManager struct {
	// Caches.  Updated immediately for now.
	wlEps    map[proto.WorkloadEndpointID]*proto.WorkloadEndpoint
	policies map[proto.PolicyID]*proto.Policy
	profiles map[proto.ProfileID]*proto.Profile
	ifaces   map[string]ifacemonitor.State

	// Indexes
	policiesToWorkloads map[proto.PolicyID]set.Set  /*proto.WorkloadEndpointID*/
	profilesToWorkloads map[proto.ProfileID]set.Set /*proto.WorkloadEndpointID*/

	dirtyWorkloads set.Set
	dirtyIfaces    set.Set

	bpfLogLevel      string
	fibLookupEnabled bool
	dataIfaceRegex   *regexp.Regexp
}

func newBPFEndpointManager(bpfLogLevel string, fibLookupEnabled bool, dataIfaceRegex *regexp.Regexp) *bpfEndpointManager {
	return &bpfEndpointManager{
		wlEps:               map[proto.WorkloadEndpointID]*proto.WorkloadEndpoint{},
		policies:            map[proto.PolicyID]*proto.Policy{},
		profiles:            map[proto.ProfileID]*proto.Profile{},
		ifaces:              map[string]ifacemonitor.State{},
		policiesToWorkloads: map[proto.PolicyID]set.Set{},
		profilesToWorkloads: map[proto.ProfileID]set.Set{},
		dirtyWorkloads:      set.New(),
		dirtyIfaces:         set.New(),
		bpfLogLevel:         bpfLogLevel,
		fibLookupEnabled:    fibLookupEnabled,
		dataIfaceRegex:      dataIfaceRegex,
	}
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
	}
}

func (m *bpfEndpointManager) onInterfaceUpdate(update *ifaceUpdate) {
	if update.State == ifacemonitor.StateUnknown {
		delete(m.ifaces, update.Name)
	} else {
		m.ifaces[update.Name] = update.State
	}
	m.dirtyIfaces.Add(update.Name)
}

// onWorkloadEndpointUpdate adds/updates the workload in the cache along with the index from active policy to
// workloads using that policy.
func (m *bpfEndpointManager) onWorkloadEndpointUpdate(msg *proto.WorkloadEndpointUpdate) {
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
	m.policies[polID] = msg.Policy
	m.markPolicyUsersDirty(polID)
}

// onPolicyRemove removes the policy from the cache and marks any endpoints using it dirty.
// The latter should be a no-op due to the ordering guarantees of the calc graph.
func (m *bpfEndpointManager) onPolicyRemove(msg *proto.ActivePolicyRemove) {
	polID := *msg.Id
	m.markPolicyUsersDirty(polID)
	delete(m.policies, polID)
	delete(m.policiesToWorkloads, polID)
}

// onProfileUpdate stores the profile in the cache and marks any endpoints that use it as dirty.
func (m *bpfEndpointManager) onProfileUpdate(msg *proto.ActiveProfileUpdate) {
	profID := *msg.Id
	m.profiles[profID] = msg.Profile
	m.markProfileUsersDirty(profID)
}

// onProfileRemove removes the profile from the cache and marks any endpoints that were using it as dirty.
// The latter should be a no-op due to the ordering guarantees of the calc graph.
func (m *bpfEndpointManager) onProfileRemove(msg *proto.ActiveProfileRemove) {
	profID := *msg.Id
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

func findIPSetIDs(policy *proto.Policy) set.Set {
	if policy == nil {
		return set.Empty()
	}
	ids := set.New()
	for _, rules := range [][]*proto.Rule{policy.InboundRules, policy.OutboundRules} {
		for _, r := range rules {
			ids.AddAll(r.DstIpSetIds)
			ids.AddAll(r.DstNamedPortIpSetIds)
			ids.AddAll(r.SrcIpSetIds)
			ids.AddAll(r.SrcNamedPortIpSetIds)
			ids.AddAll(r.NotDstIpSetIds)
			ids.AddAll(r.NotDstNamedPortIpSetIds)
			ids.AddAll(r.NotSrcIpSetIds)
			ids.AddAll(r.NotSrcNamedPortIpSetIds)
		}
	}
	return ids
}

func (m *bpfEndpointManager) CompleteDeferredWork() error {
	m.applyProgramsToDirtyDataInterfaces()
	m.applyPolicyToAllDirtyEndpoints()

	// TODO: handle cali interfaces with no WEP
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
		if m.ifaces[iface] != ifacemonitor.StateUp {
			log.WithField("iface", iface).Debug(
				"Ignoring interface that is down")
			return set.RemoveItem
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			err := m.compileAndAttachDataIfaceProgram(iface)
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

func (m *bpfEndpointManager) applyPolicyToAllDirtyEndpoints() {
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

	// FIXME Avoid flapping the tc program and qdisc
	cmd := exec.Command("tc", "qdisc", "del", "dev", ifaceName, "clsact")
	_ = cmd.Run()
	cmd = exec.Command("tc", "qdisc", "add", "dev", ifaceName, "clsact")
	_ = cmd.Run()

	var ingressErr, egressErr error
	var wg sync.WaitGroup

	wg.Add(2)
	go func() {
		defer wg.Done()
		ingressErr = m.compileAndAttachWorkloadProgram(wep, "ingress")
	}()
	go func() {
		defer wg.Done()
		egressErr = m.compileAndAttachWorkloadProgram(wep, "egress")
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

func (m *bpfEndpointManager) compileAndAttachWorkloadProgram(endpoint *proto.WorkloadEndpoint, polDirection string) error {
	rules := m.extractRules(endpoint.Tiers, endpoint.ProfileIds, polDirection)
	ap := calculateTCAttachPoint("workload", polDirection, endpoint.Name)
	return m.compileAndAttachProgram(rules, ap)
}

func (m *bpfEndpointManager) compileAndAttachDataIfaceProgram(ifaceName string) error {
	return nil
}

type TCAttachPoint struct {
	Section string
	Hook    string
	Iface   string
}

func calculateTCAttachPoint(endpointType, policyDirection, ifaceName string) TCAttachPoint {
	var ap TCAttachPoint

	if endpointType == "workload" {
		// Policy direction is relative to the workload so, from the host namespace it's flipped.
		if policyDirection == "ingress" {
			ap.Hook = "egress"
		} else {
			ap.Hook = "ingress"
		}
	} else {
		// Host endpoints have the natural relationship between policy direction and hook.
		ap.Hook = policyDirection
	}

	var fromOrTo string
	if ap.Hook == "ingress" {
		fromOrTo = "from"
	} else {
		fromOrTo = "to"
	}

	ap.Section = fmt.Sprintf("calico_%s_%s_ep", fromOrTo, endpointType)
	ap.Iface = ifaceName

	return ap
}

func (m *bpfEndpointManager) extractRules(tiers2 []*proto.TierInfo, profileNames []string, direction string) [][][]*proto.Rule {
	var allRules [][][]*proto.Rule
	for _, tier := range tiers2 {
		var pols [][]*proto.Rule

		directionalPols := tier.IngressPolicies
		if direction == "egress" {
			directionalPols = tier.EgressPolicies
		}

		if len(directionalPols) == 0 {
			continue
		}

		for _, polName := range directionalPols {
			pol := m.policies[proto.PolicyID{Tier: tier.Name, Name: polName}]
			if direction == "ingress" {
				pols = append(pols, pol.InboundRules)
			} else {
				pols = append(pols, pol.OutboundRules)
			}
		}
		allRules = append(allRules, pols)
	}
	var profs [][]*proto.Rule
	for _, profName := range profileNames {
		prof := m.profiles[proto.ProfileID{Name: profName}]
		if direction == "ingress" {
			profs = append(profs, prof.InboundRules)
		} else {
			profs = append(profs, prof.OutboundRules)
		}
	}
	allRules = append(allRules, profs)
	return allRules
}

func (m *bpfEndpointManager) compileAndAttachProgram(allRules [][][]*proto.Rule, attachPoint TCAttachPoint) error {
	tempDir, err := ioutil.TempDir("", "calico-compile")
	if err != nil {
		log.WithError(err).Panic("Failed to make temporary directory")
	}
	defer func() {
		_ = os.RemoveAll(tempDir)
	}()
	oFileName := tempDir + "/redir_tc.o"
	logLevel := strings.ToUpper(m.bpfLogLevel)
	if logLevel == "" {
		logLevel = "OFF"
	}
	clang := exec.Command("clang",
		"-x", "c",
		"-D__KERNEL__",
		"-D__ASM_SYSREG_H",
		fmt.Sprintf("-DCALI_FIB_LOOKUP_ENABLED=%v", m.fibLookupEnabled),
		fmt.Sprintf("-DCALI_LOG_LEVEL=CALI_LOG_LEVEL_%s", logLevel),
		"-Wno-unused-value",
		"-Wno-pointer-sign",
		"-Wno-compare-distinct-pointer-types",
		"-Wunused",
		"-Wall",
		"-Werror",
		"-fno-stack-protector",
		"-O2",
		"-emit-llvm",
		"-c", "-", "-o", "-")
	clang.Dir = "/code/bpf/xdp"
	clangStdin, err := clang.StdinPipe()
	if err != nil {
		return err
	}
	clangStdout, err := clang.StdoutPipe()
	if err != nil {
		return err
	}
	clangStderr, err := clang.StderrPipe()
	if err != nil {
		return err
	}
	err = clang.Start()
	if err != nil {
		log.WithError(err).Panic("Failed to write C file.")
		return err
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(clangStderr)
		for scanner.Scan() {
			log.Warnf("clang stderr: %s", scanner.Text())
		}
		if err != nil {
			log.WithError(err).Error("Error while reading clang stderr")
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		pg := bpf.NewProgramGenerator(clangStdin)
		err = pg.WriteProgram(allRules)
		if err != nil {
			log.WithError(err).Panic("Failed to write C file.")
		}
		err = clangStdin.Close()
		if err != nil {
			log.WithError(err).Panic("Failed to write C file to clang stdin (Close() failed).")
		}
	}()
	llc := exec.Command("llc", "-march=bpf", "-filetype=obj", "-o", oFileName)
	llc.Stdin = clangStdout
	out, err := llc.CombinedOutput()
	if err != nil {
		log.WithError(err).WithField("out", string(out)).Error("Failed to compile C program (llc step)")
		return err
	}
	err = clang.Wait()
	if err != nil {
		log.WithError(err).Error("Clang failed.")
		return err
	}
	wg.Wait()
	// Hook is relative to the host rather than the endpoint so we need to flip it.
	tc := exec.Command("tc",
		"filter", "add", "dev", attachPoint.Iface,
		attachPoint.Hook,
		"bpf", "da", "obj", oFileName,
		"sec", attachPoint.Section)
	out, err = tc.CombinedOutput()
	if err != nil {
		var buf bytes.Buffer
		pg := bpf.NewProgramGenerator(&buf)
		err = pg.WriteProgram(allRules)
		if err != nil {
			log.WithError(err).Panic("Failed to write C file to buffer.")
		}

		log.WithError(err).WithFields(log.Fields{"out": string(out),
			"program": buf.String()}).WithField("command", tc).Error("Failed to attach BPF program")
		return err
	}
	return nil
}

func copyFile(from, to string) error {
	input, err := ioutil.ReadFile(from)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(to, input, 0644)
	if err != nil {
		return err
	}
	return nil
}

type ipSet struct {
	Members *ip.V4Trie
	Type    proto.IPSetUpdate_IPSetType
}

type ruleAccumulator struct {
	localIPs ip.V4Trie
	policy   ip.V4Trie

	ipSets map[string]ipSet

	ruleIdx uint64

	debug bool
}

func newRuleAccumulator(localCIDRs []string, ipSets map[string]ipSet) *ruleAccumulator {
	localIPTrie := ip.V4Trie{}
	for _, c := range localCIDRs {
		localIPTrie.Update(ip.MustParseCIDROrIP(c).(ip.V4CIDR), true)
	}
	return &ruleAccumulator{
		localIPs: localIPTrie,
		policy:   ip.V4Trie{},
		ipSets:   ipSets,
		debug:    log.GetLevel() >= log.DebugLevel,
	}
}

func (a ruleAccumulator) AddRule(rule *proto.Rule) {
	// First, check if this rule applies to this endpoint.
	// TODO cover egress policy too
	if a.debug {
		log.WithField("rule", rule).Debug("Processing rule...")
	}

	if rule.IpVersion == 6 {
		return
	}

	// Ingress policy so we only care about rules where the destination selects this endpoint.
	// Inline CIDRs:
	if len(rule.DstNet) > 0 {
		match := false
		for _, n := range rule.DstNet {
			cidr := ip.MustParseCIDROrIP(n).(ip.V4CIDR)
			if a.localIPs.Intersects(cidr) {
				if a.debug {
					log.WithField("cidr", cidr).Debug("Rule CIDR matched endpoint")
				}
				match = true
				break
			}
		}
		if !match {
			if a.debug {
				log.Debug("Rule CIDRs didn't match endpoint")
			}
			return
		}
	}
	if len(rule.NotDstNet) > 0 {
		for _, n := range rule.NotDstNet {
			cidr := ip.MustParseCIDROrIP(n).(ip.V4CIDR)
			if a.localIPs.CoveredBy(cidr) {
				if a.debug {
					log.Debug("Rule CIDRs didn't match endpoint")
				}
				return
			}
			// FIXME Incorrect if CIDR only covers some IPs of the workload?
		}
	}

	// IP sets.
	if len(rule.DstIpSetIds) > 0 {
		for _, ipSetID := range rule.DstIpSetIds {
			ipSet := a.ipSets[ipSetID]
			match := false
			a.localIPs.Visit(func(cidr ip.V4CIDR, data interface{}) bool {
				if ipSet.Members.Covers(cidr) {
					match = true
					return false
				}
				return true
			})
			if !match {
				if a.debug {
					log.Debug("Rule dest IP sets didn't match endpoint")
				}
				return
			}
		}
	}
	if len(rule.NotDstIpSetIds) > 0 {
		for _, ipSetID := range rule.NotDstIpSetIds {
			ipSet := a.ipSets[ipSetID]
			match := false
			a.localIPs.Visit(func(cidr ip.V4CIDR, data interface{}) bool {
				if ipSet.Members.Covers(cidr) {
					match = true
					return false
				}
				return true
			})
			if match {
				if a.debug {
					log.Debug("Rule not dest IP sets matched endpoint")
				}
				return
			}
		}
	}

	// If we get here, the rule applies to this endpoint.  Extract the parts of the rule that
	// are common to all sources and then put them into the trie at all allowed sources.
	if a.debug {
		log.Debug("Rule matches endpoint")
	}

	cr := CompactRule{
		indexFlagsAndProto: a.ruleIdx << indexShift,
	}

	switch rule.GetAction() {
	case "", "allow":
		cr.indexFlagsAndProto |= ruleFlagActionAllow
	case "deny":
		cr.indexFlagsAndProto |= ruleFlagActionDeny
	case "pass":
		cr.indexFlagsAndProto |= ruleFlagActionPass
	case "log":
		cr.indexFlagsAndProto |= ruleFlagActionLog
	}

	var protocol, negatedProtocol uint64
	if rule.Protocol != nil {
		protocol = uint64(protocolToNumber(rule.Protocol))
		cr.indexFlagsAndProto |= ruleFlagProto | protocol
	}
	if rule.NotProtocol != nil {
		negatedProtocol = uint64(protocolToNumber(rule.NotProtocol))
		if rule.Protocol != nil {
			if protocol == negatedProtocol {
				if a.debug {
					log.Debug("Rule had equal protocol and !protocol")
				}
				return
			}
		} else {
			cr.indexFlagsAndProto |= ruleFlagNotProto | negatedProtocol
		}
	}

	var extras []CompactRuleExtra
	if protocol == 6 || protocol == 17 {
		extras = simplifyPorts(rule.SrcPorts, rule.NotSrcPorts, extraFlagSrcPorts)
		extras = append(extras, simplifyPorts(rule.DstPorts, rule.NotDstPorts, extraFlagDstPorts)...)
	} else if protocol == 1 {
		if rule.Icmp != nil {
			// TODO
		}
	}

	a.ruleIdx++

	// Now, scan all the source IP sets and CIDRs and put it in the map...
	for _, cidrStr := range rule.SrcNet {
		a.insertRule(cidrStr, cr)
	}
	// TODO not src CIDRs

	// TODO handle positive IP set IDs
	// TODO handle negated IP set IDs
}

func (a ruleAccumulator) insertRule(cidrStr string, cr CompactRule) {
	cidr := ip.MustParseCIDROrIP(cidrStr).(ip.V4CIDR)
	existingRulesIface := a.policy.Get(cidr)
	var compactRules []CompactRule
	if existingRulesIface != nil {
		compactRules = existingRulesIface.([]CompactRule)
	}
	compactRules = append(compactRules, cr)
	a.policy.Update(cidr, compactRules)
}

func protocolToNumber(protocol *proto.Protocol) uint8 {
	var pcol uint8
	switch p := protocol.NumberOrName.(type) {
	case *proto.Protocol_Name:
		switch strings.ToLower(p.Name) {
		case "tcp":
			pcol = 6
		case "udp":
			pcol = 17
		case "icmp":
			pcol = 1
		case "sctp":
			pcol = 132
		}
	case *proto.Protocol_Number:
		pcol = uint8(p.Number)
	}
	return pcol
}

// protocol      1B
// not protocol  1B
// src ports     src/dst ranges 4B
// not src ports src/dst ranges 4B
// dst ports     src/dst ranges 4B
// not dst ports src/dst ranges 4B
// ICMP type/code 2B
// not ICMP type/code 2B

const (
	indexShift              = 16
	indexMask        uint64 = 0xffffffffffff0000
	ruleFlagProto           = 1 << 8
	ruleFlagNotProto        = 2 << 8

	ruleFlagActionAllow = 1 << 10
	ruleFlagActionDeny  = 2 << 10
	ruleFlagActionLog   = 3 << 10
	ruleFlagActionPass  = 4 << 10

	extraFlagSrcPorts = 1
	extraFlagDstPorts = 2
	extraFlagICMP     = 3
	extraFlagNotICMP  = 4
)

type CompactRule struct {
	indexFlagsAndProto uint64
	extras             []CompactRuleExtra
}

// Interpretation depends on type of rule.
type CompactRuleExtra struct {
	low, high uint16
	flags     uint8
}

func simplifyPorts(ports, negatedPorts []*proto.PortRange, flags uint8) []CompactRuleExtra {
	if len(ports) == 0 && len(negatedPorts) == 0 {
		return nil
	}
	if len(ports) == 0 {
		ports = []*proto.PortRange{{0, 65535}}
	}

	decisionPoints := make([]portDecisionPoint, 0, len(ports)*2+len(negatedPorts)*4)
	for _, p := range ports {
		decisionPoints = append(decisionPoints, portDecisionPoint{
			port:       uint16(p.First),
			endOfRange: false,
		})
		decisionPoints = append(decisionPoints, portDecisionPoint{
			port:       uint16(p.Last),
			endOfRange: true,
		})
	}
	for _, p := range negatedPorts {
		decisionPoints = append(decisionPoints, portDecisionPoint{
			port:       uint16(p.First),
			endOfRange: false,
			negated:    true,
		})
		decisionPoints = append(decisionPoints, portDecisionPoint{
			port:       uint16(p.Last),
			endOfRange: true,
			negated:    true,
		})
	}
	sort.Slice(decisionPoints, func(i, j int) bool {
		if decisionPoints[i].port < decisionPoints[j].port {
			return true
		}
		if decisionPoints[i].port > decisionPoints[j].port {
			return true
		}

		if decisionPoints[i].negated && !decisionPoints[j].negated {
			return true
		}
		if !decisionPoints[i].negated && decisionPoints[j].negated {
			return false
		}

		if !decisionPoints[i].endOfRange && decisionPoints[j].endOfRange {
			return true
		}

		return false
	})

	var extras []CompactRuleExtra
	var pos, neg int
	var lastPort uint16
	for _, d := range decisionPoints {
		if !d.negated && !d.endOfRange {
			pos++
			if pos == 1 && neg == 0 {
				lastPort = d.port
			}
		} else if !d.negated && d.endOfRange {
			pos--
			if pos == 0 && neg == 0 {
				extras = append(extras, CompactRuleExtra{
					low:   lastPort,
					high:  d.port,
					flags: flags,
				})
			}
		} else if d.negated && !d.endOfRange {
			neg++
			if neg == 1 {
				// Just entered a negative region.
				if pos > 0 {
					// Was previously in a positive region so this negative region ends the
					// positive one.
					extras = append(extras, CompactRuleExtra{
						low:   lastPort,
						high:  d.port,
						flags: flags,
					})
				}
			}
		} else {
			neg--
			if neg == 0 {
				// Negative region ends, see if we we return to a positive region.
				if pos > 0 {
					lastPort = d.port
				}
			}
		}
	}
	return extras
}

type portDecisionPoint struct {
	port       uint16
	endOfRange bool
	negated    bool
}
