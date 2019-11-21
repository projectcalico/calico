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
	"strings"
	"sync"
	"time"

	"github.com/projectcalico/felix/idalloc"

	"github.com/projectcalico/felix/ifacemonitor"

	"github.com/projectcalico/felix/bpf"

	log "github.com/sirupsen/logrus"

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
	ipSetIDAlloc     *idalloc.IDAllocator
}

func newBPFEndpointManager(bpfLogLevel string, fibLookupEnabled bool, dataIfaceRegex *regexp.Regexp, ipSetIDAlloc *idalloc.IDAllocator) *bpfEndpointManager {
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
		ipSetIDAlloc:        ipSetIDAlloc,
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

func (m *bpfEndpointManager) CompleteDeferredWork() error {
	m.applyProgramsToDirtyDataInterfaces()
	m.applyProgramsToDirtyWorkloadEndpoints()

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
			log.WithField("iface", iface).Debug("Ignoring interface that is down")
			return set.RemoveItem
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			m.ensureQdisc(iface)
			err := m.compileAndAttachDataIfaceProgram(iface, "ingress")
			if err == nil {
				err = m.compileAndAttachDataIfaceProgram(iface, "egress")
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

// EnsureQdisc makes sure that qdisc is attached to the given interface
func EnsureQdisc(ifaceName string) {
	// FIXME Avoid flapping the tc program and qdisc
	cmd := exec.Command("tc", "qdisc", "del", "dev", ifaceName, "clsact")
	_ = cmd.Run()
	cmd = exec.Command("tc", "qdisc", "add", "dev", ifaceName, "clsact")
	_ = cmd.Run()
}

func (m *bpfEndpointManager) ensureQdisc(ifaceName string) {
	EnsureQdisc(ifaceName)
}

func (m *bpfEndpointManager) compileAndAttachWorkloadProgram(endpoint *proto.WorkloadEndpoint, polDirection string) error {
	rules := m.extractRules(endpoint.Tiers, endpoint.ProfileIds, polDirection)
	if polDirection == "ingress" {
		// We define our policy model so that the host can always reach its workloads.
		// FIXME: make sure we don't accept SNATted packets here.
		log.Debug("Ingress workload policy, pre-pending allow-from-host rule")
		if len(rules) == 0 {
			rules = [][][]*proto.Rule{nil}
		}
		rules[0] = append([][]*proto.Rule{{{Action: "Allow", SrcIpSetIds: []string{SpecialIPSetIDHostIPs}}}}, rules[0]...)
	}
	ap := calculateTCAttachPoint("workload", polDirection, endpoint.Name)
	return m.compileAndAttachProgram(rules, ap)
}

func (m *bpfEndpointManager) compileAndAttachDataIfaceProgram(ifaceName string, polDirection string) error {
	rules := [][][]*proto.Rule{{{{Action: "Allow"}}}}
	epType := "host"
	if ifaceName == "tunl0" {
		epType = "tunnel"
	}
	ap := calculateTCAttachPoint(epType, polDirection, ifaceName)
	return m.compileAndAttachProgram(rules, ap)
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
	srcDir := "/code/bpf/xdp"
	srcFileName := srcDir + "/redir_tc.c"
	oFileName := tempDir + "/redir_tc.o"
	logLevel := strings.ToUpper(m.bpfLogLevel)
	if logLevel == "" {
		logLevel = "OFF"
	}

	logPfx := os.Getenv("BPF_LOG_PFX") + attachPoint.Iface

	err = CompileTCProgramToFile(allRules,
		m.ipSetIDAlloc,
		CompileWithWorkingDir(srcDir),
		CompileWithSourceName(srcFileName),
		CompileWithOutputName(oFileName),
		CompileWithFIBEnabled(m.fibLookupEnabled),
		CompileWithLogLevel(logLevel),
		CompileWithLogPrefix(logPfx),
	)
	if err != nil {
		return err
	}

	err = AttachTCProgram(oFileName, attachPoint)
	if err != nil {
		var buf bytes.Buffer
		pg, err := bpf.NewProgramGenerator(srcFileName, m.ipSetIDAlloc)
		if err != nil {
			log.WithError(err).Panic("Failed to write get code generator.")
		}
		err = pg.WriteProgram(&buf, allRules)
		if err != nil {
			log.WithError(err).Panic("Failed to write C file to buffer.")
		}

		log.WithError(err).WithFields(log.Fields{"program": buf.String()}).
			Error("Failed BPF program")
		return err
	}
	return nil
}

// AttachTCProgram attaches a BPF program froma file to the TC attach point
func AttachTCProgram(fname string, attachPoint TCAttachPoint) error {
	// Hook is relative to the host rather than the endpoint so we need to flip it.
	tc := exec.Command("tc",
		"filter", "add", "dev", attachPoint.Iface,
		attachPoint.Hook,
		"bpf", "da", "obj", fname,
		"sec", attachPoint.Section)

	out, err := tc.CombinedOutput()
	if err != nil {
		if bytes.Contains(out, []byte("Cannot find device")) {
			// Avoid a big, spammy log when the issue is that the interface isn't present.
			log.WithField("iface", attachPoint.Iface).Warn(
				"Failed to attach BPF program; interface not found.  Will retry if it show up.")
			return nil
		}
		log.WithError(err).WithFields(log.Fields{"out": string(out)}).
			WithField("command", tc).Error("Failed to attach BPF program")
	}

	return err
}

// CompileTCOption specifies additional compile options for TC programs
type CompileTCOption func(interface{})

type compileTCOpts struct {
	extraArgs []string
	dir       string
	srcFile   string
	outFile   string
	bpftool   bool
}

func (o *compileTCOpts) appendExtraArg(a string) {
	o.extraArgs = append(o.extraArgs, a)
}

// CompileWithFIBEnabled sets whether FIB lookup is allowed
func CompileWithFIBEnabled(enabled bool) CompileTCOption {
	return func(opts interface{}) {
		opts.(*compileTCOpts).appendExtraArg(fmt.Sprintf("-DCALI_FIB_LOOKUP_ENABLED=%v", enabled))
	}
}

// CompileWithLogLevel sets the log level of the resulting program
func CompileWithLogLevel(level string) CompileTCOption {
	return func(opts interface{}) {
		opts.(*compileTCOpts).appendExtraArg(fmt.Sprintf("-DCALI_LOG_LEVEL=CALI_LOG_LEVEL_%s", level))
	}
}

// CompileWithLogPrefix sets a specific log prefix for the resulting program
func CompileWithLogPrefix(prefix string) CompileTCOption {
	return func(opts interface{}) {
		opts.(*compileTCOpts).appendExtraArg(fmt.Sprintf("-DCALI_LOG_PFX=%v", prefix))
	}
}

// CompileWithSourceName sets the source file name
func CompileWithSourceName(f string) CompileTCOption {
	return func(opts interface{}) {
		opts.(*compileTCOpts).srcFile = f
	}
}

// CompileWithOutputName sets the output name
func CompileWithOutputName(f string) CompileTCOption {
	return func(opts interface{}) {
		opts.(*compileTCOpts).outFile = f
	}
}

// CompileWithWorkingDir sets the working directory
func CompileWithWorkingDir(dir string) CompileTCOption {
	return func(opts interface{}) {
		opts.(*compileTCOpts).dir = dir
	}
}

func CompileWithBpftoolLoader() CompileTCOption {
	return func(opts interface{}) {
		opts.(*compileTCOpts).bpftool = true
	}
}

// CompileTCProgramToFile takes policy rules and compiles them into a tc-bpf
// program and saves it into the provided file. Extra CFLAGS can be provided
func CompileTCProgramToFile(allRules [][][]*proto.Rule, ipSetIDAlloc *idalloc.IDAllocator, opts ...CompileTCOption) error {
	compileOpts := compileTCOpts{
		srcFile: "/code/bpf/xdp/redir_tc.c",
		outFile: "/tmp/redir_tc.o",
		dir:     "/code/bpf/xdp",
	}

	for _, o := range opts {
		o(&compileOpts)
	}

	args := []string{
		"-x",
		"c",
		"-D__KERNEL__",
		"-D__ASM_SYSREG_H",
	}

	if compileOpts.bpftool {
		args = append(args, "-D__BPFTOOL_LOADER__")
	}

	args = append(args, compileOpts.extraArgs...)

	args = append(args, []string{
		"-Wno-unused-value",
		"-Wno-pointer-sign",
		"-Wno-compare-distinct-pointer-types",
		"-Wunused",
		"-Wall",
		"-Werror",
		"-fno-stack-protector",
		"-O2",
		"-emit-llvm",
		"-c", "-", "-o", "-",
	}...)

	clang := exec.Command("clang", args...)
	clang.Dir = compileOpts.dir
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
		pg, err := bpf.NewProgramGenerator(compileOpts.srcFile, ipSetIDAlloc)
		if err != nil {
			log.WithError(err).Panic("Failed to create code generator")
		}
		err = pg.WriteProgram(clangStdin, allRules)
		if err != nil {
			log.WithError(err).Panic("Failed to write C file.")
		}
		err = clangStdin.Close()
		if err != nil {
			log.WithError(err).Panic("Failed to write C file to clang stdin (Close() failed).")
		}
	}()
	llc := exec.Command("llc", "-march=bpf", "-filetype=obj", "-o", compileOpts.outFile)
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

	return nil
}
