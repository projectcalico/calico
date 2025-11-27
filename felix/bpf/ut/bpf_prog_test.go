// Copyright (c) 2020-2025 Tigera, Inc. All rights reserved.
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

package ut_test

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"
	"github.com/onsi/gomega/types"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/bpf/arp"
	"github.com/projectcalico/calico/felix/bpf/conntrack"
	"github.com/projectcalico/calico/felix/bpf/counters"
	"github.com/projectcalico/calico/felix/bpf/failsafes"
	"github.com/projectcalico/calico/felix/bpf/hook"
	"github.com/projectcalico/calico/felix/bpf/ifstate"
	"github.com/projectcalico/calico/felix/bpf/ipfrags"
	"github.com/projectcalico/calico/felix/bpf/ipsets"
	"github.com/projectcalico/calico/felix/bpf/jump"
	"github.com/projectcalico/calico/felix/bpf/libbpf"
	"github.com/projectcalico/calico/felix/bpf/maps"
	"github.com/projectcalico/calico/felix/bpf/nat"
	"github.com/projectcalico/calico/felix/bpf/perf"
	"github.com/projectcalico/calico/felix/bpf/polprog"
	"github.com/projectcalico/calico/felix/bpf/profiling"
	"github.com/projectcalico/calico/felix/bpf/qos"
	"github.com/projectcalico/calico/felix/bpf/routes"
	"github.com/projectcalico/calico/felix/bpf/state"
	tcdefs "github.com/projectcalico/calico/felix/bpf/tc/defs"
	"github.com/projectcalico/calico/felix/environment"
	"github.com/projectcalico/calico/felix/idalloc"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/logutils"
	"github.com/projectcalico/calico/felix/proto"
)

var canTestMarks bool

func init() {
	logutils.ConfigureEarlyLogging()
	log.SetLevel(log.DebugLevel)

	fd := environment.NewFeatureDetector(make(map[string]string))
	if ok, err := fd.KernelIsAtLeast("5.9.0"); err == nil && ok {
		canTestMarks = true
	}
}

// Constants that are shared with the UT binaries that we build.
const (
	natTunnelMTU      = uint16(700)
	testVxlanPort     = uint16(5665)
	testMaglevLUTSize = uint32(31)
)

var (
	rulesDefaultAllow = &polprog.Rules{
		Tiers: []polprog.Tier{{
			Name: "base tier",
			Policies: []polprog.Policy{{
				Name:  "allow all",
				Rules: []polprog.Rule{{Rule: &proto.Rule{Action: "Allow"}}},
			}},
		}},
	}
	node1ip    = net.IPv4(10, 10, 0, 1).To4()
	node1ip2   = net.IPv4(10, 10, 2, 1).To4()
	node1tunIP = net.IPv4(11, 11, 0, 1).To4()
	node2ip    = net.IPv4(10, 10, 0, 2).To4()
	node3ip    = net.IPv4(10, 10, 0, 3).To4()
	node3tunIP = net.IPv4(11, 11, 0, 3).To4()
	intfIP     = net.IPv4(10, 10, 0, 3).To4()
	node1CIDR  = net.IPNet{
		IP:   node1ip,
		Mask: net.IPv4Mask(255, 255, 255, 255),
	}
	node2CIDR = net.IPNet{
		IP:   node2ip,
		Mask: net.IPv4Mask(255, 255, 255, 255),
	}
	node3CIDR = net.IPNet{
		IP:   node3ip,
		Mask: net.IPv4Mask(255, 255, 255, 255),
	}

	node1ipV6    = net.ParseIP("abcd::ffff:0a0a:0001").To16()
	node1ip2V6   = net.ParseIP("abcd::ffff:0a0a:0201").To16()
	node1tunIPV6 = net.ParseIP("abcd::ffff:0b0b:0001").To16()
	node2ipV6    = net.ParseIP("abcd::ffff:0a0a:0002").To16()
	node3ipV6    = net.ParseIP("abcd::ffff:0a0a:0004").To16()
	node3tunIPV6 = net.ParseIP("abcd::ffff:0b0b:0004").To16()
	intfIPV6     = net.ParseIP("abcd::ffff:0a0a:0003").To16()
	node1CIDRV6  = net.IPNet{
		IP:   node1ipV6,
		Mask: net.CIDRMask(128, 128),
	}
	node2CIDRV6 = net.IPNet{
		IP:   node2ipV6,
		Mask: net.CIDRMask(128, 128),
	}
	node3CIDRV6 = net.IPNet{
		IP:   node3ipV6,
		Mask: net.CIDRMask(128, 128),
	}
)

// Globals that we use to configure the next test run.
var (
	hostIP       = node1ip
	skbMark      uint32
	bpfIfaceName string
)

const (
	resTC_ACT_OK int = iota
	resTC_ACT_RECLASSIFY
	resTC_ACT_SHOT
	resTC_ACT_PIPE
	resTC_ACT_STOLEN
	resTC_ACT_QUEUED
	resTC_ACT_REPEAT
	resTC_ACT_REDIRECT
	resTC_ACT_UNSPEC = (1 << 32) - 1
)

var retvalToStr = map[int]string{
	resTC_ACT_OK:         "TC_ACT_OK",
	resTC_ACT_RECLASSIFY: "TC_ACT_RECLASSIFY",
	resTC_ACT_SHOT:       "TC_ACT_SHOT",
	resTC_ACT_PIPE:       "TC_ACT_PIPE",
	resTC_ACT_STOLEN:     "TC_ACT_STOLEN",
	resTC_ACT_QUEUED:     "TC_ACT_QUEUED",
	resTC_ACT_REPEAT:     "TC_ACT_REPEAT",
	resTC_ACT_REDIRECT:   "TC_ACT_REDIRECT",
	resTC_ACT_UNSPEC:     "TC_ACT_UNSPEC",
}

const (
	resXDP_ABORTED int = iota
	resXDP_DROP
	resXDP_PASS
)

var retvalToStrXDP = map[int]string{
	resXDP_ABORTED: "XDP_ABORTED",
	resXDP_PASS:    "XDP_PASS",
	resXDP_DROP:    "XDP_DROP",
}

func expectMark(expect int) {
	if canTestMarks {
		ExpectWithOffset(1, skbMark).To(Equal(uint32(expect)),
			fmt.Sprintf("skbMark 0x%08x should be 0x%08x at %s", skbMark, expect, caller(2)))
	} else {
		// If we cannot verify the mark, set it to the expected value as the
		// next stage expects it to be set.
		skbMark = uint32(expect)
	}
}

var xdpJumpMapIndexes = map[string]map[int]string{
	"IPv4": map[int]string{
		tcdefs.ProgIndexMain:    "calico_xdp_main",
		tcdefs.ProgIndexPolicy:  "calico_xdp_norm_pol_tail",
		tcdefs.ProgIndexAllowed: "calico_xdp_accepted_entrypoint",
		tcdefs.ProgIndexDrop:    "calico_xdp_drop",
	},
	"IPv4 debug": map[int]string{
		tcdefs.ProgIndexMain:    "calico_xdp_main",
		tcdefs.ProgIndexPolicy:  "calico_xdp_norm_pol_tail",
		tcdefs.ProgIndexAllowed: "calico_xdp_accepted_entrypoint",
		tcdefs.ProgIndexDrop:    "calico_xdp_drop",
	},
	"IPv6": map[int]string{
		tcdefs.ProgIndexMain:    "calico_xdp_main",
		tcdefs.ProgIndexPolicy:  "calico_xdp_norm_pol_tail",
		tcdefs.ProgIndexAllowed: "calico_xdp_accepted_entrypoint",
		tcdefs.ProgIndexDrop:    "calico_xdp_drop",
	},
	"IPv6 debug": map[int]string{
		tcdefs.ProgIndexMain:    "calico_xdp_main",
		tcdefs.ProgIndexPolicy:  "calico_xdp_norm_pol_tail",
		tcdefs.ProgIndexAllowed: "calico_xdp_accepted_entrypoint",
		tcdefs.ProgIndexDrop:    "calico_xdp_drop",
	},
}

var tcJumpMapIndexes = map[string][]int{
	"IPv4": []int{
		tcdefs.ProgIndexMain,
		tcdefs.ProgIndexPolicy,
		tcdefs.ProgIndexAllowed,
		tcdefs.ProgIndexIcmp,
		tcdefs.ProgIndexDrop,
		tcdefs.ProgIndexHostCtConflict,
		tcdefs.ProgIndexIcmpInnerNat,
		tcdefs.ProgIndexNewFlow,
		tcdefs.ProgIndexIPFrag,
		tcdefs.ProgIndexMaglev,
	},
	"IPv4 debug": []int{
		tcdefs.ProgIndexMainDebug,
		tcdefs.ProgIndexPolicyDebug,
		tcdefs.ProgIndexAllowedDebug,
		tcdefs.ProgIndexIcmpDebug,
		tcdefs.ProgIndexDropDebug,
		tcdefs.ProgIndexHostCtConflictDebug,
		tcdefs.ProgIndexIcmpInnerNatDebug,
		tcdefs.ProgIndexNewFlowDebug,
		tcdefs.ProgIndexIPFragDebug,
		tcdefs.ProgIndexMaglevDebug,
	},
	"IPv6": []int{
		tcdefs.ProgIndexMain,
		tcdefs.ProgIndexPolicy,
		tcdefs.ProgIndexAllowed,
		tcdefs.ProgIndexIcmp,
		tcdefs.ProgIndexDrop,
		tcdefs.ProgIndexHostCtConflict,
		tcdefs.ProgIndexIcmpInnerNat,
		tcdefs.ProgIndexNewFlow,
		tcdefs.ProgIndexMaglev,
	},
	"IPv6 debug": []int{
		tcdefs.ProgIndexMainDebug,
		tcdefs.ProgIndexPolicyDebug,
		tcdefs.ProgIndexAllowedDebug,
		tcdefs.ProgIndexIcmpDebug,
		tcdefs.ProgIndexDropDebug,
		tcdefs.ProgIndexHostCtConflictDebug,
		tcdefs.ProgIndexIcmpInnerNatDebug,
		tcdefs.ProgIndexNewFlowDebug,
		tcdefs.ProgIndexMaglevDebug,
	},
}

func TestCompileTemplateRun(t *testing.T) {
	skbMark = tcdefs.MarkSeen
	runBpfTest(t, "calico_to_workload_ep", &polprog.Rules{}, func(bpfrun bpfProgRunFn) {
		_, _, _, _, pktBytes, err := testPacketUDPDefault()
		Expect(err).NotTo(HaveOccurred())

		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())

		// Implicitly denied by normal policy: DROP
		Expect(res.Retval).To(Equal(resTC_ACT_SHOT))
	})
}

func TestLoadZeroProgram(t *testing.T) {
	RegisterTestingT(t)
	fd, err := bpf.LoadBPFProgramFromInsns(nil, "calico_policy", "Apache-2.0", unix.BPF_PROG_TYPE_SCHED_CLS)
	if err == nil {
		_ = fd.Close()
	}
	Expect(err).To(Equal(unix.E2BIG))
}

type testLogger interface {
	Log(args ...interface{})
	Logf(format string, args ...interface{})
}

func startBPFLogging() *exec.Cmd {
	cmd := exec.Command("/usr/bin/bpftool", "prog", "tracelog")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Start()
	if err != nil {
		log.WithError(err).Warn("Failed to start bpf log collection")
		return nil
	}
	return cmd
}

func stopBPFLogging(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	err := cmd.Process.Signal(syscall.SIGTERM)
	if err != nil {
		log.WithError(err).Warn("Failed to send SIGTERM to bpftool")
		return
	}
	err = cmd.Wait()
	if err != nil {
		log.WithError(err).Warn("Failed to wait for bpftool")
	}
}

func setupAndRun(logger testLogger, loglevel, section string, rules *polprog.Rules,
	runFn func(progName string), opts ...testOption) {
	topts := testOpts{
		subtests:  true,
		logLevel:  log.DebugLevel,
		psnaStart: 20000,
		psnatEnd:  30000,
		dscp:      -1,
	}

	for _, o := range opts {
		o(&topts)
	}

	tempDir, err := os.MkdirTemp("", "calico-bpf-")
	Expect(err).NotTo(HaveOccurred())
	defer os.RemoveAll(tempDir)

	unique := path.Base(tempDir)
	bpfFsDir := "/sys/fs/bpf/" + unique

	err = os.Mkdir(bpfFsDir, os.ModePerm)
	Expect(err).NotTo(HaveOccurred())
	defer os.RemoveAll(bpfFsDir)

	err = os.Mkdir(bpfFsDir+"_v6", os.ModePerm)
	Expect(err).NotTo(HaveOccurred())
	defer os.RemoveAll(bpfFsDir + "v6")

	obj := "../../bpf-gpl/bin/test_xdp_debug"
	if !topts.xdp {
		obj = "../../bpf-gpl/bin/test_"
		if strings.Contains(section, "from") {
			obj += "from_"
		} else {
			obj += "to_"
		}

		if strings.Contains(section, "host") {
			obj += "hep_"
			topts.progLog = "HEP"
		} else if strings.Contains(section, "nat") {
			obj += "nat_"
			topts.progLog = "NAT"
		} else if strings.Contains(section, "wireguard") {
			obj += "wg_"
			topts.progLog = "WG"
		} else {
			obj += "wep_"
			topts.progLog = "WEP"
		}

		if topts.ipv6 {
			log.WithField("hostIP", hostIP).Info("Host IP")
			log.WithField("intfIP", intfIPV6).Info("Intf IP")
		} else {
			log.WithField("hostIP", hostIP).Info("Host IP")
			log.WithField("intfIP", intfIP).Info("Intf IP")
		}
		obj += loglevel

		if strings.Contains(section, "_dsr") {
			obj += "_dsr"
		}
	}

	ipFamily := "IPv4"
	policyIdx := tcdefs.ProgIndexPolicy
	if topts.ipv6 {
		ipFamily = "IPv6"
	}

	if topts.objname != "" {
		obj = topts.objname
	} else {
		obj += "_co-re"
		if topts.ipv6 {
			obj += "_v6"
		}
	}

	useIngressProgMap := strings.Contains(obj, "from_")
	if topts.xdp {
		o, err := objLoad("../../bpf-gpl/bin/xdp_preamble.o", bpfFsDir, "preamble", topts, false, false, false, false)
		Expect(err).NotTo(HaveOccurred())
		defer o.Close()
	} else {
		fileToLoad := "../../bpf-gpl/bin/tc_preamble_egress.o"
		if useIngressProgMap {
			fileToLoad = "../../bpf-gpl/bin/tc_preamble_ingress.o"
		}
		o, err := objLoad(fileToLoad, bpfFsDir, "preamble", topts, false, false, false, useIngressProgMap)
		Expect(err).NotTo(HaveOccurred())
		defer o.Close()
	}

	if loglevel == "debug" {
		ipFamily += " debug"
	}

	hasMaglev := strings.Contains(obj, "from_hep")
	obj += ".o"
	o, err := objLoad(obj, bpfFsDir, ipFamily, topts, rules != nil, true, hasMaglev, useIngressProgMap)
	Expect(err).NotTo(HaveOccurred())
	defer o.Close()

	if rules != nil {
		staticProgMap := progMap[hook.Egress]
		if useIngressProgMap {
			staticProgMap = progMap[hook.Ingress]
		}
		polMap := policyJumpMap
		popts := []polprog.Option{}
		stride := jump.TCMaxEntryPoints
		if topts.xdp {
			staticProgMap = progMapXDP
			polMap = policyJumpMapXDP
			popts = append(popts,
				polprog.WithAllowDenyJumps(tcdefs.ProgIndexAllowed, tcdefs.ProgIndexDrop),
				polprog.WithPolicyMapIndexAndStride(policyIdx, jump.XDPMaxEntryPoints),
			)
			if topts.ipv6 {
				popts = append(popts, polprog.WithIPv6())
			}
			stride = jump.XDPMaxEntryPoints
		} else {
			popts = append(popts,
				polprog.WithPolicyMapIndexAndStride(policyIdx, jump.TCMaxEntryPoints),
			)
		}
		if topts.flowLogsEnabled {
			popts = append(popts, polprog.WithFlowLogs())
		}
		alloc := &forceAllocator{alloc: idalloc.New()}
		ipsMapFD := ipsMap.MapFD()
		Expect(ipsMapFD).NotTo(BeZero())
		stateMapFD := stateMap.MapFD()
		Expect(stateMapFD).NotTo(BeZero())
		pg := polprog.NewBuilder(alloc, ipsMapFD, stateMapFD, staticProgMap.MapFD(), polMap.MapFD(), popts...)
		insns, err := pg.Instructions(*rules)
		Expect(err).NotTo(HaveOccurred())

		var polProgFDs []bpf.ProgFD
		defer func() {
			var errs []error
			for _, polProgFD := range polProgFDs {
				err := polProgFD.Close()
				if err != nil {
					errs = append(errs, err)
				}
			}
			Expect(errs).To(BeEmpty())
		}()
		var progType uint32
		if topts.xdp {
			progType = unix.BPF_PROG_TYPE_XDP
		} else {
			progType = unix.BPF_PROG_TYPE_SCHED_CLS
		}
		for i, p := range insns {
			polProgFD, err := bpf.LoadBPFProgramFromInsns(p, "calico_policy", "Apache-2.0", progType)
			Expect(err).NotTo(HaveOccurred(), "failed to load program into the kernel")
			Expect(polProgFD).NotTo(BeZero())
			polProgFDs = append(polProgFDs, polProgFD)
			err = polMap.Update(
				jump.Key(polprog.SubProgramJumpIdx(policyIdx, i, stride)),
				jump.Value(polProgFD.FD()),
			)
			Expect(err).NotTo(HaveOccurred())
		}
		log.WithField("rules", rules).Debug("set policy")
	}

	if !topts.xdp {
		_ = counters.EnsureExists(countersMap, 1, hook.Ingress)
		_ = counters.EnsureExists(countersMap, 1, hook.Egress)
		runFn(bpfFsDir + "/cali_tc_preamble")
	} else {
		_ = counters.EnsureExists(countersMap, 1, hook.XDP)
		runFn(bpfFsDir + "/cali_xdp_preamble")
	}
}

func caller(skip int) string {
	_, f, l, ok := runtime.Caller(skip)
	if ok {
		return fmt.Sprintf("%s:%d", f, l)
	}

	return "<unknown>"
}

// runBpfTest runs a specific section of the entire bpf program in isolation
func runBpfTest(t *testing.T, section string, rules *polprog.Rules, testFn func(bpfProgRunFn), opts ...testOption) {
	RegisterTestingT(t)
	xdp := strings.Contains(section, "xdp")

	ctxIn := make([]byte, 18*4)
	binary.LittleEndian.PutUint32(ctxIn[2*4:3*4], skbMark)
	if xdp {
		// XDP tests cannot take context and would fail.
		ctxIn = nil
	}

	topts := testOpts{}

	for _, o := range opts {
		o(&topts)
	}

	cllr := caller(2)

	setupAndRun(t, "debug", section, rules, func(progName string) {
		label := section
		if topts.description != "" {
			label = topts.description + " - " + section
		}
		t.Run(label, func(_ *testing.T) {
			if strings.Contains(section, "calico_from_") {
				ExpectWithOffset(2, skbMark).To(Equal(uint32(0)),
					fmt.Sprintf("skb mark 0x%08x should be zero at %s", skbMark, cllr))
			}
			if !topts.hostNetworked && !topts.fromHost && strings.Contains(section, "calico_to_") {
				ExpectWithOffset(2, skbMark&uint32(tcdefs.MarkSeen) != 0).
					To(BeTrue(), fmt.Sprintf("skb mark 0x%08x does not have tcdefs.MarkSeen 0x%08x set before tc at %s",
						skbMark, tcdefs.MarkSeen, cllr))
			}

			testFn(func(dataIn []byte) (bpfRunResult, error) {
				res, err := bpftoolProgRun(progName, dataIn, ctxIn)
				log.Debugf("dataIn  = %+v", dataIn)
				if err == nil {
					log.Debugf("dataOut = %+v", res.dataOut)
				}

				if res.Retval != resTC_ACT_SHOT && canTestMarks && strings.Contains(section, "calico_from_") {
					ExpectWithOffset(3, skbMark&uint32(tcdefs.MarkSeen) != 0).
						To(BeTrue(), fmt.Sprintf("skb mark 0x%08x does not have tcdefs.MarkSeen 0x%08x set after tc at %s",
							skbMark, tcdefs.MarkSeen, cllr))
				}

				return res, err
			})
		})
	}, opts...)
}

type forceAllocator struct {
	alloc *idalloc.IDAllocator
}

func (a *forceAllocator) GetNoAlloc(id string) uint64 {
	return a.alloc.GetOrAlloc(id)
}

func bpftool(args ...string) ([]byte, error) {
	args = append([]string{"--json", "--pretty"}, args...)
	cmd := exec.Command("bpftool", args...)
	log.WithField("cmd", cmd.String()).Debugf("executing")
	out, err := cmd.Output()
	if err != nil {
		if e, ok := err.(*exec.ExitError); ok {
			log.WithField("stderr", string(e.Stderr)).Errorf("bpftool %s failed: %v out=\n%v", args, err, string(out))
			// to make the output reflect the new lines, logrus ignores it
			fmt.Print(fmt.Sprint(string(e.Stderr)))
		}
	}

	return out, err
}

var (
	mapInitOnce sync.Once

	natMap, natBEMap, ctMap, ctCleanupMap, rtMap, ipsMap, testStateMap, affinityMap, arpMap, fsafeMap, ipfragsMap, maglevMap maps.Map
	natMapV6, natBEMapV6, ctMapV6, ctCleanupMapV6, rtMapV6, ipsMapV6, affinityMapV6, arpMapV6, fsafeMapV6, maglevMapV6       maps.Map
	stateMap, countersMap, ifstateMap, progMapXDP, policyJumpMap, policyJumpMapXDP                                           maps.Map
	perfMap                                                                                                                  maps.Map
	profilingMap, ipfragsMapTmp                                                                                              maps.Map
	qosMap                                                                                                                   maps.Map
	ctlbProgsMap                                                                                                             []maps.Map
	progMap                                                                                                                  []maps.Map
	allMaps                                                                                                                  []maps.Map
)

func initMapsOnce() {
	mapInitOnce.Do(func() {
		natMap = nat.FrontendMap()
		natBEMap = nat.BackendMap()
		natMapV6 = nat.FrontendMapV6()
		natBEMapV6 = nat.BackendMapV6()
		ctMap = conntrack.Map()
		ctMapV6 = conntrack.MapV6()
		ctCleanupMap = conntrack.CleanupMap()
		ctCleanupMapV6 = conntrack.CleanupMapV6()
		rtMap = routes.Map()
		rtMapV6 = routes.MapV6()
		ipsMap = ipsets.Map()
		ipsMapV6 = ipsets.MapV6()
		stateMap = state.Map()
		testStateMap = state.MapForTest()
		affinityMap = nat.AffinityMap()
		affinityMapV6 = nat.AffinityMapV6()
		arpMap = arp.Map()
		arpMapV6 = arp.MapV6()
		fsafeMap = failsafes.Map()
		fsafeMapV6 = failsafes.MapV6()
		countersMap = counters.Map()
		ipfragsMap = ipfrags.Map()
		ipfragsMapTmp = ipfrags.MapTmp()
		ifstateMap = ifstate.Map()
		policyJumpMap = jump.Map()
		policyJumpMapXDP = jump.XDPMap()
		profilingMap = profiling.Map()
		ctlbProgsMap = nat.ProgramsMaps()
		progMap = hook.NewProgramsMaps()
		qosMap = qos.Map()
		maglevMap = nat.MaglevMap()
		maglevMapV6 = nat.MaglevMapV6()

		perfMap = perf.Map("perf_evnt", 512)

		allMaps = []maps.Map{natMap, natBEMap, natMapV6, natBEMapV6, ctMap, ctMapV6, ctCleanupMap, ctCleanupMapV6, rtMap, rtMapV6, ipsMap, ipsMapV6,
			stateMap, testStateMap, affinityMap, affinityMapV6, arpMap, arpMapV6, fsafeMap, fsafeMapV6,
			countersMap, ipfragsMap, ipfragsMapTmp, ifstateMap, profilingMap,
			policyJumpMap, policyJumpMapXDP, ctlbProgsMap[0], ctlbProgsMap[1], ctlbProgsMap[2], qosMap, maglevMap, maglevMapV6}
		for _, m := range allMaps {
			err := m.EnsureExists()
			if err != nil {
				log.WithError(err).Panic("Failed to initialise maps")
			}
		}

		err := perfMap.EnsureExists()
		if err != nil {
			log.WithError(err).Panic("Failed to initialise perfMap")
		}

	})
}

func cleanUpMaps() {
	log.Info("Cleaning up all maps")

	logLevel := log.GetLevel()
	log.SetLevel(log.InfoLevel)
	defer log.SetLevel(logLevel)

	for _, m := range allMaps {
		if m == stateMap || m == testStateMap || m == progMap[hook.Ingress] || m == progMap[hook.Egress] || m == countersMap || m == ipfragsMapTmp {
			continue // Can't clean up array maps
		}
		log.WithField("map", m.GetName()).Info("Cleaning")
		err := m.Iter(func(_, _ []byte) maps.IteratorAction {
			return maps.IterDelete
		})
		if err != nil {
			if errors.Is(err, maps.ErrNotSupported) {
				continue
			}
			log.WithError(err).Panic("Failed to walk map")
		}
	}
	log.Info("Cleaned up all maps")
}

func jumpMapUpdatePinned(jm maps.Map, idx int, val string) error {
	out, err := bpftool("map", "update", "pinned", jm.Path(),
		"key", fmt.Sprintf("%d", idx), "0", "0", "0", "value", "pinned", val)

	if err != nil {
		return fmt.Errorf("%s\n%w", string(out), err)
	}

	return nil
}

func jumpMapUpdate(jm maps.Map, idx int, val int) error {
	var k, v [4]byte

	binary.LittleEndian.PutUint32(k[:], uint32(idx))
	binary.LittleEndian.PutUint32(v[:], uint32(val))

	return jm.Update(k[:], v[:])
}

func jumpMapDelete(jm maps.Map, idx int) error {
	var k [4]byte

	binary.LittleEndian.PutUint32(k[:], uint32(idx))

	return jm.Delete(k[:])
}

func ipToU32(ip net.IP) uint32 {
	ip = ip.To4()
	return binary.LittleEndian.Uint32([]byte(ip[:]))
}

func tcUpdateJumpMap(obj *libbpf.Obj, progs []int, hasPolicyProg, hasHostConflictProg, hasMaglev, useIngressProgMap bool) error {
	for _, idx := range progs {
		switch idx {
		case
			tcdefs.ProgIndexPolicy,
			tcdefs.ProgIndexPolicyDebug:

			if !hasPolicyProg {
				continue
			}
		case
			tcdefs.ProgIndexHostCtConflict,
			tcdefs.ProgIndexHostCtConflictDebug:
			if !hasHostConflictProg {
				continue
			}
		case
			tcdefs.ProgIndexMaglev,
			tcdefs.ProgIndexMaglevDebug:
			if !hasMaglev {
				continue
			}
		}
		pmName := progMap[hook.Egress].GetName()
		if useIngressProgMap {
			pmName = progMap[hook.Ingress].GetName()
		}
		log.WithField("prog", tcdefs.ProgramNames[idx]).WithField("idx", idx).Debug("UpdateJumpMap")
		err := obj.UpdateJumpMap(pmName, tcdefs.ProgramNames[idx], idx)
		if err != nil {
			return fmt.Errorf("error updating %s program: %w", tcdefs.ProgramNames[idx], err)
		}
	}

	return nil
}

func objLoad(fname, bpfFsDir, ipFamily string, topts testOpts, polProg, hasHostConflictProg, hasMaglev, useIngressProgMap bool) (*libbpf.Obj, error) {
	log.WithField("program", fname).Debug("Loading BPF program")

	forXDP := topts.xdp

	// XXX we do not need to create both sets of maps, but, well, who cares here ;-)
	progMap = hook.NewProgramsMaps()
	policyJumpMap = jump.Map()
	progMapXDP = hook.NewXDPProgramsMap()
	policyJumpMapXDP = jump.XDPMap()
	if ipFamily == "preamble" {
		_ = unix.Unlink(progMap[hook.Ingress].Path())
		_ = unix.Unlink(progMap[hook.Egress].Path())
		_ = unix.Unlink(policyJumpMap.Path())
		_ = unix.Unlink(progMapXDP.Path())
		_ = unix.Unlink(policyJumpMapXDP.Path())
	}
	err := progMap[hook.Ingress].EnsureExists()
	Expect(err).NotTo(HaveOccurred())
	err = progMap[hook.Egress].EnsureExists()
	Expect(err).NotTo(HaveOccurred())
	err = policyJumpMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())
	err = progMapXDP.EnsureExists()
	Expect(err).NotTo(HaveOccurred())
	err = policyJumpMapXDP.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	obj, err := libbpf.OpenObject(fname)
	if err != nil {
		return nil, fmt.Errorf("open object %s: %w", fname, err)
	}

	for m, err := obj.FirstMap(); m != nil && err == nil; m, err = m.NextMap() {
		if m.IsMapInternal() {
			if ipFamily != "preamble" {
				continue
			}
			if !strings.HasSuffix(m.Name(), ".rodata") {
				continue
			}
			if forXDP {
				var globals libbpf.XDPGlobalData
				for i := 0; i < 16; i++ {
					globals.Jumps[i] = uint32(i)
				}
				if topts.ipv6 {
					for i := 0; i < 16; i++ {
						globals.JumpsV6[i] = uint32(i)
					}
				}

				globals.IfaceName = setLogPrefix(bpfIfaceName)
				if err := globals.Set(m); err != nil {
					return nil, fmt.Errorf("failed to configure xdp program: %w", err)
				}
			} else {
				ifaceLog := topts.progLog + "-" + bpfIfaceName
				globals := libbpf.TcGlobalData{
					Tmtu:          natTunnelMTU,
					VxlanPort:     testVxlanPort,
					PSNatStart:    uint16(topts.psnaStart),
					PSNatLen:      uint16(topts.psnatEnd-topts.psnaStart) + 1,
					Flags:         libbpf.GlobalsNoDSRCidrs,
					LogFilterJmp:  0xffffffff,
					IfaceName:     setLogPrefix(ifaceLog),
					MaglevLUTSize: testMaglevLUTSize,
				}
				if topts.flowLogsEnabled {
					globals.Flags |= libbpf.GlobalsFlowLogsEnabled
				}
				if topts.natOutExcludeHosts {
					globals.Flags |= libbpf.GlobalsNATOutgoingExcludeHosts
				}

				if topts.ingressQoSPacketRate {
					globals.Flags |= libbpf.GlobalsIngressPacketRateConfigured
				}

				if topts.egressQoSPacketRate {
					globals.Flags |= libbpf.GlobalsEgressPacketRateConfigured
				}

				globals.DSCP = -1
				if topts.dscp >= 0 {
					globals.DSCP = topts.dscp
				}

				if topts.ipv6 {
					copy(globals.HostTunnelIPv6[:], node1tunIPV6.To16())
					copy(globals.HostIPv6[:], hostIP.To16())
					copy(globals.IntfIPv6[:], intfIPV6.To16())

					for i := 0; i < tcdefs.ProgIndexEnd; i++ {
						globals.JumpsV6[i] = uint32(i)
					}
					globals.Flags |= libbpf.GlobalsRPFOptionStrict
					log.WithField("globals", globals).Debugf("configure program v6")
				} else {
					copy(globals.HostIPv4[0:4], hostIP)
					copy(globals.IntfIPv4[0:4], intfIP)
					copy(globals.HostTunnelIPv4[0:4], node1tunIP.To4())

					for i := 0; i < tcdefs.ProgIndexEnd; i++ {
						globals.Jumps[i] = uint32(i)
					}
					log.WithField("globals", globals).Debugf("configure program")
				}
				if err := globals.Set(m); err != nil {
					return nil, fmt.Errorf("failed to configure tc program: %w", err)
				}
				log.WithField("program", fname).Debugf("Configured BPF program iface \"%s\"", ifaceLog)
			}
			continue
		}
		pin := "/sys/fs/bpf/tc/globals/" + m.Name()
		log.WithFields(log.Fields{
			"pin":        pin,
			"key size":   m.KeySize(),
			"value size": m.ValueSize(),
		}).Debug("Pinning map")
		fd, err := maps.GetMapFDByPin(pin)
		if err != nil {
			log.WithError(err).Debug("error getting map FD by pin")
		} else {
			mapInfo, err := maps.GetMapInfo(fd)
			if err != nil {
				log.WithError(err).Debug("error getting mapInfo by FD")
			} else {
				log.WithFields(log.Fields{"Type": mapInfo.Type, "MaxEntries": mapInfo.MaxEntries, "ValueSize": mapInfo.ValueSize, "KeySize": mapInfo.KeySize}).Debug("existing map")
			}
		}
		log.WithFields(log.Fields{"Type": m.Type(), "MaxEntries": m.MaxEntries(), "ValueSize": m.ValueSize(), "KeySize": m.KeySize()}).Debug("new map")
		if err := m.SetPinPath(pin); err != nil {
			obj.Close()
			return nil, fmt.Errorf("error pinning map %s: %w", m.Name(), err)
		}
	}

	if err := obj.Load(); err != nil {
		return nil, fmt.Errorf("load object: %w", err)
	}

	progDir := bpfFsDir
	policyIdx := tcdefs.ProgIndexPolicy

	err = obj.PinPrograms(progDir)
	if err != nil {
		obj.Close()
		return nil, fmt.Errorf("pin %s programs to %s: %w", ipFamily, progDir, err)
	}

	if polProg {
		polProgPath := "xdp_policy"
		if !forXDP {
			polProgPath = "classifier_tc_policy"
		}
		polProgPath = path.Join(bpfFsDir, polProgPath)
		_, err = os.Stat(polProgPath)
		if err == nil {
			m := policyJumpMap
			if forXDP {
				m = policyJumpMapXDP
			}
			err = jumpMapUpdatePinned(m, policyIdx, polProgPath)
			if err != nil {
				err = errors.Wrap(err, "failed to update jump map (policy program)")
				goto out
			}
			log.Debug("set default policy")
		}
	}

	if !forXDP {
		log.WithField("ipFamily", ipFamily).Debug("Updating jump map")
		err = tcUpdateJumpMap(obj, tcJumpMapIndexes[ipFamily], false, hasHostConflictProg, hasMaglev, useIngressProgMap)
		if err != nil && !strings.Contains(err.Error(), "error updating calico_tc_host_ct_conflict program") {
			goto out
		}
		err = tcUpdateJumpMap(obj, tcJumpMapIndexes[ipFamily], false, false, hasMaglev, useIngressProgMap)
	} else {
		if err = xdpUpdateJumpMap(obj, xdpJumpMapIndexes[ipFamily]); err != nil {
			goto out
		}
	}

out:
	if err != nil {
		_ = obj.UnpinPrograms(bpfFsDir)
		obj.Close()
		return nil, fmt.Errorf("%s: %w", ipFamily, err)
	}

	log.WithField("program", fname).Debug("Loaded BPF program")
	return obj, nil
}

func objUTLoad(fname, bpfFsDir, ipFamily string, topts testOpts, polProg, hasHostConflictProg bool) (*libbpf.Obj, error) {
	log.WithField("program", fname).Debug("Loading BPF UT program")

	obj, err := libbpf.OpenObject(fname)
	if err != nil {
		return nil, fmt.Errorf("open object %s: %w", fname, err)
	}

	for m, err := obj.FirstMap(); m != nil && err == nil; m, err = m.NextMap() {
		if m.IsMapInternal() {
			if !strings.HasSuffix(m.Name(), ".rodata") {
				continue
			}
			globals := libbpf.TcGlobalData{
				Tmtu:          natTunnelMTU,
				VxlanPort:     testVxlanPort,
				PSNatStart:    uint16(topts.psnaStart),
				PSNatLen:      uint16(topts.psnatEnd-topts.psnaStart) + 1,
				Flags:         libbpf.GlobalsNoDSRCidrs,
				IfaceName:     setLogPrefix(topts.progLog + "-" + bpfIfaceName),
				MaglevLUTSize: testMaglevLUTSize,
			}
			if topts.ipv6 {
				copy(globals.HostTunnelIPv6[:], node1tunIPV6.To16())
				copy(globals.HostIPv6[:], hostIP.To16())
				copy(globals.IntfIPv6[:], intfIPV6.To16())
			} else {
				copy(globals.HostTunnelIPv4[0:4], node1tunIP.To4())
				copy(globals.HostIPv4[0:4], hostIP.To4())
				copy(globals.IntfIPv4[0:4], intfIP.To4())
			}
			if err := globals.Set(m); err != nil {
				return nil, fmt.Errorf("failed to configure tc program: %w", err)
			}
			break
		}
		pin := "/sys/fs/bpf/tc/globals/" + m.Name()
		log.WithField("pin", pin).Debug("Pinning map")
		fd, err := maps.GetMapFDByPin(pin)
		if err != nil {
			log.WithError(err).Debug("error getting map FD by pin")
		} else {
			mapInfo, err := maps.GetMapInfo(fd)
			if err != nil {
				log.WithError(err).Debug("error getting mapInfo by FD")
			} else {
				log.WithFields(log.Fields{"Type": mapInfo.Type, "MaxEntries": mapInfo.MaxEntries, "ValueSize": mapInfo.ValueSize, "KeySize": mapInfo.KeySize}).Debug("existing map")
			}
		}
		log.WithFields(log.Fields{"Type": m.Type(), "MaxEntries": m.MaxEntries(), "ValueSize": m.ValueSize(), "KeySize": m.KeySize()}).Debug("new map")
		if err := m.SetPinPath(pin); err != nil {
			obj.Close()
			return nil, fmt.Errorf("error pinning map %s: %w", m.Name(), err)
		}
	}

	if err := obj.Load(); err != nil {
		return nil, fmt.Errorf("load object: %w", err)
	}

	progDir := bpfFsDir

	err = obj.PinPrograms(progDir)
	if err != nil {
		obj.Close()
		return nil, fmt.Errorf("pin %s programs to %s: %w", ipFamily, progDir, err)
	}

	log.WithField("program", fname).Debug("Loaded BPF UT program")
	return obj, nil
}

func xdpUpdateJumpMap(obj *libbpf.Obj, progs map[int]string) error {
	for idx, name := range progs {
		err := obj.UpdateJumpMap(hook.NewXDPProgramsMap().GetName(), name, idx)
		if err != nil {
			return fmt.Errorf("failed to update program '%s' at index %d: %w", name, idx, err)
		}
		log.Debugf("xdp set program '%s' at index %d", name, idx)
	}

	return nil
}

func setLogPrefix(ifaceLog string) string {
	in := []byte("---------------")
	copy(in, ifaceLog)
	return string(in)
}

type bpfRunResult struct {
	Retval   int
	Duration int
	dataOut  []byte
}

func (r bpfRunResult) RetvalStr() string {
	s := retvalToStr[r.Retval]
	if s == "" {
		return fmt.Sprint(r.Retval)
	}
	return s
}

func (r bpfRunResult) RetvalStrXDP() string {
	s := retvalToStrXDP[r.Retval]
	if s == "" {
		return fmt.Sprint(r.Retval)
	}
	return s
}

func bpftoolProgRun(progName string, dataIn, ctxIn []byte) (bpfRunResult, error) {
	return bpftoolProgRunN(progName, dataIn, ctxIn, 1)
}

func bpftoolProgRunN(progName string, dataIn, ctxIn []byte, N int) (bpfRunResult, error) {
	var res bpfRunResult

	tempDir, err := os.MkdirTemp("", "bpftool-data-")
	Expect(err).NotTo(HaveOccurred())

	defer os.RemoveAll(tempDir)

	dataInFname := tempDir + "/data_in"
	dataOutFname := tempDir + "/data_out"

	ctxInFname := tempDir + "/ctx_in"
	ctxOutFname := tempDir + "/ctx_out"

	if err := os.WriteFile(dataInFname, dataIn, 0644); err != nil {
		return res, fmt.Errorf("failed to write input data in file: %s", err)
	}

	if ctxIn != nil {
		if err := os.WriteFile(ctxInFname, ctxIn, 0644); err != nil {
			return res, fmt.Errorf("failed to write input ctx in file: %s", err)
		}
	}

	args := []string{"prog", "run", "pinned", progName, "data_in", dataInFname, "data_out", dataOutFname}
	if ctxIn != nil {
		args = append(args, "ctx_in", ctxInFname, "ctx_out", ctxOutFname)
	}
	if N > 1 {
		args = append(args, "repeat", fmt.Sprintf("%d", N))
	}

	out, err := bpftool(args...)
	if err != nil {
		return res, err
	}

	if err := json.Unmarshal(out, &res); err != nil {
		return res, fmt.Errorf("failed to unmarshall json: %s", err)
	}

	res.dataOut, err = os.ReadFile(dataOutFname)
	if err != nil {
		return res, fmt.Errorf("failed to read output data from file: %s", err)
	}

	if ctxIn != nil {
		ctxOut, err := os.ReadFile(ctxOutFname)
		if err != nil {
			return res, fmt.Errorf("failed to read output ctx from file: %s", err)
		}
		skbMark = binary.LittleEndian.Uint32(ctxOut[2*4 : 3*4])
	}

	return res, nil
}

type bpfProgRunFn func(data []byte) (bpfRunResult, error)

// runBpfUnitTest runs a small unit in isolation. It requires a small .c file
// that wraps the unit and compiles into a calico_unittest section.
func runBpfUnitTest(t *testing.T, source string, testFn func(bpfProgRunFn), opts ...testOption) {
	RegisterTestingT(t)

	topts := testOpts{
		subtests: true,
		logLevel: log.DebugLevel,
	}

	for _, o := range opts {
		o(&topts)
	}

	loglevel := log.GetLevel()
	if topts.logLevel != loglevel {
		defer log.SetLevel(loglevel)
		log.SetLevel(topts.logLevel)
	}

	tempDir, err := os.MkdirTemp("", "calico-bpf-")
	Expect(err).NotTo(HaveOccurred())
	defer os.RemoveAll(tempDir)

	unique := path.Base(tempDir)
	bpfFsDir := "/sys/fs/bpf/" + unique

	err = os.Mkdir(bpfFsDir, os.ModePerm)
	Expect(err).NotTo(HaveOccurred())
	defer os.RemoveAll(bpfFsDir)

	vExt := ""
	if topts.ipv6 {
		vExt = "_v6"
	}

	objFname := "../../bpf-gpl/ut/" + strings.TrimSuffix(source, path.Ext(source)) + vExt + ".o"
	if topts.objname != "" {
		objFname = "../../bpf-gpl/ut/" + topts.objname
	}

	obj, err := objUTLoad(objFname, bpfFsDir, "IPv4", topts, true, false)
	Expect(err).NotTo(HaveOccurred())
	defer func() { _ = obj.UnpinPrograms(bpfFsDir) }()
	defer obj.Close()

	ctxIn := make([]byte, 18*4)

	_ = counters.EnsureExists(countersMap, 1, hook.Ingress)
	_ = counters.EnsureExists(countersMap, 1, hook.Egress)

	runTest := func() {
		testFn(func(dataIn []byte) (bpfRunResult, error) {
			res, err := bpftoolProgRun(bpfFsDir+"/unittest", dataIn, ctxIn)
			log.Debugf("dataIn  = %+v", dataIn)
			if err == nil {
				log.Debugf("dataOut = %+v", res.dataOut)
			}
			return res, err
		})
	}

	if topts.subtests {
		t.Run(source, func(_ *testing.T) {
			runTest()
		})
	} else {
		runTest()
	}
}

type testOpts struct {
	description          string
	subtests             bool
	logLevel             log.Level
	xdp                  bool
	psnaStart            uint32
	psnatEnd             uint32
	hostNetworked        bool
	fromHost             bool
	progLog              string
	ipv6                 bool
	objname              string
	flowLogsEnabled      bool
	natOutExcludeHosts   bool
	ingressQoSPacketRate bool
	egressQoSPacketRate  bool
	dscp                 int8
}

type testOption func(opts *testOpts)

func withSubtests(v bool) testOption {
	return func(o *testOpts) {
		o.subtests = v
	}
}

func withLogLevel(l log.Level) testOption {
	return func(o *testOpts) {
		o.logLevel = l
	}
}

var _ = withLogLevel

func withXDP() testOption {
	return func(o *testOpts) {
		o.xdp = true
	}
}

func withPSNATPorts(start, end uint16) testOption {
	return func(o *testOpts) {
		o.psnaStart = uint32(start)
		o.psnatEnd = uint32(end)
	}
}

func withHostNetworked() testOption {
	return func(o *testOpts) {
		o.hostNetworked = true
	}
}

func withFromHost() testOption {
	return func(o *testOpts) {
		o.fromHost = true
	}
}

func withIPv6() testOption {
	return func(o *testOpts) {
		o.ipv6 = true
	}
}

func withFlowLogs() testOption {
	return func(o *testOpts) {
		o.flowLogsEnabled = true
	}
}

func withNATOutExcludeHosts() testOption {
	return func(o *testOpts) {
		o.natOutExcludeHosts = true
	}
}

func withIngressQoSPacketRate() testOption {
	return func(o *testOpts) {
		o.ingressQoSPacketRate = true
	}
}

func withEgressQoSPacketRate() testOption {
	return func(o *testOpts) {
		o.egressQoSPacketRate = true
	}
}

func withEgressDSCP(value int8) testOption {
	return func(o *testOpts) {
		o.dscp = value
	}
}

func withObjName(name string) testOption {
	return func(o *testOpts) {
		o.objname = name
	}
}

func withDescription(desc string) testOption {
	return func(o *testOpts) {
		o.description = desc
	}
}

// layersMatchFields matches all Exported fields and ignore the ones explicitly
// listed. It always ignores BaseLayer as that is not set by the tests.
func layersMatchFields(l gopacket.Layer, ignore ...string) types.GomegaMatcher {
	toIgnore := make(map[string]bool)
	for _, x := range ignore {
		toIgnore[x] = true
	}

	toIgnore["BaseLayer"] = true

	f := Fields{}
	v := reflect.Indirect(reflect.ValueOf(l))
	if v.Kind() != reflect.Struct {
		return Reject()
	}

	for i := 0; i < v.NumField(); i++ {
		name := v.Type().Field(i).Name
		if !toIgnore[name] && v.Field(i).CanInterface() {
			val := v.Field(i).Interface()
			f[name] = Equal(val)
		}
	}

	return PointTo(MatchFields(IgnoreMissing|IgnoreExtras, f))
}

func udpResponseRaw(in []byte) []byte {
	pkt := gopacket.NewPacket(in, layers.LayerTypeEthernet, gopacket.Default)
	ethL := pkt.Layer(layers.LayerTypeEthernet)
	ethR := ethL.(*layers.Ethernet)
	ethR.SrcMAC, ethR.DstMAC = ethR.DstMAC, ethR.SrcMAC

	ipv4L := pkt.Layer(layers.LayerTypeIPv4)
	ipv4R := ipv4L.(*layers.IPv4)
	ipv4R.SrcIP, ipv4R.DstIP = ipv4R.DstIP, ipv4R.SrcIP

	udpL := pkt.Layer(layers.LayerTypeUDP)
	udpR := udpL.(*layers.UDP)
	udpR.SrcPort, udpR.DstPort = udpR.DstPort, udpR.SrcPort

	_ = udpR.SetNetworkLayerForChecksum(ipv4R)

	out := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(out, gopacket.SerializeOptions{ComputeChecksums: true},
		ethR, ipv4R, udpR, gopacket.Payload(pkt.ApplicationLayer().Payload()))
	Expect(err).NotTo(HaveOccurred())

	return out.Bytes()
}

func udpResponseRawV6(in []byte) []byte {
	pkt := gopacket.NewPacket(in, layers.LayerTypeEthernet, gopacket.Default)
	ethL := pkt.Layer(layers.LayerTypeEthernet)
	ethR := ethL.(*layers.Ethernet)
	ethR.SrcMAC, ethR.DstMAC = ethR.DstMAC, ethR.SrcMAC

	ipv6L := pkt.Layer(layers.LayerTypeIPv6)
	ipv6R := ipv6L.(*layers.IPv6)
	ipv6R.SrcIP, ipv6R.DstIP = ipv6R.DstIP, ipv6R.SrcIP

	lrs := []gopacket.SerializableLayer{ethR, ipv6R}

	if ipv6R.NextHeader == layers.IPProtocolIPv6HopByHop {
		l := pkt.Layer(layers.LayerTypeIPv6HopByHop)
		lrs = append(lrs, l.(*layers.IPv6HopByHop))
	}

	udpL := pkt.Layer(layers.LayerTypeUDP)
	udpR := udpL.(*layers.UDP)
	udpR.SrcPort, udpR.DstPort = udpR.DstPort, udpR.SrcPort

	_ = udpR.SetNetworkLayerForChecksum(ipv6R)

	lrs = append(lrs, udpR, gopacket.Payload(pkt.ApplicationLayer().Payload()))

	out := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(out, gopacket.SerializeOptions{ComputeChecksums: true}, lrs...)
	Expect(err).NotTo(HaveOccurred())

	return out.Bytes()
}

func tcpResponseRaw(in []byte) []byte {
	pkt := gopacket.NewPacket(in, layers.LayerTypeEthernet, gopacket.Default)
	ethL := pkt.Layer(layers.LayerTypeEthernet)
	ethR := ethL.(*layers.Ethernet)
	ethR.SrcMAC, ethR.DstMAC = ethR.DstMAC, ethR.SrcMAC

	ipv4L := pkt.Layer(layers.LayerTypeIPv4)
	ipv4R := ipv4L.(*layers.IPv4)
	ipv4R.SrcIP, ipv4R.DstIP = ipv4R.DstIP, ipv4R.SrcIP

	tcpL := pkt.Layer(layers.LayerTypeTCP)
	tcpR := tcpL.(*layers.TCP)
	tcpR.SrcPort, tcpR.DstPort = tcpR.DstPort, tcpR.SrcPort

	if tcpR.SYN {
		tcpR.ACK = true
	}

	_ = tcpR.SetNetworkLayerForChecksum(ipv4R)

	out := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(out, gopacket.SerializeOptions{ComputeChecksums: true},
		ethR, ipv4R, tcpR, gopacket.Payload(pkt.ApplicationLayer().Payload()))
	Expect(err).NotTo(HaveOccurred())

	return out.Bytes()
}

func tcpResponseRawV6(in []byte) []byte {
	pkt := gopacket.NewPacket(in, layers.LayerTypeEthernet, gopacket.Default)
	ethL := pkt.Layer(layers.LayerTypeEthernet)
	ethR := ethL.(*layers.Ethernet)
	ethR.SrcMAC, ethR.DstMAC = ethR.DstMAC, ethR.SrcMAC

	ipv6L := pkt.Layer(layers.LayerTypeIPv6)
	ipv6R := ipv6L.(*layers.IPv6)
	ipv6R.SrcIP, ipv6R.DstIP = ipv6R.DstIP, ipv6R.SrcIP

	tcpL := pkt.Layer(layers.LayerTypeTCP)
	tcpR := tcpL.(*layers.TCP)
	tcpR.SrcPort, tcpR.DstPort = tcpR.DstPort, tcpR.SrcPort

	if tcpR.SYN {
		tcpR.ACK = true
	}

	_ = tcpR.SetNetworkLayerForChecksum(ipv6R)

	out := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(out, gopacket.SerializeOptions{ComputeChecksums: true},
		ethR, ipv6R, tcpR, gopacket.Payload(pkt.ApplicationLayer().Payload()))
	Expect(err).NotTo(HaveOccurred())

	return out.Bytes()
}

func dumpMaglevMap(mgMap maps.Map) {
	m, err := nat.LoadMaglevMap(mgMap)
	Expect(err).NotTo(HaveOccurred())
	for k, v := range m {
		fmt.Printf("%s: %s\n", k, v)
	}
}

func dumpNATMap(natMap maps.Map) {
	nt, err := nat.LoadFrontendMap(natMap)
	Expect(err).NotTo(HaveOccurred())
	for k, v := range nt {
		fmt.Printf("%s : %s\n", k, v)
	}
}

func dumpNATMapV6(natMap maps.Map) {
	nt, err := nat.LoadFrontendMapV6(natMap)
	Expect(err).NotTo(HaveOccurred())
	for k, v := range nt {
		fmt.Printf("%s : %s\n", k, v)
	}
}

func resetMap(m maps.Map) {
	err := m.Iter(func(_, _ []byte) maps.IteratorAction {
		return maps.IterDelete
	})
	Expect(err).NotTo(HaveOccurred())
}

func dumpCTMap(ctMap maps.Map) {
	ct, err := conntrack.LoadMapMem(ctMap)
	Expect(err).NotTo(HaveOccurred())
	fmt.Printf("Conntrack dump:\n")
	for k, v := range ct {
		fmt.Printf("- %s : %s\n", k, v)
	}
	fmt.Printf("\n")
}

func dumpCTMapV6(ctMap maps.Map) {
	ct, err := conntrack.LoadMapMemV6(ctMap)
	Expect(err).NotTo(HaveOccurred())
	fmt.Printf("Conntrack dump:\n")
	for k, v := range ct {
		fmt.Printf("- %s : %s\n", k, v)
	}
	fmt.Printf("\n")
}

func resetCTMap(ctMap maps.Map) {
	resetMap(ctMap)
}

func resetCTMapV6(ctMap maps.Map) {
	resetMap(ctMap)
}

func saveCTMap(ctMap maps.Map) conntrack.MapMem {
	ct, err := conntrack.LoadMapMem(ctMap)
	Expect(err).NotTo(HaveOccurred())
	return ct
}

func saveCTMapV6(ctMap maps.Map) conntrack.MapMemV6 {
	ct, err := conntrack.LoadMapMemV6(ctMap)
	Expect(err).NotTo(HaveOccurred())
	return ct
}

func restoreCTMap(ctMap maps.Map, m conntrack.MapMem) {
	for k, v := range m {
		err := ctMap.Update(k[:], v[:])
		Expect(err).NotTo(HaveOccurred())
	}
}

func restoreCTMapV6(ctMap maps.Map, m conntrack.MapMemV6) {
	for k, v := range m {
		err := ctMap.Update(k[:], v[:])
		Expect(err).NotTo(HaveOccurred())
	}
}

func dumpRTMap(rtMap maps.Map) {
	rt, err := routes.LoadMap(rtMap)
	Expect(err).NotTo(HaveOccurred())
	for k, v := range rt {
		fmt.Printf("%15s: %s\n", k.Dest(), v)
	}
}

func dumpRTMapV6(rtMap maps.Map) {
	rt, err := routes.LoadMapV6(rtMap)
	Expect(err).NotTo(HaveOccurred())
	for k, v := range rt {
		fmt.Printf("%15s: %s\n", k.Dest(), v)
	}
}

func resetRTMap(rtMap maps.Map) {
	resetMap(rtMap)
}

func resetRTMapV6(rtMap maps.Map) {
	resetMap(rtMap)
}

func resetQoSMap(qosMap maps.Map) {
	resetMap(qosMap)
}

func saveRTMap(rtMap maps.Map) routes.MapMem {
	rt, err := routes.LoadMap(rtMap)
	Expect(err).NotTo(HaveOccurred())
	return rt
}

func saveRTMapV6(rtMap maps.Map) routes.MapMemV6 {
	rt, err := routes.LoadMapV6(rtMap)
	Expect(err).NotTo(HaveOccurred())
	return rt
}

func restoreRTMap(rtMap maps.Map, m routes.MapMem) {
	for k, v := range m {
		err := rtMap.Update(k[:], v[:])
		Expect(err).NotTo(HaveOccurred())
	}
}

func restoreARPMap(arpMap maps.Map, a arp.MapMem) {
	for k, v := range a {
		err := arpMap.Update(k[:], v[:])
		Expect(err).NotTo(HaveOccurred())
	}
}

func restoreARPMapV6(arpMap maps.Map, a arp.MapMemV6) {
	for k, v := range a {
		err := arpMap.Update(k[:], v[:])
		Expect(err).NotTo(HaveOccurred())
	}
}

func restoreRTMapV6(rtMap maps.Map, m routes.MapMemV6) {
	for k, v := range m {
		err := rtMap.Update(k[:], v[:])
		Expect(err).NotTo(HaveOccurred())
	}
}

func dumpARPMap(arpMap maps.Map) {
	ct, err := arp.LoadMapMem(arpMap)
	Expect(err).NotTo(HaveOccurred())
	fmt.Printf("ARP dump:\n")
	for k, v := range ct {
		fmt.Printf("- %s : %s\n", k, v)
	}
	fmt.Printf("\n")
}

func dumpARPMapV6(arpMap maps.Map) {
	ct, err := arp.LoadMapMemV6(arpMap)
	Expect(err).NotTo(HaveOccurred())
	fmt.Printf("ARP dump:\n")
	for k, v := range ct {
		fmt.Printf("- %s : %s\n", k, v)
	}
	fmt.Printf("\n")
}

func saveARPMap(am maps.Map) arp.MapMem {
	m, err := arp.LoadMapMem(am)
	Expect(err).NotTo(HaveOccurred())
	return m
}

func saveARPMapV6(am maps.Map) arp.MapMemV6 {
	m, err := arp.LoadMapMemV6(am)
	Expect(err).NotTo(HaveOccurred())
	return m
}

var ethDefault = &layers.Ethernet{
	SrcMAC:       []byte{0, 0, 0, 0, 0, 1},
	DstMAC:       []byte{0, 0, 0, 0, 0, 2},
	EthernetType: layers.EthernetTypeIPv4,
}

var payloadDefault = []byte("ABCDEABCDEXXXXXXXXXXXX")

var srcIP = net.IPv4(1, 1, 1, 1)
var dstIP = net.IPv4(2, 2, 2, 2)
var srcV4CIDR = ip.CIDRFromNetIP(srcIP).(ip.V4CIDR)
var dstV4CIDR = ip.CIDRFromNetIP(dstIP).(ip.V4CIDR)

var ipv4Default = &layers.IPv4{
	Version:  4,
	IHL:      5,
	TTL:      64,
	Flags:    layers.IPv4DontFragment,
	SrcIP:    srcIP,
	DstIP:    dstIP,
	Protocol: layers.IPProtocolUDP,
}

var srcIPv6 = net.IP([]byte{0x20, 0x1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
var dstIPv6 = net.IP([]byte{0x20, 0x1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2})
var srcV6CIDR = ip.CIDRFromNetIP(srcIPv6).(ip.V6CIDR)
var dstV6CIDR = ip.CIDRFromNetIP(dstIPv6).(ip.V6CIDR)

var ipv6Default = &layers.IPv6{
	Version:    6,
	HopLimit:   64,
	SrcIP:      srcIPv6,
	DstIP:      dstIPv6,
	NextHeader: layers.IPProtocolUDP,
}

var udpDefault = &layers.UDP{
	SrcPort: 1234,
	DstPort: 5678,
}

func testPacket(family int, eth *layers.Ethernet, l3 gopacket.Layer, l4 gopacket.Layer,
	payload []byte, ipv6ext ...gopacket.SerializableLayer) (
	*layers.Ethernet, gopacket.Layer, gopacket.Layer, []byte, []byte, error) {
	pkt := Packet{
		family:  family,
		eth:     eth,
		l3:      l3,
		l4:      l4,
		payload: payload,
		ipv6ext: ipv6ext,
	}

	err := pkt.Generate()
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	p := gopacket.NewPacket(pkt.bytes, layers.LayerTypeEthernet, gopacket.Default)
	fmt.Printf("p = %+v\n", p)

	e := p.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)

	var (
		ipl   gopacket.Layer
		proto layers.IPProtocol
	)

	ipv4L := p.Layer(layers.LayerTypeIPv4)
	if ipv4L != nil {
		ipv4 := ipv4L.(*layers.IPv4)
		proto = ipv4.Protocol
		ipl = ipv4L
	} else {
		ipv6L := p.Layer(layers.LayerTypeIPv6)
		if ipv6L != nil {
			ipv6 := ipv6L.(*layers.IPv6)
			proto = ipv6.NextHeader
		}
		if proto == layers.IPProtocolIPv6HopByHop {
			l := p.Layer(layers.LayerTypeIPv6HopByHop)
			proto = l.(*layers.IPv6HopByHop).NextHeader
		}
		ipl = ipv6L
	}

	var l gopacket.Layer

	switch proto {
	case layers.IPProtocolUDP:
		l = p.Layer(layers.LayerTypeUDP)
	case layers.IPProtocolTCP:
		l = p.Layer(layers.LayerTypeTCP)
	case layers.IPProtocolICMPv4:
		l = p.Layer(layers.LayerTypeICMPv4)
	}

	return e, ipl, l, pkt.payload, pkt.bytes, err
}

func testPacketV4(eth *layers.Ethernet, ipv4 *layers.IPv4, l4 gopacket.Layer, payload []byte) (
	*layers.Ethernet, *layers.IPv4, gopacket.Layer, []byte, []byte, error) {
	e, ip4, l4, p, b, err := testPacket(4, eth, ipv4, l4, payload)
	return e, ip4.(*layers.IPv4), l4, p, b, err
}

func testPacketV6(eth *layers.Ethernet, ipv6 *layers.IPv6, l4 gopacket.Layer, payload []byte, ipv6ext ...gopacket.SerializableLayer) (
	*layers.Ethernet, *layers.IPv6, gopacket.Layer, []byte, []byte, error) {
	e, ip6, l4, p, b, err := testPacket(6, eth, ipv6, l4, payload, ipv6ext...)
	return e, ip6.(*layers.IPv6), l4, p, b, err
}

type Packet struct {
	family     int
	eth        *layers.Ethernet
	l3         gopacket.Layer
	ipv4       *layers.IPv4
	ipv6       *layers.IPv6
	l4         gopacket.Layer
	udp        *layers.UDP
	tcp        *layers.TCP
	icmp       *layers.ICMPv4
	icmpv6     *layers.ICMPv6
	payload    []byte
	bytes      []byte
	layers     []gopacket.SerializableLayer
	length     int
	l4Protocol layers.IPProtocol
	l3Protocol layers.EthernetType
	ipv6ext    []gopacket.SerializableLayer
}

func (pkt *Packet) handlePayload() {
	if pkt.payload == nil {
		pkt.payload = payloadDefault
	}
	pkt.length = len(pkt.payload)
	pkt.layers = []gopacket.SerializableLayer{gopacket.Payload(pkt.payload)}
}

func (pkt *Packet) handleL4() error {
	if pkt.l4 == nil {
		pkt.l4 = udpDefault
	}

	switch v := pkt.l4.(type) {
	case *layers.UDP:
		pkt.udp = v
		pkt.length += 8
		pkt.udp.Length = uint16(pkt.length)
		pkt.l4Protocol = layers.IPProtocolUDP
		pkt.layers = append(pkt.layers, pkt.udp)
	case *layers.TCP:
		pkt.tcp = v
		pkt.length += 20
		pkt.l4Protocol = layers.IPProtocolTCP
		pkt.layers = append(pkt.layers, pkt.tcp)
	case *layers.ICMPv4:
		pkt.icmp = v
		pkt.length += 8
		pkt.l4Protocol = layers.IPProtocolICMPv4
		pkt.layers = append(pkt.layers, pkt.icmp)
	case *layers.ICMPv6:
		pkt.icmpv6 = v
		pkt.length += 8
		pkt.l4Protocol = layers.IPProtocolICMPv6
		pkt.layers = append(pkt.layers, pkt.icmpv6)
	default:
		return fmt.Errorf("unrecognized l4 layer type %t", pkt.l4)
	}
	return nil
}

func (pkt *Packet) handleIPv6Ext() error {
	exts := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(exts, gopacket.SerializeOptions{FixLengths: true}, pkt.ipv6ext...)
	if err != nil {
		return err
	}

	pkt.length += len(exts.Bytes())

	return nil
}

func nextHdrIPProto(nh gopacket.Layer) layers.IPProtocol {
	switch nh.(type) {
	case *layers.IPv6HopByHop:
		return layers.IPProtocolIPv6HopByHop
	case *layers.ICMPv4:
		return layers.IPProtocolICMPv4
	case *layers.IGMP:
		return layers.IPProtocolIGMP
	case *layers.IPv4:
		return layers.IPProtocolIPv4
	case *layers.TCP:
		return layers.IPProtocolTCP
	case *layers.UDP:
		return layers.IPProtocolUDP
	case *layers.RUDP:
		return layers.IPProtocolRUDP
	case *layers.IPv6:
		return layers.IPProtocolIPv6
	case *layers.IPv6Routing:
		return layers.IPProtocolIPv6Routing
	case *layers.IPv6Fragment:
		return layers.IPProtocolIPv6Fragment
	case *layers.GRE:
		return layers.IPProtocolGRE
	case *layers.ICMPv6:
		return layers.IPProtocolICMPv6
	case *layers.IPv6Destination:
		return layers.IPProtocolIPv6Destination
	case *layers.EtherIP:
		return layers.IPProtocolEtherIP
	case *layers.SCTP:
		return layers.IPProtocolSCTP
	case *layers.UDPLite:
		return layers.IPProtocolUDPLite
	}

	panic("unknown next layer")
}

func (pkt *Packet) handleL3() error {
	v := reflect.ValueOf(pkt.l3)
	if !v.IsValid() || v.IsNil() {
		if pkt.family == 4 {
			pkt.l3 = ipv4Default
		} else {
			pkt.l3 = ipv6Default
		}
	}

	switch v := pkt.l3.(type) {
	case *layers.IPv4:
		pkt.ipv4 = v
		pkt.length += int(v.IHL * 4)
		pkt.l3Protocol = layers.EthernetTypeIPv4
		pkt.ipv4.Protocol = pkt.l4Protocol
		pkt.ipv4.Length = uint16(pkt.length)
		pkt.layers = append(pkt.layers, pkt.ipv4)
	case *layers.IPv6:
		pkt.ipv6 = v
		pkt.l3Protocol = layers.EthernetTypeIPv6
		if len(pkt.ipv6ext) > 0 {
			if err := pkt.handleIPv6Ext(); err != nil {
				return fmt.Errorf("handling ipv6 extensions: %w", err)
			}
			pkt.ipv6.NextHeader = nextHdrIPProto(pkt.ipv6ext[0].(gopacket.Layer))
			for i := len(pkt.ipv6ext); i > 0; i-- {
				pkt.layers = append(pkt.layers, pkt.ipv6ext[i-1])
			}
		} else {
			pkt.ipv6.NextHeader = pkt.l4Protocol
		}
		pkt.length += 40
		pkt.ipv6.Length = uint16(pkt.length)
		pkt.layers = append(pkt.layers, pkt.ipv6)
	default:
		return fmt.Errorf("unrecognized l3 layer type %t", pkt.l3)
	}
	return nil
}

func (pkt *Packet) handleEthernet() {
	if pkt.eth == nil {
		pkt.eth = ethDefault
	}
	pkt.eth.EthernetType = pkt.l3Protocol
	pkt.layers = append(pkt.layers, pkt.eth)
}

func (pkt *Packet) setChecksum() {
	switch pkt.l4Protocol {
	case layers.IPProtocolUDP:
		if pkt.l3Protocol == layers.EthernetTypeIPv6 {
			_ = pkt.udp.SetNetworkLayerForChecksum(pkt.ipv6)
		} else {
			_ = pkt.udp.SetNetworkLayerForChecksum(pkt.ipv4)
		}
	case layers.IPProtocolTCP:
		if pkt.l3Protocol == layers.EthernetTypeIPv6 {
			_ = pkt.tcp.SetNetworkLayerForChecksum(pkt.ipv6)
		} else {
			_ = pkt.tcp.SetNetworkLayerForChecksum(pkt.ipv4)
		}
	}
}

func (pkt *Packet) Generate() error {
	pkt.handlePayload()
	err := pkt.handleL4()
	if err != nil {
		return err
	}

	err = pkt.handleL3()
	if err != nil {
		return err
	}

	pkt.handleEthernet()
	pkt.setChecksum()
	pkt.bytes, err = generatePacket(pkt.layers)

	return err
}

func generatePacket(layers []gopacket.SerializableLayer) ([]byte, error) {
	pkt := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(pkt, gopacket.SerializeOptions{ComputeChecksums: true})
	if err != nil {
		return nil, fmt.Errorf("Failed to init packet buffer: %w", err)
	}

	for i, layer := range layers {
		log.Infof("Layer %d: %v", i, layer)
		if layer == nil {
			continue
		}
		err = layer.SerializeTo(pkt, gopacket.SerializeOptions{ComputeChecksums: true})
		if err != nil {
			return nil, fmt.Errorf("Failed to serialize packet: %w", err)
		}
	}
	return pkt.Bytes(), nil
}

func testPacketUDPDefault() (*layers.Ethernet, *layers.IPv4, gopacket.Layer, []byte, []byte, error) {
	ip := *ipv4Default
	ip.Options = []layers.IPv4Option{{
		OptionType:   123,
		OptionLength: 6,
		OptionData:   []byte{0xde, 0xad, 0xbe, 0xef},
	}}
	ip.IHL += 2

	e, ip4, l4, p, b, err := testPacket(4, nil, &ip, nil, nil)
	return e, ip4.(*layers.IPv4), l4, p, b, err
}

func testPacketUDPDefaultNPWithPayload(destIP net.IP, payload []byte) (*layers.Ethernet, *layers.IPv4, gopacket.Layer, []byte, []byte, error) {
	if destIP == nil {
		return testPacketUDPDefault()
	}

	ip := *ipv4Default
	ip.DstIP = destIP
	ip.Options = []layers.IPv4Option{{
		OptionType:   123,
		OptionLength: 6,
		OptionData:   []byte{0xde, 0xad, 0xbe, 0xef},
	}}
	ip.IHL += 2

	e, ip4, l4, p, b, err := testPacket(4, nil, &ip, nil, payload)
	return e, ip4.(*layers.IPv4), l4, p, b, err
}

func testPacketTCPV4WithPayload(destIP net.IP, srcPort, dstPort uint16, syn bool, payload []byte) (*layers.Ethernet, *layers.IPv4, *layers.TCP, []byte, []byte, error) {
	if destIP == nil {
		log.Panic("destIP must be set")
	}

	ip := *ipv4Default
	ip.DstIP = destIP
	tcp := &layers.TCP{
		SYN:        syn,
		SrcPort:    layers.TCPPort(srcPort),
		DstPort:    layers.TCPPort(dstPort),
		DataOffset: 5,
		// Window:  14600,
	}

	// ip.Options = []layers.IPv4Option{{
	// 	OptionType:   123,
	// 	OptionLength: 6,
	// 	OptionData:   []byte{0xde, 0xad, 0xbe, 0xef},
	// }}
	// ip.IHL += 2

	e, ip4, l4, p, b, err := testPacket(4, nil, &ip, tcp, payload, nil)
	return e, ip4.(*layers.IPv4), l4.(*layers.TCP), p, b, err
}

func testPacketTCPV4DefaultNP(destIP net.IP, syn bool) (*layers.Ethernet, *layers.IPv4, *layers.TCP, []byte, []byte, error) {
	return testPacketTCPV4WithPayload(destIP, 1234, 5678, syn, nil)
}

func testPacketTCPV6WithPayload(destIP net.IP, srcPort, dstPort uint16, syn bool, payload []byte) (*layers.Ethernet, *layers.IPv6, *layers.TCP, []byte, []byte, error) {
	if destIP == nil {
		panic("destIP cannot be nil")
	}

	ip := *ipv6Default
	ip.NextHeader = layers.IPProtocolTCP
	ip.DstIP = destIP

	tcp := &layers.TCP{
		SYN:        syn,
		SrcPort:    layers.TCPPort(srcPort),
		DstPort:    layers.TCPPort(dstPort),
		DataOffset: 5,
		// Window:  14600,
	}

	hop := &layers.IPv6HopByHop{}
	hop.NextHeader = layers.IPProtocolTCP
	/* from gopacket ip6_test.go */
	tlv := &layers.IPv6HopByHopOption{}
	tlv.OptionType = 0x01 // PadN
	tlv.OptionData = []byte{0x00, 0x00, 0x00, 0x00}
	hop.Options = append(hop.Options, tlv)

	e, ip6, l4, p, b, err := testPacketV6(nil, &ip, tcp, payload, hop)
	return e, ip6, l4.(*layers.TCP), p, b, err
}

func testPacketTCPV6DefaultNP(destIP net.IP, syn bool) (*layers.Ethernet, *layers.IPv6, *layers.TCP, []byte, []byte, error) {
	return testPacketTCPV6WithPayload(destIP, 1234, 5678, syn, nil)
}

func ipv6HopByHopExt() gopacket.SerializableLayer {
	hop := &layers.IPv6HopByHop{}
	hop.NextHeader = layers.IPProtocolUDP

	/* from gopacket ip6_test.go */
	tlv := &layers.IPv6HopByHopOption{}
	tlv.OptionType = 0x01 // PadN
	tlv.OptionData = []byte{0x00, 0x00, 0x00, 0x00}
	hop.Options = append(hop.Options, tlv)

	return hop
}

func testPacketUDPDefaultNP(destIP net.IP) (*layers.Ethernet, *layers.IPv4, gopacket.Layer, []byte, []byte, error) {
	return testPacketUDPDefaultNPWithPayload(destIP, nil)
}

func testPacketUDPDefaultNPV6WithPayload(destIP net.IP, payload []byte) (*layers.Ethernet, *layers.IPv6, gopacket.Layer, []byte, []byte, error) {
	if destIP == nil {
		return testPacketV6(nil, nil, nil, nil)
	}

	ip := *ipv6Default
	ip.DstIP = destIP

	hop := &layers.IPv6HopByHop{}
	hop.NextHeader = layers.IPProtocolUDP

	/* from gopacket ip6_test.go */
	tlv := &layers.IPv6HopByHopOption{}
	tlv.OptionType = 0x01 // PadN
	tlv.OptionData = []byte{0x00, 0x00, 0x00, 0x00}
	hop.Options = append(hop.Options, tlv)

	e, ip6, l4, p, b, err := testPacketV6(nil, &ip, nil, payload, hop)
	return e, ip6, l4, p, b, err
}

func testPacketUDPDefaultNPV6(destIP net.IP) (*layers.Ethernet, *layers.IPv6, gopacket.Layer, []byte, []byte, error) {
	return testPacketUDPDefaultNPV6WithPayload(destIP, nil)
}

func resetBPFMaps() {
	resetCTMap(ctMap)
	resetRTMap(rtMap)
	resetMap(fsafeMap)
	resetMap(natMap)
	resetMap(natBEMap)
	resetMap(qosMap)
	resetMap(maglevMap)
}

func TestMapIterWithDelete(t *testing.T) {
	RegisterTestingT(t)

	m := maps.NewPinnedMap(maps.MapParameters{
		Type:       "hash",
		KeySize:    8,
		ValueSize:  8,
		MaxEntries: 1000,
		Name:       "cali_tmap",
		Flags:      unix.BPF_F_NO_PREALLOC,
	})

	err := m.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	for i := 0; i < 10; i++ {
		var k, v [8]byte

		binary.LittleEndian.PutUint64(k[:], uint64(i))
		binary.LittleEndian.PutUint64(v[:], uint64(i*7))

		err := m.Update(k[:], v[:])
		Expect(err).NotTo(HaveOccurred())
	}

	out := make(map[uint64]uint64)

	cnt := 0
	err = m.Iter(func(K, V []byte) maps.IteratorAction {
		k := binary.LittleEndian.Uint64(K)
		v := binary.LittleEndian.Uint64(V)

		out[k] = v
		cnt++

		return maps.IterDelete
	})
	Expect(err).NotTo(HaveOccurred())

	Expect(cnt).To(Equal(10))

	for i := 0; i < 10; i++ {
		Expect(out).To(HaveKey(uint64(i)))
		Expect(out[uint64(i)]).To(Equal(uint64(i * 7)))
	}
}

func TestMapIterWithDeleteLastOfBatch(t *testing.T) {
	RegisterTestingT(t)

	m := maps.NewPinnedMap(maps.MapParameters{
		Type:       "hash",
		KeySize:    8,
		ValueSize:  8,
		MaxEntries: 4 * maps.IteratorNumKeys,
		Name:       "cali_tmap",
		Flags:      unix.BPF_F_NO_PREALLOC,
	})

	err := m.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	items := 3*maps.IteratorNumKeys + 5

	for i := 0; i < items; i++ {
		var k, v [8]byte

		binary.LittleEndian.PutUint64(k[:], uint64(i))
		binary.LittleEndian.PutUint64(v[:], uint64(i*7))

		err := m.Update(k[:], v[:])
		Expect(err).NotTo(HaveOccurred())
	}

	out := make(map[uint64]uint64)

	cnt := 0
	err = m.Iter(func(K, V []byte) maps.IteratorAction {
		k := binary.LittleEndian.Uint64(K)
		v := binary.LittleEndian.Uint64(V)

		out[k] = v

		cnt++
		// Delete the last of the first batch. Must not make the iteration to
		// restart from the beginning.
		if cnt == maps.IteratorNumKeys {
			return maps.IterDelete
		}
		return maps.IterNone
	})
	Expect(err).NotTo(HaveOccurred())

	Expect(len(out)).To(Equal(items))
	Expect(cnt).To(Equal(items))

	for i := 0; i < items; i++ {
		Expect(out).To(HaveKey(uint64(i)))
		Expect(out[uint64(i)]).To(Equal(uint64(i * 7)))
	}
}

func TestJumpMap(t *testing.T) {
	RegisterTestingT(t)

	progMap = hook.NewProgramsMaps()
	err := progMap[hook.Ingress].EnsureExists()
	Expect(err).NotTo(HaveOccurred())
	err = progMap[hook.Egress].EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	jumpMapFD := progMap[hook.Ingress].MapFD()
	pg := polprog.NewBuilder(idalloc.New(), ipsMap.MapFD(), stateMap.MapFD(), jumpMapFD, policyJumpMap.MapFD(),
		polprog.WithAllowDenyJumps(tcdefs.ProgIndexAllowed, tcdefs.ProgIndexDrop))
	rules := polprog.Rules{}
	insns, err := pg.Instructions(rules)
	Expect(err).NotTo(HaveOccurred())
	Expect(insns).To(HaveLen(1))
	progFD, err := bpf.LoadBPFProgramFromInsns(insns[0], "calico_policy", "Apache-2.0", unix.BPF_PROG_TYPE_SCHED_CLS)
	Expect(err).NotTo(HaveOccurred())

	k := make([]byte, 4)
	v := make([]byte, 4)
	binary.LittleEndian.PutUint32(v, uint32(progFD))

	err = maps.UpdateMapEntry(jumpMapFD, k, v)
	Expect(err).NotTo(HaveOccurred())

	err = maps.DeleteMapEntry(jumpMapFD, k)
	Expect(err).NotTo(HaveOccurred())

	err = maps.UpdateMapEntry(jumpMapFD, k, v)
	Expect(err).NotTo(HaveOccurred())

	err = maps.DeleteMapEntryIfExists(jumpMapFD, k)
	Expect(err).NotTo(HaveOccurred())

	err = maps.DeleteMapEntryIfExists(jumpMapFD, k)
	Expect(err).NotTo(HaveOccurred())

	err = maps.DeleteMapEntry(jumpMapFD, k)
	Expect(err).To(HaveOccurred())
}
