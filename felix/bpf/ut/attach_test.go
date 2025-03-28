// Copyright (c) 2023-2025 Tigera, Inc. All rights reserved.
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

package ut

import (
	"encoding/binary"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/bpf/bpfdefs"
	"github.com/projectcalico/calico/felix/bpf/bpfmap"
	"github.com/projectcalico/calico/felix/bpf/hook"
	"github.com/projectcalico/calico/felix/bpf/ifstate"
	"github.com/projectcalico/calico/felix/bpf/jump"
	"github.com/projectcalico/calico/felix/bpf/maps"
	"github.com/projectcalico/calico/felix/bpf/tc"
	tcdefs "github.com/projectcalico/calico/felix/bpf/tc/defs"
	"github.com/projectcalico/calico/felix/calc"
	linux "github.com/projectcalico/calico/felix/dataplane/linux"
	"github.com/projectcalico/calico/felix/generictables"
	"github.com/projectcalico/calico/felix/idalloc"
	"github.com/projectcalico/calico/felix/ifacemonitor"
	"github.com/projectcalico/calico/felix/ipsets"
	"github.com/projectcalico/calico/felix/logutils"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/routetable"
	"github.com/projectcalico/calico/felix/rules"
)

func newBPFTestEpMgr(
	config *linux.Config,
	bpfmaps *bpfmap.Maps,
	workloadIfaceRegex *regexp.Regexp,
) (linux.ManagerWithHEPUpdate, error) {
	return linux.NewBPFEndpointManager(nil, config, bpfmaps, true, workloadIfaceRegex, idalloc.New(), idalloc.New(),
		rules.NewRenderer(rules.Config{
			BPFEnabled:             true,
			IPIPEnabled:            true,
			IPIPTunnelAddress:      nil,
			IPSetConfigV4:          ipsets.NewIPVersionConfig(ipsets.IPFamilyV4, "cali", nil, nil),
			IPSetConfigV6:          ipsets.NewIPVersionConfig(ipsets.IPFamilyV6, "cali", nil, nil),
			MarkAccept:             0x8,
			MarkPass:               0x10,
			MarkScratch0:           0x20,
			MarkScratch1:           0x40,
			MarkDrop:               0x80,
			MarkEndpoint:           0xff00,
			MarkNonCaliEndpoint:    0x0100,
			KubeIPVSSupportEnabled: true,
			WorkloadIfacePrefixes:  []string{"cali", "tap"},
			VXLANPort:              4789,
			VXLANVNI:               4096,
			FlowLogsEnabled:        config.FlowLogsEnabled,
		}),
		generictables.NewNoopTable(),
		generictables.NewNoopTable(),
		nil,
		logutils.NewSummarizer("test"),
		&routetable.DummyTable{},
		&routetable.DummyTable{},
		calc.NewLookupsCache(),
		nil,
		nil,
		1500,
	)
}

func runAttachTest(t *testing.T, ipv6Enabled bool) {
	bpfmaps, err := bpfmap.CreateBPFMaps(ipv6Enabled)
	Expect(err).NotTo(HaveOccurred())

	commonMaps := bpfmaps.CommonMaps
	programs := commonMaps.ProgramsMap.(*hook.ProgramsMap)
	loglevel := "off"

	bpfEpMgr, err := newBPFTestEpMgr(
		&linux.Config{
			Hostname:              "uthost",
			BPFLogLevel:           loglevel,
			BPFDataIfacePattern:   regexp.MustCompile("^hostep[12]"),
			VXLANMTU:              1000,
			VXLANPort:             1234,
			BPFNodePortDSREnabled: false,
			RulesConfig: rules.Config{
				EndpointToHostAction: "RETURN",
			},
			BPFExtToServiceConnmark: 0,
			FeatureGates: map[string]string{
				"BPFConnectTimeLoadBalancingWorkaround": "enabled",
			},
			BPFPolicyDebugEnabled: true,
			BPFIpv6Enabled:        ipv6Enabled,
		},
		bpfmaps,
		regexp.MustCompile("^workloadep[0123]"),
	)
	Expect(err).NotTo(HaveOccurred())

	host1 := createHostIf("hostep1")
	defer deleteLink(host1)

	workload0 := createVethName("workloadep0")
	defer deleteLink(workload0)

	var hostep1State ifstate.Value

	t.Run("create first host endpoint with untracked (xdp) policy", func(t *testing.T) {
		bpfEpMgr.OnUpdate(linux.NewIfaceStateUpdate("hostep1", ifacemonitor.StateUp, host1.Attrs().Index))
		if ipv6Enabled {
			bpfEpMgr.OnUpdate(linux.NewIfaceStateUpdate("workloadep0", ifacemonitor.StateUp, workload0.Attrs().Index))
		}
		bpfEpMgr.OnUpdate(linux.NewIfaceAddrsUpdate("hostep1", "1.2.3.4"))
		bpfEpMgr.OnUpdate(&proto.HostMetadataUpdate{Hostname: "uthost", Ipv4Addr: "1.2.3.4"})
		err = bpfEpMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		programsCount := 13
		if ipv6Enabled {
			programsCount = 25
		}
		Expect(programs.Count()).To(Equal(programsCount))
		at := programs.Programs()
		Expect(at).To(HaveKey(hook.AttachType{
			Hook:       hook.Ingress,
			Family:     4,
			Type:       tcdefs.EpTypeHost,
			LogLevel:   loglevel,
			FIB:        true,
			ToHostDrop: false,
			DSR:        false}))
		Expect(at).To(HaveKey(hook.AttachType{
			Hook:       hook.Egress,
			Family:     4,
			Type:       tcdefs.EpTypeHost,
			LogLevel:   loglevel,
			FIB:        true,
			ToHostDrop: false,
			DSR:        false}))
		Expect(at).NotTo(HaveKey(hook.AttachType{
			Hook:       hook.Ingress,
			Family:     6,
			Type:       tcdefs.EpTypeHost,
			LogLevel:   loglevel,
			FIB:        true,
			ToHostDrop: false,
			DSR:        false}))
		Expect(at).NotTo(HaveKey(hook.AttachType{
			Hook:       hook.Egress,
			Family:     6,
			Type:       tcdefs.EpTypeHost,
			LogLevel:   loglevel,
			FIB:        true,
			ToHostDrop: false,
			DSR:        false}))

		ifstateMap := ifstateMapDump(commonMaps.IfStateMap)
		Expect(ifstateMap).To(HaveKey(ifstate.NewKey(uint32(host1.Attrs().Index))))
		if ipv6Enabled {
			Expect(ifstateMap).To(HaveKey(ifstate.NewKey(uint32(workload0.Attrs().Index))))
			workloadep0State := ifstateMap[ifstate.NewKey(uint32(workload0.Attrs().Index))]
			Expect(workloadep0State.Flags()).To(Equal(ifstate.FlgWEP | ifstate.FlgIPv4Ready))
		}

		hostep1State = ifstateMap[ifstate.NewKey(uint32(host1.Attrs().Index))]
		Expect(hostep1State.Flags()).To(Equal(ifstate.FlgIPv4Ready | ifstate.FlgHEP))

		if ipv6Enabled {
			// IPv6 address update
			bpfEpMgr.OnUpdate(linux.NewIfaceAddrsUpdate("hostep1", "1::4"))
			bpfEpMgr.OnUpdate(&proto.HostMetadataV6Update{Hostname: "uthost", Ipv6Addr: "1::4"})
			err = bpfEpMgr.CompleteDeferredWork()
			Expect(err).NotTo(HaveOccurred())
			Expect(programs.Count()).To(Equal(50))

			Expect(at).To(HaveKey(hook.AttachType{
				Hook:       hook.Ingress,
				Family:     4,
				Type:       tcdefs.EpTypeHost,
				LogLevel:   loglevel,
				FIB:        true,
				ToHostDrop: false,
				DSR:        false}))
			Expect(at).To(HaveKey(hook.AttachType{
				Hook:       hook.Egress,
				Family:     4,
				Type:       tcdefs.EpTypeHost,
				LogLevel:   loglevel,
				FIB:        true,
				ToHostDrop: false,
				DSR:        false}))
			Expect(at).To(HaveKey(hook.AttachType{
				Hook:       hook.Ingress,
				Family:     6,
				Type:       tcdefs.EpTypeHost,
				LogLevel:   loglevel,
				FIB:        true,
				ToHostDrop: false,
				DSR:        false}))
			Expect(at).To(HaveKey(hook.AttachType{
				Hook:       hook.Egress,
				Family:     6,
				Type:       tcdefs.EpTypeHost,
				LogLevel:   loglevel,
				FIB:        true,
				ToHostDrop: false,
				DSR:        false}))

		}
		bpfEpMgr.OnUpdate(&proto.ActivePolicyUpdate{
			Id:     &proto.PolicyID{Tier: "default", Name: "untracked"},
			Policy: &proto.Policy{Untracked: true},
		})

		bpfEpMgr.OnHEPUpdate(map[string]*proto.HostEndpoint{
			"hostep1": &proto.HostEndpoint{
				Name: "hostep1",
				UntrackedTiers: []*proto.TierInfo{
					&proto.TierInfo{
						Name:            "default",
						IngressPolicies: []string{"untracked"},
					},
				},
			},
		})

		err = bpfEpMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		ifstateMap = ifstateMapDump(commonMaps.IfStateMap)
		Expect(ifstateMap).To(HaveKey(ifstate.NewKey(uint32(host1.Attrs().Index))))

		hostep1State = ifstateMap[ifstate.NewKey(uint32(host1.Attrs().Index))]
		Expect(hostep1State.IngressPolicyV4()).NotTo(Equal(-1))
		Expect(hostep1State.EgressPolicyV4()).NotTo(Equal(-1))
		Expect(hostep1State.XDPPolicyV4()).NotTo(Equal(-1))

		if ipv6Enabled {
			Expect(hostep1State.IngressPolicyV6()).NotTo(Equal(-1))
			Expect(hostep1State.EgressPolicyV6()).NotTo(Equal(-1))
			Expect(hostep1State.XDPPolicyV6()).NotTo(Equal(-1))
			Expect(hostep1State.Flags()).To(Equal(ifstate.FlgIPv4Ready | ifstate.FlgIPv6Ready | ifstate.FlgHEP))
			Expect(ifstateMap).To(HaveKey(ifstate.NewKey(uint32(workload0.Attrs().Index))))
			workloadep0State := ifstateMap[ifstate.NewKey(uint32(workload0.Attrs().Index))]
			Expect(workloadep0State.Flags()).To(Equal(ifstate.FlgWEP | ifstate.FlgIPv4Ready | ifstate.FlgIPv6Ready))

		}

		pm := jumpMapDump(commonMaps.JumpMap)
		Expect(pm).To(HaveKey(hostep1State.IngressPolicyV4()))
		Expect(pm).To(HaveKey(hostep1State.EgressPolicyV4()))

		if ipv6Enabled {
			Expect(pm).To(HaveKey(hostep1State.IngressPolicyV6()))
			Expect(pm).To(HaveKey(hostep1State.EgressPolicyV6()))

		}

		progs, err := bpf.GetAllProgs()
		Expect(err).NotTo(HaveOccurred())
		hasXDP := false
		for _, p := range progs {
			if strings.Contains(p.Name, "cali_xdp_preamb") {
				hasXDP = true
				break
			}
		}
		Expect(hasXDP).To(BeTrue())

		xdppm := jumpMapDump(commonMaps.XDPJumpMap)
		xdpMapLen := 1
		if ipv6Enabled {
			xdpMapLen = 2
		}
		Expect(xdppm).To(HaveLen(xdpMapLen))
		Expect(xdppm).To(HaveKey(hostep1State.XDPPolicyV4()))
		if ipv6Enabled {
			Expect(xdppm).To(HaveKey(hostep1State.XDPPolicyV6()))
		}
	})

	t.Run("remove the untracked (xdp) policy", func(t *testing.T) {
		bpfEpMgr.OnUpdate(&proto.ActivePolicyRemove{
			Id: &proto.PolicyID{Tier: "default", Name: "untracked"},
		})
		bpfEpMgr.OnHEPUpdate(map[string]*proto.HostEndpoint{
			"hostep1": &proto.HostEndpoint{
				Name: "hostep1",
			},
		})

		err = bpfEpMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		xdppm := jumpMapDump(commonMaps.XDPJumpMap)
		Expect(xdppm).To(HaveLen(0))

		_, xdpProgs, err := bpf.ListTcXDPAttachedProgs("hostep1")
		Expect(err).NotTo(HaveOccurred())
		Expect(xdpProgs).To(HaveLen(0))
	})

	host2 := createHostIf("hostep2")
	defer deleteLink(host2)

	t.Run("create another host interface without a host endpoint (no policy)", func(t *testing.T) {
		bpfEpMgr.OnUpdate(linux.NewIfaceStateUpdate("hostep2", ifacemonitor.StateUp, host2.Attrs().Index))
		bpfEpMgr.OnUpdate(linux.NewIfaceAddrsUpdate("hostep2", "4.3.2.1"))
		err := bpfEpMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		programCount := 13
		jumpMapLen := 2
		if ipv6Enabled {
			programCount = 50
			jumpMapLen = 8
		}
		Expect(programs.Count()).To(Equal(programCount))

		pm := jumpMapDump(commonMaps.JumpMap)
		Expect(len(pm)).To(Equal(jumpMapLen)) // no policy for hep2
	})

	workload1 := createVethName("workloadep1")
	defer deleteLink(workload1)

	t.Run("create a workload", func(t *testing.T) {
		bpfEpMgr.OnUpdate(linux.NewIfaceStateUpdate("workloadep1", ifacemonitor.StateUp, workload1.Attrs().Index))
		bpfEpMgr.OnUpdate(linux.NewIfaceAddrsUpdate("workloadep1", "1.6.6.6"))
		err = bpfEpMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		programsCount := 25
		if ipv6Enabled {
			programsCount = 50
		}
		Expect(programs.Count()).To(Equal(programsCount))

		at := programs.Programs()
		Expect(at).To(HaveKey(hook.AttachType{
			Hook:       hook.Ingress,
			Family:     4,
			Type:       tcdefs.EpTypeWorkload,
			LogLevel:   loglevel,
			FIB:        true,
			ToHostDrop: false,
			DSR:        false}))
		Expect(at).To(HaveKey(hook.AttachType{
			Hook:       hook.Egress,
			Family:     4,
			Type:       tcdefs.EpTypeWorkload,
			LogLevel:   loglevel,
			FIB:        true,
			ToHostDrop: false,
			DSR:        false}))
		if ipv6Enabled {
			Expect(at).To(HaveKey(hook.AttachType{
				Hook:       hook.Ingress,
				Family:     6,
				Type:       tcdefs.EpTypeWorkload,
				LogLevel:   loglevel,
				FIB:        true,
				ToHostDrop: false,
				DSR:        false}))
			Expect(at).To(HaveKey(hook.AttachType{
				Hook:       hook.Egress,
				Family:     6,
				Type:       tcdefs.EpTypeWorkload,
				LogLevel:   loglevel,
				FIB:        true,
				ToHostDrop: false,
				DSR:        false}))
		}

		ifstateMap := ifstateMapDump(commonMaps.IfStateMap)
		wl1State := ifstateMap[ifstate.NewKey(uint32(workload1.Attrs().Index))]
		Expect(wl1State.IngressPolicyV4()).NotTo(Equal(-1))
		Expect(wl1State.EgressPolicyV4()).NotTo(Equal(-1))
		Expect(wl1State.XDPPolicyV4()).To(Equal(-1))

		pm := jumpMapDump(commonMaps.JumpMap)
		Expect(pm).To(HaveKey(wl1State.IngressPolicyV4()))
		Expect(pm).To(HaveKey(wl1State.EgressPolicyV4()))
		if ipv6Enabled {
			Expect(wl1State.IngressPolicyV6()).NotTo(Equal(-1))
			Expect(wl1State.EgressPolicyV6()).NotTo(Equal(-1))
			Expect(wl1State.XDPPolicyV6()).To(Equal(-1))

			Expect(pm).To(HaveKey(wl1State.IngressPolicyV6()))
			Expect(pm).To(HaveKey(wl1State.EgressPolicyV6()))
		}
	})

	workload2 := createVethName("workloadep2")
	defer deleteLink(workload2)

	t.Run("create another workload, should not load more than the preable", func(t *testing.T) {
		bpfEpMgr.OnUpdate(linux.NewIfaceStateUpdate("workloadep2", ifacemonitor.StateUp, workload2.Attrs().Index))
		bpfEpMgr.OnUpdate(linux.NewIfaceAddrsUpdate("workloadep2", "1.6.6.1"))
		err := bpfEpMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		programsCount := 25
		jumpMapLen := 6

		if ipv6Enabled {
			programsCount = 50
			jumpMapLen = 16
		}
		Expect(programs.Count()).To(Equal(programsCount))

		pm := jumpMapDump(commonMaps.JumpMap)
		Expect(len(pm)).To(Equal((jumpMapLen)))
	})

	t.Run("bring first host ep down, should clean up its policies", func(t *testing.T) {
		bpfEpMgr.OnUpdate(linux.NewIfaceStateUpdate("hostep1", ifacemonitor.StateDown, host1.Attrs().Index))

		err := bpfEpMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		pm := jumpMapDump(commonMaps.JumpMap)
		// We remember the state from above
		Expect(pm).NotTo(HaveKey(hostep1State.IngressPolicyV4()))
		Expect(pm).NotTo(HaveKey(hostep1State.EgressPolicyV4()))

		if ipv6Enabled {
			Expect(pm).NotTo(HaveKey(hostep1State.IngressPolicyV6()))
			Expect(pm).NotTo(HaveKey(hostep1State.EgressPolicyV6()))
		}
		xdppm := jumpMapDump(commonMaps.XDPJumpMap)
		Expect(xdppm).To(HaveLen(0))
	})

	var wl1State ifstate.Value

	t.Run("change workload policy - should apply the changes", func(t *testing.T) {
		ifstateMap := ifstateMapDump(commonMaps.IfStateMap)
		wl1State = ifstateMap[ifstate.NewKey(uint32(workload1.Attrs().Index))]
		fmt.Printf("wl1State = %+v\n", wl1State)

		pm := jumpMapDump(commonMaps.JumpMap)
		wl1IngressPol := pm[wl1State.IngressPolicyV4()]
		wl1EgressPol := pm[wl1State.EgressPolicyV4()]

		bpfEpMgr.OnUpdate(&proto.WorkloadEndpointUpdate{
			Id: &proto.WorkloadEndpointID{
				OrchestratorId: "k8s",
				WorkloadId:     "workloadep1",
				EndpointId:     "workloadep1",
			},
			Endpoint: &proto.WorkloadEndpoint{Name: "workloadep1"},
		})
		bpfEpMgr.OnUpdate(&proto.ActivePolicyUpdate{
			Id: &proto.PolicyID{Tier: "default", Name: "wl1-policy"},
			Policy: &proto.Policy{
				Namespace: "default",
				InboundRules: []*proto.Rule{&proto.Rule{
					Action:   "allow",
					Protocol: &proto.Protocol{NumberOrName: &proto.Protocol_Name{Name: "tcp"}},
					DstNet:   []string{"1.6.6.6/32"},
				}},
			},
		})
		err := bpfEpMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		// Policy indexes did not change ...
		ifstateMap2 := ifstateMapDump(commonMaps.IfStateMap)
		wl1State2 := ifstateMap2[ifstate.NewKey(uint32(workload1.Attrs().Index))]
		Expect(wl1State2).To(Equal(wl1State))

		// ... but the policy programs changed
		pm = jumpMapDump(commonMaps.JumpMap)
		Expect(wl1IngressPol).NotTo(Equal(pm[wl1State2.IngressPolicyV4()]))
		Expect(wl1EgressPol).NotTo(Equal(pm[wl1State2.IngressPolicyV4()]))

		progs, err := bpf.GetAllProgs()
		Expect(err).NotTo(HaveOccurred())
		for _, p := range progs {
			Expect(p.Id != wl1IngressPol && p.Id != wl1EgressPol).To(BeTrue(), "old workload policy is still present")
		}
	})

	t.Run("bring first workload iface down, should clean up its policies", func(t *testing.T) {
		bpfEpMgr.OnUpdate(linux.NewIfaceStateUpdate("workloadep1", ifacemonitor.StateDown, host1.Attrs().Index))

		err := bpfEpMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		pm := jumpMapDump(commonMaps.JumpMap)
		// We remember the state from above
		Expect(pm).NotTo(HaveKey(wl1State.IngressPolicyV4()))
		Expect(pm).NotTo(HaveKey(wl1State.EgressPolicyV4()))
	})

	t.Run("restart", func(t *testing.T) {
		// First create wl3 and remove the device before restart

		workload3 := createVethName("workloadep3")
		bpfEpMgr.OnUpdate(linux.NewIfaceStateUpdate("workloadep3", ifacemonitor.StateUp, workload3.Attrs().Index))
		bpfEpMgr.OnUpdate(linux.NewIfaceAddrsUpdate("workloadep3", "1.6.6.8"))
		err = bpfEpMgr.CompleteDeferredWork()

		if err != nil {
			deleteLink(workload3)
		}

		Expect(err).NotTo(HaveOccurred())
		ifstateMap := ifstateMapDump(commonMaps.IfStateMap)
		wl2State := ifstateMap[ifstate.NewKey(uint32(workload2.Attrs().Index))]
		Expect(ifstateMap).To(HaveKey(ifstate.NewKey(uint32(workload3.Attrs().Index))))

		deleteLink(workload3)

		attached, err := bpf.ListCalicoAttached()
		Expect(err).NotTo(HaveOccurred())
		Expect(attached).To(HaveKey("workloadep1"))
		Expect(attached).To(HaveKey("workloadep2"))
		Expect(attached).To(HaveKey("hostep1"))
		Expect(attached).To(HaveKey("hostep2"))
		Expect(attached).NotTo(HaveKey("workloadep3"))

		programs.ResetCount() // Because we recycle it, restarted Felix would get a fresh copy.

		bpfEpMgr, err = newBPFTestEpMgr(
			&linux.Config{
				Hostname:              "uthost",
				BPFLogLevel:           loglevel,
				BPFDataIfacePattern:   regexp.MustCompile("^hostep[12]"),
				VXLANMTU:              1000,
				VXLANPort:             1234,
				BPFNodePortDSREnabled: false,
				RulesConfig: rules.Config{
					EndpointToHostAction: "RETURN",
				},
				BPFExtToServiceConnmark: 0,
				FeatureGates: map[string]string{
					"BPFConnectTimeLoadBalancingWorkaround": "enabled",
				},
				BPFPolicyDebugEnabled: true,
			},
			bpfmaps,
			regexp.MustCompile("^workloadep[123]"),
		)
		Expect(err).NotTo(HaveOccurred())

		// Existing maps are repinned
		oldBase := path.Join(bpfdefs.GlobalPinDir, "old_jumps")
		_, err = os.Stat(path.Join(bpfdefs.GlobalPinDir, "old_jumps"))
		Expect(err).NotTo(HaveOccurred())

		var tmp string
		err = filepath.Walk(oldBase, func(path string, info fs.FileInfo, err error) error {
			if len(path) > len(oldBase) {
				tmp = path
				return filepath.SkipDir
			}
			return nil
		})
		Expect(err).NotTo(HaveOccurred())

		// And they still have the same data so that existing preamble programs
		// and policies can still point to the right stuff.
		oldProgsParams := hook.ProgramsMapParameters
		oldProgsParams.PinDir = tmp
		oldProgs := maps.NewPinnedMap(oldProgsParams)
		err = oldProgs.Open()
		Expect(err).NotTo(HaveOccurred())
		pm := jumpMapDump(oldProgs)
		programsCount := 25
		oldPoliciesCount := 4
		if ipv6Enabled {
			programsCount = 50
			oldPoliciesCount = 12
		}
		Expect(pm).To(HaveLen(programsCount))

		oldPoliciesParams := jump.MapParameters
		oldPoliciesParams.PinDir = tmp
		oldPolicies := maps.NewPinnedMap(oldPoliciesParams)
		err = oldPolicies.Open()
		Expect(err).NotTo(HaveOccurred())
		pm = jumpMapDump(oldPolicies)
		Expect(pm).To(HaveLen(oldPoliciesCount))

		// After restat we get new maps which are empty
		Expect(programs.Count()).To(Equal(0))
		pm = jumpMapDump(commonMaps.ProgramsMap)
		Expect(pm).To(HaveLen(0))
		pm = jumpMapDump(commonMaps.JumpMap)
		Expect(pm).To(HaveLen(0))

		err = bpfEpMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		// We got no new updates, we still have the same programs attached
		attached2, err := bpf.ListCalicoAttached()
		Expect(err).NotTo(HaveOccurred())
		Expect(attached2).To(Equal(attached))

		bpfEpMgr.OnUpdate(&proto.HostMetadataUpdate{Hostname: "uthost", Ipv4Addr: "1.2.3.4"})
		bpfEpMgr.OnUpdate(linux.NewIfaceStateUpdate("workloadep2", ifacemonitor.StateUp, workload2.Attrs().Index))
		bpfEpMgr.OnUpdate(linux.NewIfaceAddrsUpdate("workloadep2", "1.6.6.1"))
		bpfEpMgr.OnUpdate(linux.NewIfaceStateUpdate("hostep2", ifacemonitor.StateUp, host2.Attrs().Index))
		bpfEpMgr.OnUpdate(linux.NewIfaceAddrsUpdate("hostep2", "4.3.2.1"))
		err = bpfEpMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		Expect(programs.Count()).To(Equal(25))
		pm = jumpMapDump(commonMaps.ProgramsMap)
		Expect(pm).To(HaveLen(25))

		pm = jumpMapDump(commonMaps.JumpMap)
		// We remember the state from above
		Expect(pm).To(HaveLen(2))
		Expect(pm).To(HaveKey(wl2State.IngressPolicyV4()))
		Expect(pm).To(HaveKey(wl2State.EgressPolicyV4()))

		_, err = os.Stat(path.Join(bpfdefs.GlobalPinDir, "old_jumps"))
		Expect(err).To(HaveOccurred())

		attachedNew, err := bpf.ListCalicoAttached()
		Expect(err).NotTo(HaveOccurred())
		// All programs are replaced by now
		// XXX down infaces are not removed yet
		for _, iface := range []string{"hostep2", "workloadep2"} {
			Expect(attachedNew).To(HaveKey(iface))
			Expect(attached[iface].Ingress).NotTo(Equal(attachedNew[iface].Ingress))
			Expect(attached[iface].Egress).NotTo(Equal(attachedNew[iface].Egress))
		}
	})

	t.Run("restart - CompleteDeferredWork at once", func(t *testing.T) {
		// First create wl3 and remove the device before restart

		workload3 := createVethName("workloadep3")
		bpfEpMgr.OnUpdate(linux.NewIfaceStateUpdate("workloadep3", ifacemonitor.StateUp, workload3.Attrs().Index))
		bpfEpMgr.OnUpdate(linux.NewIfaceAddrsUpdate("workloadep3", "1.6.6.8"))
		err = bpfEpMgr.CompleteDeferredWork()

		if err != nil {
			deleteLink(workload3)
		}

		Expect(err).NotTo(HaveOccurred())
		ifstateMap := ifstateMapDump(commonMaps.IfStateMap)
		wl2State := ifstateMap[ifstate.NewKey(uint32(workload2.Attrs().Index))]
		Expect(ifstateMap).To(HaveKey(ifstate.NewKey(uint32(workload3.Attrs().Index))))

		deleteLink(workload3)

		programs.ResetCount() // Because we recycle it, restarted Felix would get a fresh copy.

		bpfEpMgr, err = newBPFTestEpMgr(
			&linux.Config{
				Hostname:              "uthost",
				BPFLogLevel:           loglevel,
				BPFDataIfacePattern:   regexp.MustCompile("^hostep[12]"),
				VXLANMTU:              1000,
				VXLANPort:             1234,
				BPFNodePortDSREnabled: false,
				RulesConfig: rules.Config{
					EndpointToHostAction: "RETURN",
				},
				BPFExtToServiceConnmark: 0,
				FeatureGates: map[string]string{
					"BPFConnectTimeLoadBalancingWorkaround": "enabled",
				},
				BPFPolicyDebugEnabled: true,
			},
			bpfmaps,
			regexp.MustCompile("^workloadep[123]"),
		)
		Expect(err).NotTo(HaveOccurred())

		pm := jumpMapDump(commonMaps.JumpMap)
		Expect(pm).To(HaveLen(0))

		bpfEpMgr.OnUpdate(&proto.HostMetadataUpdate{Hostname: "uthost", Ipv4Addr: "1.2.3.4"})
		bpfEpMgr.OnUpdate(linux.NewIfaceStateUpdate("workloadep2", ifacemonitor.StateUp, workload2.Attrs().Index))
		bpfEpMgr.OnUpdate(linux.NewIfaceAddrsUpdate("workloadep2", "1.6.6.1"))
		bpfEpMgr.OnUpdate(linux.NewIfaceStateUpdate("hostep2", ifacemonitor.StateUp, host2.Attrs().Index))
		bpfEpMgr.OnUpdate(linux.NewIfaceAddrsUpdate("hostep2", "4.3.2.1"))
		err = bpfEpMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		pm = jumpMapDump(commonMaps.JumpMap)
		// We remember the state from above
		Expect(pm).To(HaveLen(2))
		Expect(pm).To(HaveKey(wl2State.IngressPolicyV4()))
		Expect(pm).To(HaveKey(wl2State.EgressPolicyV4()))
	})
}

func TestAttach(t *testing.T) {
	RegisterTestingT(t)
	runAttachTest(t, false)
	runAttachTest(t, true)
}

// This test simulates workload updates like changing labels, annotations.
// Expectation is that multiple workload updates should still result in
// preamble program not getting re-attached.
func TestAttachWithMultipleWorkloadUpdate(t *testing.T) {
	RegisterTestingT(t)

	bpfmaps, err := bpfmap.CreateBPFMaps(false)
	Expect(err).NotTo(HaveOccurred())

	commonMaps := bpfmaps.CommonMaps
	programs := commonMaps.ProgramsMap.(*hook.ProgramsMap)
	loglevel := "off"

	bpfEpMgr, err := newBPFTestEpMgr(
		&linux.Config{
			Hostname:              "uthost",
			BPFLogLevel:           loglevel,
			BPFDataIfacePattern:   regexp.MustCompile("^hostep[12]"),
			VXLANMTU:              1000,
			VXLANPort:             1234,
			BPFNodePortDSREnabled: false,
			RulesConfig: rules.Config{
				EndpointToHostAction: "RETURN",
			},
			BPFExtToServiceConnmark: 0,
			FeatureGates: map[string]string{
				"BPFConnectTimeLoadBalancingWorkaround": "enabled",
			},
			BPFPolicyDebugEnabled: true,
		},
		bpfmaps,
		regexp.MustCompile("^workloadep[123]"),
	)
	Expect(err).NotTo(HaveOccurred())

	workload1 := createVethName("workloadep1")
	defer deleteLink(workload1)

	bpfEpMgr.OnUpdate(&proto.HostMetadataUpdate{Hostname: "uthost", Ipv4Addr: "1.2.3.4"})
	bpfEpMgr.OnUpdate(linux.NewIfaceStateUpdate("workloadep1", ifacemonitor.StateUp, workload1.Attrs().Index))
	bpfEpMgr.OnUpdate(linux.NewIfaceAddrsUpdate("workloadep1", "1.6.6.6"))
	bpfEpMgr.OnUpdate(&proto.WorkloadEndpointUpdate{
		Id: &proto.WorkloadEndpointID{
			OrchestratorId: "k8s",
			WorkloadId:     "workloadep1",
			EndpointId:     "workloadep1",
		},
		Endpoint: &proto.WorkloadEndpoint{Name: "workloadep1"},
	})
	err = bpfEpMgr.CompleteDeferredWork()
	Expect(err).NotTo(HaveOccurred())

	valid, firstPrio, firstHandle := bpfEpMgr.GetIfaceQDiscInfo("workloadep1")
	Expect(valid).To(BeTrue())
	Expect(firstPrio).To(BeNumerically(">", 0))
	Expect(firstHandle).To(BeNumerically(">", 0))

	at := programs.Programs()
	Expect(at).To(HaveKey(hook.AttachType{
		Hook:       hook.Ingress,
		Family:     4,
		Type:       tcdefs.EpTypeWorkload,
		LogLevel:   loglevel,
		FIB:        true,
		ToHostDrop: false,
		DSR:        false}))
	Expect(at).To(HaveKey(hook.AttachType{
		Hook:       hook.Egress,
		Family:     4,
		Type:       tcdefs.EpTypeWorkload,
		LogLevel:   loglevel,
		FIB:        true,
		ToHostDrop: false,
		DSR:        false}))

	// The expectation is that, WorkloadEndpointUpdates must not
	// result in re-attaching the program. Hence the priority, handle of
	// the tc filters must be the same.
	for i := 0; i < 2; i++ {
		bpfEpMgr.OnUpdate(&proto.WorkloadEndpointUpdate{
			Id: &proto.WorkloadEndpointID{
				OrchestratorId: "k8s",
				WorkloadId:     "workloadep1",
				EndpointId:     "workloadep1",
			},
			Endpoint: &proto.WorkloadEndpoint{Name: "workloadep1"},
		})
		err = bpfEpMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())
		valid, prio, handle := bpfEpMgr.GetIfaceQDiscInfo("workloadep1")
		Expect(valid).To(BeTrue())
		Expect(prio).To(Equal(firstPrio))
		Expect(handle).To(Equal(firstHandle))
	}

}

// This test verifies that we use the same tc priority but toggle between
// handles when repeatedly attaching the preamble program.
func TestRepeatedAttach(t *testing.T) {
	RegisterTestingT(t)

	iface, veth := createVeth()
	defer func() {
		deleteLink(veth)
	}()

	ap := &tc.AttachPoint{
		AttachPoint: bpf.AttachPoint{
			Iface: iface,
			Hook:  hook.Ingress,
		},
		HostIPv4: net.IPv4(8, 8, 8, 8),
		IntfIPv4: net.IPv4(7, 7, 7, 7),
	}

	_, err := tc.EnsureQdisc(iface)
	Expect(err).NotTo(HaveOccurred(), "failed to create qdisc")
	res, err := ap.AttachProgram()
	Expect(err).NotTo(HaveOccurred(), "failed to attach preamble")
	tcRes, ok := res.(tc.AttachResult)
	Expect(ok).To(BeTrue())
	prio := tcRes.Prio()
	handle := tcRes.Handle()
	for i := 0; i < 3; i++ {
		res, err = ap.AttachProgram()
		Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("failed to attach preamble : %d", i))
		tcRes, ok = res.(tc.AttachResult)
		Expect(ok).To(BeTrue())
		Expect(tcRes.Prio()).To(Equal(prio))
		if i%2 == 0 {
			Expect(tcRes.Handle()).To(Equal(handle + 1))
		} else {
			Expect(tcRes.Handle()).To(Equal(handle))
		}
	}
}

func TestLogFilters(t *testing.T) {
	RegisterTestingT(t)

	bpfmaps, err := bpfmap.CreateBPFMaps(false)
	Expect(err).NotTo(HaveOccurred())

	commonMaps := bpfmaps.CommonMaps

	cfg := linux.Config{
		Hostname:              "uthost",
		BPFLogLevel:           "debug",
		BPFDataIfacePattern:   regexp.MustCompile("^hostep[12]"),
		VXLANMTU:              1000,
		VXLANPort:             1234,
		BPFNodePortDSREnabled: false,
		RulesConfig: rules.Config{
			EndpointToHostAction: "RETURN",
		},
		BPFExtToServiceConnmark: 0,
		FeatureGates: map[string]string{
			"BPFConnectTimeLoadBalancingWorkaround": "enabled",
		},
		BPFPolicyDebugEnabled: true,
		BPFLogFilters:         map[string]string{"hostep1": "tcp"},
	}

	bpfEpMgr, err := newBPFTestEpMgr(
		&cfg,
		bpfmaps,
		regexp.MustCompile("^workloadep[0123]"),
	)
	Expect(err).NotTo(HaveOccurred())

	host1 := createHostIf("hostep1")
	defer deleteLink(host1)

	workload0 := createVethName("workloadep0")
	defer deleteLink(workload0)

	t.Run("load filter", func(t *testing.T) {
		bpfEpMgr.OnUpdate(linux.NewIfaceStateUpdate("hostep1", ifacemonitor.StateUp, host1.Attrs().Index))
		bpfEpMgr.OnUpdate(linux.NewIfaceStateUpdate("workloadep0", ifacemonitor.StateUp, workload0.Attrs().Index))
		bpfEpMgr.OnUpdate(linux.NewIfaceAddrsUpdate("hostep1", "1.2.3.4"))
		bpfEpMgr.OnUpdate(&proto.HostMetadataUpdate{Hostname: "uthost", Ipv4Addr: "1.2.3.4"})
		err = bpfEpMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		ifstateMap := ifstateMapDump(commonMaps.IfStateMap)

		Expect(ifstateMap).To(HaveKey(ifstate.NewKey(uint32(host1.Attrs().Index))))
		hostep1State := ifstateMap[ifstate.NewKey(uint32(host1.Attrs().Index))]
		Expect(hostep1State.TcIngressFilter()).NotTo(Equal(-1))
		Expect(hostep1State.TcEgressFilter()).NotTo(Equal(-1))

		Expect(ifstateMap).To(HaveKey(ifstate.NewKey(uint32(workload0.Attrs().Index))))
		wl0State := ifstateMap[ifstate.NewKey(uint32(workload0.Attrs().Index))]
		Expect(wl0State.TcIngressFilter()).To(Equal(-1))
		Expect(wl0State.TcEgressFilter()).To(Equal(-1))
	})

	cfg.BPFLogLevel = "off"

	bpfEpMgr, err = newBPFTestEpMgr(
		&cfg,
		bpfmaps,
		regexp.MustCompile("^workloadep[0123]"),
	)
	Expect(err).NotTo(HaveOccurred())

	t.Run("after restart, load filter", func(t *testing.T) {
		bpfEpMgr.OnUpdate(linux.NewIfaceStateUpdate("hostep1", ifacemonitor.StateUp, host1.Attrs().Index))
		bpfEpMgr.OnUpdate(linux.NewIfaceStateUpdate("workloadep0", ifacemonitor.StateUp, workload0.Attrs().Index))
		bpfEpMgr.OnUpdate(linux.NewIfaceAddrsUpdate("hostep1", "1.2.3.4"))
		bpfEpMgr.OnUpdate(&proto.HostMetadataUpdate{Hostname: "uthost", Ipv4Addr: "1.2.3.4"})
		err = bpfEpMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		ifstateMap := ifstateMapDump(commonMaps.IfStateMap)

		Expect(ifstateMap).To(HaveKey(ifstate.NewKey(uint32(host1.Attrs().Index))))
		hostep1State := ifstateMap[ifstate.NewKey(uint32(host1.Attrs().Index))]
		Expect(hostep1State.TcIngressFilter()).To(Equal(-1))
		Expect(hostep1State.TcEgressFilter()).To(Equal(-1))

		Expect(ifstateMap).To(HaveKey(ifstate.NewKey(uint32(workload0.Attrs().Index))))
		wl0State := ifstateMap[ifstate.NewKey(uint32(workload0.Attrs().Index))]
		Expect(wl0State.TcIngressFilter()).To(Equal(-1))
		Expect(wl0State.TcEgressFilter()).To(Equal(-1))
	})
}

func ifstateMapDump(m maps.Map) ifstate.MapMem {
	ifstateMap := make(ifstate.MapMem)
	ifstateMapIter := ifstate.MapMemIter(ifstateMap)
	_ = m.Iter(func(k, v []byte) maps.IteratorAction {
		ifstateMapIter(k, v)
		return maps.IterNone
	})

	return ifstateMap
}

func jumpMapDump(m maps.Map) map[int]int {
	jumpMap := make(map[int]int)

	for i := 0; i < 100; i++ {
		if v, err := m.Get(jump.Key(i) /* a good key for any jump map */); err == nil {
			jumpMap[i] = int(binary.LittleEndian.Uint32(v))
		}
	}

	return jumpMap
}

func BenchmarkAttachProgram(b *testing.B) {
	RegisterTestingT(b)

	b.StopTimer()

	vethName, veth := createVeth()
	defer deleteLink(veth)

	_, err := tc.EnsureQdisc(vethName)
	Expect(err).NotTo(HaveOccurred())

	ap := tc.AttachPoint{
		AttachPoint: bpf.AttachPoint{
			Hook:     hook.Egress,
			Iface:    vethName,
			LogLevel: "off",
		},
		Type:     tcdefs.EpTypeWorkload,
		ToOrFrom: tcdefs.FromEp,
		FIB:      true,
		HostIPv4: net.IPv4(1, 1, 1, 1),
		IntfIPv4: net.IPv4(1, 1, 1, 1),
	}

	_, err = ap.AttachProgram()
	Expect(err).NotTo(HaveOccurred())

	logLevel := log.GetLevel()
	log.SetLevel(log.PanicLevel)
	defer log.SetLevel(logLevel)

	b.StartTimer()

	for n := 0; n < b.N; n++ {
		_, err := ap.AttachProgram()
		if err != nil {
			b.Fatalf("AttachProgram failed: %s", err)
		}
	}
}
