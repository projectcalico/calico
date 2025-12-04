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

package ut_test

import (
	"encoding/binary"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/bpf/bpfdefs"
	"github.com/projectcalico/calico/felix/bpf/bpfmap"
	"github.com/projectcalico/calico/felix/bpf/hook"
	"github.com/projectcalico/calico/felix/bpf/ifstate"
	"github.com/projectcalico/calico/felix/bpf/jump"
	"github.com/projectcalico/calico/felix/bpf/maps"
	"github.com/projectcalico/calico/felix/bpf/nat"
	"github.com/projectcalico/calico/felix/bpf/qos"
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
	return linux.NewBPFEndpointManager(nil, config, bpfmaps, workloadIfaceRegex, idalloc.New(), idalloc.New(),
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
	programsIng := commonMaps.ProgramsMaps[hook.Ingress].(*hook.ProgramsMap)
	programsEg := commonMaps.ProgramsMaps[hook.Egress].(*hook.ProgramsMap)
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
			BPFPolicyDebugEnabled:   true,
			BPFIpv6Enabled:          ipv6Enabled,
			BPFAttachType:           "TCX",
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

		programsIngCount := 8
		programsEgCount := 7
		if ipv6Enabled {
			programsIngCount = 15
			programsEgCount = 13
		}
		Expect(programsIng.Count()).To(Equal(programsIngCount))
		Expect(programsEg.Count()).To(Equal(programsEgCount))
		atIng := programsIng.Programs()
		atEg := programsEg.Programs()
		Expect(atIng).To(HaveKey(hook.AttachType{
			Hook:       hook.Ingress,
			Family:     4,
			Type:       tcdefs.EpTypeHost,
			LogLevel:   loglevel,
			ToHostDrop: false,
			DSR:        false,
		}))
		Expect(atEg).To(HaveKey(hook.AttachType{
			Hook:       hook.Egress,
			Family:     4,
			Type:       tcdefs.EpTypeHost,
			LogLevel:   loglevel,
			ToHostDrop: false,
			DSR:        false,
		}))
		Expect(atIng).NotTo(HaveKey(hook.AttachType{
			Hook:       hook.Ingress,
			Family:     6,
			Type:       tcdefs.EpTypeHost,
			LogLevel:   loglevel,
			ToHostDrop: false,
			DSR:        false,
		}))
		Expect(atEg).NotTo(HaveKey(hook.AttachType{
			Hook:       hook.Egress,
			Family:     6,
			Type:       tcdefs.EpTypeHost,
			LogLevel:   loglevel,
			ToHostDrop: false,
			DSR:        false,
		}))

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
			Expect(programsIng.Count()).To(Equal(28))

			atIng := programsIng.Programs()
			atEg := programsEg.Programs()

			Expect(atIng).To(HaveKey(hook.AttachType{
				Hook:       hook.Ingress,
				Family:     4,
				Type:       tcdefs.EpTypeHost,
				LogLevel:   loglevel,
				ToHostDrop: false,
				DSR:        false,
			}))
			Expect(atEg).To(HaveKey(hook.AttachType{
				Hook:       hook.Egress,
				Family:     4,
				Type:       tcdefs.EpTypeHost,
				LogLevel:   loglevel,
				ToHostDrop: false,
				DSR:        false,
			}))
			Expect(atIng).To(HaveKey(hook.AttachType{
				Hook:       hook.Ingress,
				Family:     6,
				Type:       tcdefs.EpTypeHost,
				LogLevel:   loglevel,
				ToHostDrop: false,
				DSR:        false,
			}))
			Expect(atEg).To(HaveKey(hook.AttachType{
				Hook:       hook.Egress,
				Family:     6,
				Type:       tcdefs.EpTypeHost,
				LogLevel:   loglevel,
				ToHostDrop: false,
				DSR:        false,
			}))

		}
		bpfEpMgr.OnUpdate(&proto.ActivePolicyUpdate{
			Id:     &proto.PolicyID{Name: "untracked"},
			Policy: &proto.Policy{Tier: "default", Untracked: true},
		})

		bpfEpMgr.OnHEPUpdate(map[string]*proto.HostEndpoint{
			"hostep1": {
				Name: "hostep1",
				UntrackedTiers: []*proto.TierInfo{
					{
						Name:            "default",
						IngressPolicies: []*proto.PolicyID{{Name: "untracked", Kind: v3.KindGlobalNetworkPolicy}},
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

		pmIng := jumpMapDump(commonMaps.JumpMaps[hook.Ingress])
		pmEgr := jumpMapDump(commonMaps.JumpMaps[hook.Egress])
		Expect(pmIng).To(HaveKey(hostep1State.IngressPolicyV4()))
		Expect(pmEgr).To(HaveKey(hostep1State.EgressPolicyV4()))

		if ipv6Enabled {
			Expect(pmIng).To(HaveKey(hostep1State.IngressPolicyV6()))
			Expect(pmEgr).To(HaveKey(hostep1State.EgressPolicyV6()))

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
			Id: &proto.PolicyID{Name: "untracked"},
		})
		bpfEpMgr.OnHEPUpdate(map[string]*proto.HostEndpoint{
			"hostep1": {
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

		programIngCount := 8
		programEgCount := 7
		jumpMapLen := 1
		if ipv6Enabled {
			programIngCount = 28
			programEgCount = 26
			jumpMapLen = 4
		}
		Expect(programsIng.Count()).To(Equal(programIngCount))
		Expect(programsEg.Count()).To(Equal(programEgCount))

		pmIng := jumpMapDump(commonMaps.JumpMaps[hook.Ingress])
		pmEgr := jumpMapDump(commonMaps.JumpMaps[hook.Egress])
		Expect(len(pmIng)).To(Equal(jumpMapLen)) // no policy for hep2
		Expect(len(pmEgr)).To(Equal(jumpMapLen)) // no policy for hep2
	})

	workload1 := createVethName("workloadep1")
	defer deleteLink(workload1)

	t.Run("create a workload", func(t *testing.T) {
		programsIngCount := programsIng.Count()
		programsEgCount := programsEg.Count()
		bpfEpMgr.OnUpdate(linux.NewIfaceStateUpdate("workloadep1", ifacemonitor.StateUp, workload1.Attrs().Index))
		bpfEpMgr.OnUpdate(linux.NewIfaceAddrsUpdate("workloadep1", "1.6.6.6"))
		err = bpfEpMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		programsIngCount = programsIngCount + 7
		programsEgCount = programsEgCount + 6
		if ipv6Enabled {
			programsIngCount = 28
			programsEgCount = 26
		}
		Expect(programsIng.Count()).To(Equal(programsIngCount))
		Expect(programsEg.Count()).To(Equal(programsEgCount))

		atIng := programsIng.Programs()
		atEg := programsEg.Programs()
		Expect(atIng).To(HaveKey(hook.AttachType{
			Hook:       hook.Ingress,
			Family:     4,
			Type:       tcdefs.EpTypeWorkload,
			LogLevel:   loglevel,
			ToHostDrop: false,
			DSR:        false,
		}))
		Expect(atEg).To(HaveKey(hook.AttachType{
			Hook:       hook.Egress,
			Family:     4,
			Type:       tcdefs.EpTypeWorkload,
			LogLevel:   loglevel,
			ToHostDrop: false,
			DSR:        false,
		}))
		if ipv6Enabled {
			Expect(atIng).To(HaveKey(hook.AttachType{
				Hook:       hook.Ingress,
				Family:     6,
				Type:       tcdefs.EpTypeWorkload,
				LogLevel:   loglevel,
				ToHostDrop: false,
				DSR:        false,
			}))
			Expect(atEg).To(HaveKey(hook.AttachType{
				Hook:       hook.Egress,
				Family:     6,
				Type:       tcdefs.EpTypeWorkload,
				LogLevel:   loglevel,
				ToHostDrop: false,
				DSR:        false,
			}))
		}

		ifstateMap := ifstateMapDump(commonMaps.IfStateMap)
		wl1State := ifstateMap[ifstate.NewKey(uint32(workload1.Attrs().Index))]
		Expect(wl1State.IngressPolicyV4()).NotTo(Equal(-1))
		Expect(wl1State.EgressPolicyV4()).NotTo(Equal(-1))
		Expect(wl1State.XDPPolicyV4()).To(Equal(-1))

		pmIng := jumpMapDump(commonMaps.JumpMaps[hook.Ingress])
		pmEgr := jumpMapDump(commonMaps.JumpMaps[hook.Egress])
		Expect(pmIng).To(HaveKey(wl1State.IngressPolicyV4()))
		Expect(pmEgr).To(HaveKey(wl1State.EgressPolicyV4()))
		if ipv6Enabled {
			Expect(wl1State.IngressPolicyV6()).NotTo(Equal(-1))
			Expect(wl1State.EgressPolicyV6()).NotTo(Equal(-1))
			Expect(wl1State.XDPPolicyV6()).To(Equal(-1))

			Expect(pmIng).To(HaveKey(wl1State.IngressPolicyV6()))
			Expect(pmEgr).To(HaveKey(wl1State.EgressPolicyV6()))
		}
	})

	workload2 := createVethName("workloadep2")
	defer deleteLink(workload2)

	t.Run("create another workload, should not load more than the preable", func(t *testing.T) {
		programsIngCount := programsIng.Count()
		programsEgCount := programsEg.Count()
		bpfEpMgr.OnUpdate(linux.NewIfaceStateUpdate("workloadep2", ifacemonitor.StateUp, workload2.Attrs().Index))
		bpfEpMgr.OnUpdate(linux.NewIfaceAddrsUpdate("workloadep2", "1.6.6.1"))
		err := bpfEpMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		jumpMapLen := 3

		if ipv6Enabled {
			jumpMapLen = 8
		}
		Expect(programsIng.Count()).To(Equal(programsIngCount))
		Expect(programsEg.Count()).To(Equal(programsEgCount))

		pmIng := jumpMapDump(commonMaps.JumpMaps[hook.Ingress])
		pmEgr := jumpMapDump(commonMaps.JumpMaps[hook.Egress])
		Expect(len(pmIng)).To(Equal((jumpMapLen)))
		Expect(len(pmEgr)).To(Equal((jumpMapLen)))
	})

	t.Run("bring first host ep down, should clean up its policies", func(t *testing.T) {
		bpfEpMgr.OnUpdate(linux.NewIfaceStateUpdate("hostep1", ifacemonitor.StateDown, host1.Attrs().Index))

		err := bpfEpMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		pmIng := jumpMapDump(commonMaps.JumpMaps[hook.Ingress])
		pmEgr := jumpMapDump(commonMaps.JumpMaps[hook.Egress])
		// We remember the state from above
		Expect(pmIng).NotTo(HaveKey(hostep1State.IngressPolicyV4()))
		Expect(pmEgr).NotTo(HaveKey(hostep1State.EgressPolicyV4()))

		if ipv6Enabled {
			Expect(pmIng).NotTo(HaveKey(hostep1State.IngressPolicyV6()))
			Expect(pmEgr).NotTo(HaveKey(hostep1State.EgressPolicyV6()))
		}
		xdppm := jumpMapDump(commonMaps.XDPJumpMap)
		Expect(xdppm).To(HaveLen(0))
	})

	var wl1State ifstate.Value

	t.Run("change workload policy - should apply the changes", func(t *testing.T) {
		ifstateMap := ifstateMapDump(commonMaps.IfStateMap)
		wl1State = ifstateMap[ifstate.NewKey(uint32(workload1.Attrs().Index))]
		fmt.Printf("wl1State = %+v\n", wl1State)

		pmIng := jumpMapDump(commonMaps.JumpMaps[hook.Ingress])
		pmEgr := jumpMapDump(commonMaps.JumpMaps[hook.Egress])
		wl1IngressPol := pmIng[wl1State.IngressPolicyV4()]
		wl1EgressPol := pmEgr[wl1State.EgressPolicyV4()]

		bpfEpMgr.OnUpdate(&proto.WorkloadEndpointUpdate{
			Id: &proto.WorkloadEndpointID{
				OrchestratorId: "k8s",
				WorkloadId:     "workloadep1",
				EndpointId:     "workloadep1",
			},
			Endpoint: &proto.WorkloadEndpoint{Name: "workloadep1"},
		})
		bpfEpMgr.OnUpdate(&proto.ActivePolicyUpdate{
			Id: &proto.PolicyID{Name: "wl1-policy"},
			Policy: &proto.Policy{
				Tier:      "default",
				Namespace: "default",
				InboundRules: []*proto.Rule{{
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
		pmIng = jumpMapDump(commonMaps.JumpMaps[hook.Ingress])
		pmEgr = jumpMapDump(commonMaps.JumpMaps[hook.Egress])
		Expect(wl1IngressPol).NotTo(Equal(pmIng[wl1State2.IngressPolicyV4()]))
		Expect(wl1EgressPol).NotTo(Equal(pmEgr[wl1State2.EgressPolicyV4()]))

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

		pmIng := jumpMapDump(commonMaps.JumpMaps[hook.Ingress])
		pmEgr := jumpMapDump(commonMaps.JumpMaps[hook.Egress])
		// We remember the state from above
		Expect(pmIng).NotTo(HaveKey(wl1State.IngressPolicyV4()))
		Expect(pmEgr).NotTo(HaveKey(wl1State.EgressPolicyV4()))
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

		programsIng.ResetForTesting() // Because we recycle it, restarted Felix would get a fresh copy.
		programsEg.ResetForTesting()  // Because we recycle it, restarted Felix would get a fresh copy.

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
				BPFPolicyDebugEnabled:   true,
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
		oldProgsIngParams := hook.IngressProgramsMapParameters
		oldProgsIngParams.PinDir = tmp
		oldProgs := maps.NewPinnedMap(oldProgsIngParams)
		err = oldProgs.Open()
		Expect(err).NotTo(HaveOccurred())
		pm := jumpMapDump(oldProgs)
		programsCount := 15
		oldPoliciesCount := 2
		if ipv6Enabled {
			programsCount = 28
			oldPoliciesCount = 6
		}
		Expect(pm).To(HaveLen(programsCount))

		oldPoliciesParams := jump.IngressMapParameters
		oldPoliciesParams.PinDir = tmp
		oldPolicies := maps.NewPinnedMap(oldPoliciesParams)
		err = oldPolicies.Open()
		Expect(err).NotTo(HaveOccurred())
		pm = jumpMapDump(oldPolicies)
		Expect(pm).To(HaveLen(oldPoliciesCount))

		// After restat we get new maps which are empty
		Expect(programsIng.Count()).To(Equal(0))
		pm = jumpMapDump(commonMaps.ProgramsMaps[hook.Ingress])
		Expect(pm).To(HaveLen(0))
		pm = jumpMapDump(commonMaps.ProgramsMaps[hook.Egress])
		Expect(pm).To(HaveLen(0))
		pm = jumpMapDump(commonMaps.JumpMaps[hook.Ingress])
		Expect(pm).To(HaveLen(0))
		pm = jumpMapDump(commonMaps.JumpMaps[hook.Egress])
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

		Expect(programsIng.Count()).To(Equal(15))
		pm = jumpMapDump(commonMaps.ProgramsMaps[hook.Ingress])
		Expect(pm).To(HaveLen(15))

		pmIng := jumpMapDump(commonMaps.JumpMaps[hook.Ingress])
		pmEgr := jumpMapDump(commonMaps.JumpMaps[hook.Egress])
		// We remember the state from above
		Expect(pmIng).To(HaveLen(1))
		Expect(pmEgr).To(HaveLen(1))
		Expect(pmIng).To(HaveKey(wl2State.IngressPolicyV4()))
		Expect(pmEgr).To(HaveKey(wl2State.EgressPolicyV4()))

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

		programsIng.ResetForTesting() // Because we recycle it, restarted Felix would get a fresh copy.
		programsEg.ResetForTesting()  // Because we recycle it, restarted Felix would get a fresh copy.

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
				BPFPolicyDebugEnabled:   true,
			},
			bpfmaps,
			regexp.MustCompile("^workloadep[123]"),
		)
		Expect(err).NotTo(HaveOccurred())

		pmIng := jumpMapDump(commonMaps.JumpMaps[hook.Ingress])
		pmEgr := jumpMapDump(commonMaps.JumpMaps[hook.Egress])

		Expect(pmIng).To(HaveLen(0))
		Expect(pmEgr).To(HaveLen(0))

		bpfEpMgr.OnUpdate(&proto.HostMetadataUpdate{Hostname: "uthost", Ipv4Addr: "1.2.3.4"})
		bpfEpMgr.OnUpdate(linux.NewIfaceStateUpdate("workloadep2", ifacemonitor.StateUp, workload2.Attrs().Index))
		bpfEpMgr.OnUpdate(linux.NewIfaceAddrsUpdate("workloadep2", "1.6.6.1"))
		bpfEpMgr.OnUpdate(linux.NewIfaceStateUpdate("hostep2", ifacemonitor.StateUp, host2.Attrs().Index))
		bpfEpMgr.OnUpdate(linux.NewIfaceAddrsUpdate("hostep2", "4.3.2.1"))
		err = bpfEpMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		pmIng = jumpMapDump(commonMaps.JumpMaps[hook.Ingress])
		pmEgr = jumpMapDump(commonMaps.JumpMaps[hook.Egress])
		// We remember the state from above
		Expect(pmIng).To(HaveLen(1))
		Expect(pmEgr).To(HaveLen(1))
		Expect(pmIng).To(HaveKey(wl2State.IngressPolicyV4()))
		Expect(pmEgr).To(HaveKey(wl2State.EgressPolicyV4()))
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
	programsIng := commonMaps.ProgramsMaps[hook.Ingress].(*hook.ProgramsMap)
	programsEg := commonMaps.ProgramsMaps[hook.Egress].(*hook.ProgramsMap)
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
			BPFPolicyDebugEnabled:   true,
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
		Endpoint: &proto.WorkloadEndpoint{
			Name:        "workloadep1",
			QosControls: &proto.QoSControls{IngressPacketRate: 50, IngressPacketBurst: 100, EgressPacketRate: 200, EgressPacketBurst: 300},
		},
	})
	err = bpfEpMgr.CompleteDeferredWork()
	Expect(err).NotTo(HaveOccurred())

	ingressProg, err := tc.ListAttachedPrograms("workloadep1", hook.Ingress.String(), true)
	Expect(err).NotTo(HaveOccurred())
	Expect(len(ingressProg)).To(Equal(1))

	egressProg, err := tc.ListAttachedPrograms("workloadep1", hook.Egress.String(), true)
	Expect(err).NotTo(HaveOccurred())
	Expect(len(egressProg)).To(Equal(1))

	Expect(ingressProg[0].Pref).To(Equal(egressProg[0].Pref))
	Expect(ingressProg[0].Handle).To(Equal(egressProg[0].Handle))

	// Verify that QoS map state is correctly created
	qosMap := commonMaps.QoSMap
	qosKey1 := qos.NewKey(uint32(workload1.Attrs().Index), 1)
	qosValBytes1, err := qosMap.Get(qosKey1.AsBytes())
	Expect(err).NotTo(HaveOccurred())
	qosVal1 := qos.ValueFromBytes(qosValBytes1)
	Expect(qosVal1.PacketRate()).To(Equal(int16(50)))
	Expect(qosVal1.PacketBurst()).To(Equal(int16(100)))
	Expect(qosVal1.PacketRateTokens()).To(Equal(int16(-1)))
	Expect(qosVal1.PacketRateLastUpdate()).To(Equal(uint64(0)))

	qosKey2 := qos.NewKey(uint32(workload1.Attrs().Index), 0)
	qosValBytes2, err := qosMap.Get(qosKey2.AsBytes())
	Expect(err).NotTo(HaveOccurred())
	qosVal2 := qos.ValueFromBytes(qosValBytes2)
	Expect(qosVal2.PacketRate()).To(Equal(int16(200)))
	Expect(qosVal2.PacketBurst()).To(Equal(int16(300)))
	Expect(qosVal2.PacketRateTokens()).To(Equal(int16(-1)))
	Expect(qosVal2.PacketRateLastUpdate()).To(Equal(uint64(0)))

	atIng := programsIng.Programs()
	atEg := programsEg.Programs()
	Expect(atIng).To(HaveKey(hook.AttachType{
		Hook:       hook.Ingress,
		Family:     4,
		Type:       tcdefs.EpTypeWorkload,
		LogLevel:   loglevel,
		ToHostDrop: false,
		DSR:        false,
	}))
	Expect(atEg).To(HaveKey(hook.AttachType{
		Hook:       hook.Egress,
		Family:     4,
		Type:       tcdefs.EpTypeWorkload,
		LogLevel:   loglevel,
		ToHostDrop: false,
		DSR:        false,
	}))

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
			Endpoint: &proto.WorkloadEndpoint{
				Name:        "workloadep1",
				QosControls: &proto.QoSControls{IngressPacketRate: 50, IngressPacketBurst: 100, EgressPacketRate: 200, EgressPacketBurst: 300},
			},
		})
		err = bpfEpMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())
	}
	ingProg, err := tc.ListAttachedPrograms("workloadep1", hook.Ingress.String(), true)
	Expect(err).NotTo(HaveOccurred())
	Expect(len(ingProg)).To(Equal(1))

	egrProg, err := tc.ListAttachedPrograms("workloadep1", hook.Egress.String(), true)
	Expect(err).NotTo(HaveOccurred())
	Expect(len(egrProg)).To(Equal(1))

	Expect(ingressProg[0].Pref).To(Equal(ingProg[0].Pref))
	Expect(ingressProg[0].Handle).To(Equal(ingProg[0].Handle))
	Expect(egressProg[0].Pref).To(Equal(egrProg[0].Pref))
	Expect(egressProg[0].Handle).To(Equal(egrProg[0].Handle))
	Expect(ingProg[0].Pref).To(Equal(egrProg[0].Pref))
	Expect(ingProg[0].Handle).To(Equal(egrProg[0].Handle))

	// Verify that QoS state in map persists correctly after a workload endpoint update
	qosValBytes1, err = qosMap.Get(qosKey1.AsBytes())
	Expect(err).NotTo(HaveOccurred())
	qosVal1 = qos.ValueFromBytes(qosValBytes1)
	Expect(qosVal1.PacketRate()).To(Equal(int16(50)))
	Expect(qosVal1.PacketBurst()).To(Equal(int16(100)))
	Expect(qosVal1.PacketRateTokens()).To(Equal(int16(-1)))
	Expect(qosVal1.PacketRateLastUpdate()).To(Equal(uint64(0)))

	qosValBytes2, err = qosMap.Get(qosKey2.AsBytes())
	Expect(err).NotTo(HaveOccurred())
	qosVal2 = qos.ValueFromBytes(qosValBytes2)
	Expect(qosVal2.PacketRate()).To(Equal(int16(200)))
	Expect(qosVal2.PacketBurst()).To(Equal(int16(300)))
	Expect(qosVal2.PacketRateTokens()).To(Equal(int16(-1)))
	Expect(qosVal2.PacketRateLastUpdate()).To(Equal(uint64(0)))
}

// This test verifies if the tc program gets replaced
// and thus returns the same handle and priority.
func TestRepeatedAttach(t *testing.T) {
	RegisterTestingT(t)

	iface := createVethName("workloadep1")
	defer func() {
		deleteLink(iface)
	}()

	ifaceName := iface.Attrs().Name
	ap := &tc.AttachPoint{
		AttachPoint: bpf.AttachPoint{
			Iface: ifaceName,
			Hook:  hook.Ingress,
		},
		HostIPv4: net.IPv4(1, 2, 3, 4),
		IntfIPv4: net.IPv4(1, 6, 6, 6),
	}

	_, err := tc.EnsureQdisc(ifaceName)
	Expect(err).NotTo(HaveOccurred(), "failed to create qdisc")
	err = ap.AttachProgram()
	Expect(err).NotTo(HaveOccurred(), "failed to attach preamble")
	ingressProg, err := tc.ListAttachedPrograms(ap.Iface, ap.Hook.String(), true)
	Expect(err).NotTo(HaveOccurred())
	Expect(len(ingressProg)).To(Equal(1))
	for i := 0; i < 3; i++ {
		err = ap.AttachProgram()
		Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("failed to attach preamble : %d", i))
	}

	ingProg, err := tc.ListAttachedPrograms(ap.Iface, ap.Hook.String(), true)
	Expect(err).NotTo(HaveOccurred())
	Expect(len(ingProg)).To(Equal(1))

	Expect(ingProg[0].Pref).To(Equal(ingressProg[0].Pref))
	Expect(ingProg[0].Handle).To(Equal(ingressProg[0].Handle))
	// We have a BPF program attached to ingress hook and nothing on the egress hook.
	// Now when there is a workload update, ingress program must be replaced and new program
	// must be attached to egress.
	bpfmaps, err := bpfmap.CreateBPFMaps(false)
	Expect(err).NotTo(HaveOccurred())

	bpfEpMgr, err := newBPFTestEpMgr(
		&linux.Config{
			Hostname:              "uthost",
			BPFLogLevel:           "off",
			BPFDataIfacePattern:   regexp.MustCompile("^hostep[12]"),
			VXLANMTU:              1000,
			VXLANPort:             1234,
			BPFNodePortDSREnabled: false,
			RulesConfig: rules.Config{
				EndpointToHostAction: "RETURN",
			},
			BPFExtToServiceConnmark: 0,
			BPFPolicyDebugEnabled:   true,
		},
		bpfmaps,
		regexp.MustCompile("^workloadep[123]"),
	)
	Expect(err).NotTo(HaveOccurred())
	bpfEpMgr.OnUpdate(&proto.HostMetadataUpdate{Hostname: "uthost", Ipv4Addr: "1.2.3.4"})
	bpfEpMgr.OnUpdate(linux.NewIfaceStateUpdate("workloadep1", ifacemonitor.StateUp, iface.Attrs().Index))
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

	ingProg, err = tc.ListAttachedPrograms(ap.Iface, hook.Ingress.String(), true)
	Expect(err).NotTo(HaveOccurred())
	Expect(len(ingProg)).To(Equal(1))

	egrProg, err := tc.ListAttachedPrograms(ap.Iface, hook.Egress.String(), true)
	Expect(err).NotTo(HaveOccurred())
	Expect(len(egrProg)).To(Equal(1))

	Expect(ingProg[0].Pref).To(Equal(ingressProg[0].Pref))
	Expect(ingProg[0].Handle).To(Equal(ingressProg[0].Handle))
	Expect(egrProg[0].Pref).To(Equal(ingressProg[0].Pref))
	Expect(egrProg[0].Handle).To(Equal(ingressProg[0].Handle))
}

func TestCTLBAttachLegacy(t *testing.T) {
	RegisterTestingT(t)

	testCtlbAttachLegacy := func(v4, v6 bool) {
		bpfmaps, err := bpfmap.CreateBPFMaps(false)
		Expect(err).NotTo(HaveOccurred())

		commonMaps := bpfmaps.CommonMaps
		err = nat.InstallConnectTimeLoadBalancerLegacy(v4, v6, "", "debug", 60*time.Second, false, commonMaps.CTLBProgramsMaps)
		Expect(err).NotTo(HaveOccurred())

		checkPinPath := func(pinPath string, mustExist bool) {
			_, err := os.Stat(pinPath)
			if mustExist {
				Expect(err).NotTo(HaveOccurred())
			} else {
				Expect(err).To(HaveOccurred())
			}
		}

		checkPinPath("/sys/fs/bpf/ctlb/calico_connect_v4", false)
		checkPinPath("/sys/fs/bpf/ctlb/calico_connect_v46", false)
		checkPinPath("/sys/fs/bpf/ctlb/calico_sendmsg_v4", false)
		checkPinPath("/sys/fs/bpf/ctlb/calico_sendmsg_v46", false)
		checkPinPath("/sys/fs/bpf/ctlb/calico_recvmsg_v4", false)
		checkPinPath("/sys/fs/bpf/ctlb/calico_recvmsg_v46", false)
		checkPinPath("/sys/fs/bpf/ctlb/calico_connect_v6", false)
		checkPinPath("/sys/fs/bpf/ctlb/calico_sendmsg_v6", false)
		checkPinPath("/sys/fs/bpf/ctlb/calico_recvmsg_v6", false)

		cmd := exec.Command("bpftool", "cgroup", "show", "/run/calico/cgroup")
		out, err := cmd.Output()
		Expect(err).NotTo(HaveOccurred())
		if v4 {
			Expect(string(out)).Should(ContainSubstring("calico_connect_v4"))
			Expect(string(out)).Should(ContainSubstring("calico_sendmsg_v4"))
			Expect(string(out)).Should(ContainSubstring("calico_recvmsg_v4"))
			Expect(string(out)).Should(ContainSubstring("calico_connect_v46"))
			Expect(string(out)).Should(ContainSubstring("calico_sendmsg_v46"))
			Expect(string(out)).Should(ContainSubstring("calico_recvmsg_v46"))
		} else if v6 {
			Expect(string(out)).Should(ContainSubstring("calico_connect_v6"))
			Expect(string(out)).Should(ContainSubstring("calico_sendmsg_v6"))
			Expect(string(out)).Should(ContainSubstring("calico_recvmsg_v6"))
		}
		err = nat.RemoveConnectTimeLoadBalancer(v4, "")
		Expect(err).NotTo(HaveOccurred())

		cmd = exec.Command("bpftool", "cgroup", "show", "/run/calico/cgroup")
		out, err = cmd.Output()
		Expect(err).NotTo(HaveOccurred())
		if v4 {
			Expect(string(out)).ShouldNot(ContainSubstring("calico_connect_v4"))
			Expect(string(out)).ShouldNot(ContainSubstring("calico_sendmsg_v4"))
			Expect(string(out)).ShouldNot(ContainSubstring("calico_recvmsg_v4"))
			Expect(string(out)).ShouldNot(ContainSubstring("calico_connect_v46"))
			Expect(string(out)).ShouldNot(ContainSubstring("calico_sendmsg_v46"))
			Expect(string(out)).ShouldNot(ContainSubstring("calico_recvmsg_v46"))
		} else if v6 {
			Expect(string(out)).ShouldNot(ContainSubstring("calico_connect_v6"))
			Expect(string(out)).ShouldNot(ContainSubstring("calico_sendmsg_v6"))
			Expect(string(out)).ShouldNot(ContainSubstring("calico_recvmsg_v6"))
		}
		cmd = exec.Command("bpftool", "prog", "show")
		out, err = cmd.Output()
		Expect(err).NotTo(HaveOccurred())
		Expect(string(out)).ShouldNot(ContainSubstring("calico_connect"))
		Expect(string(out)).ShouldNot(ContainSubstring("calico_send"))
		Expect(string(out)).ShouldNot(ContainSubstring("calico_recv"))
	}
	testCtlbAttachLegacy(true, false)
	testCtlbAttachLegacy(false, true)
	testCtlbAttachLegacy(true, true)
}

func TestCTLBAttach(t *testing.T) {
	RegisterTestingT(t)
	testCtlbAttach := func(v4, v6 bool) {
		bpfmaps, err := bpfmap.CreateBPFMaps(false)
		Expect(err).NotTo(HaveOccurred())

		commonMaps := bpfmaps.CommonMaps
		err = nat.InstallConnectTimeLoadBalancer(v4, v6, "", "debug", 60*time.Second, false, commonMaps.CTLBProgramsMaps)
		Expect(err).NotTo(HaveOccurred())

		checkPinPath := func(pinPath string, mustExist bool) {
			_, err := os.Stat(pinPath)
			if mustExist {
				Expect(err).NotTo(HaveOccurred())
			} else {
				Expect(err).To(HaveOccurred())
			}
		}
		if v4 {
			checkPinPath("/sys/fs/bpf/ctlb/calico_connect_v4", true)
			checkPinPath("/sys/fs/bpf/ctlb/calico_connect_v46", true)
			checkPinPath("/sys/fs/bpf/ctlb/calico_sendmsg_v4", true)
			checkPinPath("/sys/fs/bpf/ctlb/calico_sendmsg_v46", true)
			checkPinPath("/sys/fs/bpf/ctlb/calico_recvmsg_v4", true)
			checkPinPath("/sys/fs/bpf/ctlb/calico_recvmsg_v46", true)
		} else if v6 {
			checkPinPath("/sys/fs/bpf/ctlb/calico_connect_v6", true)
			checkPinPath("/sys/fs/bpf/ctlb/calico_sendmsg_v6", true)
			checkPinPath("/sys/fs/bpf/ctlb/calico_recvmsg_v6", true)
		}

		cmd := exec.Command("bpftool", "cgroup", "show", "/run/calico/cgroup")
		out, err := cmd.Output()
		Expect(err).NotTo(HaveOccurred())
		if v4 {
			Expect(string(out)).Should(ContainSubstring("calico_connect_v4"))
			Expect(string(out)).Should(ContainSubstring("calico_sendmsg_v4"))
			Expect(string(out)).Should(ContainSubstring("calico_recvmsg_v4"))
			Expect(string(out)).Should(ContainSubstring("calico_connect_v46"))
			Expect(string(out)).Should(ContainSubstring("calico_sendmsg_v46"))
			Expect(string(out)).Should(ContainSubstring("calico_recvmsg_v46"))
		} else if v6 {
			Expect(string(out)).Should(ContainSubstring("calico_connect_v6"))
			Expect(string(out)).Should(ContainSubstring("calico_sendmsg_v6"))
			Expect(string(out)).Should(ContainSubstring("calico_recvmsg_v6"))
		}
		err = nat.RemoveConnectTimeLoadBalancer(v4, "")
		Expect(err).NotTo(HaveOccurred())
		if v4 {
			checkPinPath("/sys/fs/bpf/ctlb/calico_connect_v4", false)
			checkPinPath("/sys/fs/bpf/ctlb/calico_connect_v46", false)
			checkPinPath("/sys/fs/bpf/ctlb/calico_sendmsg_v4", false)
			checkPinPath("/sys/fs/bpf/ctlb/calico_sendmsg_v46", false)
			checkPinPath("/sys/fs/bpf/ctlb/calico_recvmsg_v4", false)
			checkPinPath("/sys/fs/bpf/ctlb/calico_recvmsg_v46", false)
		} else if v6 {
			checkPinPath("/sys/fs/bpf/ctlb/calico_connect_v6", false)
			checkPinPath("/sys/fs/bpf/ctlb/calico_sendmsg_v6", false)
			checkPinPath("/sys/fs/bpf/ctlb/calico_recvmsg_v6", false)
		}

		cmd = exec.Command("bpftool", "cgroup", "show", "/run/calico/cgroup")
		out, err = cmd.Output()
		Expect(err).NotTo(HaveOccurred())
		if v4 {
			Expect(string(out)).ShouldNot(ContainSubstring("calico_connect_v4"))
			Expect(string(out)).ShouldNot(ContainSubstring("calico_sendmsg_v4"))
			Expect(string(out)).ShouldNot(ContainSubstring("calico_recvmsg_v4"))
			Expect(string(out)).ShouldNot(ContainSubstring("calico_connect_v46"))
			Expect(string(out)).ShouldNot(ContainSubstring("calico_sendmsg_v46"))
			Expect(string(out)).ShouldNot(ContainSubstring("calico_recvmsg_v46"))
		} else if v6 {
			Expect(string(out)).ShouldNot(ContainSubstring("calico_connect_v6"))
			Expect(string(out)).ShouldNot(ContainSubstring("calico_sendmsg_v6"))
			Expect(string(out)).ShouldNot(ContainSubstring("calico_recvmsg_v6"))
		}
		cmd = exec.Command("bpftool", "prog", "show")
		out, err = cmd.Output()
		Expect(err).NotTo(HaveOccurred())
		Expect(string(out)).ShouldNot(ContainSubstring("calico_connect"))
		Expect(string(out)).ShouldNot(ContainSubstring("calico_send"))
		Expect(string(out)).ShouldNot(ContainSubstring("calico_recv"))
	}
	testCtlbAttach(true, false)
	testCtlbAttach(false, true)
	testCtlbAttach(true, true)
}

func TestAttachInterfaceRecreate(t *testing.T) {
	RegisterTestingT(t)
	bpfmaps, err := bpfmap.CreateBPFMaps(false)
	Expect(err).NotTo(HaveOccurred())

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
			BPFPolicyDebugEnabled:   true,
			BPFAttachType:           v3.BPFAttachOptionTCX,
		},
		bpfmaps,
		regexp.MustCompile("^workloadep[0123]"),
	)
	Expect(err).NotTo(HaveOccurred())

	workload0 := createVethName("workloadep0")
	defer func() {
		if workload0 != nil {
			deleteLink(workload0)
		}
	}()

	bpfEpMgr.OnUpdate(&proto.HostMetadataUpdate{Hostname: "uthost", Ipv4Addr: "1.2.3.4"})
	bpfEpMgr.OnUpdate(linux.NewIfaceStateUpdate("workloadep0", ifacemonitor.StateUp, workload0.Attrs().Index))
	bpfEpMgr.OnUpdate(linux.NewIfaceAddrsUpdate("workloadep0", "1.6.6.6"))
	bpfEpMgr.OnUpdate(&proto.WorkloadEndpointUpdate{
		Id: &proto.WorkloadEndpointID{
			OrchestratorId: "k8s",
			WorkloadId:     "workloadep0",
			EndpointId:     "workloadep0",
		},
		Endpoint: &proto.WorkloadEndpoint{Name: "workloadep0"},
	})
	err = bpfEpMgr.CompleteDeferredWork()
	Expect(err).NotTo(HaveOccurred())
	_, err = os.Stat(bpfdefs.TcxPinDir + "/workloadep0_ingress")
	Expect(err).NotTo(HaveOccurred())
	_, err = os.Stat(bpfdefs.TcxPinDir + "/workloadep0_egress")
	Expect(err).NotTo(HaveOccurred())

	// Endpoint managed gets interface deleted but interface still exists.
	// This can happen if the interface is deleted and recreated quickly.
	// The BPF endpoint manager gets the update that interface is gone but
	// the interface is still there. The pinned programs must remain.
	bpfEpMgr.OnUpdate(linux.NewIfaceStateUpdate("workloadep0", ifacemonitor.StateNotPresent, workload0.Attrs().Index))
	err = bpfEpMgr.CompleteDeferredWork()
	Expect(err).NotTo(HaveOccurred())
	_, err = os.Stat(bpfdefs.TcxPinDir + "/workloadep0_ingress")
	Expect(err).NotTo(HaveOccurred())
	_, err = os.Stat(bpfdefs.TcxPinDir + "/workloadep0_egress")
	Expect(err).NotTo(HaveOccurred())

	// Now simulate interface being deleted and recreated.
	deleteLink(workload0)
	workload0 = nil
	workload0_new := createVethName("workloadep0")
	defer func() {
		if workload0_new != nil {
			deleteLink(workload0_new)
		}
	}()
	bpfEpMgr.OnUpdate(linux.NewIfaceStateUpdate("workloadep0", ifacemonitor.StateUp, workload0_new.Attrs().Index))
	bpfEpMgr.OnUpdate(linux.NewIfaceAddrsUpdate("workloadep0", "1.6.6.6"))
	err = bpfEpMgr.CompleteDeferredWork()
	Expect(err).NotTo(HaveOccurred())
	_, err = os.Stat(bpfdefs.TcxPinDir + "/workloadep0_ingress")
	Expect(err).NotTo(HaveOccurred())
	_, err = os.Stat(bpfdefs.TcxPinDir + "/workloadep0_egress")
	Expect(err).NotTo(HaveOccurred())

	// Interface is deleted. BPF endpoint manager gets the update.
	// The pinned programs must be removed.
	deleteLink(workload0_new)
	workload0_new = nil

	bpfEpMgr.OnUpdate(linux.NewIfaceStateUpdate("workloadep0", ifacemonitor.StateNotPresent, 0))
	err = bpfEpMgr.CompleteDeferredWork()
	Expect(err).NotTo(HaveOccurred())
	_, err = os.Stat(bpfdefs.TcxPinDir + "/workloadep0_ingress")
	Expect(err).To(HaveOccurred())
	_, err = os.Stat(bpfdefs.TcxPinDir + "/workloadep0_egress")
	Expect(err).To(HaveOccurred())
}

func TestAttachTcx(t *testing.T) {
	RegisterTestingT(t)
	bpfmaps, err := bpfmap.CreateBPFMaps(false)
	Expect(err).NotTo(HaveOccurred())

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
			BPFPolicyDebugEnabled:   true,
			BPFAttachType:           v3.BPFAttachOptionTCX,
		},
		bpfmaps,
		regexp.MustCompile("^workloadep[0123]"),
	)
	Expect(err).NotTo(HaveOccurred())

	workload0 := createVethName("workloadep0")
	defer deleteLink(workload0)

	bpfEpMgr.OnUpdate(&proto.HostMetadataUpdate{Hostname: "uthost", Ipv4Addr: "1.2.3.4"})
	bpfEpMgr.OnUpdate(linux.NewIfaceStateUpdate("workloadep0", ifacemonitor.StateUp, workload0.Attrs().Index))
	bpfEpMgr.OnUpdate(linux.NewIfaceAddrsUpdate("workloadep0", "1.6.6.6"))
	bpfEpMgr.OnUpdate(&proto.WorkloadEndpointUpdate{
		Id: &proto.WorkloadEndpointID{
			OrchestratorId: "k8s",
			WorkloadId:     "workloadep0",
			EndpointId:     "workloadep0",
		},
		Endpoint: &proto.WorkloadEndpoint{Name: "workloadep0"},
	})
	err = bpfEpMgr.CompleteDeferredWork()
	Expect(err).NotTo(HaveOccurred())
	// Ensure there is no qdisc.
	hasQdisc, err := tc.HasQdisc("workloadep0")
	Expect(err).NotTo(HaveOccurred())
	Expect(hasQdisc).To(BeFalse())
	// Check if there are no tc programs.
	progs, err := tc.ListAttachedPrograms("workloadep0", hook.Ingress.String(), true)
	Expect(err).NotTo(HaveOccurred())
	Expect(len(progs)).To(Equal(0))
	progs, err = tc.ListAttachedPrograms("workloadep0", hook.Egress.String(), true)
	Expect(err).NotTo(HaveOccurred())
	Expect(len(progs)).To(Equal(0))

	_, err = os.Stat(bpfdefs.TcxPinDir + "/workloadep0_ingress")
	Expect(err).NotTo(HaveOccurred())
	_, err = os.Stat(bpfdefs.TcxPinDir + "/workloadep0_egress")
	Expect(err).NotTo(HaveOccurred())
	tcxProgs, err := tc.ListAttachedTcxPrograms("workloadep0", "ingress")
	Expect(err).NotTo(HaveOccurred())
	Expect(len(tcxProgs)).To(Equal(1))
	// Now attach Tc program.
	ap := &tc.AttachPoint{
		AttachPoint: bpf.AttachPoint{
			Iface: "workloadep0",
			Hook:  hook.Ingress,
		},
		HostIPv4:   net.IPv4(1, 2, 3, 4),
		IntfIPv4:   net.IPv4(1, 6, 6, 6),
		AttachType: v3.BPFAttachOptionTC,
	}

	_, err = tc.EnsureQdisc("workloadep0")
	Expect(err).NotTo(HaveOccurred())
	err = ap.AttachProgram()
	Expect(err).NotTo(HaveOccurred())
	progs, err = tc.ListAttachedPrograms("workloadep0", hook.Ingress.String(), true)
	Expect(err).NotTo(HaveOccurred())
	Expect(len(progs)).To(Equal(1))
	_, err = os.Stat(bpfdefs.TcxPinDir + "/workloadep0_ingress")
	Expect(err).To(HaveOccurred())
	tcxProgs, err = tc.ListAttachedTcxPrograms("workloadep0", "ingress")
	Expect(err).NotTo(HaveOccurred())
	Expect(len(tcxProgs)).To(Equal(0))
	// Now attach TCx again
	bpfEpMgr.OnUpdate(&proto.WorkloadEndpointUpdate{
		Id: &proto.WorkloadEndpointID{
			OrchestratorId: "k8s",
			WorkloadId:     "workloadep0",
			EndpointId:     "workloadep0",
		},
		Endpoint: &proto.WorkloadEndpoint{Name: "workloadep0"},
	})
	err = bpfEpMgr.CompleteDeferredWork()
	Expect(err).NotTo(HaveOccurred())
	hasQdisc, err = tc.HasQdisc("workloadep0")
	Expect(err).NotTo(HaveOccurred())
	// switching from tcx to tc removes the qdisc.
	Expect(hasQdisc).To(BeFalse())
	progs, err = tc.ListAttachedPrograms("workloadep0", hook.Ingress.String(), true)
	Expect(err).NotTo(HaveOccurred())
	Expect(len(progs)).To(Equal(0))
	tcxProgs, err = tc.ListAttachedTcxPrograms("workloadep0", "ingress")
	Expect(err).NotTo(HaveOccurred())
	Expect(len(tcxProgs)).To(Equal(1))
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
		BPFPolicyDebugEnabled:   true,
		BPFLogFilters:           map[string]string{"hostep1": "tcp"},
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

func qosMapDump(m maps.Map) qos.MapMem {
	qosMap := make(qos.MapMem)
	qosMapIter := qos.MapMemIter(qosMap)
	_ = m.Iter(func(k, v []byte) maps.IteratorAction {
		qosMapIter(k, v)
		return maps.IterNone
	})

	return qosMap
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
		HostIPv4: net.IPv4(1, 1, 1, 1),
		IntfIPv4: net.IPv4(1, 1, 1, 1),
	}

	err = ap.AttachProgram()
	Expect(err).NotTo(HaveOccurred())

	logLevel := log.GetLevel()
	log.SetLevel(log.PanicLevel)
	defer log.SetLevel(logLevel)

	b.StartTimer()

	for n := 0; n < b.N; n++ {
		err := ap.AttachProgram()
		if err != nil {
			b.Fatalf("AttachProgram failed: %s", err)
		}
	}
}
