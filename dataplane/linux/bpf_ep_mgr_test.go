// +build !windows

// Copyright (c) 2021 Tigera, Inc. All rights reserved.
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
	"regexp"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/felix/bpf"
	bpfipsets "github.com/projectcalico/felix/bpf/ipsets"
	"github.com/projectcalico/felix/bpf/polprog"
	"github.com/projectcalico/felix/bpf/state"
	"github.com/projectcalico/felix/bpf/tc"
	"github.com/projectcalico/felix/idalloc"
	"github.com/projectcalico/felix/ifacemonitor"
	"github.com/projectcalico/felix/ipsets"
	"github.com/projectcalico/felix/proto"
	"github.com/projectcalico/felix/rules"
)

type mockDataplane struct {
	lastFD uint32
	fds    map[string]uint32
	state  map[uint32]polprog.Rules
}

func newMockDataplane() *mockDataplane {
	return &mockDataplane{
		lastFD: 5,
		fds:    map[string]uint32{},
		state:  map[uint32]polprog.Rules{},
	}
}

func (m *mockDataplane) ensureProgramAttached(ap *tc.AttachPoint, polDirection PolDirection) (bpf.MapFD, error) {
	suffixes := []string{"-I", "-E"}
	key := ap.Iface + suffixes[int(polDirection)]
	if fd, exists := m.fds[key]; exists {
		return bpf.MapFD(fd), nil
	}
	m.lastFD += 1
	m.fds[key] = m.lastFD
	return bpf.MapFD(m.lastFD), nil
}

func (m *mockDataplane) ensureQdisc(iface string) error {
	return nil
}

func (m *mockDataplane) updatePolicyProgram(jumpMapFD bpf.MapFD, rules polprog.Rules) error {
	m.state[uint32(jumpMapFD)] = rules
	return nil
}

func (m *mockDataplane) removePolicyProgram(jumpMapFD bpf.MapFD) error {
	delete(m.state, uint32(jumpMapFD))
	return nil
}

func (m *mockDataplane) setAcceptLocal(iface string, val bool) error {
	return nil
}

var _ = Describe("BPF Endpoint Manager", func() {

	var (
		bpfEpMgr             *bpfEndpointManager
		dp                   *mockDataplane
		fibLookupEnabled     bool
		endpointToHostAction string
		dataIfacePattern     string
		workloadIfaceRegex   string
		ipSetIDAllocator     *idalloc.IDAllocator
		vxlanMTU             int
		nodePortDSR          bool
		bpfMapContext        *bpf.MapContext
		ipSetsMap            bpf.Map
		stateMap             bpf.Map
		rrConfigNormal       rules.Config
		ruleRenderer         rules.RuleRenderer
		filterTableV4        iptablesTable
	)

	BeforeEach(func() {
		fibLookupEnabled = true
		endpointToHostAction = "DROP"
		dataIfacePattern = "^((en|wl|ww|sl|ib)[opsx].*|(eth|wlan|wwan).*|tunl0$|wireguard.cali$)"
		workloadIfaceRegex = "cali"
		ipSetIDAllocator = idalloc.New()
		vxlanMTU = 0
		nodePortDSR = true
		bpfMapContext = &bpf.MapContext{
			RepinningEnabled: true,
		}
		ipSetsMap = bpfipsets.Map(bpfMapContext)
		stateMap = state.Map(bpfMapContext)
		rrConfigNormal = rules.Config{
			IPIPEnabled:                 true,
			IPIPTunnelAddress:           nil,
			IPSetConfigV4:               ipsets.NewIPVersionConfig(ipsets.IPFamilyV4, "cali", nil, nil),
			IPSetConfigV6:               ipsets.NewIPVersionConfig(ipsets.IPFamilyV6, "cali", nil, nil),
			IptablesMarkAccept:          0x8,
			IptablesMarkPass:            0x10,
			IptablesMarkScratch0:        0x20,
			IptablesMarkScratch1:        0x40,
			IptablesMarkEndpoint:        0xff00,
			IptablesMarkNonCaliEndpoint: 0x0100,
			KubeIPVSSupportEnabled:      true,
			WorkloadIfacePrefixes:       []string{"cali", "tap"},
			VXLANPort:                   4789,
			VXLANVNI:                    4096,
		}
		ruleRenderer = rules.NewRenderer(rrConfigNormal)
		filterTableV4 = newMockTable("filter")
	})

	JustBeforeEach(func() {
		dp = newMockDataplane()
		bpfEpMgr = newBPFEndpointManager(
			"info", // config.BPFLogLevel,
			"uthost",
			fibLookupEnabled,
			endpointToHostAction,
			regexp.MustCompile(dataIfacePattern),
			regexp.MustCompile(workloadIfaceRegex),
			ipSetIDAllocator,
			vxlanMTU,
			uint16(rrConfigNormal.VXLANPort),
			nodePortDSR,
			ipSetsMap,
			stateMap,
			ruleRenderer,
			filterTableV4,
			nil,
		)
		bpfEpMgr.dp = dp
	})

	It("exists", func() {
		Expect(bpfEpMgr).NotTo(BeNil())
	})

	genIfaceUpdate := func(name string, state ifacemonitor.State, index int) func() {
		return func() {
			bpfEpMgr.OnUpdate(&ifaceUpdate{Name: name, State: state, Index: index})
			err := bpfEpMgr.CompleteDeferredWork()
			Expect(err).NotTo(HaveOccurred())
		}
	}

	genHEPUpdate := func(heps ...interface{}) func() {
		return func() {
			hostIfaceToEp := make(map[string]proto.HostEndpoint)
			for i := 0; i < len(heps); i += 2 {
				log.Infof("%v = %v", heps[i], heps[i+1])
				hostIfaceToEp[heps[i].(string)] = heps[i+1].(proto.HostEndpoint)
			}
			log.Infof("2 hostIfaceToEp = %v", hostIfaceToEp)
			bpfEpMgr.OnHEPUpdate(hostIfaceToEp)
			err := bpfEpMgr.CompleteDeferredWork()
			Expect(err).NotTo(HaveOccurred())
		}
	}

	genPolicy := func(tier, policy string) func() {
		return func() {
			bpfEpMgr.OnUpdate(&proto.ActivePolicyUpdate{
				Id:     &proto.PolicyID{Tier: tier, Name: policy},
				Policy: &proto.Policy{},
			})
			err := bpfEpMgr.CompleteDeferredWork()
			Expect(err).NotTo(HaveOccurred())
		}
	}

	genWLUpdate := func(name string) func() {
		return func() {
			bpfEpMgr.OnUpdate(&proto.WorkloadEndpointUpdate{
				Id: &proto.WorkloadEndpointID{
					OrchestratorId: "k8s",
					WorkloadId:     name,
					EndpointId:     name,
				},
				Endpoint: &proto.WorkloadEndpoint{Name: name},
			})
			err := bpfEpMgr.CompleteDeferredWork()
			Expect(err).NotTo(HaveOccurred())
		}
	}

	hostEp := proto.HostEndpoint{
		Name: "uthost-eth0",
		PreDnatTiers: []*proto.TierInfo{
			&proto.TierInfo{
				Name:            "default",
				IngressPolicies: []string{"mypolicy"},
			},
		},
	}

	hostEpNorm := proto.HostEndpoint{
		Name: "uthost-eth0",
		Tiers: []*proto.TierInfo{
			&proto.TierInfo{
				Name:            "default",
				IngressPolicies: []string{"mypolicy"},
				EgressPolicies:  []string{"mypolicy"},
			},
		},
	}

	It("does not have HEP in initial state", func() {
		Expect(bpfEpMgr.hostIfaceToEpMap["eth0"]).NotTo(Equal(hostEp))
	})

	Context("with workload and host-* endpoints", func() {
		JustBeforeEach(func() {
			genPolicy("default", "mypolicy")()
			genIfaceUpdate("eth0", ifacemonitor.StateUp, 10)()
			genWLUpdate("cali12345")()
			genIfaceUpdate("cali12345", ifacemonitor.StateUp, 15)()
			genHEPUpdate(allInterfaces, hostEpNorm)()
		})

		It("does not have host-* policy on the workload interface", func() {
			Eventually(func() map[string]uint32 {
				return dp.fds
			}).Should(HaveLen(4))

			// Check eth0 ingress.
			eth0I := dp.fds["eth0-I"]
			Expect(eth0I).NotTo(BeZero())
			Expect(dp.state).To(HaveKey(eth0I))
			Expect(dp.state[eth0I].ForHostInterface).To(BeTrue())
			Expect(dp.state[eth0I].HostNormalTiers).To(HaveLen(1))
			Expect(dp.state[eth0I].HostNormalTiers[0].Policies).To(HaveLen(1))
			Expect(dp.state[eth0I].SuppressNormalHostPolicy).To(BeFalse())

			// Check eth0 egress.
			eth0E := dp.fds["eth0-E"]
			Expect(eth0E).NotTo(BeZero())
			Expect(dp.state).To(HaveKey(eth0E))
			Expect(dp.state[eth0E].ForHostInterface).To(BeTrue())
			Expect(dp.state[eth0E].HostNormalTiers).To(HaveLen(1))
			Expect(dp.state[eth0E].HostNormalTiers[0].Policies).To(HaveLen(1))
			Expect(dp.state[eth0E].SuppressNormalHostPolicy).To(BeFalse())

			// Check workload ingress.
			caliI := dp.fds["cali12345-I"]
			Expect(caliI).NotTo(BeZero())
			Expect(dp.state).To(HaveKey(caliI))
			Expect(dp.state[caliI].ForHostInterface).To(BeFalse())
			Expect(dp.state[caliI].SuppressNormalHostPolicy).To(BeTrue())

			// Check workload egress.
			caliE := dp.fds["cali12345-E"]
			Expect(caliE).NotTo(BeZero())
			Expect(dp.state).To(HaveKey(caliE))
			Expect(dp.state[caliE].ForHostInterface).To(BeFalse())
			Expect(dp.state[caliE].SuppressNormalHostPolicy).To(BeTrue())
		})

		Context("with DefaultEndpointToHostAction RETURN", func() {
			BeforeEach(func() {
				endpointToHostAction = "RETURN"
			})

			It("has host-* policy on workload egress but not ingress", func() {
				Eventually(func() map[string]uint32 {
					return dp.fds
				}).Should(HaveLen(4))

				// Check workload ingress.
				caliI := dp.fds["cali12345-I"]
				Expect(caliI).NotTo(BeZero())
				Expect(dp.state).To(HaveKey(caliI))
				Expect(dp.state[caliI].ForHostInterface).To(BeFalse())
				Expect(dp.state[caliI].SuppressNormalHostPolicy).To(BeTrue())

				// Check workload egress.
				caliE := dp.fds["cali12345-E"]
				Expect(caliE).NotTo(BeZero())
				Expect(dp.state).To(HaveKey(caliE))
				Expect(dp.state[caliE].ForHostInterface).To(BeFalse())
				Expect(dp.state[caliE].HostNormalTiers).To(HaveLen(1))
				Expect(dp.state[caliE].HostNormalTiers[0].Policies).To(HaveLen(1))
				Expect(dp.state[caliE].SuppressNormalHostPolicy).To(BeFalse())
			})
		})
	})

	Context("with eth0 up", func() {
		JustBeforeEach(func() {
			genPolicy("default", "mypolicy")()
			genIfaceUpdate("eth0", ifacemonitor.StateUp, 10)()
		})

		Context("with eth0 host endpoint", func() {
			JustBeforeEach(genHEPUpdate("eth0", hostEp))

			It("stores host endpoint for eth0", func() {
				Expect(bpfEpMgr.hostIfaceToEpMap["eth0"]).To(Equal(hostEp))
				Expect(bpfEpMgr.policiesToWorkloads[proto.PolicyID{
					Tier: "default",
					Name: "mypolicy",
				}]).To(HaveKey("eth0"))

				// Check ingress rules.
				eth0I := dp.fds["eth0-I"]
				Expect(eth0I).NotTo(BeZero())
				Expect(dp.state).To(HaveKey(eth0I))
				Expect(dp.state[eth0I].ForHostInterface).To(BeTrue())
				Expect(dp.state[eth0I].HostPreDnatTiers).To(HaveLen(1))
				Expect(dp.state[eth0I].HostPreDnatTiers[0].Policies).To(HaveLen(1))

				// Check egress rules.
				eth0E := dp.fds["eth0-E"]
				Expect(eth0E).NotTo(BeZero())
				Expect(dp.state).To(HaveKey(eth0E))
				Expect(dp.state[eth0E].ForHostInterface).To(BeTrue())
				Expect(dp.state[eth0E].HostPreDnatTiers).To(BeNil())
			})
		})

		Context("with host-* endpoint", func() {
			JustBeforeEach(genHEPUpdate(allInterfaces, hostEp))

			It("stores host endpoint for eth0", func() {
				Expect(bpfEpMgr.hostIfaceToEpMap["eth0"]).To(Equal(hostEp))
				Expect(bpfEpMgr.policiesToWorkloads[proto.PolicyID{
					Tier: "default",
					Name: "mypolicy",
				}]).To(HaveKey("eth0"))
			})
		})
	})

	Context("with eth0 host endpoint", func() {
		JustBeforeEach(func() {
			genPolicy("default", "mypolicy")()
			genHEPUpdate("eth0", hostEp)()
		})

		Context("with eth0 up", func() {
			JustBeforeEach(genIfaceUpdate("eth0", ifacemonitor.StateUp, 10))

			It("stores host endpoint for eth0", func() {
				Expect(bpfEpMgr.hostIfaceToEpMap["eth0"]).To(Equal(hostEp))
				Expect(bpfEpMgr.policiesToWorkloads[proto.PolicyID{
					Tier: "default",
					Name: "mypolicy",
				}]).To(HaveKey("eth0"))
			})
		})
	})

	Context("with host-* endpoint", func() {
		JustBeforeEach(func() {
			genPolicy("default", "mypolicy")()
			genHEPUpdate(allInterfaces, hostEp)()
		})

		Context("with eth0 up", func() {
			JustBeforeEach(genIfaceUpdate("eth0", ifacemonitor.StateUp, 10))

			It("stores host endpoint for eth0", func() {
				Expect(bpfEpMgr.hostIfaceToEpMap["eth0"]).To(Equal(hostEp))
				Expect(bpfEpMgr.policiesToWorkloads[proto.PolicyID{
					Tier: "default",
					Name: "mypolicy",
				}]).To(HaveKey("eth0"))
			})

			Context("with eth0 down", func() {
				JustBeforeEach(genIfaceUpdate("eth0", ifacemonitor.StateDown, 10))

				It("clears host endpoint for eth0", func() {
					Expect(bpfEpMgr.hostIfaceToEpMap).To(BeEmpty())
					Expect(bpfEpMgr.policiesToWorkloads[proto.PolicyID{
						Tier: "default",
						Name: "mypolicy",
					}]).NotTo(HaveKey("eth0"))
				})
			})
		})
	})
})
