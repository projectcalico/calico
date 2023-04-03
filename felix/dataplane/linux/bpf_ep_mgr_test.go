//go:build !windows

// Copyright (c) 2021-2022 Tigera, Inc. All rights reserved.
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
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"net"
	"regexp"
	"strconv"
	"sync"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/environment"
	"github.com/projectcalico/calico/felix/logutils"

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/bpf/bpfmap"
	"github.com/projectcalico/calico/felix/bpf/conntrack"
	"github.com/projectcalico/calico/felix/bpf/counters"
	"github.com/projectcalico/calico/felix/bpf/ifstate"
	bpfipsets "github.com/projectcalico/calico/felix/bpf/ipsets"
	bpfmaps "github.com/projectcalico/calico/felix/bpf/maps"
	"github.com/projectcalico/calico/felix/bpf/mock"
	"github.com/projectcalico/calico/felix/bpf/polprog"
	"github.com/projectcalico/calico/felix/bpf/state"
	"github.com/projectcalico/calico/felix/idalloc"
	"github.com/projectcalico/calico/felix/ifacemonitor"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/ipsets"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/rules"
)

type mockDataplane struct {
	mutex  sync.Mutex
	lastFD uint32
	fds    map[string]uint32
	state  map[uint32]polprog.Rules
	routes map[ip.V4CIDR]struct{}

	ensureStartedFn func()
}

func newMockDataplane() *mockDataplane {
	return &mockDataplane{
		lastFD: 5,
		fds:    map[string]uint32{},
		state:  map[uint32]polprog.Rules{},
		routes: map[ip.V4CIDR]struct{}{},
	}
}

func (m *mockDataplane) ensureStarted() {
	if m.ensureStartedFn != nil {
		m.ensureStartedFn()
	}
}

func (m *mockDataplane) ensureBPFDevices() error {
	return nil
}

func (m *mockDataplane) ensureProgramAttached(ap attachPoint) (bpfmaps.FD, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	key := ap.IfaceName() + ":" + ap.JumpMapFDMapKey()
	if fd, exists := m.fds[key]; exists {
		return bpfmaps.FD(fd), nil
	}
	m.lastFD += 1
	m.fds[key] = m.lastFD
	return bpfmaps.FD(m.lastFD), nil
}

func (m *mockDataplane) ensureNoProgram(ap attachPoint) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	key := ap.IfaceName() + ":" + ap.JumpMapFDMapKey()
	if fd, exists := m.fds[key]; exists {
		delete(m.state, uint32(fd))
		delete(m.fds, key)
	}
	return nil
}

func (m *mockDataplane) ensureQdisc(iface string) error {
	return nil
}

func (m *mockDataplane) updatePolicyProgram(jumpMapFD bpfmaps.FD, rules polprog.Rules, polDir string, ap attachPoint) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.state[uint32(jumpMapFD)] = rules
	return nil
}

func (m *mockDataplane) removePolicyProgram(jumpMapFD bpfmaps.FD, ap attachPoint) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	delete(m.state, uint32(jumpMapFD))
	return nil
}

func (m *mockDataplane) setAcceptLocal(iface string, val bool) error {
	return nil
}

func (m *mockDataplane) setRPFilter(iface string, val int) error {
	return nil
}

func (m *mockDataplane) getRules(key string) *polprog.Rules {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	fd := m.fds[key]
	if fd != 0 {
		rules, exist := m.state[fd]
		if exist {
			return &rules
		}
	}
	return nil
}

func (m *mockDataplane) setAndReturn(vari **polprog.Rules, key string) func() *polprog.Rules {
	return func() *polprog.Rules {
		*vari = m.getRules(key)
		return *vari
	}
}

func (m *mockDataplane) programAttached(key string) bool {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	return m.fds[key] != 0
}

func (m *mockDataplane) setRoute(cidr ip.V4CIDR) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.routes[cidr] = struct{}{}
}

func (m *mockDataplane) delRoute(cidr ip.V4CIDR) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	delete(m.routes, cidr)
}

func (m *mockDataplane) ruleMatchID(dir, action, owner, name string, idx int) polprog.RuleMatchID {
	h := fnv.New64a()
	h.Write([]byte(action + owner + dir + strconv.Itoa(idx+1) + name))
	return h.Sum64()
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
		maps                 *bpfmap.Maps
		rrConfigNormal       rules.Config
		ruleRenderer         rules.RuleRenderer
		filterTableV4        iptablesTable
		ifStateMap           *mock.Map
		countersMap          *mock.Map
	)

	BeforeEach(func() {
		fibLookupEnabled = true
		endpointToHostAction = "DROP"
		dataIfacePattern = "^eth0"
		workloadIfaceRegex = "cali"
		ipSetIDAllocator = idalloc.New()
		vxlanMTU = 0
		nodePortDSR = true

		bpfmaps.EnableRepin()

		maps = new(bpfmap.Maps)

		maps.IpsetsMap = bpfipsets.Map()
		maps.StateMap = state.Map()
		maps.CtMap = conntrack.Map()
		ifStateMap = mock.NewMockMap(ifstate.MapParams)
		maps.IfStateMap = ifStateMap
		cparams := counters.MapParameters
		cparams.ValueSize *= bpfmaps.NumPossibleCPUs()
		countersMap = mock.NewMockMap(cparams)
		maps.CountersMap = countersMap
		maps.RuleCountersMap = mock.NewMockMap(counters.PolicyMapParameters)
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

	AfterEach(func() {
		bpfmaps.DisableRepin()
	})

	newBpfEpMgr := func() {
		bpfEpMgr, _ = newBPFEndpointManager(
			dp,
			&Config{
				Hostname:              "uthost",
				BPFLogLevel:           "info",
				BPFDataIfacePattern:   regexp.MustCompile(dataIfacePattern),
				VXLANMTU:              vxlanMTU,
				VXLANPort:             rrConfigNormal.VXLANPort,
				BPFNodePortDSREnabled: nodePortDSR,
				RulesConfig: rules.Config{
					EndpointToHostAction: endpointToHostAction,
				},
				BPFExtToServiceConnmark: 0,
				FeatureGates: map[string]string{
					"BPFConnectTimeLoadBalancingWorkaround": "enabled",
				},
				BPFPolicyDebugEnabled: true,
			},
			maps,
			fibLookupEnabled,
			regexp.MustCompile(workloadIfaceRegex),
			ipSetIDAllocator,
			ruleRenderer,
			filterTableV4,
			nil,
			logutils.NewSummarizer("test"),
			&environment.FakeFeatureDetector{},
		)
		bpfEpMgr.Features = environment.NewFeatureDetector(nil).GetFeatures()
		bpfEpMgr.hostIP = net.ParseIP("1.2.3.4")
	}

	genIfaceUpdate := func(name string, state ifacemonitor.State, index int) func() {
		return func() {
			bpfEpMgr.OnUpdate(&ifaceStateUpdate{Name: name, State: state, Index: index})
			err := bpfEpMgr.CompleteDeferredWork()
			Expect(err).NotTo(HaveOccurred())
			if state == ifacemonitor.StateUp && (bpfEpMgr.isDataIface(name) || bpfEpMgr.isWorkloadIface(name)) {
				ExpectWithOffset(1, ifStateMap.ContainsKey(ifstate.NewKey(uint32(index)).AsBytes())).To(BeTrue())
			}
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

	genUntracked := func(tier, policy string) func() {
		return func() {
			bpfEpMgr.OnUpdate(&proto.ActivePolicyUpdate{
				Id:     &proto.PolicyID{Tier: tier, Name: policy},
				Policy: &proto.Policy{Untracked: true},
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

	JustBeforeEach(func() {
		dp = newMockDataplane()
		newBpfEpMgr()
	})

	It("exists", func() {
		Expect(bpfEpMgr).NotTo(BeNil())
	})

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
			var eth0I, eth0E, eth0X, caliI, caliE *polprog.Rules

			// Check eth0 ingress.
			Eventually(dp.setAndReturn(&eth0I, "eth0:ingress")).ShouldNot(BeNil())
			Expect(eth0I.ForHostInterface).To(BeTrue())
			Expect(eth0I.HostNormalTiers).To(HaveLen(1))
			Expect(eth0I.HostNormalTiers[0].Policies).To(HaveLen(1))
			Expect(eth0I.SuppressNormalHostPolicy).To(BeFalse())

			// Check eth0 egress.
			Eventually(dp.setAndReturn(&eth0E, "eth0:egress")).ShouldNot(BeNil())
			Expect(eth0E.ForHostInterface).To(BeTrue())
			Expect(eth0E.HostNormalTiers).To(HaveLen(1))
			Expect(eth0E.HostNormalTiers[0].Policies).To(HaveLen(1))
			Expect(eth0E.SuppressNormalHostPolicy).To(BeFalse())

			// Check workload ingress.
			Eventually(dp.setAndReturn(&caliI, "cali12345:egress")).ShouldNot(BeNil())
			Expect(caliI.ForHostInterface).To(BeFalse())
			Expect(caliI.SuppressNormalHostPolicy).To(BeTrue())

			// Check workload egress.
			Eventually(dp.setAndReturn(&caliE, "cali12345:ingress")).ShouldNot(BeNil())
			Expect(caliE.ForHostInterface).To(BeFalse())
			Expect(caliE.SuppressNormalHostPolicy).To(BeTrue())

			// Check no XDP.
			Eventually(dp.setAndReturn(&eth0X, "eth0:xdp")).Should(BeNil())
		})

		Context("with DefaultEndpointToHostAction RETURN", func() {
			BeforeEach(func() {
				endpointToHostAction = "RETURN"
			})

			It("has host-* policy on workload egress but not ingress", func() {
				var caliI, caliE *polprog.Rules

				// Check workload ingress.
				Eventually(dp.setAndReturn(&caliI, "cali12345:egress")).ShouldNot(BeNil())
				Expect(caliI.ForHostInterface).To(BeFalse())
				Expect(caliI.SuppressNormalHostPolicy).To(BeTrue())

				// Check workload egress.
				Eventually(dp.setAndReturn(&caliE, "cali12345:ingress")).ShouldNot(BeNil())
				Expect(caliE.ForHostInterface).To(BeFalse())
				Expect(caliE.HostNormalTiers).To(HaveLen(1))
				Expect(caliE.HostNormalTiers[0].Policies).To(HaveLen(1))
				Expect(caliE.SuppressNormalHostPolicy).To(BeFalse())
			})
		})
	})

	Context("with eth0 up", func() {
		JustBeforeEach(func() {
			genPolicy("default", "mypolicy")()
			genIfaceUpdate("eth0", ifacemonitor.StateUp, 10)()
		})

		It("should attach to eth0", func() {
			Expect(dp.programAttached("eth0:ingress")).To(BeTrue())
			Expect(dp.programAttached("eth0:egress")).To(BeTrue())
		})

		Context("with dataIfacePattern changed to eth1", func() {
			JustBeforeEach(func() {
				dataIfacePattern = "^eth1"
				newBpfEpMgr()

				dp.ensureStartedFn = func() {
					bpfEpMgr.initAttaches = map[string]bpf.EPAttachInfo{
						"eth0": {TCId: 12345},
					}
				}

			})

			It("should detach from eth0 when eth0 up before first CompleteDeferredWork()", func() {
				Expect(dp.programAttached("eth0:ingress")).To(BeTrue())
				Expect(dp.programAttached("eth0:egress")).To(BeTrue())

				genIfaceUpdate("eth0", ifacemonitor.StateUp, 10)()
				genIfaceUpdate("eth1", ifacemonitor.StateUp, 11)()

				err := bpfEpMgr.CompleteDeferredWork()
				Expect(err).NotTo(HaveOccurred())

				// We inherited dp from the previous bpfEpMgr and it has eth0
				// attached. This should clean it up.
				Expect(dp.programAttached("eth0:ingress")).To(BeFalse())
				Expect(dp.programAttached("eth0:egress")).To(BeFalse())

				Expect(dp.programAttached("eth1:ingress")).To(BeTrue())
				Expect(dp.programAttached("eth1:egress")).To(BeTrue())
			})

			It("should detach from eth0 when eth0 up after first CompleteDeferredWork()", func() {
				Expect(dp.programAttached("eth0:ingress")).To(BeTrue())
				Expect(dp.programAttached("eth0:egress")).To(BeTrue())

				genIfaceUpdate("eth1", ifacemonitor.StateUp, 11)()

				err := bpfEpMgr.CompleteDeferredWork()
				Expect(err).NotTo(HaveOccurred())

				// We inherited dp from the previous bpfEpMgr and it has eth0
				// attached. We should see it.
				Expect(dp.programAttached("eth0:ingress")).To(BeTrue())
				Expect(dp.programAttached("eth0:egress")).To(BeTrue())

				Expect(dp.programAttached("eth1:ingress")).To(BeTrue())
				Expect(dp.programAttached("eth1:egress")).To(BeTrue())

				genIfaceUpdate("eth0", ifacemonitor.StateUp, 10)()

				err = bpfEpMgr.CompleteDeferredWork()
				Expect(err).NotTo(HaveOccurred())

				// We inherited dp from the previous bpfEpMgr and it has eth0
				// attached. This should clean it up.
				Expect(dp.programAttached("eth0:ingress")).To(BeFalse())
				Expect(dp.programAttached("eth0:egress")).To(BeFalse())

				Expect(dp.programAttached("eth1:ingress")).To(BeTrue())
				Expect(dp.programAttached("eth1:egress")).To(BeTrue())
			})
		})

		Context("with eth0 host endpoint", func() {
			JustBeforeEach(genHEPUpdate("eth0", hostEp))

			It("stores host endpoint for eth0", func() {
				Expect(bpfEpMgr.hostIfaceToEpMap["eth0"]).To(Equal(hostEp))
				Expect(bpfEpMgr.policiesToWorkloads[proto.PolicyID{
					Tier: "default",
					Name: "mypolicy",
				}]).To(HaveKey("eth0"))

				var eth0I, eth0E, eth0X *polprog.Rules

				// Check ingress rules.
				Eventually(dp.setAndReturn(&eth0I, "eth0:ingress")).ShouldNot(BeNil())
				Expect(eth0I.ForHostInterface).To(BeTrue())
				Expect(eth0I.HostPreDnatTiers).To(HaveLen(1))
				Expect(eth0I.HostPreDnatTiers[0].Policies).To(HaveLen(1))

				// Check egress rules.
				Eventually(dp.setAndReturn(&eth0E, "eth0:egress")).ShouldNot(BeNil())
				Expect(eth0E.ForHostInterface).To(BeTrue())
				Expect(eth0E.HostPreDnatTiers).To(BeNil())

				// Check no XDP.
				Eventually(dp.setAndReturn(&eth0X, "eth0:xdp")).Should(BeNil())

				By("adding untracked policy")
				genUntracked("default", "untracked1")()
				newHEP := hostEp
				newHEP.UntrackedTiers = []*proto.TierInfo{{
					Name:            "default",
					IngressPolicies: []string{"untracked1"},
				}}
				genHEPUpdate("eth0", newHEP)()

				// Check XDP.
				Eventually(dp.setAndReturn(&eth0X, "eth0:xdp")).ShouldNot(BeNil())
				Expect(eth0X.ForHostInterface).To(BeTrue())
				Expect(eth0X.ForXDP).To(BeTrue())
				Expect(eth0X.HostNormalTiers).To(HaveLen(1))
				Expect(eth0X.HostNormalTiers[0].Policies).To(HaveLen(1))

				By("removing untracked policy again")
				genHEPUpdate("eth0", hostEp)()

				// Check no XDP.
				Eventually(dp.setAndReturn(&eth0X, "eth0:xdp")).Should(BeNil())
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
			Context("with eth0 deleted", func() {
				JustBeforeEach(genIfaceUpdate("eth0", ifacemonitor.StateNotPresent, 10))

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

	Describe("polCounters", func() {
		It("should update the maps with ruleIds", func() {
			ingRule := &proto.Rule{Action: "Allow", RuleId: "INGRESSALLOW1234"}
			egrRule := &proto.Rule{Action: "Allow", RuleId: "EGRESSALLOW12345"}
			ingRuleMatchId := bpfEpMgr.dp.ruleMatchID("Ingress", "Allow", "Policy", "allowPol", 0)
			egrRuleMatchId := bpfEpMgr.dp.ruleMatchID("Egress", "Allow", "Policy", "allowPol", 0)
			k := make([]byte, 8)
			v := make([]byte, 8)
			rcMap := bpfEpMgr.bpfmaps.RuleCountersMap

			// create a new policy
			bpfEpMgr.OnUpdate(&proto.ActivePolicyUpdate{
				Id:     &proto.PolicyID{Tier: "default", Name: "allowPol"},
				Policy: &proto.Policy{InboundRules: []*proto.Rule{ingRule}, OutboundRules: []*proto.Rule{egrRule}},
			})
			Expect(bpfEpMgr.polNameToMatchIDs).To(HaveLen(1))
			val := bpfEpMgr.polNameToMatchIDs["allowPol"]
			Expect(val.Contains(ingRuleMatchId)).To(BeTrue())
			Expect(val.Contains(egrRuleMatchId)).To(BeTrue())
			binary.LittleEndian.PutUint64(k, ingRuleMatchId)
			binary.LittleEndian.PutUint64(v, uint64(10))
			err := rcMap.Update(k[:], v[:])
			Expect(err).NotTo(HaveOccurred())
			binary.LittleEndian.PutUint64(k, egrRuleMatchId)
			err = rcMap.Update(k[:], v[:])
			Expect(err).NotTo(HaveOccurred())

			// update the ingress rule of the policy
			ingDenyRule := &proto.Rule{Action: "Deny", RuleId: "INGRESSDENY12345"}
			ingDenyRuleMatchId := bpfEpMgr.dp.ruleMatchID("Ingress", "Deny", "Policy", "allowPol", 0)
			bpfEpMgr.OnUpdate(&proto.ActivePolicyUpdate{
				Id:     &proto.PolicyID{Tier: "default", Name: "allowPol"},
				Policy: &proto.Policy{InboundRules: []*proto.Rule{ingDenyRule}, OutboundRules: []*proto.Rule{egrRule}},
			})
			Expect(bpfEpMgr.polNameToMatchIDs).To(HaveLen(1))
			val = bpfEpMgr.polNameToMatchIDs["allowPol"]
			Expect(val.Contains(ingDenyRuleMatchId)).To(BeTrue())
			Expect(val.Contains(egrRuleMatchId)).To(BeTrue())
			Expect(bpfEpMgr.dirtyRules.Contains(ingRuleMatchId)).To(BeTrue())
			err = bpfEpMgr.CompleteDeferredWork()
			Expect(err).NotTo(HaveOccurred())
			Expect(bpfEpMgr.dirtyRules.Contains(ingRuleMatchId)).NotTo(BeTrue())
			binary.LittleEndian.PutUint64(k, ingRuleMatchId)
			_, err = rcMap.Get(k)
			Expect(err).To(HaveOccurred())
			binary.LittleEndian.PutUint64(k, egrRuleMatchId)
			v, err = rcMap.Get(k)
			Expect(err).NotTo(HaveOccurred())
			Expect(binary.LittleEndian.Uint64(v)).To(Equal(uint64(10)))

			// delete the policy
			bpfEpMgr.OnUpdate(&proto.ActivePolicyRemove{Id: &proto.PolicyID{Tier: "default", Name: "allowPol"}})
			Expect(bpfEpMgr.dirtyRules.Contains(egrRuleMatchId)).To(BeTrue())
			Expect(bpfEpMgr.dirtyRules.Contains(ingDenyRuleMatchId)).To(BeTrue())
			Expect(bpfEpMgr.polNameToMatchIDs).To(HaveLen(0))
			err = bpfEpMgr.CompleteDeferredWork()
			Expect(err).NotTo(HaveOccurred())
			binary.LittleEndian.PutUint64(k, ingRuleMatchId)
			_, err = rcMap.Get(k)
			Expect(err).To(HaveOccurred())
			binary.LittleEndian.PutUint64(k, egrRuleMatchId)
			_, err = rcMap.Get(k)
			Expect(err).To(HaveOccurred())
			binary.LittleEndian.PutUint64(k, ingDenyRuleMatchId)
			_, err = rcMap.Get(k)
			Expect(err).To(HaveOccurred())

		})

		It("should cleanup the bpf map after restart", func() {
			ingRuleMatchId := bpfEpMgr.dp.ruleMatchID("Ingress", "Allow", "Policy", "allowPol", 0)
			egrRuleMatchId := bpfEpMgr.dp.ruleMatchID("Egress", "Allow", "Policy", "allowPol", 0)
			k := make([]byte, 8)
			v := make([]byte, 8)
			rcMap := bpfEpMgr.bpfmaps.RuleCountersMap

			binary.LittleEndian.PutUint64(k, ingRuleMatchId)
			binary.LittleEndian.PutUint64(v, uint64(10))
			err := rcMap.Update(k[:], v[:])
			Expect(err).NotTo(HaveOccurred())

			binary.LittleEndian.PutUint64(k, egrRuleMatchId)
			binary.LittleEndian.PutUint64(v, uint64(10))
			err = rcMap.Update(k[:], v[:])
			Expect(err).NotTo(HaveOccurred())

			newBpfEpMgr()
			binary.LittleEndian.PutUint64(k, ingRuleMatchId)
			_, err = rcMap.Get(k[:])
			Expect(err).To(HaveOccurred())
			binary.LittleEndian.PutUint64(k, egrRuleMatchId)
			_, err = rcMap.Get(k[:])
			Expect(err).To(HaveOccurred())
		})
	})

	Describe("bpfnatip", func() {
		It("should program the routes reflecting service state", func() {
			bpfEpMgr.OnUpdate(&proto.ServiceUpdate{
				Name:      "service",
				Namespace: "test",
				ClusterIp: "1.2.3.4",
			})
			err := bpfEpMgr.CompleteDeferredWork()
			Expect(err).NotTo(HaveOccurred())
			Expect(dp.routes).To(HaveLen(1))
			Expect(dp.routes).To(HaveKey(ip.MustParseCIDROrIP("1.2.3.4")))

			bpfEpMgr.OnUpdate(&proto.ServiceUpdate{
				Name:           "service",
				Namespace:      "test",
				ClusterIp:      "1.2.3.4",
				LoadbalancerIp: "5.6.7.8",
			})
			err = bpfEpMgr.CompleteDeferredWork()
			Expect(err).NotTo(HaveOccurred())
			Expect(dp.routes).To(HaveLen(2))
			Expect(dp.routes).To(HaveKey(ip.MustParseCIDROrIP("1.2.3.4")))
			Expect(dp.routes).To(HaveKey(ip.MustParseCIDROrIP("5.6.7.8")))

			bpfEpMgr.OnUpdate(&proto.ServiceUpdate{
				Name:           "service",
				Namespace:      "test",
				ClusterIp:      "1.2.3.4",
				LoadbalancerIp: "5.6.7.8",
				ExternalIps:    []string{"1.0.0.1", "1.0.0.2"},
			})
			err = bpfEpMgr.CompleteDeferredWork()
			Expect(err).NotTo(HaveOccurred())
			Expect(dp.routes).To(HaveLen(2))
			Expect(dp.routes).To(HaveKey(ip.MustParseCIDROrIP("1.2.3.4")))
			Expect(dp.routes).To(HaveKey(ip.MustParseCIDROrIP("5.6.7.8")))

			bpfEpMgr.OnUpdate(&proto.ServiceUpdate{
				Name:      "service",
				Namespace: "test",
				ClusterIp: "1.2.3.4",
			})
			err = bpfEpMgr.CompleteDeferredWork()
			Expect(err).NotTo(HaveOccurred())
			Expect(dp.routes).To(HaveLen(1))
			Expect(dp.routes).To(HaveKey(ip.MustParseCIDROrIP("1.2.3.4")))

			bpfEpMgr.OnUpdate(&proto.ServiceRemove{
				Name:      "service",
				Namespace: "test",
			})
			err = bpfEpMgr.CompleteDeferredWork()
			Expect(err).NotTo(HaveOccurred())
			Expect(dp.routes).To(HaveLen(0))

			bpfEpMgr.OnUpdate(&proto.ServiceUpdate{
				Name:           "service",
				Namespace:      "test",
				ClusterIp:      "1.2.3.4",
				LoadbalancerIp: "5.6.7.8",
			})
			err = bpfEpMgr.CompleteDeferredWork()
			Expect(err).NotTo(HaveOccurred())
			Expect(dp.routes).To(HaveLen(2))
			Expect(dp.routes).To(HaveKey(ip.MustParseCIDROrIP("1.2.3.4")))
			Expect(dp.routes).To(HaveKey(ip.MustParseCIDROrIP("5.6.7.8")))

			bpfEpMgr.OnUpdate(&proto.ServiceRemove{
				Name:      "service",
				Namespace: "test",
			})
			err = bpfEpMgr.CompleteDeferredWork()
			Expect(err).NotTo(HaveOccurred())
			Expect(dp.routes).To(HaveLen(0))
		})
	})

	Describe("counters", func() {
		It("should clean up after restart", func() {
			err := counters.EnsureExists(countersMap, 12345, bpf.HookEgress)
			Expect(err).NotTo(HaveOccurred())
			err = counters.EnsureExists(countersMap, 12345, bpf.HookIngress)
			Expect(err).NotTo(HaveOccurred())
			err = counters.EnsureExists(countersMap, 12345, bpf.HookXDP)
			Expect(err).NotTo(HaveOccurred())
			err = counters.EnsureExists(countersMap, 54321, bpf.HookEgress)
			Expect(err).NotTo(HaveOccurred())
			err = counters.EnsureExists(countersMap, 54321, bpf.HookIngress)
			Expect(err).NotTo(HaveOccurred())

			Expect(countersMap.Contents).To(HaveLen(5))

			genIfaceUpdate("cali12345", ifacemonitor.StateUp, 15)()
			genWLUpdate("cali12345")()

			err = bpfEpMgr.CompleteDeferredWork()
			Expect(err).NotTo(HaveOccurred())

			Expect(countersMap.Contents).To(HaveLen(0))
			// The BPF programs will create the counters the first time they
		})
	})

	Describe("ifstate", func() {
		checkIfState := func(idx int, name string, flags uint32) {
			k := ifstate.NewKey(uint32(idx))
			v := ifstate.NewValue(flags, name)
			vb, err := ifStateMap.Get(k.AsBytes())
			if err != nil {
				Fail(fmt.Sprintf("Ifstate does not have key %s", k), 1)
			}
			if string(v.AsBytes()) != string(vb) {
				vv := ifstate.ValueFromBytes(vb)
				Fail(fmt.Sprintf("Ifstate key %s value %s does not match expected %s", k, vv, v), 1)
			}
		}

		It("should clean up", func() {
			_ = ifStateMap.Update(
				ifstate.NewKey(123).AsBytes(),
				ifstate.NewValue(ifstate.FlgReady, "eth123").AsBytes(),
			)
			_ = ifStateMap.Update(
				ifstate.NewKey(124).AsBytes(),
				ifstate.NewValue(0, "eth124").AsBytes(),
			)
			_ = ifStateMap.Update(
				ifstate.NewKey(125).AsBytes(),
				ifstate.NewValue(ifstate.FlgWEP|ifstate.FlgReady, "eth125").AsBytes(),
			)
			_ = ifStateMap.Update(
				ifstate.NewKey(126).AsBytes(),
				ifstate.NewValue(ifstate.FlgWEP, "eth123").AsBytes(),
			)

			err := bpfEpMgr.CompleteDeferredWork()
			Expect(err).NotTo(HaveOccurred())

			Expect(ifStateMap.IsEmpty()).To(BeTrue())
		})

		It("should clean up with update", func() {
			_ = ifStateMap.Update(
				ifstate.NewKey(123).AsBytes(),
				ifstate.NewValue(ifstate.FlgReady, "eth123").AsBytes(),
			)

			genIfaceUpdate("cali12345", ifacemonitor.StateUp, 15)()
			genWLUpdate("cali12345")()

			err := bpfEpMgr.CompleteDeferredWork()
			Expect(err).NotTo(HaveOccurred())

			Expect(ifStateMap.ContainsKey(ifstate.NewKey(123).AsBytes())).To(BeFalse())
			checkIfState(15, "cali12345", ifstate.FlgWEP|ifstate.FlgReady)
		})

		It("iface up -> wl", func() {
			genIfaceUpdate("cali12345", ifacemonitor.StateUp, 15)()
			genWLUpdate("cali12345")()

			err := bpfEpMgr.CompleteDeferredWork()
			Expect(err).NotTo(HaveOccurred())

			checkIfState(15, "cali12345", ifstate.FlgWEP|ifstate.FlgReady)
		})

		It("iface up -> defer -> wl", func() {
			genIfaceUpdate("cali12345", ifacemonitor.StateUp, 15)()

			err := bpfEpMgr.CompleteDeferredWork()
			Expect(err).NotTo(HaveOccurred())

			checkIfState(15, "cali12345", ifstate.FlgWEP|ifstate.FlgReady)

			genWLUpdate("cali12345")()

			err = bpfEpMgr.CompleteDeferredWork()
			Expect(err).NotTo(HaveOccurred())

			checkIfState(15, "cali12345", ifstate.FlgWEP|ifstate.FlgReady)
		})

		It("wl -> iface up", func() {
			genWLUpdate("cali12345")()
			genIfaceUpdate("cali12345", ifacemonitor.StateUp, 15)()

			err := bpfEpMgr.CompleteDeferredWork()
			Expect(err).NotTo(HaveOccurred())

			checkIfState(15, "cali12345", ifstate.FlgWEP|ifstate.FlgReady)
		})

		It("wl -> defer -> iface up", func() {
			genWLUpdate("cali12345")()

			err := bpfEpMgr.CompleteDeferredWork()
			Expect(err).NotTo(HaveOccurred())
			Expect(ifStateMap.ContainsKey(ifstate.NewKey(uint32(15)).AsBytes())).To(BeFalse())

			genIfaceUpdate("cali12345", ifacemonitor.StateUp, 15)()

			err = bpfEpMgr.CompleteDeferredWork()
			Expect(err).NotTo(HaveOccurred())

			checkIfState(15, "cali12345", ifstate.FlgWEP|ifstate.FlgReady)
		})

		It("iface up -> wl -> iface down", func() {
			genIfaceUpdate("cali12345", ifacemonitor.StateUp, 15)()
			genWLUpdate("cali12345")()

			err := bpfEpMgr.CompleteDeferredWork()
			Expect(err).NotTo(HaveOccurred())

			genIfaceUpdate("cali12345", ifacemonitor.StateDown, 15)()

			err = bpfEpMgr.CompleteDeferredWork()
			Expect(err).NotTo(HaveOccurred())

			Expect(ifStateMap.ContainsKey(ifstate.NewKey(15).AsBytes())).To(BeFalse())
		})

		It("iface up -> wl -> iface down, up, down", func() {
			genIfaceUpdate("cali12345", ifacemonitor.StateUp, 15)()
			genWLUpdate("cali12345")()

			err := bpfEpMgr.CompleteDeferredWork()
			Expect(err).NotTo(HaveOccurred())

			genIfaceUpdate("cali12345", ifacemonitor.StateDown, 15)()
			genIfaceUpdate("cali12345", ifacemonitor.StateUp, 15)()
			genIfaceUpdate("cali12345", ifacemonitor.StateDown, 15)()

			err = bpfEpMgr.CompleteDeferredWork()
			Expect(err).NotTo(HaveOccurred())

			Expect(ifStateMap.ContainsKey(ifstate.NewKey(15).AsBytes())).To(BeFalse())
		})

		It("iface up -> wl -> iface down -> iface up", func() {
			genIfaceUpdate("cali12345", ifacemonitor.StateUp, 15)()
			genWLUpdate("cali12345")()

			err := bpfEpMgr.CompleteDeferredWork()
			Expect(err).NotTo(HaveOccurred())

			genIfaceUpdate("cali12345", ifacemonitor.StateDown, 15)()

			err = bpfEpMgr.CompleteDeferredWork()
			Expect(err).NotTo(HaveOccurred())

			genIfaceUpdate("cali12345", ifacemonitor.StateUp, 15)()

			err = bpfEpMgr.CompleteDeferredWork()
			Expect(err).NotTo(HaveOccurred())

			checkIfState(15, "cali12345", ifstate.FlgWEP|ifstate.FlgReady)
		})
	})
})
