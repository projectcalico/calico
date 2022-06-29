//go:build !windows

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
	"fmt"
	"regexp"
	"sync"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/environment"
	"github.com/projectcalico/calico/felix/logutils"

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/bpf/asm"
	"github.com/projectcalico/calico/felix/bpf/conntrack"
	bpfipsets "github.com/projectcalico/calico/felix/bpf/ipsets"
	"github.com/projectcalico/calico/felix/bpf/polprog"
	"github.com/projectcalico/calico/felix/bpf/state"
	"github.com/projectcalico/calico/felix/idalloc"
	"github.com/projectcalico/calico/felix/ifacemonitor"
	"github.com/projectcalico/calico/felix/ipsets"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/rules"
)

type mockDataplane struct {
	mutex     sync.Mutex
	lastFD    uint32
	fds       map[string]uint32
	state     map[uint32]polprog.Rules
	routes    map[string]struct{}
	shouldErr bool
}

func newMockDataplane() *mockDataplane {
	return &mockDataplane{
		lastFD: 5,
		fds:    map[string]uint32{},
		state:  map[uint32]polprog.Rules{},
		routes: map[string]struct{}{},
	}
}

func (m *mockDataplane) ensureStarted() {
}

func (m *mockDataplane) ensureBPFDevices() error {
	return nil
}

func (m *mockDataplane) ensureProgramAttached(ap attachPoint) (bpf.MapFD, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	key := ap.IfaceName() + ":" + ap.JumpMapFDMapKey()
	if fd, exists := m.fds[key]; exists {
		return bpf.MapFD(fd), nil
	}
	m.lastFD += 1
	m.fds[key] = m.lastFD
	return bpf.MapFD(m.lastFD), nil
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

func (m *mockDataplane) updatePolicyProgram(jumpMapFD bpf.MapFD, rules polprog.Rules) (asm.Insns, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.state[uint32(jumpMapFD)] = rules
	return nil, nil
}

func (m *mockDataplane) removePolicyProgram(jumpMapFD bpf.MapFD) error {
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

func (m *mockDataplane) setRoute(ip string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	defer func() { m.shouldErr = false }()

	if m.shouldErr {
		return fmt.Errorf("setRoute error")
	}

	m.routes[ip] = struct{}{}

	return nil
}

func (m *mockDataplane) delRoute(ip string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	defer func() { m.shouldErr = false }()

	if m.shouldErr {
		return fmt.Errorf("delRoute error")
	}

	if _, ok := m.routes[ip]; !ok {
		return fmt.Errorf("no route for %s", ip)
	}

	delete(m.routes, ip)

	return nil
}

func (m *mockDataplane) setErr() {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.shouldErr = true
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
		bpfMapContext.IpsetsMap = bpfipsets.Map(bpfMapContext)
		bpfMapContext.StateMap = state.Map(bpfMapContext)
		bpfMapContext.CtMap = conntrack.Map(bpfMapContext)
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
				FeatureDetectOverrides: map[string]string{
					"BPFConnectTimeLoadBalancingWorkaround": "enabled",
				},
			},
			bpfMapContext,
			fibLookupEnabled,
			regexp.MustCompile(workloadIfaceRegex),
			ipSetIDAllocator,
			ruleRenderer,
			filterTableV4,
			nil,
			logutils.NewSummarizer("test"),
		)
		bpfEpMgr.Features = environment.NewFeatureDetector(nil).GetFeatures()
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
			Eventually(dp.setAndReturn(&eth0I, "eth0:tc-ingress")).ShouldNot(BeNil())
			Expect(eth0I.ForHostInterface).To(BeTrue())
			Expect(eth0I.HostNormalTiers).To(HaveLen(1))
			Expect(eth0I.HostNormalTiers[0].Policies).To(HaveLen(1))
			Expect(eth0I.SuppressNormalHostPolicy).To(BeFalse())

			// Check eth0 egress.
			Eventually(dp.setAndReturn(&eth0E, "eth0:tc-egress")).ShouldNot(BeNil())
			Expect(eth0E.ForHostInterface).To(BeTrue())
			Expect(eth0E.HostNormalTiers).To(HaveLen(1))
			Expect(eth0E.HostNormalTiers[0].Policies).To(HaveLen(1))
			Expect(eth0E.SuppressNormalHostPolicy).To(BeFalse())

			// Check workload ingress.
			Eventually(dp.setAndReturn(&caliI, "cali12345:tc-egress")).ShouldNot(BeNil())
			Expect(caliI.ForHostInterface).To(BeFalse())
			Expect(caliI.SuppressNormalHostPolicy).To(BeTrue())

			// Check workload egress.
			Eventually(dp.setAndReturn(&caliE, "cali12345:tc-ingress")).ShouldNot(BeNil())
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
				Eventually(dp.setAndReturn(&caliI, "cali12345:tc-egress")).ShouldNot(BeNil())
				Expect(caliI.ForHostInterface).To(BeFalse())
				Expect(caliI.SuppressNormalHostPolicy).To(BeTrue())

				// Check workload egress.
				Eventually(dp.setAndReturn(&caliE, "cali12345:tc-ingress")).ShouldNot(BeNil())
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
				Eventually(dp.setAndReturn(&eth0I, "eth0:tc-ingress")).ShouldNot(BeNil())
				Expect(eth0I.ForHostInterface).To(BeTrue())
				Expect(eth0I.HostPreDnatTiers).To(HaveLen(1))
				Expect(eth0I.HostPreDnatTiers[0].Policies).To(HaveLen(1))

				// Check egress rules.
				Eventually(dp.setAndReturn(&eth0E, "eth0:tc-egress")).ShouldNot(BeNil())
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
			Expect(dp.routes).To(HaveKey("1.2.3.4"))

			bpfEpMgr.OnUpdate(&proto.ServiceUpdate{
				Name:           "service",
				Namespace:      "test",
				ClusterIp:      "1.2.3.4",
				LoadbalancerIp: "5.6.7.8",
			})
			err = bpfEpMgr.CompleteDeferredWork()
			Expect(err).NotTo(HaveOccurred())
			Expect(dp.routes).To(HaveLen(2))
			Expect(dp.routes).To(HaveKey("1.2.3.4"))
			Expect(dp.routes).To(HaveKey("5.6.7.8"))

			bpfEpMgr.OnUpdate(&proto.ServiceUpdate{
				Name:           "service",
				Namespace:      "test",
				ClusterIp:      "1.2.3.4",
				LoadbalancerIp: "5.6.7.8",
				ExternalIps:    []string{"1.0.0.1", "1.0.0.2"},
			})
			err = bpfEpMgr.CompleteDeferredWork()
			Expect(err).NotTo(HaveOccurred())
			Expect(dp.routes).To(HaveLen(4))
			Expect(dp.routes).To(HaveKey("1.2.3.4"))
			Expect(dp.routes).To(HaveKey("5.6.7.8"))
			Expect(dp.routes).To(HaveKey("1.0.0.1"))
			Expect(dp.routes).To(HaveKey("1.0.0.2"))

			bpfEpMgr.OnUpdate(&proto.ServiceUpdate{
				Name:      "service",
				Namespace: "test",
				ClusterIp: "1.2.3.4",
			})
			err = bpfEpMgr.CompleteDeferredWork()
			Expect(err).NotTo(HaveOccurred())
			Expect(dp.routes).To(HaveLen(1))
			Expect(dp.routes).To(HaveKey("1.2.3.4"))

			bpfEpMgr.OnUpdate(&proto.ServiceRemove{
				Name:      "service",
				Namespace: "test",
			})
			err = bpfEpMgr.CompleteDeferredWork()
			Expect(err).NotTo(HaveOccurred())
			Expect(dp.routes).To(HaveLen(0))

			dp.setErr()
			bpfEpMgr.OnUpdate(&proto.ServiceUpdate{
				Name:           "service",
				Namespace:      "test",
				ClusterIp:      "1.2.3.4",
				LoadbalancerIp: "5.6.7.8",
			})
			err = bpfEpMgr.CompleteDeferredWork()
			Expect(err).NotTo(HaveOccurred())
			Expect(dp.routes).To(HaveLen(1))
			Expect(dp.routes).To(HaveKey("5.6.7.8"))
			err = bpfEpMgr.CompleteDeferredWork()
			Expect(err).NotTo(HaveOccurred())
			Expect(dp.routes).To(HaveLen(2))
			Expect(dp.routes).To(HaveKey("1.2.3.4"))
			Expect(dp.routes).To(HaveKey("5.6.7.8"))

			dp.setErr()
			bpfEpMgr.OnUpdate(&proto.ServiceRemove{
				Name:      "service",
				Namespace: "test",
			})
			err = bpfEpMgr.CompleteDeferredWork()
			Expect(err).NotTo(HaveOccurred())
			Expect(dp.routes).To(HaveLen(1))
			Expect(dp.routes).To(HaveKey("1.2.3.4"))
			err = bpfEpMgr.CompleteDeferredWork()
			Expect(err).NotTo(HaveOccurred())
			Expect(dp.routes).To(HaveLen(0))
		})
	})
})
