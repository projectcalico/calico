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
	"github.com/projectcalico/felix/bpf/state"
	"github.com/projectcalico/felix/idalloc"
	"github.com/projectcalico/felix/ifacemonitor"
	"github.com/projectcalico/felix/ipsets"
	"github.com/projectcalico/felix/proto"
	"github.com/projectcalico/felix/rules"
)

var _ = Describe("BPF Endpoint Manager", func() {

	var (
		bpfEpMgr *bpfEndpointManager
	)

	fibLookupEnabled := true
	endpointToHostAction := "DROP"
	dataIfacePattern := "^((en|wl|ww|sl|ib)[opsx].*|(eth|wlan|wwan).*|tunl0$|wireguard.cali$)"
	workloadIfaceRegex := "cali"
	ipSetIDAllocator := idalloc.New()
	vxlanMTU := 0
	nodePortDSR := true
	bpfMapContext := &bpf.MapContext{
		RepinningEnabled: true,
	}
	ipSetsMap := bpfipsets.Map(bpfMapContext)
	stateMap := state.Map(bpfMapContext)
	rrConfigNormal := rules.Config{
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
	ruleRenderer := rules.NewRenderer(rrConfigNormal)
	filterTableV4 := newMockTable("filter")

	BeforeEach(func() {
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
	})

	It("exists", func() {
		Expect(bpfEpMgr).NotTo(BeNil())
	})

	genIfaceUpdate := func(name string, state ifacemonitor.State, index int) func() {
		return func() {
			bpfEpMgr.OnUpdate(&ifaceUpdate{Name: name, State: state, Index: index})
			bpfEpMgr.CompleteDeferredWork()
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
			bpfEpMgr.CompleteDeferredWork()
		}
	}

	hostEp := proto.HostEndpoint{
		Name: "uthost-eth0",
		PreDnatTiers: []*proto.TierInfo{
			&proto.TierInfo{
				Name:            "mytier",
				IngressPolicies: []string{"mypolicy"},
			},
		},
	}

	It("does not have HEP in initial state", func() {
		Expect(bpfEpMgr.hostIfaceToEpMap["eth0"]).NotTo(Equal(hostEp))
	})

	Context("with eth0 up", func() {
		BeforeEach(genIfaceUpdate("eth0", ifacemonitor.StateUp, 10))

		Context("with eth0 host endpoint", func() {
			BeforeEach(genHEPUpdate("eth0", hostEp))

			It("stores host endpoint for eth0", func() {
				Expect(bpfEpMgr.hostIfaceToEpMap["eth0"]).To(Equal(hostEp))
				Expect(bpfEpMgr.policiesToWorkloads[proto.PolicyID{
					Tier: "default",
					Name: "mypolicy",
				}]).To(HaveKey("eth0"))
			})
		})

		Context("with host-* endpoint", func() {
			BeforeEach(genHEPUpdate(allInterfaces, hostEp))

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
		BeforeEach(genHEPUpdate("eth0", hostEp))

		Context("with eth0 up", func() {
			BeforeEach(genIfaceUpdate("eth0", ifacemonitor.StateUp, 10))

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
		BeforeEach(genHEPUpdate(allInterfaces, hostEp))

		Context("with eth0 up", func() {
			BeforeEach(genIfaceUpdate("eth0", ifacemonitor.StateUp, 10))

			It("stores host endpoint for eth0", func() {
				Expect(bpfEpMgr.hostIfaceToEpMap["eth0"]).To(Equal(hostEp))
				Expect(bpfEpMgr.policiesToWorkloads[proto.PolicyID{
					Tier: "default",
					Name: "mypolicy",
				}]).To(HaveKey("eth0"))
			})

			Context("with eth0 down", func() {
				BeforeEach(genIfaceUpdate("eth0", ifacemonitor.StateDown, 10))

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
