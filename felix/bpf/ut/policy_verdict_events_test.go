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
	"fmt"
	"net"
	"testing"

	"github.com/google/gopacket/layers"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/bpf/events"
	"github.com/projectcalico/calico/felix/bpf/polprog"
	"github.com/projectcalico/calico/felix/bpf/state"
	tcdefs "github.com/projectcalico/calico/felix/bpf/tc/defs"
	"github.com/projectcalico/calico/felix/proto"
)

func TestPolicyVerdictEvents(t *testing.T) {
	RegisterTestingT(t)

	tests := []struct {
		name     string
		accept   bool
		policy   polprog.Rules
		hits     int
		rulesIDs [state.MaxRuleIDs]uint64
	}{
		{
			name:   "no rules, drop all",
			accept: false,
			policy: polprog.Rules{},
			hits:   1,
		},
		{
			name:   "allow all",
			accept: true,
			policy: polprog.Rules{
				Tiers: []polprog.Tier{{
					Name: "base tier",
					Policies: []polprog.Policy{{
						Name:  "allow all",
						Rules: []polprog.Rule{{Rule: &proto.Rule{Action: "Allow"}, MatchID: 0x1234}},
					}},
				}},
			},
			hits:     1,
			rulesIDs: [state.MaxRuleIDs]uint64{0x1234},
		},
		{
			name:   "udp tier",
			accept: true,
			policy: polprog.Rules{
				Tiers: []polprog.Tier{
					{
						Name: "base tier",
						Policies: []polprog.Policy{
							{
								Name: "pass udp",
								Rules: []polprog.Rule{{
									Rule: &proto.Rule{
										Action: "Pass",
										Protocol: &proto.Protocol{
											NumberOrName: &proto.Protocol_Name{Name: "udp"},
										},
									},
									MatchID: 17,
								}},
							},
							{
								Name:  "allow all",
								Rules: []polprog.Rule{{Rule: &proto.Rule{Action: "Allow"}, MatchID: 0x1234}},
							},
						},
					},
					{
						Name: "allow udp",
						Policies: []polprog.Policy{
							{
								Name: "allow udp",
								Rules: []polprog.Rule{{
									Rule: &proto.Rule{
										Action: "allow",
										Protocol: &proto.Protocol{
											NumberOrName: &proto.Protocol_Name{Name: "udp"},
										},
									},
									MatchID: 1717,
								}},
							},
							{
								Name:  "allow all",
								Rules: []polprog.Rule{{Rule: &proto.Rule{Action: "Allow"}, MatchID: 0x1234}},
							},
						},
					},
				},
			},
			hits:     2,
			rulesIDs: [state.MaxRuleIDs]uint64{17, 1717},
		},
	}

	evnts, err := events.New(events.SourcePerfEvents, 1<<20)
	Expect(err).NotTo(HaveOccurred())
	defer evnts.Close()

	defer func() { bpfIfaceName = "" }()

	_, ipv4, l4, _, pktBytes, err := testPacketUDPDefault()
	Expect(err).NotTo(HaveOccurred())
	udp := l4.(*layers.UDP)

	hostIP = node1ip

	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {

			tcRes := resTC_ACT_UNSPEC
			policyRC := state.PolicyAllow

			if !tc.accept {
				tcRes = resTC_ACT_SHOT
				policyRC = state.PolicyDeny
			}

			bpfIfaceName = fmt.Sprintf("FLG%d", i)

			skbMark = tcdefs.MarkSeen
			resetCTMap(ctMap) // ensure it is clean to enforce policy

			runBpfTest(t, "calico_to_workload_ep", &tc.policy, func(bpfrun bpfProgRunFn) {
				res, err := bpfrun(pktBytes)
				Expect(err).NotTo(HaveOccurred())
				Expect(res.Retval).To(Equal(tcRes))
			})

			var evnt events.Event
			done := make(chan struct{})
			go func() {
				defer close(done)
				evnt, err = evnts.Next()
			}()
			Eventually(done, "5s").Should(BeClosed())
			Expect(err).NotTo(HaveOccurred())
			Expect(evnt.Type()).To(Equal(events.TypePolicyVerdict))

			fl := events.ParsePolicyVerdict(evnt.Data(), false)

			Expect(fl.SrcAddr.Equal(ipv4.SrcIP)).To(BeTrue())
			Expect(fl.DstAddr.Equal(ipv4.DstIP)).To(BeTrue())
			Expect(fl.SrcPort).To(Equal(uint16(udp.SrcPort)))
			Expect(fl.DstPort).To(Equal(uint16(udp.DstPort)))
			Expect(fl.IPProto).To(Equal(uint8(17)))

			Expect(fl.PostNATDstAddr.Equal(ipv4.DstIP)).To(BeTrue())
			Expect(fl.PostNATDstPort).To(Equal(uint16(udp.DstPort)))

			Expect(fl.NATTunSrcAddr.Equal(net.IPv4(0, 0, 0, 0))).To(BeTrue())

			Expect(fl.PolicyRC).To(Equal(policyRC))

			Expect(fl.RulesHit).To(Equal(uint32(tc.hits)))
			Expect(fl.RuleIDs).To(Equal(tc.rulesIDs))

			Expect(fl.IPSize).To(Equal(uint16(ipv4.Length)))
		})
	}
}
