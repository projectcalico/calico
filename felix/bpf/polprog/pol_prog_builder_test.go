// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.

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

package polprog

import (
	"testing"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/idalloc"
	"github.com/projectcalico/calico/felix/proto"
)

func TestPolicySanityCheck(t *testing.T) {
	// Just a basic sanity check with a kitchen sink policy.  The policy behaviour is tested "for real" in the
	// bpf/ut package.

	RegisterTestingT(t)
	alloc := idalloc.New()
	setID := func(id string) string {
		alloc.GetOrAlloc(id)
		return id
	}
	pg := NewBuilder(alloc, 1, 2, 3)
	insns, err := pg.Instructions(Rules{
		Tiers: []Tier{{
			Policies: []Policy{{
				Rules: []Rule{{
					Rule: &proto.Rule{
						Action:                  "Allow",
						IpVersion:               4,
						Protocol:                &proto.Protocol{NumberOrName: &proto.Protocol_Number{Number: 6}},
						SrcNet:                  []string{"10.0.0.0/8"},
						SrcPorts:                []*proto.PortRange{{First: 80, Last: 81}, {First: 8080, Last: 8081}},
						SrcNamedPortIpSetIds:    []string{setID("n:abcdef1234567890")},
						DstNet:                  []string{"11.0.0.0/8"},
						DstPorts:                []*proto.PortRange{{First: 3000, Last: 3001}},
						DstNamedPortIpSetIds:    []string{setID("n:foo1234567890")},
						Icmp:                    &proto.Rule_IcmpTypeCode{IcmpTypeCode: &proto.IcmpTypeAndCode{Type: 10, Code: 12}},
						SrcIpSetIds:             []string{setID("s:sbcdef1234567890")},
						DstIpSetIds:             []string{setID("s:dbcdef1234567890")},
						DstIpPortSetIds:         []string{setID("svc:abcdefg1234567")},
						NotProtocol:             &proto.Protocol{NumberOrName: &proto.Protocol_Name{Name: "UDP"}},
						NotSrcNet:               []string{"12.0.0.0/8"},
						NotSrcPorts:             []*proto.PortRange{{First: 5000, Last: 5000}},
						NotDstNet:               []string{"13.0.0.0/8"},
						NotDstPorts:             []*proto.PortRange{{First: 4000, Last: 4000}},
						NotIcmp:                 &proto.Rule_NotIcmpTypeCode{NotIcmpTypeCode: &proto.IcmpTypeAndCode{Type: 10, Code: 12}},
						NotSrcIpSetIds:          []string{setID("s:abcdef1234567890")},
						NotDstIpSetIds:          []string{setID("s:abcdef123456789l")},
						NotSrcNamedPortIpSetIds: []string{setID("n:0bcdef1234567890")},
						NotDstNamedPortIpSetIds: []string{setID("n:0bcdef1234567890")},
					},
				}},
			}},
		}},
	}, false)

	Expect(err).NotTo(HaveOccurred())
	for i, in := range insns {
		t.Log(i, ": ", in.Instruction)
	}
}

func TestLogActionIgnored(t *testing.T) {
	RegisterTestingT(t)
	alloc := idalloc.New()

	pg := NewBuilder(alloc, 1, 2, 3)
	insns, err := pg.Instructions(Rules{
		Tiers: []Tier{{
			Name: "default",
			Policies: []Policy{{
				Name: "test policy",
				Rules: []Rule{{Rule: &proto.Rule{
					Action: "Log",
				}}},
			}},
		}}}, false)
	Expect(err).NotTo(HaveOccurred())

	pg = NewBuilder(alloc, 1, 2, 3)
	noOpInsns, err := pg.Instructions(Rules{
		Tiers: []Tier{{
			Name:     "default",
			Policies: []Policy{},
		}}}, false)
	Expect(err).NotTo(HaveOccurred())
	Expect(noOpInsns).To(Equal(insns))
}
