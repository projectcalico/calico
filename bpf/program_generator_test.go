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

package bpf

import (
	"bytes"
	"testing"

	"github.com/projectcalico/felix/idalloc"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/felix/proto"
)

const kitchenSink = `// Start of tier 0
// Start of policy 0
// Start of rule 0
RULE_START(0);
RULE_MATCH_PROTOCOL(0, false, 6);
RULE_MATCH_PROTOCOL(0, true, 6);
RULE_MATCH_CIDRS(0, false, saddr, {0xff000000, 0xa000000});
RULE_MATCH_CIDRS(0, true, saddr, {0xff000000, 0xc000000});
RULE_MATCH_CIDRS(0, false, daddr, {0xff000000, 0xb000000});
RULE_MATCH_CIDRS(0, true, daddr, {0xff000000, 0xd000000});
RULE_MATCH_IP_SET(0, false, saddr, 0xc9e0b8362d2ae7aa);
RULE_MATCH_IP_SET(0, true, saddr, 0x29b3de884a8af6f9);
RULE_MATCH_IP_SET(0, false, daddr, 0xf20c840819a42ca1);
RULE_MATCH_IP_SET(0, true, daddr, 0xec1688a46fc26ccd);
RULE_MATCH_PORT_RANGES(0, false, saddr, sport, {0, 80, 81}, {0, 8080, 8081}, {0x9c25c5cc8b9adf71, 0, 0});
RULE_MATCH_PORT_RANGES(0, true, saddr, sport, {0, 5000, 5000}, {0xaf80e4b9093f7c4f, 0, 0});
RULE_MATCH_PORT_RANGES(0, false, daddr, dport, {0, 3000, 3001}, {0xd1a42775a0e513c5, 0, 0});
RULE_MATCH_PORT_RANGES(0, true, daddr, dport, {0, 4000, 4000}, {0xaf80e4b9093f7c4f, 0, 0});
RULE_END(0, allow);
// End of rule 0

// End of policy 0
// End of tier drop
RULE_START(1);
RULE_END(1, deny);
end_of_tier_0:;

`

func TestBPFProgramGeneration(t *testing.T) {
	RegisterTestingT(t)
	var pg *ProgramGenerator
	var buf bytes.Buffer

	buf.Reset()
	alloc := idalloc.New()
	setID := func(id string) string {
		alloc.GetOrAlloc(id)
		return id
	}
	pg, err := NewProgramGenerator("xdp/redir_tc.c", alloc)
	Expect(err).NotTo(HaveOccurred())

	err = pg.WriteCalicoRules(&buf, [][][]*proto.Rule{{{{
		Action:                  "Allow",
		IpVersion:               4,
		Protocol:                &proto.Protocol{NumberOrName: &proto.Protocol_Number{Number: 6}},
		SrcNet:                  []string{"10.0.0.0/8"},
		SrcPorts:                []*proto.PortRange{{First: 80, Last: 81}, {First: 8080, Last: 8081}},
		SrcNamedPortIpSetIds:    []string{setID("n:abcdef1234567890")},
		DstNet:                  []string{"11.0.0.0/8"},
		DstPorts:                []*proto.PortRange{{First: 3000, Last: 3001}},
		DstNamedPortIpSetIds:    []string{setID("n:foo1234567890")},
		Icmp:                    nil,
		SrcIpSetIds:             []string{setID("s:sbcdef1234567890")},
		DstIpSetIds:             []string{setID("s:dbcdef1234567890")},
		NotProtocol:             &proto.Protocol{NumberOrName: &proto.Protocol_Name{Name: "UDP"}},
		NotSrcNet:               []string{"12.0.0.0/8"},
		NotSrcPorts:             []*proto.PortRange{{First: 5000, Last: 5000}},
		NotDstNet:               []string{"13.0.0.0/8"},
		NotDstPorts:             []*proto.PortRange{{First: 4000, Last: 4000}},
		NotIcmp:                 nil,
		NotSrcIpSetIds:          []string{setID("s:abcdef1234567890")},
		NotDstIpSetIds:          []string{setID("s:abcdef123456789l")},
		NotSrcNamedPortIpSetIds: []string{setID("n:0bcdef1234567890")},
		NotDstNamedPortIpSetIds: []string{setID("n:0bcdef1234567890")},
	}}}})
	Expect(err).NotTo(HaveOccurred())
	t.Log("Output:", buf.String())
	Expect(buf.String()).To(Equal(kitchenSink))
}
