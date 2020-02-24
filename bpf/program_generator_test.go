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

	. "github.com/onsi/gomega"

	"github.com/projectcalico/felix/proto"
)

const kitchenSink = `// Start of tier 0
// Start of policy 0
// Start of rule 0
RULE_MATCH_PROTOCOL(0, false, 6);
RULE_MATCH_PROTOCOL(0, true, 6);
RULE_MATCH_CIDRS(0, false, saddr, {0xff000000, 0xa000000});
RULE_MATCH_CIDRS(0, true, saddr, {0xff000000, 0xc000000});
RULE_MATCH_CIDRS(0, false, daddr, {0xff000000, 0xb000000});
RULE_MATCH_CIDRS(0, true, daddr, {0xff000000, 0xd000000});
RULE_MATCH_IP_SET(0, false, saddr, 0x684b8f3987d0f29a);
RULE_MATCH_IP_SET(0, true, saddr, 0x9c682697bb48145e);
RULE_MATCH_IP_SET(0, false, daddr, 0xfb195f795561b40e);
RULE_MATCH_IP_SET(0, true, daddr, 0x87210273bf1e9ac7);
RULE_MATCH_PORT_RANGES(0, false, sport, {80, 81}, {8080, 8081});
RULE_MATCH_PORT_RANGES(0, true, sport, {5000, 5000});
RULE_MATCH_PORT_RANGES(0, false, dport, {3000, 3001});
RULE_MATCH_PORT_RANGES(0, true, dport, {4000, 4000});
RULE_END(0, allow);
// End of rule 0

// End of policy 0
// End of tier drop
RULE_END(1, deny);
end_of_tier_0:;

`

func TestBPFProgramGeneration(t *testing.T) {
	RegisterTestingT(t)
	var pg *ProgramGenerator
	var buf bytes.Buffer

	buf.Reset()
	pg = NewProgramGenerator(&buf)

	err := pg.WriteCalicoRules([][][]*proto.Rule{{{{
		Action:                  "Allow",
		IpVersion:               4,
		Protocol:                &proto.Protocol{NumberOrName: &proto.Protocol_Number{Number: 6}},
		SrcNet:                  []string{"10.0.0.0/8"},
		SrcPorts:                []*proto.PortRange{{First: 80, Last: 81}, {First: 8080, Last: 8081}},
		SrcNamedPortIpSetIds:    []string{"n:abcdef1234567890"},
		DstNet:                  []string{"11.0.0.0/8"},
		DstPorts:                []*proto.PortRange{{First: 3000, Last: 3001}},
		DstNamedPortIpSetIds:    []string{"n:foo1234567890"},
		Icmp:                    nil,
		SrcIpSetIds:             []string{"s:sbcdef1234567890"},
		DstIpSetIds:             []string{"s:dbcdef1234567890"},
		NotProtocol:             &proto.Protocol{NumberOrName: &proto.Protocol_Name{Name: "UDP"}},
		NotSrcNet:               []string{"12.0.0.0/8"},
		NotSrcPorts:             []*proto.PortRange{{First: 5000, Last: 5000}},
		NotDstNet:               []string{"13.0.0.0/8"},
		NotDstPorts:             []*proto.PortRange{{First: 4000, Last: 4000}},
		NotIcmp:                 nil,
		NotSrcIpSetIds:          []string{"s:abcdef1234567890"},
		NotDstIpSetIds:          []string{"s:abcdef123456789l"},
		NotSrcNamedPortIpSetIds: []string{"n:0bcdef1234567890"},
		NotDstNamedPortIpSetIds: []string{"n:0bcdef1234567890"},
	}}}})
	Expect(err).NotTo(HaveOccurred())
	t.Log("Output:", buf.String())
	Expect(buf.String()).To(Equal(kitchenSink))
}
