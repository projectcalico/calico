// Copyright (c) 2016 Tigera, Inc. All rights reserved.
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

package rules_test

import (
	. "github.com/projectcalico/felix/go/felix/rules"

	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	"github.com/projectcalico/felix/go/felix/ipsets"
	"github.com/projectcalico/felix/go/felix/iptables"
	"github.com/projectcalico/felix/go/felix/proto"
)

var (
	rrConfig = Config{
		IPIPEnabled:           true,
		IPIPTunnelAddress:     nil,
		IPSetConfigV4:         ipsets.NewIPSetConfig(ipsets.IPFamilyV4, "cali", nil, nil),
		IPSetConfigV6:         ipsets.NewIPSetConfig(ipsets.IPFamilyV6, "cali", nil, nil),
		IptablesMarkAccept:    0x8,
		IptablesMarkNextTier:  0x10,
		IptablesMarkEndpoints: 0x20,
	}
)

var _ = DescribeTable(
	"Protobuf rule to iptables rule conversion",
	func(ipVer int, rrConfig Config, in proto.Rule, expMatch string) {
		renderer := NewRenderer(rrConfig)
		rules := renderer.ProtoRuleToIptablesRules(&in, uint8(ipVer))
		// Should be one match rule that sets the mark, then one that reads the mark and
		// returns.
		Expect(len(rules)).To(Equal(2))
		Expect(rules[0].Match.Render()).To(Equal(expMatch))
		Expect(rules[0].Action).To(Equal(iptables.SetMarkAction{Mark: 0x8}))
		Expect(rules[1]).To(Equal(iptables.Rule{
			Match:  iptables.Match().MarkSet(0x8),
			Action: iptables.ReturnAction{},
		}))

		// Explicit allow should be treated the same as empty.
		in.Action = "allow"
		rules2 := renderer.ProtoRuleToIptablesRules(&in, uint8(ipVer))
		Expect(rules2).To(Equal(rules))
	},
	Entry("Empty rule", 4, rrConfig, proto.Rule{}, ""),

	// Non-negated matches...

	Entry("Protocol name", 4, rrConfig,
		proto.Rule{Protocol: &proto.Protocol{NumberOrName: &proto.Protocol_Name{"tcp"}}},
		"-p tcp"),
	Entry("Protocol num", 4, rrConfig,
		proto.Rule{Protocol: &proto.Protocol{NumberOrName: &proto.Protocol_Number{8}}},
		"-p 8"),

	Entry("Source net", 4, rrConfig,
		proto.Rule{SrcNet: "10.0.0.0/16"},
		"--source 10.0.0.0/16"),
	Entry("Source IP set", 4, rrConfig,
		proto.Rule{SrcIpSetIds: []string{"ipsetid1"}},
		"-m set --match-set cali4-ipsetid1 src"),
	Entry("Source IP sets", 4, rrConfig,
		proto.Rule{SrcIpSetIds: []string{"ipsetid1", "ipsetid2"}},
		"-m set --match-set cali4-ipsetid1 src -m set --match-set cali4-ipsetid2 src"),
	Entry("Source ports", 4, rrConfig,
		proto.Rule{SrcPorts: []*proto.PortRange{{First: 10, Last: 12}}},
		"-m multiport --source-ports 10:12"),
	Entry("Source ports (multiple)", 4, rrConfig,
		proto.Rule{SrcPorts: []*proto.PortRange{
			{First: 10, Last: 12},
			{First: 20, Last: 30},
			{First: 8080, Last: 8080},
		}},
		"-m multiport --source-ports 10:12,20:30,8080"),
	Entry("ICMP", 4, rrConfig,
		proto.Rule{Icmp: &proto.Rule_IcmpType{IcmpType: 10}},
		"-m icmp --icmp-type 10"),
	Entry("ICMP with code", 4, rrConfig,
		proto.Rule{Icmp: &proto.Rule_IcmpTypeCode{IcmpTypeCode: &proto.IcmpTypeAndCode{Type: 10, Code: 12}}},
		"-m icmp --icmp-type 10/12"),
	Entry("ICMP", 6, rrConfig,
		proto.Rule{Icmp: &proto.Rule_IcmpType{IcmpType: 10}},
		"-m icmp6 --icmpv6-type 10"),
	Entry("ICMP with code", 6, rrConfig,
		proto.Rule{Icmp: &proto.Rule_IcmpTypeCode{IcmpTypeCode: &proto.IcmpTypeAndCode{Type: 10, Code: 12}}},
		"-m icmp6 --icmpv6-type 10/12"),

	Entry("Dest net", 4, rrConfig,
		proto.Rule{DstNet: "10.0.0.0/16"},
		"--destination 10.0.0.0/16"),
	Entry("Dest IP set", 4, rrConfig,
		proto.Rule{DstIpSetIds: []string{"ipsetid1"}},
		"-m set --match-set cali4-ipsetid1 dst"),
	Entry("Dest IP sets", 4, rrConfig,
		proto.Rule{DstIpSetIds: []string{"ipsetid1", "ipsetid2"}},
		"-m set --match-set cali4-ipsetid1 dst -m set --match-set cali4-ipsetid2 dst"),
	Entry("Dest ports", 4, rrConfig,
		proto.Rule{DstPorts: []*proto.PortRange{{First: 10, Last: 12}}},
		"-m multiport --destination-ports 10:12"),
	Entry("Dest ports (multiple)", 4, rrConfig,
		proto.Rule{DstPorts: []*proto.PortRange{
			{First: 10, Last: 12},
			{First: 20, Last: 30},
			{First: 8080, Last: 8080},
		}},
		"-m multiport --destination-ports 10:12,20:30,8080"),

	// Negated matches...

	Entry("Protocol name", 4, rrConfig,
		proto.Rule{NotProtocol: &proto.Protocol{NumberOrName: &proto.Protocol_Name{"tcp"}}},
		"! -p tcp"),
	Entry("Protocol num", 4, rrConfig,
		proto.Rule{NotProtocol: &proto.Protocol{NumberOrName: &proto.Protocol_Number{8}}},
		"! -p 8"),

	Entry("Source net", 4, rrConfig,
		proto.Rule{NotSrcNet: "10.0.0.0/16"},
		"! --source 10.0.0.0/16"),
	Entry("Source IP set", 4, rrConfig,
		proto.Rule{NotSrcIpSetIds: []string{"ipsetid1"}},
		"-m set ! --match-set cali4-ipsetid1 src"),
	Entry("Source IP sets", 4, rrConfig,
		proto.Rule{NotSrcIpSetIds: []string{"ipsetid1", "ipsetid2"}},
		"-m set ! --match-set cali4-ipsetid1 src -m set ! --match-set cali4-ipsetid2 src"),
	Entry("Source ports", 4, rrConfig,
		proto.Rule{NotSrcPorts: []*proto.PortRange{{First: 10, Last: 12}}},
		"-m multiport ! --source-ports 10:12"),
	Entry("Source ports (multiple)", 4, rrConfig,
		proto.Rule{NotSrcPorts: []*proto.PortRange{
			{First: 10, Last: 12},
			{First: 20, Last: 30},
			{First: 8080, Last: 8080},
		}},
		"-m multiport ! --source-ports 10:12,20:30,8080"),
	Entry("ICMP", 4, rrConfig,
		proto.Rule{NotIcmp: &proto.Rule_NotIcmpType{NotIcmpType: 10}},
		"-m icmp ! --icmp-type 10"),
	Entry("ICMP with code", 4, rrConfig,
		proto.Rule{NotIcmp: &proto.Rule_NotIcmpTypeCode{NotIcmpTypeCode: &proto.IcmpTypeAndCode{Type: 10, Code: 12}}},
		"-m icmp ! --icmp-type 10/12"),
	Entry("ICMP", 6, rrConfig,
		proto.Rule{NotIcmp: &proto.Rule_NotIcmpType{NotIcmpType: 10}},
		"-m icmp6 ! --icmpv6-type 10"),
	Entry("ICMP with code", 6, rrConfig,
		proto.Rule{NotIcmp: &proto.Rule_NotIcmpTypeCode{NotIcmpTypeCode: &proto.IcmpTypeAndCode{Type: 10, Code: 12}}},
		"-m icmp6 ! --icmpv6-type 10/12"),

	Entry("Dest net", 4, rrConfig,
		proto.Rule{NotDstNet: "10.0.0.0/16"},
		"! --destination 10.0.0.0/16"),
	Entry("Dest IP set", 4, rrConfig,
		proto.Rule{NotDstIpSetIds: []string{"ipsetid1"}},
		"-m set ! --match-set cali4-ipsetid1 dst"),
	Entry("Dest IP sets", 4, rrConfig,
		proto.Rule{NotDstIpSetIds: []string{"ipsetid1", "ipsetid2"}},
		"-m set ! --match-set cali4-ipsetid1 dst -m set ! --match-set cali4-ipsetid2 dst"),
	Entry("Dest ports", 4, rrConfig,
		proto.Rule{NotDstPorts: []*proto.PortRange{{First: 10, Last: 12}}},
		"-m multiport ! --destination-ports 10:12"),
	Entry("Dest ports (multiple)", 4, rrConfig,
		proto.Rule{NotDstPorts: []*proto.PortRange{
			{First: 10, Last: 12},
			{First: 20, Last: 30},
			{First: 8080, Last: 8080},
		}},
		"-m multiport ! --destination-ports 10:12,20:30,8080"),
)
