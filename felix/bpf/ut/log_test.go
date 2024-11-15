// Copyright (c) 2019-2021 Tigera, Inc. All rights reserved.
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
	"net"
	"testing"

	"github.com/google/gopacket/layers"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/bpf/polprog"
	"github.com/projectcalico/calico/felix/bpf/routes"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/proto"
)

func TestLog(t *testing.T) {
	RegisterTestingT(t)

	defer resetBPFMaps()
	bpfIfaceName = "LOG"
	defer func() { bpfIfaceName = "" }()

	hostIP = node1ip

	_, iphdr, _, _, pktBytes, _ := testPacketUDPDefault()

	resetRTMap(rtMap)
	beV4CIDR := ip.CIDRFromNetIP(iphdr.SrcIP).(ip.V4CIDR)
	bertKey := routes.NewKey(beV4CIDR).AsBytes()
	bertVal := routes.NewValueWithIfIndex(routes.FlagsLocalWorkload|routes.FlagInIPAMPool, 1).AsBytes()
	err := rtMap.Update(bertKey, bertVal)
	Expect(err).NotTo(HaveOccurred())

	rules := &polprog.Rules{
		Tiers: []polprog.Tier{{
			Name: "base tier",
			Policies: []polprog.Policy{
				{
					Name: "log icmp",
					Rules: []polprog.Rule{
						{
							Rule: &proto.Rule{
								Protocol: &proto.Protocol{NumberOrName: &proto.Protocol_Number{Number: 1}},
								DstNet:   []string{"8.8.8.8/32"},
								Action:   "Allow",
							},
						},
						{
							Rule: &proto.Rule{
								Protocol: &proto.Protocol{NumberOrName: &proto.Protocol_Number{Number: 1}},
								Action:   "Log", // Denied by default deny when not matching any rule
							},
						},
					},
				},
				{
					Name: "log tcp allow",
					Rules: []polprog.Rule{
						{
							Rule: &proto.Rule{
								Protocol: &proto.Protocol{NumberOrName: &proto.Protocol_Number{Number: 6}},
								Action:   "Log",
							},
						},
						{
							Rule: &proto.Rule{
								Protocol: &proto.Protocol{NumberOrName: &proto.Protocol_Number{Number: 6}},
								Action:   "Allow",
							},
						},
					},
				},
				{
					Name: "log udp deny",
					Rules: []polprog.Rule{
						{
							Rule: &proto.Rule{
								Protocol: &proto.Protocol{NumberOrName: &proto.Protocol_Number{Number: 17}},
								Action:   "Log",
							},
						},
						{
							Rule: &proto.Rule{
								Protocol: &proto.Protocol{NumberOrName: &proto.Protocol_Number{Number: 17}},
								Action:   "Deny",
							},
						},
					},
				},
			},
		}},
	}

	runBpfTest(t, "calico_from_workload_ep", rules, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_SHOT))
	})

	pktIPHdr := *ipv4Default
	pktIPHdr.Protocol = layers.IPProtocolTCP

	pktTCPHdr := &layers.TCP{
		SrcPort:    layers.TCPPort(12345),
		DstPort:    layers.TCPPort(321),
		SYN:        true,
		DataOffset: 5,
	}

	_, _, _, _, pktBytes, _ = testPacketV4(nil, &pktIPHdr, pktTCPHdr,
		[]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 11, 22, 33, 44, 55, 66, 77, 88, 99, 0})

	skbMark = 0

	runBpfTest(t, "calico_from_workload_ep", rules, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))
	})

	pktBytes = makeICMPErrorFrom(ipv4Default.SrcIP, &pktIPHdr, pktTCPHdr, 0, 0)

	skbMark = 0

	runBpfTest(t, "calico_from_workload_ep", rules, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_SHOT))
	})

	pktIPHdr2 := pktIPHdr
	pktIPHdr2.SrcIP = net.ParseIP("8.8.8.8")
	pktBytes = makeICMPErrorFrom(ipv4Default.SrcIP, &pktIPHdr2, pktTCPHdr, 0, 0)

	skbMark = 0

	runBpfTest(t, "calico_from_workload_ep", rules, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))
	})
}
