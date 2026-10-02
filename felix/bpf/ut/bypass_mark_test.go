// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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
	"testing"

	"github.com/gopacket/gopacket/layers"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/bpf/conntrack"
	v4 "github.com/projectcalico/calico/felix/bpf/conntrack/v4"
	"github.com/projectcalico/calico/felix/bpf/routes"
	tcdefs "github.com/projectcalico/calico/felix/bpf/tc/defs"
)

// A fully approved host-stack flow keeps its code: SKIP_FIB gains BYPASS, NAT_OUT stays plain.
func TestBypassMarkKeepsHostStackMark(t *testing.T) {
	RegisterTestingT(t)

	bpfIfaceName = "BYPm"
	defer func() { bpfIfaceName = "" }()
	defer cleanUpMaps()

	hostIP = node1ip

	_, ipv4, l4, _, pktBytes, err := testPacketUDPDefault()
	Expect(err).NotTo(HaveOccurred())
	udp := l4.(*layers.UDP)
	ctKey := conntrack.NewKey(uint8(ipv4.Protocol),
		ipv4.SrcIP, uint16(udp.SrcPort), ipv4.DstIP, uint16(udp.DstPort))

	localWEP := routes.NewValueWithIfIndex(routes.FlagsLocalWorkload|routes.FlagInIPAMPool, 1).AsBytes()
	srcRT := routes.NewKey(srcV4CIDR).AsBytes()

	for _, c := range []struct {
		name    string
		section string
		ctFlags uint32
		srcLeg  conntrack.Leg
		retval  string
		mark    uint32
	}{
		{"from-WEP, no flags", "calico_from_workload_ep", 0,
			conntrack.Leg{Approved: true, Workload: true, Opener: true}, "TC_ACT_REDIRECT", tcdefs.MarkSeenBypass},
		{"from-WEP, SKIP_FIB", "calico_from_workload_ep", v4.FlagSkipFIB,
			conntrack.Leg{Approved: true, Workload: true, Opener: true}, "TC_ACT_UNSPEC", tcdefs.MarkSeenSkipFIB | tcdefs.MarkSeenBypass},
		{"from-WEP, NAT_OUT", "calico_from_workload_ep", v4.FlagNATOut,
			conntrack.Leg{Approved: true, Workload: true, Opener: true}, "TC_ACT_UNSPEC", tcdefs.MarkSeenNATOutgoing},
		{"from-HEP, no flags", "calico_from_host_ep", 0,
			conntrack.Leg{Approved: true, Opener: true}, "TC_ACT_REDIRECT", tcdefs.MarkSeenBypass},
		{"from-HEP, SKIP_FIB", "calico_from_host_ep", v4.FlagSkipFIB,
			conntrack.Leg{Approved: true, Opener: true}, "TC_ACT_UNSPEC", tcdefs.MarkSeenSkipFIB | tcdefs.MarkSeenBypass},
		// A reply on an outgoing-NAT flow that was not SNATed, so host conntrack sees both directions.
		{"from-HEP, NAT_OUT reply", "calico_from_host_ep", v4.FlagNATOut,
			conntrack.Leg{Approved: true, Opener: true}, "TC_ACT_UNSPEC", tcdefs.MarkSeenNATOutgoing},
	} {
		t.Run(c.name, func(t *testing.T) {
			resetCTMap(ctMap)
			resetRTMap(rtMap)
			if c.section == "calico_from_workload_ep" {
				Expect(rtMap.Update(srcRT, localWEP)).NotTo(HaveOccurred())
			}
			val := conntrack.NewValueNormal(0, c.ctFlags, c.srcLeg, conntrack.Leg{Approved: true})
			Expect(ctMap.Update(ctKey.AsBytes(), val.AsBytes())).NotTo(HaveOccurred())

			skbMark = 0
			runBpfTest(t, c.section, rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
				res, err := bpfrun(pktBytes)
				Expect(err).NotTo(HaveOccurred())
				Expect(res.RetvalStr()).To(Equal(c.retval))
			})
			expectMark(int(c.mark))
		})
	}
}
