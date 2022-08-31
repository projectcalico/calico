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
	"fmt"
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/bpf/failsafes"
	"github.com/projectcalico/calico/felix/bpf/polprog"
	"github.com/projectcalico/calico/felix/bpf/routes"
	tcdefs "github.com/projectcalico/calico/felix/bpf/tc/defs"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/proto"
)

var fsafeDstIP = net.IPv4(3, 3, 3, 3)

var denyAllRulesHost = polprog.Rules{
	ForHostInterface: true,
	HostNormalTiers: []polprog.Tier{{
		Policies: []polprog.Policy{{
			Name: "deny all",
			Rules: []polprog.Rule{{Rule: &proto.Rule{
				Action: "Deny",
			}}},
		}},
	}},
}

var denyAllRulesWorkloads = polprog.Rules{
	Tiers: []polprog.Tier{{
		Policies: []polprog.Policy{{
			Name: "deny all",
			Rules: []polprog.Rule{{Rule: &proto.Rule{
				Action: "Deny",
			}}},
		}},
	}},
}

var failsafeTests = []failsafeTest{
	{
		Description:  "Packets from failsafe IP and port to localhost are allowed",
		Rules:        &denyAllRulesHost,
		IPHeaderIPv4: ipv4Default,
		Outbound:     false,
		Allowed:      true,
	},
	{
		Description: "Packets from non-failsafe IP to localhost are denied",
		Rules:       &denyAllRulesHost,
		IPHeaderIPv4: &layers.IPv4{
			Version:  4,
			IHL:      5,
			TTL:      64,
			Flags:    layers.IPv4DontFragment,
			SrcIP:    net.IPv4(4, 4, 4, 4),
			DstIP:    dstIP,
			Protocol: layers.IPProtocolUDP,
		},
		Outbound: false,
		Allowed:  false,
	},
	{
		Description: "Packets from localhost to failsafe IP and port are allowed",
		Rules:       &denyAllRulesHost,
		IPHeaderIPv4: &layers.IPv4{
			Version:  4,
			IHL:      5,
			TTL:      64,
			Flags:    layers.IPv4DontFragment,
			SrcIP:    dstIP,
			DstIP:    fsafeDstIP,
			Protocol: layers.IPProtocolUDP,
		},
		Outbound: true,
		Allowed:  true,
	},
	{
		Description: "Packets from localhost to non-failsafe IP are denied",
		Rules:       &denyAllRulesHost,
		IPHeaderIPv4: &layers.IPv4{
			Version:  4,
			IHL:      5,
			TTL:      64,
			Flags:    layers.IPv4DontFragment,
			SrcIP:    dstIP,
			DstIP:    net.IPv4(4, 4, 4, 4),
			Protocol: layers.IPProtocolUDP,
		},
		Outbound: false,
		Allowed:  false,
	},
	{
		Description: "Packets from outbound failsafes to inbound failsafes are denied",
		Rules:       &denyAllRulesWorkloads,
		IPHeaderIPv4: &layers.IPv4{
			Version:  4,
			IHL:      5,
			TTL:      64,
			Flags:    layers.IPv4DontFragment,
			SrcIP:    fsafeDstIP,
			DstIP:    srcIP,
			Protocol: layers.IPProtocolUDP,
		},
		Outbound: false,
		Allowed:  false,
	},
	{
		Description: "Packets from non-failsafe IP to failsafe IP are denied",
		Rules:       &denyAllRulesWorkloads,
		IPHeaderIPv4: &layers.IPv4{
			Version:  4,
			IHL:      5,
			TTL:      64,
			Flags:    layers.IPv4DontFragment,
			SrcIP:    net.IPv4(4, 4, 4, 4),
			DstIP:    fsafeDstIP,
			Protocol: layers.IPProtocolUDP,
		},
		Outbound: false,
		Allowed:  false,
	},
	{
		Description: "Packets from failsafe IP to non-failsafe IP are denied",
		Rules:       &denyAllRulesWorkloads,
		IPHeaderIPv4: &layers.IPv4{
			Version:  4,
			IHL:      5,
			TTL:      64,
			Flags:    layers.IPv4DontFragment,
			SrcIP:    fsafeDstIP,
			DstIP:    net.IPv4(4, 4, 4, 4),
			Protocol: layers.IPProtocolUDP,
		},
		Outbound: false,
		Allowed:  false,
	},
	{
		Description:  "Packets from failsafe IP and non-failsafe port to localhost are denied",
		Rules:        &denyAllRulesHost,
		IPHeaderIPv4: ipv4Default,
		IPHeaderUDP: &layers.UDP{
			DstPort: 161,
		},
		Outbound: false,
		Allowed:  false,
	},
	{
		Description: "Packets from localhost to failsafe IP and non-failsafe port are denied",
		Rules:       &denyAllRulesHost,
		IPHeaderIPv4: &layers.IPv4{
			Version:  4,
			IHL:      5,
			TTL:      64,
			Flags:    layers.IPv4DontFragment,
			SrcIP:    dstIP,
			DstIP:    fsafeDstIP,
			Protocol: layers.IPProtocolUDP,
		},
		IPHeaderUDP: &layers.UDP{
			DstPort: 161,
		},
		Outbound: true,
		Allowed:  false,
	},
}

func TestFailsafes(t *testing.T) {
	RegisterTestingT(t)

	defer resetBPFMaps()

	hostIP = dstIP // set host IP to the default dest
	hostCIDR := ip.CIDRFromNetIP(hostIP).(ip.V4CIDR)

	// Setup routing so that failsafe check knows it is localhost
	rtKey := routes.NewKey(hostCIDR).AsBytes()
	rtVal := routes.NewValueWithIfIndex(routes.FlagsLocalHost, 1).AsBytes()
	err := rtMap.Update(rtKey, rtVal)
	Expect(err).NotTo(HaveOccurred())

	// Set up failsafe to accept incoming connections from srcIP (1.1.1.1/16)
	err = fsafeMap.Update(
		failsafes.MakeKey(17, 5678, false, srcIP.String(), 16).ToSlice(),
		failsafes.Value(),
	)
	Expect(err).NotTo(HaveOccurred())

	// Set up failsafe to accept outgoing connections to 3.3.3.3/16
	err = fsafeMap.Update(
		failsafes.MakeKey(17, 5678, true, fsafeDstIP.String(), 16).ToSlice(),
		failsafes.Value(),
	)
	Expect(err).NotTo(HaveOccurred())

	for _, test := range failsafeTests {
		_, _, _, _, pktBytes, err := testPacket(nil, test.IPHeaderIPv4, test.IPHeaderUDP, nil)
		Expect(err).NotTo(HaveOccurred())

		prog := "calico_from_host_ep"
		skbMark = 0
		if test.Outbound {
			skbMark = tcdefs.MarkSeen
			prog = "calico_to_host_ep"
		}

		result := "TC_ACT_SHOT"
		if test.Allowed {
			result = "TC_ACT_UNSPEC"
		}

		runBpfTest(t, prog, test.Rules, func(bpfrun bpfProgRunFn) {
			res, err := bpfrun(pktBytes)
			Expect(err).NotTo(HaveOccurred())
			Expect(res.RetvalStr()).To(Equal(result), fmt.Sprintf("expected program to return %s", result))
		})
		if !test.Outbound && test.Allowed {
			expectMark(tcdefs.MarkSeen)
		}
	}
}

type failsafeTest struct {
	Description  string
	Rules        *polprog.Rules
	IPHeaderIPv4 *layers.IPv4
	IPHeaderUDP  gopacket.Layer
	Outbound     bool
	Allowed      bool
}
