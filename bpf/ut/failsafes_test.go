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

	"github.com/projectcalico/felix/bpf/failsafes"
	"github.com/projectcalico/felix/bpf/polprog"
	"github.com/projectcalico/felix/bpf/routes"
	"github.com/projectcalico/felix/ip"
	"github.com/projectcalico/felix/proto"
)

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
		failsafes.MakeKey(17, 5678, false, srcIP, 16).ToSlice(),
		failsafes.Value(),
	)
	Expect(err).NotTo(HaveOccurred())

	// Set up failsafe to accept outgoing connections to 3.3.3.3/16
	fsafeDstIP := net.IPv4(3, 3, 3, 3)
	err = fsafeMap.Update(
		failsafes.MakeKey(17, 5678, true, fsafeDstIP, 16).ToSlice(),
		failsafes.Value(),
	)
	Expect(err).NotTo(HaveOccurred())

	denyAllRules := polprog.Rules{
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

	denyAllRulesWorkloads := polprog.Rules{
		Tiers: []polprog.Tier{{
			Policies: []polprog.Policy{{
				Name: "deny all",
				Rules: []polprog.Rule{{Rule: &proto.Rule{
					Action: "Deny",
				}}},
			}},
		}},
	}

	// Packet from 1.1.1.1 to 2.2.2.2
	iphdr := *ipv4Default
	_, _, _, _, pktBytesIn, err := testPacket(nil, &iphdr, nil, nil)
	Expect(err).NotTo(HaveOccurred())
	// Packets from failsafe IP to localhost are allowed
	runBpfTest(t, "calico_from_host_ep", &denyAllRules, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytesIn)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.RetvalStr()).To(Equal("TC_ACT_UNSPEC"), "expected program to return TC_ACT_UNSPEC")
	})

	// Packet from IP not in failsafe (4.4.4.4) to localhost (2.2.2.2)
	ipHeaderInBlocked := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Flags:    layers.IPv4DontFragment,
		SrcIP:    net.IPv4(4, 4, 4, 4),
		DstIP:    dstIP,
		Protocol: layers.IPProtocolUDP,
	}
	_, _, _, _, pktBytesInBlocked, err := testPacket(nil, ipHeaderInBlocked, nil, nil)
	Expect(err).NotTo(HaveOccurred())
	// Packets from non-failsafe IP to localhost are denied
	runBpfTest(t, "calico_from_host_ep", &denyAllRules, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytesInBlocked)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.RetvalStr()).To(Equal("TC_ACT_SHOT"), "expected program to return TC_ACT_SHOT")
	})

	// Packet from 2.2.2.2 to 3.3.3.3
	ipHeaderOut := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Flags:    layers.IPv4DontFragment,
		SrcIP:    dstIP,
		DstIP:    fsafeDstIP,
		Protocol: layers.IPProtocolUDP,
	}
	_, _, _, _, pktBytesOut, err := testPacket(nil, ipHeaderOut, nil, nil)
	Expect(err).NotTo(HaveOccurred())
	// Packets from localhost to failsafe IP are allowed
	runBpfTest(t, "calico_to_host_ep", &denyAllRules, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytesOut)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.RetvalStr()).To(Equal("TC_ACT_UNSPEC"), "expected program to return TC_ACT_UNSPEC")
	})

	// Packet from localhost (2.2.2.2) to IP not in failsafe (4.4.4.4)
	ipHeaderOutBlocked := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Flags:    layers.IPv4DontFragment,
		SrcIP:    dstIP,
		DstIP:    net.IPv4(4, 4, 4, 4),
		Protocol: layers.IPProtocolUDP,
	}
	_, _, _, _, pktBytesOutBlocked, err := testPacket(nil, ipHeaderOutBlocked, nil, nil)
	Expect(err).NotTo(HaveOccurred())
	// Packets from localhost to non-failsafe IP are denied
	runBpfTest(t, "calico_from_host_ep", &denyAllRules, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytesOutBlocked)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.RetvalStr()).To(Equal("TC_ACT_SHOT"), "expected program to return TC_ACT_SHOT")
	})

	// Packet from an allowed outbound failsafe IP (3.3.3.3) to an allowed inbound failsafe IP (1.1.1.1)
	ipHeaderSwappedFailsafes := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Flags:    layers.IPv4DontFragment,
		SrcIP:    fsafeDstIP,
		DstIP:    srcIP,
		Protocol: layers.IPProtocolUDP,
	}
	_, _, _, _, pktBytesSwappedFailsafes, err := testPacket(nil, ipHeaderSwappedFailsafes, nil, nil)
	Expect(err).NotTo(HaveOccurred())
	// Packets from outbound failsafes to inbound failsafes are denied
	runBpfTest(t, "calico_from_host_ep", &denyAllRulesWorkloads, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytesSwappedFailsafes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.RetvalStr()).To(Equal("TC_ACT_SHOT"), "expected program to return TC_ACT_SHOT")
	})

	// Packet from unallowed IP (4.4.4.4) to failsafe IP (3.3.3.3)
	ipHeaderToFailsafe := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Flags:    layers.IPv4DontFragment,
		SrcIP:    net.IPv4(4, 4, 4, 4),
		DstIP:    fsafeDstIP,
		Protocol: layers.IPProtocolUDP,
	}
	_, _, _, _, pktBytesToFailsafe, err := testPacket(nil, ipHeaderToFailsafe, nil, nil)
	Expect(err).NotTo(HaveOccurred())
	// Packets from non-failsafe IP to failsafe IP are denied
	runBpfTest(t, "calico_from_host_ep", &denyAllRulesWorkloads, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytesToFailsafe)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.RetvalStr()).To(Equal("TC_ACT_SHOT"), "expected program to return TC_ACT_SHOT")
	})

	// Packet from failsafe IP (3.3.3.3) to unallowed IP (4.4.4.4)
	ipHeaderFromFailsafe := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Flags:    layers.IPv4DontFragment,
		SrcIP:    fsafeDstIP,
		DstIP:    net.IPv4(4, 4, 4, 4),
		Protocol: layers.IPProtocolUDP,
	}
	_, _, _, _, pktBytesFromFailsafe, err := testPacket(nil, ipHeaderFromFailsafe, nil, nil)
	Expect(err).NotTo(HaveOccurred())
	// Packets from failsafe IP to non-failsafe IP are denied
	runBpfTest(t, "calico_from_host_ep", &denyAllRulesWorkloads, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytesFromFailsafe)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.RetvalStr()).To(Equal("TC_ACT_SHOT"), "expected program to return TC_ACT_SHOT")
	})
}
