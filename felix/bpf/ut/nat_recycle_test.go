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
	"net"
	"testing"

	"github.com/gopacket/gopacket/layers"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/bpf/conntrack"
	"github.com/projectcalico/calico/felix/bpf/routes"
	"github.com/projectcalico/calico/felix/ip"
)

func TestIPv6ClosedNATReverseDoesNotMatchNewHostSYN(t *testing.T) {
	RegisterTestingT(t)

	cleanUpMaps()
	defer cleanUpMaps()

	bpfIfaceName = "NREV6"
	defer func() { bpfIfaceName = "" }()

	hostIP = node1ipV6
	backendIP := net.ParseIP("abcd::ffff:0808:0808").To16()
	serviceIP := net.ParseIP("c471::c000:8080:8080").To16()
	srcPort := uint16(1234)
	dstPort := uint16(6443)

	resetCTMapV6(ctMapV6)
	resetRTMapV6(rtMapV6)
	defer resetRTMapV6(rtMapV6)

	backendCIDR := net.IPNet{
		IP:   backendIP,
		Mask: net.CIDRMask(128, 128),
	}
	Expect(rtMapV6.Update(
		routes.NewKeyV6(ip.CIDRFromIPNet(&backendCIDR).(ip.V6CIDR)).AsBytes(),
		routes.NewValueV6WithNextHop(routes.FlagsRemoteWorkload|routes.FlagInIPAMPool,
			ip.FromNetIP(node2ipV6).(ip.V6Addr)).AsBytes(),
	)).NotTo(HaveOccurred())
	Expect(rtMapV6.Update(
		routes.NewKeyV6(ip.CIDRFromIPNet(&node1CIDRV6).(ip.V6CIDR)).AsBytes(),
		routes.NewValueV6(routes.FlagsLocalHost).AsBytes(),
	)).NotTo(HaveOccurred())
	Expect(rtMapV6.Update(
		routes.NewKeyV6(ip.CIDRFromIPNet(&node2CIDRV6).(ip.V6CIDR)).AsBytes(),
		routes.NewValueV6(routes.FlagsRemoteHost).AsBytes(),
	)).NotTo(HaveOccurred())

	revKey := conntrack.NewKeyV6(conntrack.ProtoTCP, hostIP, srcPort, backendIP, dstPort)
	closedRev := conntrack.NewValueV6NATReverse(
		0, 0,
		conntrack.Leg{SynSeen: true, AckSeen: true, FinSeen: true, Approved: true, Opener: true},
		conntrack.Leg{SynSeen: true, AckSeen: true, FinSeen: true, Approved: true},
		nil, serviceIP, dstPort,
	)
	Expect(ctMapV6.Update(revKey.AsBytes(), closedRev.AsBytes())).NotTo(HaveOccurred())

	ipv6Hdr := *ipv6Default
	ipv6Hdr.SrcIP = hostIP
	ipv6Hdr.DstIP = backendIP
	ipv6Hdr.NextHeader = layers.IPProtocolTCP
	tcpHdr := &layers.TCP{
		SYN:        true,
		SrcPort:    layers.TCPPort(srcPort),
		DstPort:    layers.TCPPort(dstPort),
		DataOffset: 5,
	}
	_, _, _, _, pktBytes, err := testPacketV6(nil, &ipv6Hdr, tcpHdr, nil)
	Expect(err).NotTo(HaveOccurred())

	skbMark = 0
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).NotTo(Equal(resTC_ACT_SHOT))
	}, withIPv6())

	ct, err := conntrack.LoadMapMemV6(ctMapV6)
	Expect(err).NotTo(HaveOccurred())
	if val, ok := ct[revKey]; ok {
		Expect(val.Data().FINsSeen()).To(BeFalse(),
			"new SYN must not reuse a closed IPv6 NATReverse conntrack entry")
	}
}

func TestIPv4ClosedNATReverseDoesNotMatchNewHostSYN(t *testing.T) {
	RegisterTestingT(t)

	cleanUpMaps()
	defer cleanUpMaps()

	bpfIfaceName = "NREV4"
	defer func() { bpfIfaceName = "" }()

	hostIP = node1ip
	backendIP := net.IPv4(8, 8, 8, 8).To4()
	serviceIP := net.IPv4(192, 0, 2, 16).To4()
	srcPort := uint16(1234)
	dstPort := uint16(6443)

	resetCTMap(ctMap)
	resetRTMap(rtMap)
	defer resetRTMap(rtMap)

	backendCIDR := net.IPNet{
		IP:   backendIP,
		Mask: net.CIDRMask(32, 32),
	}
	Expect(rtMap.Update(
		routes.NewKey(ip.CIDRFromIPNet(&backendCIDR).(ip.V4CIDR)).AsBytes(),
		routes.NewValueWithNextHop(routes.FlagsRemoteWorkload|routes.FlagInIPAMPool,
			ip.FromNetIP(node2ip).(ip.V4Addr)).AsBytes(),
	)).NotTo(HaveOccurred())
	Expect(rtMap.Update(
		routes.NewKey(ip.CIDRFromIPNet(&node1CIDR).(ip.V4CIDR)).AsBytes(),
		routes.NewValue(routes.FlagsLocalHost).AsBytes(),
	)).NotTo(HaveOccurred())
	Expect(rtMap.Update(
		routes.NewKey(ip.CIDRFromIPNet(&node2CIDR).(ip.V4CIDR)).AsBytes(),
		routes.NewValue(routes.FlagsRemoteHost).AsBytes(),
	)).NotTo(HaveOccurred())

	revKey := conntrack.NewKey(conntrack.ProtoTCP, hostIP, srcPort, backendIP, dstPort)
	closedRev := conntrack.NewValueNATReverse(
		0, 0,
		conntrack.Leg{SynSeen: true, AckSeen: true, FinSeen: true, Approved: true, Opener: true},
		conntrack.Leg{SynSeen: true, AckSeen: true, FinSeen: true, Approved: true},
		nil, serviceIP, dstPort,
	)
	Expect(ctMap.Update(revKey.AsBytes(), closedRev.AsBytes())).NotTo(HaveOccurred())

	ipv4Hdr := *ipv4Default
	ipv4Hdr.SrcIP = hostIP
	ipv4Hdr.DstIP = backendIP
	ipv4Hdr.Protocol = layers.IPProtocolTCP
	tcpHdr := &layers.TCP{
		SYN:        true,
		SrcPort:    layers.TCPPort(srcPort),
		DstPort:    layers.TCPPort(dstPort),
		DataOffset: 5,
	}
	_, _, _, _, pktBytes, err := testPacketV4(nil, &ipv4Hdr, tcpHdr, nil)
	Expect(err).NotTo(HaveOccurred())

	skbMark = 0
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).NotTo(Equal(resTC_ACT_SHOT))
	})

	ct, err := conntrack.LoadMapMem(ctMap)
	Expect(err).NotTo(HaveOccurred())
	if val, ok := ct[revKey]; ok {
		Expect(val.Data().FINsSeen()).To(BeFalse(),
			"new SYN must not reuse a closed IPv4 NATReverse conntrack entry")
	}
}
