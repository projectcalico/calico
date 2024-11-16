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
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/projectcalico/calico/felix/bpf/conntrack"
	"github.com/projectcalico/calico/felix/bpf/nat"
	"github.com/projectcalico/calico/felix/bpf/routes"
	tcdefs "github.com/projectcalico/calico/felix/bpf/tc/defs"
	"github.com/projectcalico/calico/felix/ip"
)

func TestToHostAllowedCTFull(t *testing.T) {
	RegisterTestingT(t)

	resetBPFMaps()

	hostIP := net.IPv4(1, 1, 1, 1)
	hostPort := uint16(666)

	srcPort := uint16(12345)

	defer func() {
		// Disable debug while cleaning up the maps
		logrus.SetLevel(logrus.WarnLevel)
		cleanUpMaps()
	}()

	// Disable debug while filling up the map
	loglevel := logrus.GetLevel()
	logrus.SetLevel(logrus.WarnLevel)
	defer logrus.SetLevel(loglevel)

	val := conntrack.NewValueNormal(0, 0, 0, conntrack.Leg{}, conntrack.Leg{})

	var err error
	var firstCTKey conntrack.Key
	var firstCTVal conntrack.Value

	for i := 1; err == nil; i++ {
		srcIP := net.IPv4(10, byte((i&0xff0000)>>16), byte((i&0xff00)>>8), byte(i&0xff))

		key := conntrack.NewKey(1, srcIP, srcPort, hostIP, hostPort)
		err = ctMap.Update(key[:], val[:])

		if i == 1 {
			copy(firstCTKey[:], key[:])
			copy(firstCTVal[:], val[:])
		}
	}

	// Make sure we failed because the CT table is full
	Expect(err).To(Equal(unix.E2BIG))

	// re-enable debug
	logrus.SetLevel(loglevel)

	tcpSyn := &layers.TCP{
		SrcPort:    54321,
		DstPort:    7890,
		SYN:        true,
		DataOffset: 5,
	}

	_, ipv4, _, _, synPkt, err := testPacketV4(nil, nil, tcpSyn, nil)
	Expect(err).NotTo(HaveOccurred())

	destCIDR := net.IPNet{
		IP:   ipv4.DstIP,
		Mask: net.IPv4Mask(255, 255, 255, 255),
	}

	defer resetRTMap(rtMap)
	defer func() { bpfIfaceName = "" }()

	// Not NAT programmed

	// No route - should not pass
	bpfIfaceName = "ctNO"
	skbMark = 0
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(synPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_SHOT))
	})

	// Destination is a local workload - should not pass
	err = rtMap.Update(
		routes.NewKey(ip.CIDRFromIPNet(&destCIDR).(ip.V4CIDR)).AsBytes(),
		routes.NewValue(routes.FlagsLocalWorkload|routes.FlagInIPAMPool).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	bpfIfaceName = "ctLW"
	skbMark = 0
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(synPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_SHOT))
	})

	// Destination is a remote workload - should not pass
	err = rtMap.Update(
		routes.NewKey(ip.CIDRFromIPNet(&destCIDR).(ip.V4CIDR)).AsBytes(),
		routes.NewValue(routes.FlagsRemoteWorkload|routes.FlagInIPAMPool).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	bpfIfaceName = "ctRW"
	skbMark = 0
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(synPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_SHOT))
	})

	// Destination is a remote host - should not pass
	err = rtMap.Update(
		routes.NewKey(ip.CIDRFromIPNet(&destCIDR).(ip.V4CIDR)).AsBytes(),
		routes.NewValue(routes.FlagsRemoteHost).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	bpfIfaceName = "ctRH"
	skbMark = 0
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(synPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_SHOT))
	})

	// Destination is the local host - should pass
	err = rtMap.Update(
		routes.NewKey(ip.CIDRFromIPNet(&destCIDR).(ip.V4CIDR)).AsBytes(),
		routes.NewValue(routes.FlagsLocalHost).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	bpfIfaceName = "ctLH"
	skbMark = 0
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(synPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))
	})
	expectMark(tcdefs.MarkSeen)

	// Source is the local host - should pass
	tcpSynAck := &layers.TCP{
		SrcPort:    7890,
		DstPort:    54321,
		SYN:        true,
		ACK:        true,
		DataOffset: 5,
	}

	ipv4Ret := *ipv4
	ipv4Ret.SrcIP, ipv4Ret.DstIP = ipv4Ret.DstIP, ipv4Ret.SrcIP

	_, _, _, _, synAckPkt, err := testPacketV4(nil, &ipv4Ret, tcpSynAck, nil)
	Expect(err).NotTo(HaveOccurred())

	skbMark = tcdefs.MarkSeen
	runBpfTest(t, "calico_to_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(synAckPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))
	})

	// Non-SYN packet
	tcpAck := &layers.TCP{
		SrcPort:    54321,
		DstPort:    7890,
		ACK:        true,
		DataOffset: 5,
	}

	_, _, _, _, ackPkt, err := testPacketV4(nil, nil, tcpAck, nil)
	Expect(err).NotTo(HaveOccurred())

	skbMark = 0
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(ackPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))
	})
	expectMark(tcdefs.MarkSeenFallThrough)

	// Make space in the CT table
	err = ctMap.Delete(firstCTKey[:])
	Expect(err).NotTo(HaveOccurred())

	skbMark = 0
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(ackPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))
	})
	expectMark(tcdefs.MarkSeenFallThrough)

	// No conntrack created for non-SYN packet (should fall through to iptables).  We test by
	// trying to create an entry, which should succeed.
	err = ctMap.Update(firstCTKey[:], firstCTVal[:])
	Expect(err).NotTo(HaveOccurred())

	// Towards WEP, the feature is disabled - should not pass
	//
	// Such a packet would not make it here anyway due to routing.
	skbMark = tcdefs.MarkSeen
	runBpfTest(t, "calico_to_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(synPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_SHOT))
	})

	// It we hit NAT, the feature is disabled - should not pass
	//
	// Create NAT entry
	err = natMap.Update(
		nat.NewNATKey(ipv4.DstIP, uint16(tcpSyn.DstPort), uint8(ipv4.Protocol)).AsBytes(),
		nat.NewNATValue(0, 1, 0, 0).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	natIP := net.IPv4(8, 8, 8, 8)
	natPort := uint16(666)

	err = natBEMap.Update(
		nat.NewNATBackendKey(0, 0).AsBytes(),
		nat.NewNATBackendValue(natIP, natPort).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	// Setup routing to allow NAT on HEP (encap)
	node2wCIDR := net.IPNet{
		IP:   natIP,
		Mask: net.IPv4Mask(255, 255, 255, 0),
	}

	err = rtMap.Update(
		routes.NewKey(ip.CIDRFromIPNet(&node2wCIDR).(ip.V4CIDR)).AsBytes(),
		routes.NewValueWithNextHop(routes.FlagsRemoteWorkload, ip.FromNetIP(node2ip).(ip.V4Addr)).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())
	err = rtMap.Update(
		routes.NewKey(ip.CIDRFromIPNet(&node1CIDR).(ip.V4CIDR)).AsBytes(),
		routes.NewValue(routes.FlagsLocalHost).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())
	err = rtMap.Update(
		routes.NewKey(ip.CIDRFromIPNet(&node2CIDR).(ip.V4CIDR)).AsBytes(),
		routes.NewValue(routes.FlagsRemoteHost).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	skbMark = 0
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(synPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_SHOT))
	})
}
