// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/bpf/conntrack"
	"github.com/projectcalico/calico/felix/bpf/ipsets"
	"github.com/projectcalico/calico/felix/bpf/routes"
	tcdefs "github.com/projectcalico/calico/felix/bpf/tc/defs"
)

// TestIstioDSCPv4 tests the BPF implementation of Istio DSCP marking for IPv4 packets.
// It verifies that TCP SYN packets from workloads in the Istio mesh get marked with
// the configured DSCP value when going to another workload endpoint.
func TestIstioDSCPv4(t *testing.T) {
	RegisterTestingT(t)

	bpfIfaceName = "IWep"
	defer func() {
		bpfIfaceName = ""
		skbMark = 0
	}()

	ctMap := conntrack.Map()
	Expect(ctMap.EnsureExists()).NotTo(HaveOccurred())
	defer resetCTMap(ctMap)

	ifIndex := 1
	istioDSCP := uint8(26) // DSCP 26 = EF (Expedited Forwarding)

	// Setup routes for source and destination workloads
	rtKey := routes.NewKey(srcV4CIDR).AsBytes()
	rtVal := routes.NewValueWithIfIndex(routes.FlagsLocalWorkload|routes.FlagInIPAMPool, ifIndex).AsBytes()
	Expect(rtMap.Update(rtKey, rtVal)).NotTo(HaveOccurred())

	rtKey = routes.NewKey(dstV4CIDR).AsBytes()
	rtVal = routes.NewValueWithIfIndex(routes.FlagsRemoteWorkload|routes.FlagInIPAMPool, ifIndex).AsBytes()
	Expect(rtMap.Update(rtKey, rtVal)).NotTo(HaveOccurred())
	defer resetRTMap(rtMap)

	// Add source IP to Istio WEPs IP set
	ipsetMap := ipsets.Map()
	Expect(ipsetMap.EnsureExists()).NotTo(HaveOccurred())
	ipsetEntry := ipsets.ProtoIPSetMemberToBPFEntry(ipsets.AllIstioWEPsID, fmt.Sprintf("%s/32", srcIP.String()))
	Expect(ipsetMap.Update(ipsetEntry.AsBytes(), ipsets.DummyValue)).NotTo(HaveOccurred())
	defer func() {
		_ = ipsetMap.Delete(ipsetEntry.AsBytes())
	}()

	t.Run("TCP SYN from Istio mesh gets DSCP marked", func(t *testing.T) {
		// Send through FROM_WEP to create CT entry
		skbMark = 0
		runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
			tcpHdr := &layers.TCP{
				SrcPort:    12345,
				DstPort:    80,
				SYN:        true,
				Seq:        1000,
				Window:     65535,
				DataOffset: 5,
			}

			ipv4Hdr := *ipv4Default
			ipv4Hdr.SrcIP = srcIP
			ipv4Hdr.DstIP = dstIP
			ipv4Hdr.Protocol = layers.IPProtocolTCP

			_, _, _, _, pktBytes, err := testPacketV4(nil, &ipv4Hdr, tcpHdr, []byte{})
			Expect(err).NotTo(HaveOccurred())
			res, err := bpfrun(pktBytes)
			Expect(err).NotTo(HaveOccurred())
			Expect(res.Retval).To(Equal(resTC_ACT_REDIRECT))
			Expect(res.dataOut).To(Equal(pktBytes), "Packet should be unchanged in FROM_WEP")
		}, withIstioDSCP(istioDSCP))

		// Verify the syn packet to WEP receives the DSCP mark
		skbMark = tcdefs.MarkSeen
		runBpfTest(t, "calico_to_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
			tcpHdr := &layers.TCP{
				SrcPort:    12345,
				DstPort:    80,
				SYN:        true,
				Seq:        1000,
				Window:     65535,
				DataOffset: 5,
			}

			ipv4Hdr := *ipv4Default
			ipv4Hdr.SrcIP = srcIP
			ipv4Hdr.DstIP = dstIP
			ipv4Hdr.Protocol = layers.IPProtocolTCP

			_, _, _, _, pktBytes, err := testPacketV4(nil, &ipv4Hdr, tcpHdr, []byte{})
			Expect(err).NotTo(HaveOccurred())
			res, err := bpfrun(pktBytes)
			Expect(err).NotTo(HaveOccurred())
			Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

			pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
			ipv4L := pktR.Layer(layers.LayerTypeIPv4)
			Expect(ipv4L).NotTo(BeNil())
			ipv4R := ipv4L.(*layers.IPv4)

			actualDSCP := ipv4R.TOS >> 2
			Expect(actualDSCP).To(Equal(istioDSCP), "Expected DSCP to be set to %d, got %d", istioDSCP, actualDSCP)
		}, withIstioDSCP(istioDSCP))
	})

	// NOTE: Relies on CT entry from previous test
	t.Run("TCP ACK from Istio mesh does not get DSCP marked", func(t *testing.T) {
		skbMark = tcdefs.MarkSeen
		runBpfTest(t, "calico_to_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
			tcpHdr := &layers.TCP{
				SrcPort:    12345,
				DstPort:    80,
				ACK:        true,
				Seq:        1001,
				Ack:        2000,
				Window:     65535,
				DataOffset: 5,
			}

			ipv4Hdr := *ipv4Default
			ipv4Hdr.SrcIP = srcIP
			ipv4Hdr.DstIP = dstIP
			ipv4Hdr.Protocol = layers.IPProtocolTCP

			_, _, _, _, pktBytes, err := testPacketV4(nil, &ipv4Hdr, tcpHdr, []byte{})
			Expect(err).NotTo(HaveOccurred())
			res, err := bpfrun(pktBytes)
			Expect(err).NotTo(HaveOccurred())
			Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

			pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
			ipv4L := pktR.Layer(layers.LayerTypeIPv4)
			Expect(ipv4L).NotTo(BeNil())
			ipv4R := ipv4L.(*layers.IPv4)

			actualDSCP := ipv4R.TOS >> 2
			Expect(actualDSCP).To(Equal(uint8(0)), "Expected DSCP to remain 0, got %d", actualDSCP)
		}, withIstioDSCP(istioDSCP))
	})

	t.Run("UDP from Istio mesh does not get DSCP marked", func(t *testing.T) {
		skbMark = tcdefs.MarkSeen
		runBpfTest(t, "calico_to_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
			_, _, _, _, pktBytes, err := testPacketUDPDefault()
			Expect(err).NotTo(HaveOccurred())
			res, err := bpfrun(pktBytes)
			Expect(err).NotTo(HaveOccurred())
			Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

			pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
			ipv4L := pktR.Layer(layers.LayerTypeIPv4)
			Expect(ipv4L).NotTo(BeNil())
			ipv4R := ipv4L.(*layers.IPv4)

			actualDSCP := ipv4R.TOS >> 2
			Expect(actualDSCP).To(Equal(uint8(0)), "Expected DSCP to remain 0 for UDP, got %d", actualDSCP)
		}, withIstioDSCP(istioDSCP))
	})

	t.Run("TCP SYN from non-mesh workload does not get DSCP marked", func(t *testing.T) {
		skbMark = tcdefs.MarkSeen
		nonMeshIP := net.IPv4(10, 10, 0, 99).To4()

		runBpfTest(t, "calico_to_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
			tcpHdr := &layers.TCP{
				SrcPort:    12345,
				DstPort:    80,
				SYN:        true,
				Seq:        1000,
				Window:     65535,
				DataOffset: 5,
			}

			ipv4Hdr := *ipv4Default
			ipv4Hdr.SrcIP = nonMeshIP
			ipv4Hdr.DstIP = dstIP
			ipv4Hdr.Protocol = layers.IPProtocolTCP

			_, _, _, _, pktBytes, err := testPacketV4(nil, &ipv4Hdr, tcpHdr, []byte{})
			Expect(err).NotTo(HaveOccurred())
			res, err := bpfrun(pktBytes)
			Expect(err).NotTo(HaveOccurred())
			Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

			pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
			ipv4L := pktR.Layer(layers.LayerTypeIPv4)
			Expect(ipv4L).NotTo(BeNil())
			ipv4R := ipv4L.(*layers.IPv4)

			actualDSCP := ipv4R.TOS >> 2
			Expect(actualDSCP).To(Equal(uint8(0)), "Expected DSCP to remain 0 for non-mesh source, got %d", actualDSCP)
		}, withIstioDSCP(istioDSCP))
	})

	t.Run("Istio DSCP disabled does not mark packets", func(t *testing.T) {
		skbMark = tcdefs.MarkSeen
		runBpfTest(t, "calico_to_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
			tcpHdr := &layers.TCP{
				SrcPort:    12345,
				DstPort:    80,
				SYN:        true,
				Seq:        1000,
				Window:     65535,
				DataOffset: 5,
			}

			ipv4Hdr := *ipv4Default
			ipv4Hdr.SrcIP = srcIP
			ipv4Hdr.DstIP = dstIP
			ipv4Hdr.Protocol = layers.IPProtocolTCP
			preDSCP := uint8(11)
			ipv4Hdr.TOS = (ipv4Hdr.TOS & 0x03) | (preDSCP << 2)

			_, _, _, _, pktBytes, err := testPacketV4(nil, &ipv4Hdr, tcpHdr, []byte{})
			Expect(err).NotTo(HaveOccurred())
			res, err := bpfrun(pktBytes)
			Expect(err).NotTo(HaveOccurred())
			Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

			pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
			ipv4L := pktR.Layer(layers.LayerTypeIPv4)
			Expect(ipv4L).NotTo(BeNil())
			ipv4R := ipv4L.(*layers.IPv4)

			actualDSCP := ipv4R.TOS >> 2
			Expect(actualDSCP).To(Equal(preDSCP), "Expected DSCP not changed when feature disabled, got %d", actualDSCP)
		})
	})
}

// TestIstioDSCPv6 tests the BPF implementation of Istio DSCP marking for IPv6 packets.
func TestIstioDSCPv6(t *testing.T) {
	RegisterTestingT(t)
	hostIP = node1ipV6
	skbMark = 0
	defer func() {
		hostIP = node1ip
		skbMark = 0
	}()

	bpfIfaceName = "IWep6"
	defer func() { bpfIfaceName = "" }()

	ctMap := conntrack.Map()
	Expect(ctMap.EnsureExists()).NotTo(HaveOccurred())
	defer resetCTMap(ctMap)

	ifIndex := 1
	istioDSCP := uint8(26)

	// Setup routes for source and destination workloads
	rtKey := routes.NewKeyV6(srcV6CIDR).AsBytes()
	rtVal := routes.NewValueV6WithIfIndex(routes.FlagsLocalWorkload|routes.FlagInIPAMPool, ifIndex).AsBytes()
	Expect(rtMapV6.Update(rtKey, rtVal)).NotTo(HaveOccurred())

	rtKey = routes.NewKeyV6(dstV6CIDR).AsBytes()
	rtVal = routes.NewValueV6WithIfIndex(routes.FlagsRemoteWorkload|routes.FlagInIPAMPool, ifIndex).AsBytes()
	Expect(rtMapV6.Update(rtKey, rtVal)).NotTo(HaveOccurred())
	defer resetRTMap(rtMapV6)

	// Add source IP to Istio WEPs IP set
	ipsetMap := ipsets.MapV6()
	Expect(ipsetMap.EnsureExists()).NotTo(HaveOccurred())
	ipsetEntry := ipsets.ProtoIPSetMemberToBPFEntryV6(ipsets.AllIstioWEPsID, fmt.Sprintf("%s/128", srcIPv6.String()))
	Expect(ipsetMap.Update(ipsetEntry.AsBytes(), ipsets.DummyValue)).NotTo(HaveOccurred())
	defer func() {
		_ = ipsetMap.Delete(ipsetEntry.AsBytes())
	}()

	t.Run("IPv6 TCP SYN from Istio mesh gets DSCP marked", func(t *testing.T) {
		// Send through FROM_WEP to create CT entry
		skbMark = 0
		runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
			tcpHdr := &layers.TCP{
				SrcPort:    12345,
				DstPort:    80,
				SYN:        true,
				Seq:        1000,
				Window:     65535,
				DataOffset: 5,
			}

			ipv6Hdr := *ipv6Default
			ipv6Hdr.SrcIP = srcIPv6
			ipv6Hdr.DstIP = dstIPv6
			ipv6Hdr.NextHeader = layers.IPProtocolTCP

			_, _, _, _, pktBytes, err := testPacketV6(nil, &ipv6Hdr, tcpHdr, []byte{})
			Expect(err).NotTo(HaveOccurred())
			res, err := bpfrun(pktBytes)
			Expect(err).NotTo(HaveOccurred())
			Expect(res.Retval).To(Equal(resTC_ACT_REDIRECT))
			Expect(res.dataOut).To(Equal(pktBytes), "Packet should be unchanged in FROM_WEP")
		}, withIstioDSCP(istioDSCP), withIPv6())

		// Send through TO_WEP where DSCP marking happens
		skbMark = tcdefs.MarkSeen
		runBpfTest(t, "calico_to_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
			tcpHdr := &layers.TCP{
				SrcPort:    12345,
				DstPort:    80,
				SYN:        true,
				Seq:        1000,
				Window:     65535,
				DataOffset: 5,
			}

			ipv6Hdr := *ipv6Default
			ipv6Hdr.SrcIP = srcIPv6
			ipv6Hdr.DstIP = dstIPv6
			ipv6Hdr.NextHeader = layers.IPProtocolTCP

			_, _, _, _, pktBytes, err := testPacketV6(nil, &ipv6Hdr, tcpHdr, []byte{})
			Expect(err).NotTo(HaveOccurred())
			res, err := bpfrun(pktBytes)
			Expect(err).NotTo(HaveOccurred())
			Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

			pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
			ipv6L := pktR.Layer(layers.LayerTypeIPv6)
			Expect(ipv6L).NotTo(BeNil())
			ipv6R := ipv6L.(*layers.IPv6)

			actualDSCP := ipv6R.TrafficClass >> 2
			Expect(actualDSCP).To(Equal(istioDSCP), "Expected DSCP to be set to %d, got %d", istioDSCP, actualDSCP)
		}, withIstioDSCP(istioDSCP), withIPv6())
	})

	// NOTE: Relies on CT entry from previous test
	t.Run("IPv6 TCP ACK from Istio mesh does not get DSCP marked", func(t *testing.T) {
		skbMark = tcdefs.MarkSeen
		runBpfTest(t, "calico_to_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
			tcpHdr := &layers.TCP{
				SrcPort:    12345,
				DstPort:    80,
				ACK:        true,
				Seq:        1001,
				Ack:        2000,
				Window:     65535,
				DataOffset: 5,
			}

			ipv6Hdr := *ipv6Default
			ipv6Hdr.SrcIP = srcIPv6
			ipv6Hdr.DstIP = dstIPv6
			ipv6Hdr.NextHeader = layers.IPProtocolTCP

			_, _, _, _, pktBytes, err := testPacketV6(nil, &ipv6Hdr, tcpHdr, []byte{})
			Expect(err).NotTo(HaveOccurred())
			res, err := bpfrun(pktBytes)
			Expect(err).NotTo(HaveOccurred())
			Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

			pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
			ipv6L := pktR.Layer(layers.LayerTypeIPv6)
			Expect(ipv6L).NotTo(BeNil())
			ipv6R := ipv6L.(*layers.IPv6)

			actualDSCP := ipv6R.TrafficClass >> 2
			Expect(actualDSCP).To(Equal(uint8(0)), "Expected DSCP to remain 0, got %d", actualDSCP)
		}, withIstioDSCP(istioDSCP), withIPv6())
	})

	t.Run("IPv6 Istio DSCP disabled does not mark packets", func(t *testing.T) {
		skbMark = tcdefs.MarkSeen
		runBpfTest(t, "calico_to_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
			tcpHdr := &layers.TCP{
				SrcPort:    12345,
				DstPort:    80,
				SYN:        true,
				Seq:        1000,
				Window:     65535,
				DataOffset: 5,
			}

			ipv6Hdr := *ipv6Default
			ipv6Hdr.SrcIP = srcIPv6
			ipv6Hdr.DstIP = dstIPv6
			ipv6Hdr.NextHeader = layers.IPProtocolTCP
			preDSCP := uint8(11)
			ipv6Hdr.TrafficClass = (ipv6Hdr.TrafficClass & 0x03) | (preDSCP << 2)

			_, _, _, _, pktBytes, err := testPacketV6(nil, &ipv6Hdr, tcpHdr, []byte{})
			Expect(err).NotTo(HaveOccurred())
			res, err := bpfrun(pktBytes)
			Expect(err).NotTo(HaveOccurred())
			Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

			pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
			ipv6L := pktR.Layer(layers.LayerTypeIPv6)
			Expect(ipv6L).NotTo(BeNil())
			ipv6R := ipv6L.(*layers.IPv6)

			actualDSCP := ipv6R.TrafficClass >> 2
			Expect(actualDSCP).To(Equal(preDSCP), "Expected DSCP not changed when feature disabled, got %d", actualDSCP)
		}, withIPv6())
	})
}
