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
	"hash/fnv"
	"net"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/bpf/arp"
	"github.com/projectcalico/calico/felix/bpf/conntrack"
	conntrack4 "github.com/projectcalico/calico/felix/bpf/conntrack/v4"
	"github.com/projectcalico/calico/felix/bpf/consistenthash"
	chtypes "github.com/projectcalico/calico/felix/bpf/consistenthash/test"
	"github.com/projectcalico/calico/felix/bpf/maps"
	"github.com/projectcalico/calico/felix/bpf/nat"
	"github.com/projectcalico/calico/felix/bpf/polprog"
	"github.com/projectcalico/calico/felix/bpf/routes"
	tcdefs "github.com/projectcalico/calico/felix/bpf/tc/defs"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/proto"
)

// Important note to the delevoper:
// While we program both the maglev map *and* backend map in the real world,
// We neglect to program the backend map in these UTs, as it should not be
// used by the BPF program, and would be an error to do so.
// We would like such errors to be immediately apparent, hence the omission.

var maglevTestM = 31

func TestMaglevNATServiceIPTCP(t *testing.T) {
	RegisterTestingT(t)

	var natMap, mgMap maps.MapWithExistsCheck
	var ctMap, rtMap maps.Map
	var err error

	natMap = nat.FrontendMap()
	err = natMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	mgMap = nat.MaglevMap()
	err = mgMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	ctMap = conntrack.Map()
	err = ctMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	rtMap = routes.Map()
	err = rtMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	resetMaps := func() {
		resetMap(natMap)
		resetMap(mgMap)
		resetCTMap(ctMap)
		resetRTMap(rtMap)
		resetMap(arpMap)
	}
	defer resetMaps()

	newNode := func(nodeIP net.IP) {
		resetMaps()
		hostIP = nodeIP
		skbMark = 0
		bpfIfaceName = fmt.Sprintf("MNP-%d", nodeIP[3])
	}

	var rtNode1, rtNode2 routes.MapMem
	var ctNode1, ctNode2 conntrack.MapMem
	var arpNode1, arpNode2 arp.MapMem

	// First, node 3 will initiate a connection to node 2.
	// Then, node 1 will pick up the connection mid-flow.
	// Node 2 should begin forwarding back to node 1.
	newNode(node3ip)
	defer func() { bpfIfaceName = "" }()

	serviceIP := net.IPv4(172, 16, 1, 1)
	podIP := net.IPv4(8, 8, 8, 8)
	podPort := uint16(666)

	node2WlCIDR := net.IPNet{
		IP:   podIP,
		Mask: net.IPv4Mask(255, 255, 255, 0),
	}
	var encapedPkt []byte

	// Prepare a test packet.
	// SYN, Src IP 1.1.1.1, Src Port 1234, Dst IP 172.16.1.1, Dst Port 5678.
	_, ipv4, tcp, payload, pktBytes, err := testPacketTCPV4DefaultNP(serviceIP, true)
	Expect(err).NotTo(HaveOccurred())

	// Node 3: Flagging frontend map item with the consistent-hash flag.
	err = natMap.Update(
		nat.NewNATKey(ipv4.DstIP, uint16(tcp.DstPort), uint8(layers.IPProtocolTCP)).AsBytes(),
		nat.NewNATValueWithFlags(0, 1, 0, 0, nat.NATFlgMaglev).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	// Node 3: Build a maglev LUT and program each item to the BPF map.
	mglv := consistenthash.New(maglevTestM, fnv.New32(), fnv.New32())
	mglv.AddBackend(chtypes.MockEndpoint{
		Ip:  podIP.String(),
		Prt: podPort,
	})
	lut := mglv.Generate()
	for ordinal, ep := range lut {
		err = mgMap.Update(
			nat.NewMaglevBackendKey(ipv4.DstIP, uint16(tcp.DstPort), uint8(layers.IPProtocolTCP), uint32(ordinal)).AsBytes(),
			nat.NewNATBackendValue(net.ParseIP(ep.IP()), uint16(ep.Port())).AsBytes(),
		)
		Expect(err).NotTo(HaveOccurred())
	}

	// Node 3: Setup routing.
	err = rtMap.Update(
		routes.NewKey(ip.CIDRFromIPNet(&node2WlCIDR).(ip.V4CIDR)).AsBytes(),
		routes.NewValueWithNextHop(routes.FlagsRemoteWorkload|routes.FlagInIPAMPool,
			ip.FromNetIP(node2ip).(ip.V4Addr)).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())
	err = rtMap.Update(
		routes.NewKey(ip.CIDRFromIPNet(&node3CIDR).(ip.V4CIDR)).AsBytes(),
		routes.NewValue(routes.FlagsLocalHost).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())
	err = rtMap.Update(
		routes.NewKey(ip.CIDRFromIPNet(&node1CIDR).(ip.V4CIDR)).AsBytes(),
		routes.NewValue(routes.FlagsRemoteHost).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())
	err = rtMap.Update(
		routes.NewKey(ip.CIDRFromIPNet(&node2CIDR).(ip.V4CIDR)).AsBytes(),
		routes.NewValue(routes.FlagsRemoteHost).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	// Arriving at node 3
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		// Do comparison on the strings rather than the numbers to give more
		// meaning to Gomega failure messages.
		Expect(retvalToStr[res.Retval]).To(Equal(retvalToStr[resTC_ACT_REDIRECT]))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		ipv4L := pktR.Layer(layers.LayerTypeIPv4)
		Expect(ipv4L).NotTo(BeNil())
		ipv4R := ipv4L.(*layers.IPv4)
		Expect(ipv4R.SrcIP.String()).To(Equal(hostIP.String()))
		Expect(ipv4R.DstIP.String()).To(Equal(node2ip.String()))

		checkVxlanEncap(pktR, false, ipv4, tcp, payload)

		encapedPkt = res.dataOut

		ct, err := conntrack.LoadMapMem(ctMap)
		Expect(err).NotTo(HaveOccurred())

		dumpCTMap(ctMap)

		ctKey := conntrack.NewKey(uint8(layers.IPProtocolTCP),
			ipv4.SrcIP, uint16(tcp.SrcPort), ipv4.DstIP, uint16(tcp.DstPort))

		Expect(ct).Should(HaveKey(ctKey))
		ctr := ct[ctKey]
		Expect(ctr.Type()).To(Equal(conntrack.TypeNATForward))

		ctKey = ctr.ReverseNATKey().(conntrack.Key)
		Expect(ct).Should(HaveKey(ctKey))
		ctr = ct[ctKey]
		Expect(ctr.Type()).To(Equal(conntrack.TypeNATReverse))

		// Approved for both sides due to forwarding through the tunnel
		Expect(ctr.Data().A2B.Approved).To(BeTrue())
		Expect(ctr.Data().B2A.Approved).To(BeTrue())

		v, ok := ct[conntrack.NewKey(uint8(layers.IPProtocolTCP), ipv4.SrcIP, uint16(tcp.SrcPort), podIP.To4(), podPort)]
		Expect(ok).To(BeTrue())
		Expect(v.Type()).To(Equal(conntrack.TypeNATReverse))
		Expect(v.Flags()).To(Equal(conntrack4.FlagNATNPFwd | conntrack4.FlagMaglev))
	})
	expectMark(tcdefs.MarkSeenBypassForward)

	// Leaving node 3.
	runBpfTest(t, "calico_to_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(encapedPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		Expect(res.dataOut).To(Equal(encapedPkt))
	})

	dumpCTMap(ctMap)

	// Now arriving at Node 2.
	encapedPktArrivesAtNode2 := make([]byte, len(encapedPkt))
	copy(encapedPktArrivesAtNode2, encapedPkt)

	newNode(node2ip)

	// change the routing - backing workload is local now
	err = rtMap.Update(
		routes.NewKey(ip.CIDRFromIPNet(&node2WlCIDR).(ip.V4CIDR)).AsBytes(),
		routes.NewValue(routes.FlagsLocalWorkload|routes.FlagInIPAMPool).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())
	// we must know that the encaped packet src ip is from a known host
	err = rtMap.Update(
		routes.NewKey(ip.CIDRFromIPNet(&node3CIDR).(ip.V4CIDR)).AsBytes(),
		routes.NewValue(routes.FlagsRemoteHost).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())
	err = rtMap.Update(
		routes.NewKey(ip.CIDRFromIPNet(&node1CIDR).(ip.V4CIDR)).AsBytes(),
		routes.NewValue(routes.FlagsRemoteHost).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())
	err = rtMap.Update(
		routes.NewKey(ip.CIDRFromIPNet(&node2CIDR).(ip.V4CIDR)).AsBytes(),
		routes.NewValue(routes.FlagsLocalHost).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	dumpRTMap(rtMap)
	// Node 2: now we are at the node with local workload
	err = natMap.Update(
		nat.NewNATKey(ipv4.DstIP, uint16(tcp.DstPort), uint8(layers.IPProtocolTCP)).AsBytes(),
		nat.NewNATValueWithFlags(0 /* id */, 1 /* count */, 1 /* local */, 0, nat.NATFlgMaglev).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	// Node 2: Build a maglev LUT and program each item to the BPF map.
	mglv = consistenthash.New(maglevTestM, fnv.New32(), fnv.New32())
	mglv.AddBackend(chtypes.MockEndpoint{
		Ip:  podIP.String(),
		Prt: podPort,
	})
	lut = mglv.Generate()
	for ordinal, ep := range lut {
		err = mgMap.Update(
			nat.NewMaglevBackendKey(ipv4.DstIP, uint16(tcp.DstPort), uint8(layers.IPProtocolTCP), uint32(ordinal)).AsBytes(),
			nat.NewNATBackendValue(net.ParseIP(ep.IP()), uint16(ep.Port())).AsBytes(),
		)
		Expect(err).NotTo(HaveOccurred())
	}

	// Packet hits node 2.
	var recvPkt []byte
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(encapedPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(retvalToStr[res.Retval]).To(Equal(retvalToStr[resTC_ACT_REDIRECT]))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)
		payloadL := pktR.ApplicationLayer()
		Expect(payloadL).NotTo(BeNil())
		vxlanL := gopacket.NewPacket(payloadL.Payload(), layers.LayerTypeVXLAN, gopacket.Default)
		Expect(vxlanL).NotTo(BeNil())
		fmt.Printf("vxlanL = %+v\n", vxlanL)

		ipv4L := pktR.Layer(layers.LayerTypeIPv4)
		ipv4R := ipv4L.(*layers.IPv4)
		Expect(ipv4R.SrcIP.String()).To(Equal(ipv4.SrcIP.String()))
		Expect(ipv4R.DstIP.String()).To(Equal(podIP.String()))

		tcpL := pktR.Layer(layers.LayerTypeTCP)
		Expect(tcpL).NotTo(BeNil())
		tcpR := tcpL.(*layers.TCP)
		Expect(tcpR.SrcPort).To(Equal(layers.TCPPort(tcp.SrcPort)))
		Expect(tcpR.DstPort).To(Equal(layers.TCPPort(podPort)))

		ct, err := conntrack.LoadMapMem(ctMap)
		Expect(err).NotTo(HaveOccurred())

		ctKey := conntrack.NewKey(uint8(layers.IPProtocolTCP),
			ipv4.SrcIP, uint16(tcp.SrcPort), ipv4.DstIP, uint16(tcp.DstPort))

		Expect(ct).Should(HaveKey(ctKey))
		ctr := ct[ctKey]
		Expect(ctr.Type()).To(Equal(conntrack.TypeNATForward))
		Expect(ctr.NATSPort()).To(Equal(uint16(0)))

		ctKey = ctr.ReverseNATKey().(conntrack.Key)
		Expect(ct).Should(HaveKey(ctKey))
		ctr = ct[ctKey]
		Expect(ctr.Type()).To(Equal(conntrack.TypeNATReverse))

		// Approved source side
		Expect(ctr.Data().A2B.Approved).To(BeTrue())
		// Dest not approved yet
		Expect(ctr.Data().B2A.Approved).NotTo(BeTrue())

		recvPkt = res.dataOut

		dumpCTMap(ctMap)
		ct, err = conntrack.LoadMapMem(ctMap)
		Expect(err).NotTo(HaveOccurred())

		v, ok := ct[conntrack.NewKey(uint8(layers.IPProtocolTCP), ipv4.SrcIP, uint16(tcp.SrcPort), podIP.To4(), podPort)]
		Expect(ok).To(BeTrue())
		Expect(v.Type()).To(Equal(conntrack.TypeNATReverse))
		Expect(v.Flags()).To(Equal(conntrack4.FlagExtLocal | conntrack4.FlagMaglev))
	})
	expectMark(tcdefs.MarkSeen)

	dumpARPMap(arpMap)
	arpNode2 = saveARPMap(arpMap)
	ctNode2 = saveCTMap(ctMap)
	Expect(arpNode2).To(HaveLen(1))

	arpKey := arp.NewKey(node3ip, 1 /* ifindex is always 1 in UT */)
	Expect(arpNode2).To(HaveKey(arpKey))

	macDst := encapedPkt[0:6]
	macSrc := encapedPkt[6:12]
	Expect(arpNode2[arpKey]).To(Equal(arp.NewValue(macDst, macSrc)))

	// try a spoofed tunnel packet, should be dropped and have no effect
	skbMark = 0
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		// modify the only known good src IP, we do not care about csums at this point
		spoofedPkt := make([]byte, len(encapedPkt))
		copy(spoofedPkt, encapedPkt)
		spoofedPkt[26] = 234
		res, err := bpfrun(spoofedPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_SHOT))
	})

	skbMark = tcdefs.MarkSeen

	// Insert the reverse route for backend for RPF check.
	beV4CIDR := ip.CIDRFromNetIP(podIP).(ip.V4CIDR)
	bertKey := routes.NewKey(beV4CIDR).AsBytes()
	bertVal := routes.NewValueWithIfIndex(routes.FlagsLocalWorkload|routes.FlagInIPAMPool, 1).AsBytes()
	err = rtMap.Update(bertKey, bertVal)
	Expect(err).NotTo(HaveOccurred())

	// Arriving at workload at node 2
	runBpfTest(t, "calico_to_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(recvPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(retvalToStr[res.Retval]).To(Equal(retvalToStr[resTC_ACT_UNSPEC]))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		Expect(res.dataOut).To(Equal(recvPkt))

		ctNode2, err = conntrack.LoadMapMem(ctMap)
		Expect(err).NotTo(HaveOccurred())

		ctKey := conntrack.NewKey(uint8(layers.IPProtocolTCP),
			ipv4.SrcIP, uint16(tcp.SrcPort), ipv4.DstIP, uint16(tcp.DstPort))

		Expect(ctNode2).Should(HaveKey(ctKey))
		ctr := ctNode2[ctKey]
		Expect(ctr.Type()).To(Equal(conntrack.TypeNATForward))

		ctKey = ctr.ReverseNATKey().(conntrack.Key)
		Expect(ctNode2).Should(HaveKey(ctKey))
		ctr = ctNode2[ctKey]
		Expect(ctr.Type()).To(Equal(conntrack.TypeNATReverse),
			fmt.Sprintf("Expected reverse conntrack entry but got %v", ctr))

		// Approved source side
		Expect(ctr.Data().A2B.Approved).To(BeTrue())
		// Approved destination side as well
		Expect(ctr.Data().B2A.Approved).To(BeTrue())
	})

	skbMark = 0

	// Response leaving workload at node 2
	runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		respPkt := tcpResponseRaw(recvPkt)
		// Change the MAC addresses so that we can observe that the right
		// addresses were patched in.
		copy(respPkt[:6], []byte{1, 2, 3, 4, 5, 6})
		copy(respPkt[6:12], []byte{6, 5, 4, 3, 2, 1})
		res, err := bpfrun(respPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(retvalToStr[res.Retval]).To(Equal(retvalToStr[resTC_ACT_REDIRECT]))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		ethL := pktR.Layer(layers.LayerTypeEthernet)
		Expect(ethL).NotTo(BeNil())
		ethR := ethL.(*layers.Ethernet)
		Expect(ethR).To(layersMatchFields(&layers.Ethernet{
			SrcMAC:       macDst,
			DstMAC:       macSrc,
			EthernetType: layers.EthernetTypeIPv4,
		}))

		ipv4L := pktR.Layer(layers.LayerTypeIPv4)
		Expect(ipv4L).NotTo(BeNil())
		ipv4R := ipv4L.(*layers.IPv4)
		Expect(ipv4R.SrcIP.String()).To(Equal(hostIP.String()))
		Expect(ipv4R.DstIP.String()).To(Equal(node3ip.String()))

		checkVxlan(pktR)

		encapedPkt = res.dataOut
	})

	dumpCTMap(ctMap)
	expectMark(tcdefs.MarkSeen)

	// Response leaving node 2
	runBpfTest(t, "calico_to_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(encapedPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(retvalToStr[res.Retval]).To(Equal(retvalToStr[resTC_ACT_UNSPEC]))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		ipv4L := pktR.Layer(layers.LayerTypeIPv4)
		Expect(ipv4L).NotTo(BeNil())
		ipv4R := ipv4L.(*layers.IPv4)
		// check that the IP is fixed up
		Expect(ipv4R.SrcIP.String()).To(Equal(node2ip.String()))
		Expect(ipv4R.DstIP.String()).To(Equal(node3ip.String()))

		checkVxlan(pktR)

		encapedPkt = res.dataOut
	})
	expectMark(tcdefs.MarkSeen)

	rtNode2 = saveRTMap(rtMap)
	ctNode2 = saveCTMap(ctMap)
	arpNode2 = saveARPMap(arpMap)

	// Now on node 1, handling a failing-over connection.
	newNode(node1ip)
	encapedPkt = nil

	// Src IP 1.1.1.1, Src Port 1234, Dst IP 172.16.1.1, Dst Port 5678.
	_, ipv4, tcp, payload, pktBytes, err = testPacketTCPV4DefaultNP(serviceIP, false)
	Expect(err).NotTo(HaveOccurred())

	// Node 1: Flagging frontend map item with the consistent-hash flag.
	err = natMap.Update(
		nat.NewNATKey(ipv4.DstIP, uint16(tcp.DstPort), uint8(layers.IPProtocolTCP)).AsBytes(),
		nat.NewNATValueWithFlags(0, 1, 0, 0, nat.NATFlgMaglev).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	// Node 1: Build a maglev LUT and program each item to the BPF map.
	mglv = consistenthash.New(maglevTestM, fnv.New32(), fnv.New32())
	mglv.AddBackend(chtypes.MockEndpoint{
		Ip:  podIP.String(),
		Prt: podPort,
	})
	lut = mglv.Generate()
	for ordinal, ep := range lut {
		err = mgMap.Update(
			nat.NewMaglevBackendKey(ipv4.DstIP, uint16(tcp.DstPort), uint8(layers.IPProtocolTCP), uint32(ordinal)).AsBytes(),
			nat.NewNATBackendValue(net.ParseIP(ep.IP()), uint16(ep.Port())).AsBytes(),
		)
		Expect(err).NotTo(HaveOccurred())
	}

	// Arriving at node 1 - non-routable -> denied
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_SHOT))
	})

	err = rtMap.Update(
		routes.NewKey(ip.CIDRFromIPNet(&node2WlCIDR).(ip.V4CIDR)).AsBytes(),
		routes.NewValueWithNextHop(routes.FlagsRemoteWorkload|routes.FlagInIPAMPool,
			ip.FromNetIP(node2ip).(ip.V4Addr)).AsBytes(),
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
	dumpRTMap(rtMap)

	// Arriving at node 1
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		// Do comparison on the strings rather than the numbers to give more
		// meaning to Gomega failure messages.
		Expect(retvalToStr[res.Retval]).To(Equal(retvalToStr[resTC_ACT_REDIRECT]))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		ipv4L := pktR.Layer(layers.LayerTypeIPv4)
		Expect(ipv4L).NotTo(BeNil())
		ipv4R := ipv4L.(*layers.IPv4)
		Expect(ipv4R.SrcIP.String()).To(Equal(hostIP.String()))
		Expect(ipv4R.DstIP.String()).To(Equal(node2ip.String()))

		checkVxlanEncap(pktR, false, ipv4, tcp, payload)

		encapedPkt = res.dataOut

		ct, err := conntrack.LoadMapMem(ctMap)
		Expect(err).NotTo(HaveOccurred())

		ctKey := conntrack.NewKey(uint8(layers.IPProtocolTCP),
			ipv4.SrcIP, uint16(tcp.SrcPort), ipv4.DstIP, uint16(tcp.DstPort))

		Expect(ct).Should(HaveKey(ctKey))
		ctr := ct[ctKey]
		Expect(ctr.Type()).To(Equal(conntrack.TypeNATForward))

		ctKey = ctr.ReverseNATKey().(conntrack.Key)
		Expect(ct).Should(HaveKey(ctKey))
		ctr = ct[ctKey]
		Expect(ctr.Type()).To(Equal(conntrack.TypeNATReverse))

		// Approved for both sides due to forwarding through the tunnel
		Expect(ctr.Data().A2B.Approved).To(BeTrue())
		Expect(ctr.Data().B2A.Approved).To(BeTrue())
	})
	expectMark(tcdefs.MarkSeenBypassForward)

	dumpCTMap(ctMap)
	ct, err := conntrack.LoadMapMem(ctMap)
	Expect(err).NotTo(HaveOccurred())
	v, ok := ct[conntrack.NewKey(uint8(layers.IPProtocolTCP), ipv4.SrcIP, uint16(tcp.SrcPort), podIP.To4(), podPort)]
	Expect(ok).To(BeTrue())
	Expect(v.Type()).To(Equal(conntrack.TypeNATReverse))
	Expect(v.Flags()).To(Equal(conntrack4.FlagNATNPFwd | conntrack4.FlagMaglev))

	// Leaving node 1
	runBpfTest(t, "calico_to_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(encapedPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		Expect(res.dataOut).To(Equal(encapedPkt))
	})

	dumpCTMap(ctMap)
	ctNode1 = saveCTMap(ctMap)
	rtNode1 = saveRTMap(rtMap)
	arpNode1 = saveARPMap(arpMap)

	encapedPktArrivesAtNode2 = make([]byte, len(encapedPkt))
	copy(encapedPktArrivesAtNode2, encapedPkt)

	recvPkt = nil
	newNode(node2ip)
	restoreCTMap(ctMap, ctNode2)
	restoreRTMap(rtMap, rtNode2)
	restoreARPMap(arpMap, arpNode2)

	dumpRTMap(rtMap)

	// now we are at the node with local workload
	err = natMap.Update(
		nat.NewNATKey(ipv4.DstIP, uint16(tcp.DstPort), uint8(layers.IPProtocolTCP)).AsBytes(),
		nat.NewNATValueWithFlags(0 /* id */, 1 /* count */, 1 /* local */, 0, nat.NATFlgMaglev).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	// Node 2: Build a maglev LUT and program each item to the BPF map.
	mglv = consistenthash.New(maglevTestM, fnv.New32(), fnv.New32())
	mglv.AddBackend(chtypes.MockEndpoint{
		Ip:  podIP.String(),
		Prt: podPort,
	})
	lut = mglv.Generate()
	for ordinal, ep := range lut {
		err = mgMap.Update(
			nat.NewMaglevBackendKey(ipv4.DstIP, uint16(tcp.DstPort), uint8(layers.IPProtocolTCP), uint32(ordinal)).AsBytes(),
			nat.NewNATBackendValue(net.ParseIP(ep.IP()), uint16(ep.Port())).AsBytes(),
		)
		Expect(err).NotTo(HaveOccurred())
	}

	// Arriving at node 2
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(encapedPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(retvalToStr[res.Retval]).To(Equal(retvalToStr[resTC_ACT_REDIRECT]))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)
		payloadL := pktR.ApplicationLayer()
		Expect(payloadL).NotTo(BeNil())
		vxlanL := gopacket.NewPacket(payloadL.Payload(), layers.LayerTypeVXLAN, gopacket.Default)
		Expect(vxlanL).NotTo(BeNil())
		fmt.Printf("vxlanL = %+v\n", vxlanL)

		ipv4L := pktR.Layer(layers.LayerTypeIPv4)
		ipv4R := ipv4L.(*layers.IPv4)
		Expect(ipv4R.SrcIP.String()).To(Equal(ipv4.SrcIP.String()))
		Expect(ipv4R.DstIP.String()).To(Equal(podIP.String()))

		tcpL := pktR.Layer(layers.LayerTypeTCP)
		Expect(tcpL).NotTo(BeNil())
		tcpR := tcpL.(*layers.TCP)
		Expect(tcpR.SrcPort).To(Equal(layers.TCPPort(tcp.SrcPort)))
		Expect(tcpR.DstPort).To(Equal(layers.TCPPort(podPort)))

		ct, err := conntrack.LoadMapMem(ctMap)
		Expect(err).NotTo(HaveOccurred())

		ctKey := conntrack.NewKey(uint8(layers.IPProtocolTCP),
			ipv4.SrcIP, uint16(tcp.SrcPort), ipv4.DstIP, uint16(tcp.DstPort))

		Expect(ct).Should(HaveKey(ctKey))
		ctr := ct[ctKey]
		Expect(ctr.Type()).To(Equal(conntrack.TypeNATForward))
		Expect(ctr.NATSPort()).To(Equal(uint16(0)))

		ctKey = ctr.ReverseNATKey().(conntrack.Key)
		Expect(ct).Should(HaveKey(ctKey))
		ctr = ct[ctKey]
		Expect(ctr.Type()).To(Equal(conntrack.TypeNATReverse))

		// Approved source side
		Expect(ctr.Data().A2B.Approved).To(BeTrue())
		Expect(ctr.Data().B2A.Approved).To(BeTrue())

		recvPkt = res.dataOut

		dumpCTMap(ctMap)
		ct, err = conntrack.LoadMapMem(ctMap)
		Expect(err).NotTo(HaveOccurred())
		v, ok = ct[conntrack.NewKey(uint8(layers.IPProtocolTCP), ipv4.SrcIP, uint16(tcp.SrcPort), podIP.To4(), podPort)]
		Expect(ok).To(BeTrue())
		Expect(v.Type()).To(Equal(conntrack.TypeNATReverse))
		Expect(v.Flags()).To(Equal(conntrack4.FlagExtLocal | conntrack4.FlagMaglev))
	})
	expectMark(tcdefs.MarkSeen)

	dumpARPMap(arpMap)
	arpNode2 = saveARPMap(arpMap)
	Expect(arpNode2).To(HaveLen(2))
	arpKey = arp.NewKey(node1ip, 1 /* ifindex is always 1 in UT */)
	Expect(arpNode2).To(HaveKey(arpKey))
	macDst = encapedPkt[0:6]
	macSrc = encapedPkt[6:12]
	Expect(arpNode2[arpKey]).To(Equal(arp.NewValue(macDst, macSrc)))

	// try a spoofed tunnel packet, should be dropped and have no effect
	skbMark = 0
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		// modify the only known good src IP, we do not care about csums at this point
		encapedPkt[26] = 234
		res, err := bpfrun(encapedPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_SHOT))
	})

	skbMark = tcdefs.MarkSeen

	// Insert the reverse route for backend for RPF check.
	resetRTMap(rtMap)
	beV4CIDR = ip.CIDRFromNetIP(podIP).(ip.V4CIDR)
	bertKey = routes.NewKey(beV4CIDR).AsBytes()
	bertVal = routes.NewValueWithIfIndex(routes.FlagsLocalWorkload|routes.FlagInIPAMPool, 1).AsBytes()
	err = rtMap.Update(bertKey, bertVal)
	Expect(err).NotTo(HaveOccurred())

	// Arriving at workload at node 2
	runBpfTest(t, "calico_to_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(recvPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(retvalToStr[res.Retval]).To(Equal(retvalToStr[resTC_ACT_UNSPEC]))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		Expect(res.dataOut).To(Equal(recvPkt))

		ct, err := conntrack.LoadMapMem(ctMap)
		Expect(err).NotTo(HaveOccurred())

		ctKey := conntrack.NewKey(uint8(layers.IPProtocolTCP),
			ipv4.SrcIP, uint16(tcp.SrcPort), ipv4.DstIP, uint16(tcp.DstPort))

		Expect(ct).Should(HaveKey(ctKey))
		ctr := ct[ctKey]
		Expect(ctr.Type()).To(Equal(conntrack.TypeNATForward))

		ctKey = ctr.ReverseNATKey().(conntrack.Key)
		Expect(ct).Should(HaveKey(ctKey))
		ctr = ct[ctKey]
		Expect(ctr.Type()).To(Equal(conntrack.TypeNATReverse),
			fmt.Sprintf("Expected reverse conntrack entry but got %v", ctr))

		// Approved source side
		Expect(ctr.Data().A2B.Approved).To(BeTrue())
		// Approved destination side as well
		Expect(ctr.Data().B2A.Approved).To(BeTrue())
	})

	skbMark = 0

	// Response leaving workload at node 2
	runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		respPkt := tcpResponseRaw(recvPkt)
		// Change the MAC addresses so that we can observe that the right
		// addresses were patched in.
		copy(respPkt[:6], []byte{1, 2, 3, 4, 5, 6})
		copy(respPkt[6:12], []byte{6, 5, 4, 3, 2, 1})
		res, err := bpfrun(respPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(retvalToStr[res.Retval]).To(Equal(retvalToStr[resTC_ACT_REDIRECT]))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		ethL := pktR.Layer(layers.LayerTypeEthernet)
		Expect(ethL).NotTo(BeNil())
		ethR := ethL.(*layers.Ethernet)
		Expect(ethR).To(layersMatchFields(&layers.Ethernet{
			SrcMAC:       macDst,
			DstMAC:       macSrc,
			EthernetType: layers.EthernetTypeIPv4,
		}))

		ipv4L := pktR.Layer(layers.LayerTypeIPv4)
		Expect(ipv4L).NotTo(BeNil())
		ipv4R := ipv4L.(*layers.IPv4)
		Expect(ipv4R.SrcIP.String()).To(Equal(hostIP.String()))
		Expect(ipv4R.DstIP.String()).To(Equal(node1ip.String()))

		checkVxlan(pktR)

		encapedPkt = res.dataOut
	})

	dumpCTMap(ctMap)
	expectMark(tcdefs.MarkSeen)

	// Response leaving node 2
	runBpfTest(t, "calico_to_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(encapedPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(retvalToStr[res.Retval]).To(Equal(retvalToStr[resTC_ACT_UNSPEC]))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		ipv4L := pktR.Layer(layers.LayerTypeIPv4)
		Expect(ipv4L).NotTo(BeNil())
		ipv4R := ipv4L.(*layers.IPv4)
		// check that the IP is fixed up
		Expect(ipv4R.SrcIP.String()).To(Equal(node2ip.String()))
		Expect(ipv4R.DstIP.String()).To(Equal(node1ip.String()))

		checkVxlan(pktR)

		encapedPkt = res.dataOut
	})

	dumpCTMap(ctMap)
	ctNode2 = saveCTMap(ctMap)

	// Back at node 1
	newNode(node1ip)
	restoreCTMap(ctMap, ctNode1)
	restoreARPMap(arpMap, arpNode1)
	restoreRTMap(rtMap, rtNode1)

	err = natMap.Update(
		nat.NewNATKey(ipv4.DstIP, uint16(tcp.DstPort), uint8(layers.IPProtocolTCP)).AsBytes(),
		nat.NewNATValueWithFlags(0, 1, 0, 0, nat.NATFlgMaglev).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())
	mglv = consistenthash.New(maglevTestM, fnv.New32(), fnv.New32())
	mglv.AddBackend(chtypes.MockEndpoint{
		Ip:  podIP.String(),
		Prt: podPort,
	})
	lut = mglv.Generate()
	for ordinal, ep := range lut {
		err = mgMap.Update(
			nat.NewMaglevBackendKey(ipv4.DstIP, uint16(tcp.DstPort), uint8(layers.IPProtocolTCP), uint32(ordinal)).AsBytes(),
			nat.NewNATBackendValue(net.ParseIP(ep.IP()), uint16(ep.Port())).AsBytes(),
		)
		Expect(err).NotTo(HaveOccurred())
	}

	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(encapedPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(retvalToStr[res.Retval]).To(Equal(retvalToStr[resTC_ACT_REDIRECT]))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		ipv4L := pktR.Layer(layers.LayerTypeIPv4)
		Expect(ipv4L).NotTo(BeNil())
		ipv4R := ipv4L.(*layers.IPv4)
		Expect(ipv4R.DstIP.String()).To(Equal(ipv4.SrcIP.String()))
		Expect(ipv4R.SrcIP.String()).To(Equal(ipv4.DstIP.String()))

		tcpL := pktR.Layer(layers.LayerTypeTCP)
		Expect(tcpL).NotTo(BeNil())
		tcpR := tcpL.(*layers.TCP)
		Expect(tcpR.SrcPort).To(Equal(tcp.DstPort))
		Expect(tcpR.DstPort).To(Equal(tcp.SrcPort))

		payloadL := pktR.ApplicationLayer()
		Expect(payloadL).NotTo(BeNil())
		Expect(payload).To(Equal(payloadL.Payload()))

		recvPkt = res.dataOut
	})

	expectMark(tcdefs.MarkSeenBypassForward)

	skbMark = 0

	// Another pkt arriving at node 1 - uses existing CT entries.
	// Change original packet not to be a SYN.
	_, ipv4, tcp, payload, pktBytes, err = testPacketTCPV4DefaultNP(serviceIP, false)
	Expect(err).NotTo(HaveOccurred())
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(retvalToStr[res.Retval]).To(Equal(retvalToStr[resTC_ACT_REDIRECT]))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		ipv4L := pktR.Layer(layers.LayerTypeIPv4)
		Expect(ipv4L).NotTo(BeNil())
		ipv4R := ipv4L.(*layers.IPv4)
		Expect(ipv4R.SrcIP.String()).To(Equal(hostIP.String()))
		Expect(ipv4R.DstIP.String()).To(Equal(node2ip.String()))

		// Should be a VXLAN tunnel packet.
		udpL := pktR.Layer(layers.LayerTypeUDP)
		Expect(udpL).NotTo(BeNil())
		udpR := udpL.(*layers.UDP)

		Expect(udpR.SrcPort).To(BeEquivalentTo(tcp.SrcPort ^ tcp.DstPort))

		checkVxlanEncap(pktR, false, ipv4, tcp, payload)
	})

	skbMark = 0

	hostIP = node2ip

	// change the routing - it is a local workload now!
	err = rtMap.Update(
		routes.NewKey(ip.CIDRFromIPNet(&node2WlCIDR).(ip.V4CIDR)).AsBytes(),
		routes.NewValue(routes.FlagsLocalWorkload|routes.FlagInIPAMPool).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	// we must know that the encaped packet src ip if from a known host
	err = rtMap.Update(
		routes.NewKey(ip.CIDRFromIPNet(&node1CIDR).(ip.V4CIDR)).AsBytes(),
		routes.NewValue(routes.FlagsRemoteHost).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())
	err = rtMap.Update(
		routes.NewKey(ip.CIDRFromIPNet(&node2CIDR).(ip.V4CIDR)).AsBytes(),
		routes.NewValue(routes.FlagsLocalHost).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	dumpRTMap(rtMap)
	dumpCTMap(ctMap)
}

func TestMaglevNATServiceIPTCPV6(t *testing.T) {
	RegisterTestingT(t)

	bpfIfaceName = "MNP-1"
	defer func() { bpfIfaceName = "" }()

	serviceIP := net.ParseIP("c471::c000:8080:8080").To16()
	Expect(serviceIP).NotTo(BeNil())

	_, ipv6, tcp, payload, pktBytes, err := testPacketTCPV6DefaultNP(serviceIP, true)
	Expect(err).NotTo(HaveOccurred())

	err = natMapV6.Update(
		nat.NewNATKeyV6(ipv6.DstIP, uint16(tcp.DstPort), uint8(layers.IPProtocolTCP)).AsBytes(),
		nat.NewNATValueV6WithFlags(0, 1, 0, 0, nat.NATFlgMaglev).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	natIP := net.ParseIP("abcd::ffff:0808:0808")
	natPort := uint16(666)

	mgMap6 := nat.MaglevMapV6()
	err = mgMap6.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	// Build a maglev LUT and program each item to the BPF map.
	mglv := consistenthash.New(maglevTestM, fnv.New32(), fnv.New32())
	mglv.AddBackend(chtypes.MockEndpoint{
		Ip:  natIP.String(),
		Prt: natPort,
	})
	lut := mglv.Generate()
	for ordinal, ep := range lut {
		err = mgMap6.Update(
			nat.NewMaglevBackendKeyV6(ipv6.DstIP, uint16(tcp.DstPort), uint8(layers.IPProtocolTCP), uint32(ordinal)).AsBytes(),
			nat.NewNATBackendValueV6(net.ParseIP(ep.IP()), uint16(ep.Port())).AsBytes(),
		)
		Expect(err).NotTo(HaveOccurred())
	}

	node2wCIDR := net.IPNet{
		IP:   natIP,
		Mask: net.CIDRMask(128, 128),
	}

	resetCTMapV6(ctMapV6) // ensure it is clean

	var encapedPkt []byte

	resetRTMap(rtMapV6)

	hostIP = node1ipV6
	skbMark = 0

	defer resetRTMapV6(rtMapV6)
	Expect(err).NotTo(HaveOccurred())
	err = rtMapV6.Update(
		routes.NewKeyV6(ip.CIDRFromIPNet(&node2wCIDR).(ip.V6CIDR)).AsBytes(),
		routes.NewValueV6WithNextHop(routes.FlagsRemoteWorkload|routes.FlagInIPAMPool,
			ip.FromNetIP(node2ipV6).(ip.V6Addr)).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())
	err = rtMapV6.Update(
		routes.NewKeyV6(ip.CIDRFromIPNet(&node1CIDRV6).(ip.V6CIDR)).AsBytes(),
		routes.NewValueV6(routes.FlagsLocalHost).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())
	err = rtMapV6.Update(
		routes.NewKeyV6(ip.CIDRFromIPNet(&node2CIDRV6).(ip.V6CIDR)).AsBytes(),
		routes.NewValueV6(routes.FlagsRemoteHost).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())
	dumpRTMapV6(rtMapV6)
	rtNode1 := saveRTMapV6(rtMapV6)

	// Arriving at node 1
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Or(
			Equal(resTC_ACT_REDIRECT),
			Equal(resTC_ACT_UNSPEC),
		))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		ipv6L := pktR.Layer(layers.LayerTypeIPv6)
		Expect(ipv6L).NotTo(BeNil())
		ipv6R := ipv6L.(*layers.IPv6)
		Expect(ipv6R.SrcIP.String()).To(Equal(hostIP.String()))
		Expect(ipv6R.DstIP.String()).To(Equal(node2ipV6.String()))

		checkVxlanEncap(pktR, false, ipv6, tcp, payload)

		encapedPkt = res.dataOut

		ct, err := conntrack.LoadMapMemV6(ctMapV6)
		Expect(err).NotTo(HaveOccurred())

		ctKey := conntrack.NewKeyV6(uint8(layers.IPProtocolTCP),
			ipv6.SrcIP, uint16(tcp.SrcPort), ipv6.DstIP, uint16(tcp.DstPort))

		Expect(ct).Should(HaveKey(ctKey))
		ctr := ct[ctKey]
		Expect(ctr.Type()).To(Equal(conntrack.TypeNATForward))

		ctKey = ctr.ReverseNATKey().(conntrack.KeyV6)
		Expect(ct).Should(HaveKey(ctKey))
		ctr = ct[ctKey]
		Expect(ctr.Type()).To(Equal(conntrack.TypeNATReverse))

		// Approved for both sides due to forwarding through the tunnel
		Expect(ctr.Data().A2B.Approved).To(BeTrue())
		Expect(ctr.Data().B2A.Approved).To(BeTrue())
	}, withIPv6())

	dumpCTMapV6(ctMapV6)
	ct, err := conntrack.LoadMapMemV6(ctMapV6)
	Expect(err).NotTo(HaveOccurred())
	v, ok := ct[conntrack.NewKeyV6(uint8(layers.IPProtocolTCP), ipv6.SrcIP, uint16(tcp.SrcPort), natIP, natPort)]
	Expect(ok).To(BeTrue())
	Expect(v.Type()).To(Equal(conntrack.TypeNATReverse))
	Expect(v.Flags()).To(Equal(conntrack4.FlagNATNPFwd | conntrack4.FlagMaglev))

	expectMark(tcdefs.MarkSeenBypassForward)

	// Leaving node 1
	runBpfTest(t, "calico_to_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(encapedPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		Expect(res.dataOut).To(Equal(encapedPkt))
	}, withIPv6())

	dumpCTMapV6(ctMapV6)
	fromHostCT := saveCTMapV6(ctMapV6)

	encapedPktArrivesAtNode2 := make([]byte, len(encapedPkt))
	copy(encapedPktArrivesAtNode2, encapedPkt)

	resetCTMapV6(ctMapV6)

	var recvPkt []byte

	hostIP = node2ipV6

	// change the routing - it is a local workload now!
	err = rtMapV6.Update(
		routes.NewKeyV6(ip.CIDRFromIPNet(&node2wCIDR).(ip.V6CIDR)).AsBytes(),
		routes.NewValueV6(routes.FlagsLocalWorkload|routes.FlagInIPAMPool).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	// we must know that the encaped packet src ip if from a known host
	err = rtMapV6.Update(
		routes.NewKeyV6(ip.CIDRFromIPNet(&node1CIDRV6).(ip.V6CIDR)).AsBytes(),
		routes.NewValueV6(routes.FlagsRemoteHost).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())
	err = rtMapV6.Update(
		routes.NewKeyV6(ip.CIDRFromIPNet(&node2CIDRV6).(ip.V6CIDR)).AsBytes(),
		routes.NewValueV6(routes.FlagsLocalHost).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	dumpRTMapV6(rtMapV6)

	// now we are at the node with local workload
	err = natMapV6.Update(
		nat.NewNATKeyV6(ipv6.DstIP, uint16(tcp.DstPort), uint8(layers.IPProtocolTCP)).AsBytes(),
		nat.NewNATValueV6WithFlags(0 /* id */, 1 /* count */, 1 /* local */, 0, nat.NATFlgMaglev).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	// Arriving at node 2
	bpfIfaceName = "NP-2"

	arpMapN2 := saveARPMapV6(arpMapV6)
	Expect(arpMapN2).To(HaveLen(0))

	skbMark = 0
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(encapedPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(retvalToStr[res.Retval]).To(Equal(retvalToStr[resTC_ACT_REDIRECT]))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)
		payloadL := pktR.ApplicationLayer()
		Expect(payloadL).NotTo(BeNil())
		vxlanL := gopacket.NewPacket(payloadL.Payload(), layers.LayerTypeVXLAN, gopacket.Default)
		Expect(vxlanL).NotTo(BeNil())
		fmt.Printf("vxlanL = %+v\n", vxlanL)

		ipv6L := pktR.Layer(layers.LayerTypeIPv6)
		ipv6R := ipv6L.(*layers.IPv6)
		Expect(ipv6R.SrcIP.String()).To(Equal(ipv6.SrcIP.String()))
		Expect(ipv6R.DstIP.String()).To(Equal(natIP.String()))

		tcpL := pktR.Layer(layers.LayerTypeTCP)
		Expect(tcpL).NotTo(BeNil())
		tcpR := tcpL.(*layers.TCP)
		Expect(tcpR.SrcPort).To(Equal(layers.TCPPort(tcp.SrcPort)))
		Expect(tcpR.DstPort).To(Equal(layers.TCPPort(natPort)))

		ct, err := conntrack.LoadMapMemV6(ctMapV6)
		Expect(err).NotTo(HaveOccurred())

		ctKey := conntrack.NewKeyV6(uint8(layers.IPProtocolTCP),
			ipv6.SrcIP, uint16(tcp.SrcPort), ipv6.DstIP, uint16(tcp.DstPort))

		Expect(ct).Should(HaveKey(ctKey))
		ctr := ct[ctKey]
		Expect(ctr.Type()).To(Equal(conntrack.TypeNATForward))
		Expect(ctr.NATSPort()).To(Equal(uint16(0)))

		ctKey = ctr.ReverseNATKey().(conntrack.KeyV6)
		Expect(ct).Should(HaveKey(ctKey))
		ctr = ct[ctKey]
		Expect(ctr.Type()).To(Equal(conntrack.TypeNATReverse))

		// Approved source side
		Expect(ctr.Data().A2B.Approved).To(BeTrue())
		// Dest not approved yet
		Expect(ctr.Data().B2A.Approved).NotTo(BeTrue())

		recvPkt = res.dataOut
	}, withIPv6())

	expectMark(tcdefs.MarkSeen)

	dumpCTMapV6(ctMapV6)
	ct, err = conntrack.LoadMapMemV6(ctMapV6)
	Expect(err).NotTo(HaveOccurred())
	v, ok = ct[conntrack.NewKeyV6(uint8(layers.IPProtocolTCP), ipv6.SrcIP, uint16(tcp.SrcPort), natIP, natPort)]
	Expect(ok).To(BeTrue())
	Expect(v.Type()).To(Equal(conntrack.TypeNATReverse))
	Expect(v.Flags()).To(Equal(conntrack4.FlagExtLocal | conntrack4.FlagMaglev))

	dumpARPMapV6(arpMapV6)

	arpMapN2 = saveARPMapV6(arpMapV6)
	Expect(arpMapN2).To(HaveLen(1))
	arpKey := arp.NewKeyV6(node1ipV6, 1) // ifindex is always 1 in UT
	Expect(arpMapN2).To(HaveKey(arpKey))
	macDst := encapedPkt[0:6]
	macSrc := encapedPkt[6:12]
	Expect(arpMapN2[arpKey]).To(Equal(arp.NewValue(macDst, macSrc)))

	// try a spoofed tunnel packet, should be dropped and have no effect
	skbMark = 0
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		// modify the only known good src IP, we do not care about csums at this point
		encapedPkt[26] = 234
		res, err := bpfrun(encapedPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_SHOT))
	}, withIPv6())

	skbMark = tcdefs.MarkSeen

	// Insert the reverse route for backend for RPF check.
	resetRTMap(rtMapV6)
	beV4CIDR := ip.CIDRFromNetIP(natIP).(ip.V6CIDR)
	bertKey := routes.NewKeyV6(beV4CIDR).AsBytes()
	bertVal := routes.NewValueV6WithIfIndex(routes.FlagsLocalWorkload|routes.FlagInIPAMPool, 1).AsBytes()
	err = rtMapV6.Update(bertKey, bertVal)
	Expect(err).NotTo(HaveOccurred())

	// Arriving at workload at node 2
	runBpfTest(t, "calico_to_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(recvPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		Expect(res.dataOut).To(Equal(recvPkt))

		ct, err := conntrack.LoadMapMemV6(ctMapV6)
		Expect(err).NotTo(HaveOccurred())

		ctKey := conntrack.NewKeyV6(uint8(layers.IPProtocolTCP),
			ipv6.SrcIP, uint16(tcp.SrcPort), ipv6.DstIP, uint16(tcp.DstPort))

		Expect(ct).Should(HaveKey(ctKey))
		ctr := ct[ctKey]
		Expect(ctr.Type()).To(Equal(conntrack.TypeNATForward))

		ctKey = ctr.ReverseNATKey().(conntrack.KeyV6)
		Expect(ct).Should(HaveKey(ctKey))
		ctr = ct[ctKey]
		Expect(ctr.Type()).To(Equal(conntrack.TypeNATReverse),
			fmt.Sprintf("Expected reverse conntrack entry but got %v", ctr))

		// Approved source side
		Expect(ctr.Data().A2B.Approved).To(BeTrue())
		// Approved destination side as well
		Expect(ctr.Data().B2A.Approved).To(BeTrue())
	}, withIPv6())

	skbMark = 0

	// Response leaving workload at node 2
	runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		// SYN,ACK
		respPkt := tcpResponseRawV6(recvPkt)
		// Change the MAC addresses so that we can observe that the right
		// addresses were patched in.
		copy(respPkt[:6], []byte{1, 2, 3, 4, 5, 6})
		copy(respPkt[6:12], []byte{6, 5, 4, 3, 2, 1})
		res, err := bpfrun(respPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Or(
			Equal(resTC_ACT_REDIRECT),
			Equal(resTC_ACT_UNSPEC),
		))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		ethL := pktR.Layer(layers.LayerTypeEthernet)
		Expect(ethL).NotTo(BeNil())
		ethR := ethL.(*layers.Ethernet)
		Expect(ethR).To(layersMatchFields(&layers.Ethernet{
			SrcMAC:       macDst,
			DstMAC:       macSrc,
			EthernetType: layers.EthernetTypeIPv6,
		}))

		ipv6L := pktR.Layer(layers.LayerTypeIPv6)
		Expect(ipv6L).NotTo(BeNil())
		ipv6R := ipv6L.(*layers.IPv6)
		Expect(ipv6R.SrcIP.String()).To(Equal(hostIP.String()))
		Expect(ipv6R.DstIP.String()).To(Equal(node1ipV6.String()))

		checkVxlan(pktR)

		encapedPkt = res.dataOut
	}, withIPv6())

	dumpCTMapV6(ctMapV6)

	expectMark(tcdefs.MarkSeen)

	hostIP = node2ipV6

	// Response leaving node 2
	runBpfTest(t, "calico_to_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(encapedPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		ipv6L := pktR.Layer(layers.LayerTypeIPv6)
		Expect(ipv6L).NotTo(BeNil())
		ipv6R := ipv6L.(*layers.IPv6)
		// check that the IP is fixed up
		Expect(ipv6R.SrcIP.String()).To(Equal(node2ipV6.String()))
		Expect(ipv6R.DstIP.String()).To(Equal(node1ipV6.String()))

		checkVxlan(pktR)

		encapedPkt = res.dataOut
	}, withIPv6())

	dumpCTMapV6(ctMapV6)
	resetCTMapV6(ctMapV6)
	restoreCTMapV6(ctMapV6, fromHostCT)
	dumpCTMapV6(ctMapV6)

	hostIP = node1ipV6

	// change to routing again to a remote workload
	resetRTMap(rtMapV6)
	restoreRTMapV6(rtMapV6, rtNode1)
	dumpRTMapV6(rtMapV6)

	// Response arriving at node 1
	bpfIfaceName = "NP-1"
	skbMark = 0

	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(encapedPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(retvalToStr[res.Retval]).To(Equal(retvalToStr[resTC_ACT_REDIRECT]))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		ipv6L := pktR.Layer(layers.LayerTypeIPv6)
		Expect(ipv6L).NotTo(BeNil())
		ipv6R := ipv6L.(*layers.IPv6)
		Expect(ipv6R.DstIP.String()).To(Equal(ipv6.SrcIP.String()))
		Expect(ipv6R.SrcIP.String()).To(Equal(ipv6.DstIP.String()))

		tcpL := pktR.Layer(layers.LayerTypeTCP)
		Expect(tcpL).NotTo(BeNil())
		tcpR := tcpL.(*layers.TCP)
		Expect(tcpR.SrcPort).To(Equal(tcp.DstPort))
		Expect(tcpR.DstPort).To(Equal(tcp.SrcPort))

		payloadL := pktR.ApplicationLayer()
		Expect(payloadL).NotTo(BeNil())
		Expect(payload).To(Equal(payloadL.Payload()))

		recvPkt = res.dataOut
	}, withIPv6())

	expectMark(tcdefs.MarkSeenBypassForward)
	saveMark := skbMark

	dumpCTMapV6(ctMapV6)

	skbMark = 0
	// try a spoofed tunnel packet returning back, should be dropped and have no effect
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		// modify the only known good src IP, we do not care about csums at this point
		encapedPkt[26] = 235
		res, err := bpfrun(encapedPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(retvalToStr[res.Retval]).To(Equal(retvalToStr[resTC_ACT_SHOT]))
	}, withIPv6())

	skbMark = saveMark
	// Response leaving to original source
	runBpfTest(t, "calico_to_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(recvPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(retvalToStr[res.Retval]).To(Equal(retvalToStr[resTC_ACT_UNSPEC]))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		ct, err := conntrack.LoadMapMemV6(ctMapV6)
		Expect(err).NotTo(HaveOccurred())

		ctKey := conntrack.NewKeyV6(uint8(layers.IPProtocolTCP),
			ipv6.SrcIP, uint16(tcp.SrcPort), ipv6.DstIP, uint16(tcp.DstPort))

		Expect(ct).Should(HaveKey(ctKey))
		ctr := ct[ctKey]
		Expect(ctr.Type()).To(Equal(conntrack.TypeNATForward))

		ctKey = ctr.ReverseNATKey().(conntrack.KeyV6)
		Expect(ct).Should(HaveKey(ctKey))
		ctr = ct[ctKey]
		Expect(ctr.Type()).To(Equal(conntrack.TypeNATReverse))

		// Approved for both sides due to forwarding through the tunnel
		Expect(ctr.Data().A2B.Approved).To(BeTrue())
		Expect(ctr.Data().B2A.Approved).To(BeTrue())
	}, withIPv6())

	dumpCTMapV6(ctMapV6)

	skbMark = 0
	// Another pkt arriving at node 1 - uses existing CT entries
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(retvalToStr[res.Retval]).To(Or(
			Equal(retvalToStr[resTC_ACT_REDIRECT]),
			Equal(retvalToStr[resTC_ACT_UNSPEC]),
		))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		ipv6L := pktR.Layer(layers.LayerTypeIPv6)
		Expect(ipv6L).NotTo(BeNil())
		ipv6R := ipv6L.(*layers.IPv6)
		Expect(ipv6R.SrcIP.String()).To(Equal(hostIP.String()))
		Expect(ipv6R.DstIP.String()).To(Equal(node2ipV6.String()))

		checkVxlanEncap(pktR, false, ipv6, tcp, payload)
	}, withIPv6())

	expectMark(tcdefs.MarkSeenBypassForward)

	_, ipv6, tcp, payload, pktBytes, err = testPacketTCPV6DefaultNP(serviceIP, true)
	Expect(err).NotTo(HaveOccurred())

	err = natMapV6.Update(
		nat.NewNATKeyV6(ipv6.DstIP, uint16(tcp.DstPort), uint8(layers.IPProtocolTCP)).AsBytes(),
		nat.NewNATValueV6WithFlags(0, 1, 0, 0, nat.NATFlgMaglev).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	mgMap6 = nat.MaglevMapV6()
	err = mgMap6.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	// Build a maglev LUT and program each item to the BPF map.
	mglv = consistenthash.New(maglevTestM, fnv.New32(), fnv.New32())
	mglv.AddBackend(chtypes.MockEndpoint{
		Ip:  natIP.String(),
		Prt: natPort,
	})
	lut = mglv.Generate()
	for ordinal, ep := range lut {
		err = mgMap6.Update(
			nat.NewMaglevBackendKeyV6(ipv6.DstIP, uint16(tcp.DstPort), uint8(layers.IPProtocolTCP), uint32(ordinal)).AsBytes(),
			nat.NewNATBackendValueV6(net.ParseIP(ep.IP()), uint16(ep.Port())).AsBytes(),
		)
		Expect(err).NotTo(HaveOccurred())
	}

	resetCTMapV6(ctMapV6) // ensure it is clean
	resetRTMap(rtMapV6)
	encapedPkt = nil

	hostIP = node3ipV6
	skbMark = 0

	// Arriving at node 3 - non-routable -> denied
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_SHOT))
	}, withIPv6())

	defer resetRTMapV6(rtMapV6)
	Expect(err).NotTo(HaveOccurred())
	err = rtMapV6.Update(
		routes.NewKeyV6(ip.CIDRFromIPNet(&node2wCIDR).(ip.V6CIDR)).AsBytes(),
		routes.NewValueV6WithNextHop(routes.FlagsRemoteWorkload|routes.FlagInIPAMPool,
			ip.FromNetIP(node2ipV6).(ip.V6Addr)).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())
	err = rtMapV6.Update(
		routes.NewKeyV6(ip.CIDRFromIPNet(&node2CIDRV6).(ip.V6CIDR)).AsBytes(),
		routes.NewValueV6(routes.FlagsRemoteHost).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())
	err = rtMapV6.Update(
		routes.NewKeyV6(ip.CIDRFromIPNet(&node3CIDRV6).(ip.V6CIDR)).AsBytes(),
		routes.NewValueV6(routes.FlagsLocalHost).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	dumpRTMapV6(rtMapV6)
	rtNode3 := saveRTMapV6(rtMapV6)

	// Arriving at node 3
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Or(
			Equal(resTC_ACT_REDIRECT),
			Equal(resTC_ACT_UNSPEC),
		))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		ipv6L := pktR.Layer(layers.LayerTypeIPv6)
		Expect(ipv6L).NotTo(BeNil())
		ipv6R := ipv6L.(*layers.IPv6)
		Expect(ipv6R.SrcIP.String()).To(Equal(hostIP.String()))
		Expect(ipv6R.DstIP.String()).To(Equal(node2ipV6.String()))

		checkVxlanEncap(pktR, false, ipv6, tcp, payload)

		encapedPkt = res.dataOut

		ct, err := conntrack.LoadMapMemV6(ctMapV6)
		Expect(err).NotTo(HaveOccurred())

		ctKey := conntrack.NewKeyV6(uint8(layers.IPProtocolTCP),
			ipv6.SrcIP, uint16(tcp.SrcPort), ipv6.DstIP, uint16(tcp.DstPort))

		Expect(ct).Should(HaveKey(ctKey))
		ctr := ct[ctKey]
		Expect(ctr.Type()).To(Equal(conntrack.TypeNATForward))

		ctKey = ctr.ReverseNATKey().(conntrack.KeyV6)
		Expect(ct).Should(HaveKey(ctKey))
		ctr = ct[ctKey]
		Expect(ctr.Type()).To(Equal(conntrack.TypeNATReverse))

		// Approved for both sides due to forwarding through the tunnel
		Expect(ctr.Data().A2B.Approved).To(BeTrue())
		Expect(ctr.Data().B2A.Approved).To(BeTrue())
	}, withIPv6())

	dumpCTMapV6(ctMapV6)
	ct, err = conntrack.LoadMapMemV6(ctMapV6)
	Expect(err).NotTo(HaveOccurred())
	v, ok = ct[conntrack.NewKeyV6(uint8(layers.IPProtocolTCP), ipv6.SrcIP, uint16(tcp.SrcPort), natIP, natPort)]
	Expect(ok).To(BeTrue())
	Expect(v.Type()).To(Equal(conntrack.TypeNATReverse))
	Expect(v.Flags()).To(Equal(conntrack4.FlagNATNPFwd | conntrack4.FlagMaglev))

	expectMark(tcdefs.MarkSeenBypassForward)

	// Leaving node 1
	runBpfTest(t, "calico_to_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(encapedPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		Expect(res.dataOut).To(Equal(encapedPkt))
	}, withIPv6())

	dumpCTMapV6(ctMapV6)
	fromHostCT = saveCTMapV6(ctMapV6)

	encapedPktArrivesAtNode2 = make([]byte, len(encapedPkt))
	copy(encapedPktArrivesAtNode2, encapedPkt)

	resetCTMapV6(ctMapV6)

	recvPkt = nil
	hostIP = node2ipV6

	// change the routing - it is a local workload now!
	err = rtMapV6.Update(
		routes.NewKeyV6(ip.CIDRFromIPNet(&node2wCIDR).(ip.V6CIDR)).AsBytes(),
		routes.NewValueV6(routes.FlagsLocalWorkload|routes.FlagInIPAMPool).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	// we must know that the encaped packet src ip if from a known host
	err = rtMapV6.Update(
		routes.NewKeyV6(ip.CIDRFromIPNet(&node3CIDRV6).(ip.V6CIDR)).AsBytes(),
		routes.NewValueV6(routes.FlagsRemoteHost).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())
	err = rtMapV6.Update(
		routes.NewKeyV6(ip.CIDRFromIPNet(&node2CIDRV6).(ip.V6CIDR)).AsBytes(),
		routes.NewValueV6(routes.FlagsLocalHost).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	dumpRTMapV6(rtMapV6)

	// now we are at the node with local workload
	err = natMapV6.Update(
		nat.NewNATKeyV6(ipv6.DstIP, uint16(tcp.DstPort), uint8(layers.IPProtocolTCP)).AsBytes(),
		nat.NewNATValueV6WithFlags(0 /* id */, 1 /* count */, 1 /* local */, 0, nat.NATFlgMaglev).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	// Arriving at node 2
	bpfIfaceName = "NP-2"

	resetMap(arpMapV6)
	restoreARPMapV6(arpMapV6, arpMapN2)
	Expect(arpMapN2).To(HaveLen(1))

	skbMark = 0
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(encapedPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_REDIRECT))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)
		payloadL := pktR.ApplicationLayer()
		Expect(payloadL).NotTo(BeNil())
		vxlanL := gopacket.NewPacket(payloadL.Payload(), layers.LayerTypeVXLAN, gopacket.Default)
		Expect(vxlanL).NotTo(BeNil())
		fmt.Printf("vxlanL = %+v\n", vxlanL)

		ipv6L := pktR.Layer(layers.LayerTypeIPv6)
		ipv6R := ipv6L.(*layers.IPv6)
		Expect(ipv6R.SrcIP.String()).To(Equal(ipv6.SrcIP.String()))
		Expect(ipv6R.DstIP.String()).To(Equal(natIP.String()))

		tcpL := pktR.Layer(layers.LayerTypeTCP)
		Expect(tcpL).NotTo(BeNil())
		tcpR := tcpL.(*layers.TCP)
		Expect(tcpR.SrcPort).To(Equal(layers.TCPPort(tcp.SrcPort)))
		Expect(tcpR.DstPort).To(Equal(layers.TCPPort(natPort)))

		ct, err := conntrack.LoadMapMemV6(ctMapV6)
		Expect(err).NotTo(HaveOccurred())

		ctKey := conntrack.NewKeyV6(uint8(layers.IPProtocolTCP),
			ipv6.SrcIP, uint16(tcp.SrcPort), ipv6.DstIP, uint16(tcp.DstPort))

		Expect(ct).Should(HaveKey(ctKey))
		ctr := ct[ctKey]
		Expect(ctr.Type()).To(Equal(conntrack.TypeNATForward))
		Expect(ctr.NATSPort()).To(Equal(uint16(0)))

		ctKey = ctr.ReverseNATKey().(conntrack.KeyV6)
		Expect(ct).Should(HaveKey(ctKey))
		ctr = ct[ctKey]
		Expect(ctr.Type()).To(Equal(conntrack.TypeNATReverse))

		// Approved source side
		Expect(ctr.Data().A2B.Approved).To(BeTrue())
		// Dest not approved yet
		Expect(ctr.Data().B2A.Approved).NotTo(BeTrue())

		recvPkt = res.dataOut
	}, withIPv6())

	expectMark(tcdefs.MarkSeen)

	dumpCTMapV6(ctMapV6)
	ct, err = conntrack.LoadMapMemV6(ctMapV6)
	Expect(err).NotTo(HaveOccurred())
	v, ok = ct[conntrack.NewKeyV6(uint8(layers.IPProtocolTCP), ipv6.SrcIP, uint16(tcp.SrcPort), natIP, natPort)]
	Expect(ok).To(BeTrue())
	Expect(v.Type()).To(Equal(conntrack.TypeNATReverse))
	Expect(v.Flags()).To(Equal(conntrack4.FlagExtLocal | conntrack4.FlagMaglev))

	dumpARPMapV6(arpMapV6)

	arpMapN2 = saveARPMapV6(arpMapV6)
	Expect(arpMapN2).To(HaveLen(2))
	arpKey = arp.NewKeyV6(node3ipV6, 1) // ifindex is always 1 in UT
	Expect(arpMapN2).To(HaveKey(arpKey))
	macDst = encapedPkt[0:6]
	macSrc = encapedPkt[6:12]
	Expect(arpMapN2[arpKey]).To(Equal(arp.NewValue(macDst, macSrc)))

	// try a spoofed tunnel packet, should be dropped and have no effect
	skbMark = 0
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		// modify the only known good src IP, we do not care about csums at this point
		encapedPkt[26] = 234
		res, err := bpfrun(encapedPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_SHOT))
	}, withIPv6())

	skbMark = tcdefs.MarkSeen

	// Insert the reverse route for backend for RPF check.
	resetRTMap(rtMapV6)
	beV4CIDR = ip.CIDRFromNetIP(natIP).(ip.V6CIDR)
	bertKey = routes.NewKeyV6(beV4CIDR).AsBytes()
	bertVal = routes.NewValueV6WithIfIndex(routes.FlagsLocalWorkload|routes.FlagInIPAMPool, 1).AsBytes()
	err = rtMapV6.Update(bertKey, bertVal)
	Expect(err).NotTo(HaveOccurred())

	// Arriving at workload at node 2
	runBpfTest(t, "calico_to_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(recvPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		Expect(res.dataOut).To(Equal(recvPkt))

		ct, err := conntrack.LoadMapMemV6(ctMapV6)
		Expect(err).NotTo(HaveOccurred())

		ctKey := conntrack.NewKeyV6(uint8(layers.IPProtocolTCP),
			ipv6.SrcIP, uint16(tcp.SrcPort), ipv6.DstIP, uint16(tcp.DstPort))

		Expect(ct).Should(HaveKey(ctKey))
		ctr := ct[ctKey]
		Expect(ctr.Type()).To(Equal(conntrack.TypeNATForward))

		ctKey = ctr.ReverseNATKey().(conntrack.KeyV6)
		Expect(ct).Should(HaveKey(ctKey))
		ctr = ct[ctKey]
		Expect(ctr.Type()).To(Equal(conntrack.TypeNATReverse),
			fmt.Sprintf("Expected reverse conntrack entry but got %v", ctr))

		// Approved source side
		Expect(ctr.Data().A2B.Approved).To(BeTrue())
		// Approved destination side as well
		Expect(ctr.Data().B2A.Approved).To(BeTrue())
	}, withIPv6())

	skbMark = 0

	// Response leaving workload at node 2
	runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		// SYN,ACK
		respPkt := tcpResponseRawV6(recvPkt)
		// Change the MAC addresses so that we can observe that the right
		// addresses were patched in.
		copy(respPkt[:6], []byte{1, 2, 3, 4, 5, 6})
		copy(respPkt[6:12], []byte{6, 5, 4, 3, 2, 1})
		res, err := bpfrun(respPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Or(
			Equal(resTC_ACT_REDIRECT),
			Equal(resTC_ACT_UNSPEC),
		))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		ethL := pktR.Layer(layers.LayerTypeEthernet)
		Expect(ethL).NotTo(BeNil())
		ethR := ethL.(*layers.Ethernet)
		Expect(ethR).To(layersMatchFields(&layers.Ethernet{
			SrcMAC:       macDst,
			DstMAC:       macSrc,
			EthernetType: layers.EthernetTypeIPv6,
		}))

		ipv6L := pktR.Layer(layers.LayerTypeIPv6)
		Expect(ipv6L).NotTo(BeNil())
		ipv6R := ipv6L.(*layers.IPv6)
		Expect(ipv6R.SrcIP.String()).To(Equal(hostIP.String()))
		Expect(ipv6R.DstIP.String()).To(Equal(node3ipV6.String()))

		checkVxlan(pktR)

		encapedPkt = res.dataOut
	}, withIPv6())

	dumpCTMapV6(ctMapV6)

	expectMark(tcdefs.MarkSeen)

	// Response leaving node 2
	runBpfTest(t, "calico_to_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(encapedPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		ipv6L := pktR.Layer(layers.LayerTypeIPv6)
		Expect(ipv6L).NotTo(BeNil())
		ipv6R := ipv6L.(*layers.IPv6)
		// check that the IP is fixed up
		Expect(ipv6R.SrcIP.String()).To(Equal(node2ipV6.String()))
		Expect(ipv6R.DstIP.String()).To(Equal(node3ipV6.String()))

		checkVxlan(pktR)

		encapedPkt = res.dataOut
	}, withIPv6())

	dumpCTMapV6(ctMapV6)
	resetCTMapV6(ctMapV6)
	restoreCTMapV6(ctMapV6, fromHostCT)
	dumpCTMapV6(ctMapV6)

	hostIP = node3ipV6

	// change to routing again to a remote workload
	resetRTMap(rtMapV6)
	restoreRTMapV6(rtMapV6, rtNode3)
	dumpRTMapV6(rtMapV6)

	// Response arriving at node 1
	bpfIfaceName = "NP-1"
	skbMark = 0

	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(encapedPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(retvalToStr[res.Retval]).To(Equal(retvalToStr[resTC_ACT_REDIRECT]))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		ipv6L := pktR.Layer(layers.LayerTypeIPv6)
		Expect(ipv6L).NotTo(BeNil())
		ipv6R := ipv6L.(*layers.IPv6)
		Expect(ipv6R.DstIP.String()).To(Equal(ipv6.SrcIP.String()))
		Expect(ipv6R.SrcIP.String()).To(Equal(ipv6.DstIP.String()))

		tcpL := pktR.Layer(layers.LayerTypeTCP)
		Expect(tcpL).NotTo(BeNil())
		tcpR := tcpL.(*layers.TCP)
		Expect(tcpR.SrcPort).To(Equal(tcp.DstPort))
		Expect(tcpR.DstPort).To(Equal(tcp.SrcPort))

		payloadL := pktR.ApplicationLayer()
		Expect(payloadL).NotTo(BeNil())
		Expect(payload).To(Equal(payloadL.Payload()))

		recvPkt = res.dataOut
	}, withIPv6())

	expectMark(tcdefs.MarkSeenBypassForward)
	saveMark = skbMark

	dumpCTMapV6(ctMapV6)

	skbMark = 0
	// try a spoofed tunnel packet returning back, should be dropped and have no effect
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		// modify the only known good src IP, we do not care about csums at this point
		encapedPkt[26] = 235
		res, err := bpfrun(encapedPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(retvalToStr[res.Retval]).To(Equal(retvalToStr[resTC_ACT_SHOT]))
	}, withIPv6())

	skbMark = saveMark
	// Response leaving to original source
	runBpfTest(t, "calico_to_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(recvPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(retvalToStr[res.Retval]).To(Equal(retvalToStr[resTC_ACT_UNSPEC]))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		ct, err := conntrack.LoadMapMemV6(ctMapV6)
		Expect(err).NotTo(HaveOccurred())

		ctKey := conntrack.NewKeyV6(uint8(layers.IPProtocolTCP),
			ipv6.SrcIP, uint16(tcp.SrcPort), ipv6.DstIP, uint16(tcp.DstPort))

		Expect(ct).Should(HaveKey(ctKey))
		ctr := ct[ctKey]
		Expect(ctr.Type()).To(Equal(conntrack.TypeNATForward))

		ctKey = ctr.ReverseNATKey().(conntrack.KeyV6)
		Expect(ct).Should(HaveKey(ctKey))
		ctr = ct[ctKey]
		Expect(ctr.Type()).To(Equal(conntrack.TypeNATReverse))

		// Approved for both sides due to forwarding through the tunnel
		Expect(ctr.Data().A2B.Approved).To(BeTrue())
		Expect(ctr.Data().B2A.Approved).To(BeTrue())
	}, withIPv6())

	dumpCTMapV6(ctMapV6)

	skbMark = 0
	// Another pkt arriving at node 1 - uses existing CT entries
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(retvalToStr[res.Retval]).To(Or(
			Equal(retvalToStr[resTC_ACT_REDIRECT]),
			Equal(retvalToStr[resTC_ACT_UNSPEC]),
		))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		ipv6L := pktR.Layer(layers.LayerTypeIPv6)
		Expect(ipv6L).NotTo(BeNil())
		ipv6R := ipv6L.(*layers.IPv6)
		Expect(ipv6R.SrcIP.String()).To(Equal(hostIP.String()))
		Expect(ipv6R.DstIP.String()).To(Equal(node2ipV6.String()))

		checkVxlanEncap(pktR, false, ipv6, tcp, payload)
	}, withIPv6())

	expectMark(tcdefs.MarkSeenBypassForward)
}

func TestMaglevNATNodePortNoFWD(t *testing.T) {
	RegisterTestingT(t)

	defer resetCTMap(ctMap)

	bpfIfaceName = "MNPlo"
	defer func() { bpfIfaceName = "" }()

	_, ipv4, l4, payload, pktBytes, err := testPacketUDPDefaultNP(node1ip)
	Expect(err).NotTo(HaveOccurred())
	udp := l4.(*layers.UDP)
	natMap := nat.FrontendMap()
	err = natMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	mgMap := nat.MaglevMap()
	err = mgMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	// local workload
	err = natMap.Update(
		nat.NewNATKey(ipv4.DstIP, uint16(udp.DstPort), uint8(ipv4.Protocol)).AsBytes(),
		nat.NewNATValueWithFlags(0 /* count */, 1 /* local */, 1, 0, nat.NATFlgMaglev).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	natIP := net.IPv4(8, 8, 8, 8)
	natPort := uint16(666)

	// Build a maglev LUT and program each item to the BPF map.
	mglv := consistenthash.New(maglevTestM, fnv.New32(), fnv.New32())
	mglv.AddBackend(chtypes.MockEndpoint{
		Ip:  natIP.String(),
		Prt: natPort,
	})
	lut := mglv.Generate()
	for ordinal, ep := range lut {
		err = mgMap.Update(
			nat.NewMaglevBackendKey(ipv4.DstIP, uint16(udp.DstPort), uint8(ipv4.Protocol), uint32(ordinal)).AsBytes(),
			nat.NewNATBackendValue(net.ParseIP(ep.IP()), uint16(ep.Port())).AsBytes(),
		)
		Expect(err).NotTo(HaveOccurred())
	}

	ctMap := conntrack.Map()
	err = ctMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())
	resetCTMap(ctMap) // ensure it is clean

	var recvPkt []byte

	hostIP = node1ip
	skbMark = 0

	// Setup routing
	rtMap := routes.Map()
	err = rtMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())
	defer resetRTMap(rtMap)
	// backend it is a local workload
	resetRTMap(rtMap)
	beV4CIDR := ip.CIDRFromNetIP(natIP).(ip.V4CIDR)
	bertKey := routes.NewKey(beV4CIDR).AsBytes()
	bertVal := routes.NewValueWithIfIndex(routes.FlagsLocalWorkload|routes.FlagInIPAMPool, 1).AsBytes()
	err = rtMap.Update(bertKey, bertVal)
	Expect(err).NotTo(HaveOccurred())
	dumpRTMap(rtMap)

	// Arriving at node
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_REDIRECT))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		ipv4L := pktR.Layer(layers.LayerTypeIPv4)
		ipv4R := ipv4L.(*layers.IPv4)
		Expect(ipv4R.SrcIP.String()).To(Equal(ipv4.SrcIP.String()))
		Expect(ipv4R.DstIP.String()).To(Equal(natIP.String()))

		udpL := pktR.Layer(layers.LayerTypeUDP)
		Expect(udpL).NotTo(BeNil())
		udpR := udpL.(*layers.UDP)
		Expect(udpR.SrcPort).To(Equal(layers.UDPPort(udp.SrcPort)))
		Expect(udpR.DstPort).To(Equal(layers.UDPPort(natPort)))

		recvPkt = res.dataOut
	})

	dumpCTMap(ctMap)

	hostIP = net.IPv4(0, 0, 0, 0) // workloads do not have it set

	expectMark(tcdefs.MarkSeen)

	ct, err := conntrack.LoadMapMem(ctMap)
	Expect(err).NotTo(HaveOccurred())
	v, ok := ct[conntrack.NewKey(uint8(ipv4.Protocol), ipv4.SrcIP, uint16(udp.SrcPort), natIP.To4(), natPort)]
	Expect(ok).To(BeTrue())
	Expect(v.Type()).To(Equal(conntrack.TypeNATReverse))
	Expect(v.Flags()).To(Equal(conntrack4.FlagExtLocal | conntrack4.FlagMaglev))

	// Arriving at workload
	runBpfTest(t, "calico_to_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(recvPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		Expect(res.dataOut).To(Equal(recvPkt))
	})

	skbMark = 0
	var respPkt []byte

	// Response leaving workload
	runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		respPkt = udpResponseRaw(recvPkt)
		res, err := bpfrun(respPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_REDIRECT))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		Expect(res.dataOut).To(Equal(respPkt))
	})

	expectMark(tcdefs.MarkSeen)

	// Response leaving to original source
	runBpfTest(t, "calico_to_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(respPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		ipv4L := pktR.Layer(layers.LayerTypeIPv4)
		Expect(ipv4L).NotTo(BeNil())
		ipv4R := ipv4L.(*layers.IPv4)
		Expect(ipv4R.DstIP.String()).To(Equal(ipv4.SrcIP.String()))
		Expect(ipv4R.SrcIP.String()).To(Equal(ipv4.DstIP.String()))

		udpL := pktR.Layer(layers.LayerTypeUDP)
		Expect(udpL).NotTo(BeNil())
		udpR := udpL.(*layers.UDP)
		Expect(udpR.SrcPort).To(Equal(udp.DstPort))
		Expect(udpR.DstPort).To(Equal(udp.SrcPort))

		payloadL := pktR.ApplicationLayer()
		Expect(payloadL).NotTo(BeNil())
		Expect(payload).To(Equal(payloadL.Payload()))

	})

	dumpCTMap(ctMap)
}

// TestNormalSYNRetryForcePolicy does the same test for forcing policy
// as TestNATSYNRetryGoesToSameBackend but without NAT.
func TestMaglevNormalSYNRetryForcePolicy(t *testing.T) {
	RegisterTestingT(t)

	defer func() { bpfIfaceName = "" }()
	bpfIfaceName = "MSYN1"

	tcpSyn := &layers.TCP{
		SrcPort:    54321,
		DstPort:    7890,
		SYN:        true,
		DataOffset: 5,
	}

	_, ipv4, _, _, synPkt, err := testPacketV4(nil, nil, tcpSyn, nil)
	Expect(err).NotTo(HaveOccurred())

	// Insert a reverse route for the source workload.
	rtKey := routes.NewKey(srcV4CIDR).AsBytes()
	rtVal := routes.NewValueWithIfIndex(routes.FlagsLocalWorkload|routes.FlagInIPAMPool, 1).AsBytes()
	defer resetRTMap(rtMap)
	err = rtMap.Update(rtKey, rtVal)
	Expect(err).NotTo(HaveOccurred())

	skbMark = 0
	runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(synPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_REDIRECT))
		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)
	})

	expectMark(tcdefs.MarkSeen)

	bpfIfaceName = "SYN2"
	explicitAllow := &polprog.Rules{
		Tiers: []polprog.Tier{{
			Name: "base tier",
			Policies: []polprog.Policy{{
				Name: "expAllow",
				Rules: []polprog.Rule{{
					Rule: &proto.Rule{
						Action:   "Allow",
						DstPorts: []*proto.PortRange{{First: 7890, Last: 7890}},
						DstNet:   []string{ipv4.DstIP.String()},
					}}},
			}},
		}},
	}

	skbMark = 0
	// Make sure that policy still allows the retry (is enforce correctly)
	runBpfTest(t, "calico_from_workload_ep", explicitAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(synPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_REDIRECT))
		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)
	})
	expectMark(tcdefs.MarkSeen)

	bpfIfaceName = "SYN3"
	changedToDeny := &polprog.Rules{
		Tiers: []polprog.Tier{{
			Name: "base tier",
			Policies: []polprog.Policy{{
				Name: "allow->deny",
				Rules: []polprog.Rule{{
					Rule: &proto.Rule{
						Action:      "Allow",
						NotDstPorts: []*proto.PortRange{{First: 7890, Last: 7890}},
						NotDstNet:   []string{ipv4.DstIP.String()},
					}}},
			}},
		}},
	}

	skbMark = 0
	// Make sure that when the policy changes, it is applied correctly to the next SYN
	runBpfTest(t, "calico_from_workload_ep", changedToDeny, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(synPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_SHOT))
		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)
	})
}

func withLogLevelWarnDo(f func()) {
	// Disable debug while filling up maps.
	loglevel := logrus.GetLevel()
	logrus.SetLevel(logrus.WarnLevel)
	defer logrus.SetLevel(loglevel)
	f()
}
