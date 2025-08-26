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
	. "github.com/onsi/gomega"

	"github.com/sirupsen/logrus"

	"fmt"
	"hash/fnv"
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	. "github.com/onsi/ginkgo"

	"github.com/projectcalico/calico/felix/bpf/arp"
	"github.com/projectcalico/calico/felix/bpf/conntrack"
	conntrack3 "github.com/projectcalico/calico/felix/bpf/conntrack/v3"
	"github.com/projectcalico/calico/felix/bpf/consistenthash"
	chtypes "github.com/projectcalico/calico/felix/bpf/consistenthash/test"
	"github.com/projectcalico/calico/felix/bpf/nat"
	"github.com/projectcalico/calico/felix/bpf/polprog"
	"github.com/projectcalico/calico/felix/bpf/routes"
	tcdefs "github.com/projectcalico/calico/felix/bpf/tc/defs"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/proto"
)

func TestConsistentHashTable(t *testing.T) {
	RegisterTestingT(t)

	chMap := nat.ConsistentHashMap()
	err := chMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	svcIP := net.ParseIP("169.172.9.1")
	svcPort := uint16(80)
	backendPort := uint16(8080)
	svcProto := uint8(layers.IPProtocolUDP)

	mg := consistenthash.New(consistenthash.WithHash(fnv.New32(), fnv.New32()), consistenthash.WithPreferenceLength(31))
	programmed := make(map[nat.ConsistentHashBackendKey]nat.BackendValue)

	By("Creating creating 5 ConsistentHash-enabled backends")
	backends := make(map[string]chtypes.MockEndpoint)
	for _, b := range []string{"192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4", "192.168.1.5"} {
		backend := chtypes.MockEndpoint{
			Ip:  b,
			Prt: backendPort,
		}
		mg.AddBackend(backend)
		backends[backend.String()] = backend
	}

	By("Generating a ConsistentHash LUT")
	lut := mg.Generate()
	for i, b := range lut {
		Expect(backends).To(HaveKey(b.String()))
		expectedBackend := backends[b.String()]
		Expect(expectedBackend.Ip).To(Equal(b.IP()))
		Expect(expectedBackend.Port()).To(Equal(b.Port()))

		backendIP := net.ParseIP(b.IP())
		key := nat.NewConsistentHashBackendKey(svcIP, svcPort, svcProto, uint32(i))
		val := nat.NewNATBackendValue(backendIP, uint16(backendPort))
		err := chMap.Update(key.AsBytes(), val.AsBytes())
		Expect(err).NotTo(HaveOccurred())

		programmed[key] = val
	}

	By("Reading back the BPF map")
	m, err := nat.LoadConsistentHashMap(chMap)
	Expect(err).NotTo(HaveOccurred())
	Expect(len(m)).To(Equal(len(programmed)))

	keys := make([]nat.ConsistentHashBackendKey, len(m))
	for k := range m {
		keys[k.Ordinal()] = k
	}

	for _, k := range keys {
		fmt.Printf("%v: %s\n", k, m[k])
	}
}

func TestMaglevMidflowFailoverNoConntrack(t *testing.T) {
	RegisterTestingT(t)
	resetBPFMaps()
	var err error

	loglevel := logrus.GetLevel()
	defer withLogLevelWarnDo(cleanUpMaps)
	defer func() { bpfIfaceName = "" }()
	defer logrus.SetLevel(loglevel)

	// A mock nodeport.
	hostIP := net.IPv4(1, 1, 1, 1)
	hostPort := uint16(7890)
	backingPodIP := "192.168.0.1"
	backingPodIPCIDR := ip.MustParseCIDROrIP(backingPodIP + "/32")
	backingPodPort := 8080
	svcKey := nat.NewNATKey(hostIP, hostPort, 6)
	svcVal := nat.NewNATValue(123, 1, 0, 0)

	ipLayer := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Flags:    layers.IPv4DontFragment,
		SrcIP:    net.IPv4(1, 2, 3, 4),
		DstIP:    hostIP,
		Protocol: layers.IPProtocolTCP,
	}

	connLayer := &layers.TCP{
		SrcPort:    54321,
		DstPort:    7890,
		SYN:        false,
		DataOffset: 5,
	}

	withLogLevelWarnDo(func() {
		err = natMap.Update(svcKey.AsBytes(), svcVal.AsBytes())
		Expect(err).NotTo(HaveOccurred())
	})

	_, _, _, _, packetBytes, err := testPacketV4(nil, ipLayer, connLayer, nil)
	Expect(err).NotTo(HaveOccurred())

	bpfIfaceName = "mf00"
	skbMark = 0
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		// Destination is a remote workload, but pkt is midflow, and a conntrack miss.
		// Not a ConsistentHash-enabled packet; Should allow pkt to fallthrough to *tables.
		res, err := bpfrun(packetBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(retvalToStr[res.Retval]).To(Equal(retvalToStr[resTC_ACT_SHOT]))
		// We won't see the fallthrough mark because, once jumped to Maglev, we are not allowing fallthrough to occur.
	})

	svcVal = nat.NewNATValueWithFlags(123, 1, 0, 0, nat.NATFlgConsistentHash)
	withLogLevelWarnDo(func() {
		resetMap(natMap)
		err = natMap.Update(svcKey.AsBytes(), svcVal.AsBytes())
		Expect(err).NotTo(HaveOccurred())

		// Add a route to the backing pod to keep the NAT happy.
		err = rtMap.EnsureExists()
		Expect(err).NotTo(HaveOccurred())
		rtKey := routes.NewKey(backingPodIPCIDR).AsBytes()
		rtVal := routes.NewValueWithIfIndex(routes.FlagsLocalWorkload, 1).AsBytes()
		err = rtMap.Update(rtKey, rtVal)
		Expect(err).NotTo(HaveOccurred())
	})

	mgMap := nat.ConsistentHashMap()
	err = mgMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())
	// Build a maglev LUT and program each item to the BPF map.
	mglv := consistenthash.New(consistenthash.WithHash(fnv.New32(), fnv.New32()), consistenthash.WithPreferenceLength(31))
	mglv.AddBackend(chtypes.MockEndpoint{
		Ip:  backingPodIP,
		Prt: uint16(backingPodPort),
	})
	lut := mglv.Generate()
	for ordinal, ep := range lut {
		err = mgMap.Update(
			nat.NewConsistentHashBackendKeyIntf(hostIP, hostPort, uint8(layers.IPProtocolTCP), uint32(ordinal)).AsBytes(),
			nat.NewNATBackendValue(net.ParseIP(ep.IP()), uint16(ep.Port())).AsBytes(),
		)
		Expect(err).NotTo(HaveOccurred())
	}

	skbMark = 0
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		// Same as before but now, pkt belongs to a ConsistentHash service.
		// Should attempt to tunnel to the destination.
		res, err := bpfrun(packetBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(retvalToStr[res.Retval]).To(Equal(retvalToStr[resTC_ACT_UNSPEC]))
		// We expect the program to have attempted to tunnel the packet.
	})
}

func TestMaglevNATPodPodXNodeUDP(t *testing.T) {
	RegisterTestingT(t)

	bpfIfaceName = "MNAT1"
	defer func() { bpfIfaceName = "" }()
	natIP := net.IPv4(8, 8, 8, 8)
	natPort := uint16(666)

	eth, ipv4, l4, payload, pktBytes, err := testPacketUDPDefaultNP(node1ip)
	Expect(err).NotTo(HaveOccurred())
	udp := l4.(*layers.UDP)

	natMap := nat.FrontendMap()
	err = natMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	natBEMap := nat.BackendMap()
	err = natBEMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	mgMap := nat.ConsistentHashMap()
	err = mgMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	// Flagging frontend map item with the consistent-hash flag.
	err = natMap.Update(
		nat.NewNATKey(ipv4.DstIP, uint16(udp.DstPort), uint8(ipv4.Protocol)).AsBytes(),
		nat.NewNATValueWithFlags(0, 1, 0, 0, nat.NATFlgConsistentHash).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	err = natBEMap.Update(
		nat.NewNATBackendKey(0, 0).AsBytes(),
		nat.NewNATBackendValue(natIP, natPort).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	// Build a maglev LUT and program each item to the BPF map.
	mglv := consistenthash.New(consistenthash.WithHash(fnv.New32(), fnv.New32()), consistenthash.WithPreferenceLength(31))
	mglv.AddBackend(chtypes.MockEndpoint{
		Ip:  natIP.String(),
		Prt: natPort,
	})
	lut := mglv.Generate()
	for ordinal, ep := range lut {
		err = mgMap.Update(
			nat.NewConsistentHashBackendKey(ipv4.DstIP, uint16(udp.DstPort), uint8(ipv4.Protocol), uint32(ordinal)).AsBytes(),
			nat.NewNATBackendValue(net.ParseIP(ep.IP()), uint16(ep.Port())).AsBytes(),
		)
		Expect(err).NotTo(HaveOccurred())

	}

	dumpNATMap(natMap)

	ctMap := conntrack.Map()
	err = ctMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	resetCTMap(ctMap)

	var natedPkt []byte

	hostIP = node1ip

	// Insert a reverse route for the source workload that is not in a calico
	// pool, for example 3rd party CNI is used.
	rtKey := routes.NewKey(srcV4CIDR).AsBytes()
	rtVal := routes.NewValueWithIfIndex(routes.FlagsLocalWorkload, 1).AsBytes()
	err = rtMap.Update(rtKey, rtVal)
	Expect(err).NotTo(HaveOccurred())

	skbMark = 0
	// Leaving workloada test for fc711b192f */
	runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		ipv4Nat := *ipv4
		ipv4Nat.DstIP = natIP

		udpNat := *udp
		udpNat.DstPort = layers.UDPPort(natPort)

		// created the expected packet after NAT, with recalculated csums
		_, _, _, _, resPktBytes, err := testPacketV4(eth, &ipv4Nat, &udpNat, payload)
		Expect(err).NotTo(HaveOccurred())

		// expect them to be the same
		Expect(res.dataOut).To(Equal(resPktBytes))

		natedPkt = res.dataOut
	})
	expectMark(tcdefs.MarkSeenSkipFIB)

	resetCTMap(ctMap)

	// Insert a reverse route for the source workload that is in pool.
	rtVal = routes.NewValueWithIfIndex(routes.FlagsLocalWorkload|routes.FlagInIPAMPool, 1).AsBytes()
	err = rtMap.Update(rtKey, rtVal)
	Expect(err).NotTo(HaveOccurred())

	skbMark = 0
	// Leaving workload
	runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_REDIRECT))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		ipv4Nat := *ipv4
		ipv4Nat.DstIP = natIP

		udpNat := *udp
		udpNat.DstPort = layers.UDPPort(natPort)

		// created the expected packet after NAT, with recalculated csums
		_, _, _, _, resPktBytes, err := testPacketV4(eth, &ipv4Nat, &udpNat, payload)
		Expect(err).NotTo(HaveOccurred())

		// expect them to be the same
		Expect(res.dataOut).To(Equal(resPktBytes))

		natedPkt = res.dataOut
	})

	// Leaving node 1
	expectMark(tcdefs.MarkSeen)

	runBpfTest(t, "calico_to_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(natedPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		Expect(res.dataOut).To(Equal(natedPkt))
	})

	dumpCTMap(ctMap)
	fromHostCT := saveCTMap(ctMap)
	resetCTMap(ctMap)

	// We are now on node 2.
	var recvPkt []byte
	hostIP = node2ip
	bpfIfaceName = "MNAT2"
	skbMark = 0

	// Insert the reverse route for backend for RPF check.
	resetRTMap(rtMap)
	beV4CIDR := ip.CIDRFromNetIP(natIP).(ip.V4CIDR)
	bertKey := routes.NewKey(beV4CIDR).AsBytes()
	bertVal := routes.NewValueWithIfIndex(routes.FlagsLocalWorkload|routes.FlagInIPAMPool, 1).AsBytes()
	err = rtMap.Update(bertKey, bertVal)
	Expect(err).NotTo(HaveOccurred())

	// Arriving at node 2
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(natedPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_REDIRECT))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		Expect(res.dataOut).To(Equal(natedPkt))
	})

	ct, err := conntrack.LoadMapMem(ctMap)
	Expect(err).NotTo(HaveOccurred())
	v, ok := ct[conntrack.NewKey(uint8(ipv4.Protocol), ipv4.SrcIP, uint16(udp.SrcPort), natIP.To4(), natPort)]
	Expect(ok).To(BeTrue())
	// No NATing, service already resolved
	Expect(v.Type()).To(Equal(conntrack.TypeNormal))
	Expect(v.Flags()).To(Equal(uint16(0)))

	// Arriving at workload at node 2
	expectMark(tcdefs.MarkSeen)
	runBpfTest(t, "calico_to_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(natedPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		Expect(res.dataOut).To(Equal(natedPkt))

		recvPkt = res.dataOut
	})

	dumpCTMap(ctMap)

	var respPkt []byte

	// Response leaving workload at node 2
	skbMark = 0
	runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		respPkt = udpResponseRaw(recvPkt)
		res, err := bpfrun(respPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_REDIRECT))
		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		Expect(res.dataOut).To(Equal(respPkt))
	})

	// Response leaving node 2
	expectMark(tcdefs.MarkSeenBypass)
	runBpfTest(t, "calico_to_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(respPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		Expect(res.dataOut).To(Equal(respPkt))
	})

	dumpCTMap(ctMap)
	resetCTMap(ctMap)
	restoreCTMap(ctMap, fromHostCT)
	dumpCTMap(ctMap)

	hostIP = node1ip

	// Response arriving at node 1
	bpfIfaceName = "MNAT1"
	skbMark = 0
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(respPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_REDIRECT))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		Expect(res.dataOut).To(Equal(respPkt))
	})

	dumpCTMap(ctMap)

	// Response arriving at workload at node 1
	expectMark(tcdefs.MarkSeen)
	runBpfTest(t, "calico_to_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		pktExp := gopacket.NewPacket(respPkt, layers.LayerTypeEthernet, gopacket.Default)
		ipv4L := pktExp.Layer(layers.LayerTypeIPv4)
		Expect(ipv4L).NotTo(BeNil())
		ipv4R := ipv4L.(*layers.IPv4)
		udpL := pktExp.Layer(layers.LayerTypeUDP)
		Expect(udpL).NotTo(BeNil())
		udpR := udpL.(*layers.UDP)

		ipv4R.SrcIP = ipv4.DstIP
		udpR.SrcPort = udp.DstPort
		_ = udpR.SetNetworkLayerForChecksum(ipv4R)

		pktExpSer := gopacket.NewSerializeBuffer()
		err := gopacket.SerializePacket(pktExpSer, gopacket.SerializeOptions{ComputeChecksums: true}, pktExp)
		Expect(err).NotTo(HaveOccurred())

		res, err := bpfrun(respPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		Expect(res.dataOut).To(Equal(pktExpSer.Bytes()))
	})

	dumpCTMap(ctMap)

	// clean up
	resetCTMap(ctMap)
}

func TestMaglevNATNodePort(t *testing.T) {
	RegisterTestingT(t)

	bpfIfaceName = "MNP-1"
	defer func() { bpfIfaceName = "" }()
	natIP := net.IPv4(8, 8, 8, 8)
	natPort := uint16(666)

	_, ipv4, l4, payload, pktBytes, err := testPacketUDPDefaultNP(node1ip)
	Expect(err).NotTo(HaveOccurred())
	udp := l4.(*layers.UDP)
	natMap := nat.FrontendMap()
	err = natMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	natBEMap := nat.BackendMap()
	err = natBEMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	mgMap := nat.ConsistentHashMap()
	err = mgMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	// Flagging frontend map item with the consistent-hash flag.
	err = natMap.Update(
		nat.NewNATKey(ipv4.DstIP, uint16(udp.DstPort), uint8(ipv4.Protocol)).AsBytes(),
		nat.NewNATValueWithFlags(0, 1, 0, 0, nat.NATFlgConsistentHash).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	err = natBEMap.Update(
		nat.NewNATBackendKey(0, 0).AsBytes(),
		nat.NewNATBackendValue(natIP, natPort).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	// Build a maglev LUT and program each item to the BPF map.
	mglv := consistenthash.New(consistenthash.WithHash(fnv.New32(), fnv.New32()), consistenthash.WithPreferenceLength(31))
	mglv.AddBackend(chtypes.MockEndpoint{
		Ip:  natIP.String(),
		Prt: natPort,
	})
	lut := mglv.Generate()
	for ordinal, ep := range lut {
		err = mgMap.Update(
			nat.NewConsistentHashBackendKey(ipv4.DstIP, uint16(udp.DstPort), uint8(ipv4.Protocol), uint32(ordinal)).AsBytes(),
			nat.NewNATBackendValue(net.ParseIP(ep.IP()), uint16(ep.Port())).AsBytes(),
		)
		Expect(err).NotTo(HaveOccurred())

	}
	dumpConsistentHashMap(mgMap)

	node2wCIDR := net.IPNet{
		IP:   natIP,
		Mask: net.IPv4Mask(255, 255, 255, 0),
	}

	ctMap := conntrack.Map()
	err = ctMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())
	resetCTMap(ctMap) // ensure it is clean

	var encapedPkt []byte

	resetRTMap(rtMap)

	hostIP = node1ip
	skbMark = 0

	// Arriving at node 1 - non-routable -> denied
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_SHOT))
	})

	// Setup routing
	rtMap := routes.Map()
	err = rtMap.EnsureExists()
	defer resetRTMap(rtMap)
	Expect(err).NotTo(HaveOccurred())
	err = rtMap.Update(
		routes.NewKey(ip.CIDRFromIPNet(&node2wCIDR).(ip.V4CIDR)).AsBytes(),
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
	rtNode1 := saveRTMap(rtMap)

	vni := uint32(0)

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

		checkVxlanEncap(pktR, false, ipv4, udp, payload)
		vni = getVxlanVNI(pktR)

		encapedPkt = res.dataOut

		ct, err := conntrack.LoadMapMem(ctMap)
		Expect(err).NotTo(HaveOccurred())

		ctKey := conntrack.NewKey(uint8(ipv4.Protocol),
			ipv4.DstIP, uint16(udp.DstPort), ipv4.SrcIP, uint16(udp.SrcPort))

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

	dumpCTMap(ctMap)
	ct, err := conntrack.LoadMapMem(ctMap)
	Expect(err).NotTo(HaveOccurred())
	v, ok := ct[conntrack.NewKey(uint8(ipv4.Protocol), ipv4.SrcIP, uint16(udp.SrcPort), natIP.To4(), natPort)]
	Expect(ok).To(BeTrue())
	Expect(v.Type()).To(Equal(conntrack.TypeNATReverse))
	Expect(v.Flags()).To(Equal(conntrack3.FlagNATNPFwd))

	expectMark(tcdefs.MarkSeenBypassForward)
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
	fromHostCT := saveCTMap(ctMap)

	encapedPktArrivesAtNode2 := make([]byte, len(encapedPkt))
	copy(encapedPktArrivesAtNode2, encapedPkt)

	resetCTMap(ctMap)

	var recvPkt []byte

	hostIP = node2ip

	// change the routing - it is a local workload now!
	err = rtMap.Update(
		routes.NewKey(ip.CIDRFromIPNet(&node2wCIDR).(ip.V4CIDR)).AsBytes(),
		routes.NewValue(routes.FlagsLocalWorkload|routes.FlagInIPAMPool).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	// we must know that the encaped packet src ip is from a known host
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

	// now we are at the node with local workload
	err = natMap.Update(
		nat.NewNATKey(ipv4.DstIP, uint16(udp.DstPort), uint8(ipv4.Protocol)).AsBytes(),
		nat.NewNATValueWithFlags(0 /* id */, 1 /* count */, 1 /* local */, 0, nat.NATFlgConsistentHash).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	// Arriving at node 2
	bpfIfaceName = "MNP-2"

	arpMapN2 := saveARPMap(arpMap)
	Expect(arpMapN2).To(HaveLen(0))

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

		ipv4L := pktR.Layer(layers.LayerTypeIPv4)
		ipv4R := ipv4L.(*layers.IPv4)
		Expect(ipv4R.SrcIP.String()).To(Equal(ipv4.SrcIP.String()))
		Expect(ipv4R.DstIP.String()).To(Equal(natIP.String()))

		udpL := pktR.Layer(layers.LayerTypeUDP)
		Expect(udpL).NotTo(BeNil())
		udpR := udpL.(*layers.UDP)
		Expect(udpR.SrcPort).To(Equal(layers.UDPPort(udp.SrcPort)))
		Expect(udpR.DstPort).To(Equal(layers.UDPPort(natPort)))

		ct, err := conntrack.LoadMapMem(ctMap)
		Expect(err).NotTo(HaveOccurred())

		ctKey := conntrack.NewKey(uint8(ipv4.Protocol),
			ipv4.DstIP, uint16(udp.DstPort), ipv4.SrcIP, uint16(udp.SrcPort))

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
	})

	expectMark(tcdefs.MarkSeen)

	dumpCTMap(ctMap)
	ct, err = conntrack.LoadMapMem(ctMap)
	Expect(err).NotTo(HaveOccurred())
	v, ok = ct[conntrack.NewKey(uint8(ipv4.Protocol), ipv4.SrcIP, uint16(udp.SrcPort), natIP.To4(), natPort)]
	Expect(ok).To(BeTrue())
	Expect(v.Type()).To(Equal(conntrack.TypeNATReverse))
	Expect(v.Flags()).To(Equal(conntrack3.FlagExtLocal))

	dumpARPMap(arpMap)

	arpMapN2 = saveARPMap(arpMap)
	Expect(arpMapN2).To(HaveLen(1))
	arpKey := arp.NewKey(node1ip, 1 /* ifindex is always 1 in UT */)
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
	})

	skbMark = tcdefs.MarkSeen

	// Insert the reverse route for backend for RPF check.
	resetRTMap(rtMap)
	beV4CIDR := ip.CIDRFromNetIP(natIP).(ip.V4CIDR)
	bertKey := routes.NewKey(beV4CIDR).AsBytes()
	bertVal := routes.NewValueWithIfIndex(routes.FlagsLocalWorkload|routes.FlagInIPAMPool, 1).AsBytes()
	err = rtMap.Update(bertKey, bertVal)
	Expect(err).NotTo(HaveOccurred())

	// Arriving at workload at node 2
	runBpfTest(t, "calico_to_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(recvPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		Expect(res.dataOut).To(Equal(recvPkt))

		ct, err := conntrack.LoadMapMem(ctMap)
		Expect(err).NotTo(HaveOccurred())

		ctKey := conntrack.NewKey(uint8(ipv4.Protocol),
			ipv4.DstIP, uint16(udp.DstPort), ipv4.SrcIP, uint16(udp.SrcPort))

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
		respPkt := udpResponseRaw(recvPkt)
		// Change the MAC addresses so that we can observe that the right
		// addresses were patched in.
		copy(respPkt[:6], []byte{1, 2, 3, 4, 5, 6})
		copy(respPkt[6:12], []byte{6, 5, 4, 3, 2, 1})
		res, err := bpfrun(respPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_REDIRECT))

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

	hostIP = node2ip

	// Response leaving node 2
	runBpfTest(t, "calico_to_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(encapedPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

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
	host2CT := saveCTMap(ctMap)
	resetCTMap(ctMap)
	restoreCTMap(ctMap, fromHostCT)
	dumpCTMap(ctMap)

	hostIP = node1ip

	// change to routing again to a remote workload
	resetRTMap(rtMap)
	restoreRTMap(rtMap, rtNode1)
	dumpRTMap(rtMap)

	// Response arriving at node 1
	bpfIfaceName = "MNP-1"
	skbMark = 0

	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(encapedPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_REDIRECT))

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

		recvPkt = res.dataOut
	})

	expectMark(tcdefs.MarkSeenBypassForward)
	saveMark := skbMark

	dumpCTMap(ctMap)

	skbMark = 0
	// try a spoofed tunnel packet returning back, should be dropped and have no effect
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		// modify the only known good src IP, we do not care about csums at this point
		encapedPkt[26] = 235
		res, err := bpfrun(encapedPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_SHOT))
	})

	var icmpMTUTooBig []byte

	skbMark = saveMark
	// Response leaving to original source
	runBpfTest(t, "calico_to_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(recvPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		ct, err := conntrack.LoadMapMem(ctMap)
		Expect(err).NotTo(HaveOccurred())

		ctKey := conntrack.NewKey(uint8(ipv4.Protocol),
			ipv4.DstIP, uint16(udp.DstPort), ipv4.SrcIP, uint16(udp.SrcPort))

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

		ipv4L := pktR.Layer(layers.LayerTypeIPv4)
		Expect(ipv4L).NotTo(BeNil())
		ipv4R := ipv4L.(*layers.IPv4)

		udpL := pktR.Layer(layers.LayerTypeUDP)
		Expect(udpL).NotTo(BeNil())
		udpR := udpL.(*layers.UDP)

		icmpMTUTooBig = makeICMPErrorFrom(net.ParseIP("69.69.69.69"), ipv4R, udpR,
			layers.ICMPv4TypeDestinationUnreachable, layers.ICMPv4CodeFragmentationNeeded)
	})

	dumpCTMap(ctMap)

	var vxlanSrcPort layers.UDPPort

	skbMark = 0
	// Another pkt arriving at node 1 - uses existing CT entries
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_REDIRECT))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		ipv4L := pktR.Layer(layers.LayerTypeIPv4)
		Expect(ipv4L).NotTo(BeNil())
		ipv4R := ipv4L.(*layers.IPv4)
		Expect(ipv4R.SrcIP.String()).To(Equal(hostIP.String()))
		Expect(ipv4R.DstIP.String()).To(Equal(node2ip.String()))

		udpL := pktR.Layer(layers.LayerTypeUDP)
		Expect(udpL).NotTo(BeNil())
		udpR := udpL.(*layers.UDP)

		Expect(udpR.SrcPort).To(Equal(udp.SrcPort ^ udp.DstPort))
		vxlanSrcPort = udpR.SrcPort

		checkVxlanEncap(pktR, false, ipv4, udp, payload)
	})

	var icmpEncaped []byte

	skbMark = 0
	// ICMP too big response from internet towards the backend on node1 from some middle box
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		pktR := gopacket.NewPacket(icmpMTUTooBig, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		payloadL := pktR.ApplicationLayer()
		Expect(payloadL).NotTo(BeNil())

		pktR = gopacket.NewPacket(payloadL.Payload(), layers.LayerTypeIPv4, gopacket.Default)
		fmt.Printf("ICMP = %+v\n", pktR)

		res, err := bpfrun(icmpMTUTooBig)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_REDIRECT))

		pktR = gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)
		payloadL = pktR.ApplicationLayer()
		Expect(payloadL).NotTo(BeNil())
		vxlanL := gopacket.NewPacket(payloadL.Payload(), layers.LayerTypeVXLAN, gopacket.Default)
		Expect(vxlanL).NotTo(BeNil())
		fmt.Printf("vxlanL = %+v\n", vxlanL)

		ethL := vxlanL.Layer(layers.LayerTypeEthernet)
		Expect(ethL).NotTo(BeNil())

		pktR = gopacket.NewPacket(ethL.LayerPayload(), layers.LayerTypeIPv4, gopacket.Default)

		ipv4L := pktR.Layer(layers.LayerTypeIPv4)
		ipv4R := ipv4L.(*layers.IPv4)
		Expect(ipv4R.SrcIP.String()).To(Equal("69.69.69.69"))
		Expect(ipv4R.DstIP.String()).To(Equal(node1ip.String()))

		icmpL := pktR.Layer(layers.LayerTypeICMPv4)
		Expect(icmpL).NotTo(BeNil())

		icmpEncaped = res.dataOut
	})

	skbMark = 0
	// Another pkt with a different source port arriving at node 1
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {

		// Change the source port
		pktBytes[14+(20+8)] = 0xde
		pktBytes[14+(20+8)+1] = 0xad

		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_REDIRECT))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		ipv4L := pktR.Layer(layers.LayerTypeIPv4)
		Expect(ipv4L).NotTo(BeNil())
		ipv4R := ipv4L.(*layers.IPv4)
		Expect(ipv4R.SrcIP.String()).To(Equal(hostIP.String()))
		Expect(ipv4R.DstIP.String()).To(Equal(node2ip.String()))

		udpL := pktR.Layer(layers.LayerTypeUDP)
		Expect(udpL).NotTo(BeNil())
		udpR := udpL.(*layers.UDP)

		Expect(udpR.SrcPort).NotTo(Equal(vxlanSrcPort))
	})

	expectMark(tcdefs.MarkSeenBypassForward)

	/*
	 * TEST that unknown VNI is passed through
	 */
	testUnrelatedVXLAN(4, t, node2ip, vni)

	hostIP = node2ip

	// change the routing - it is a local workload now!
	err = rtMap.Update(
		routes.NewKey(ip.CIDRFromIPNet(&node2wCIDR).(ip.V4CIDR)).AsBytes(),
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

	restoreCTMap(ctMap, host2CT)
	dumpCTMap(ctMap)

	// now we are at the node with local workload
	err = natMap.Update(
		nat.NewNATKey(ipv4.DstIP, uint16(udp.DstPort), uint8(ipv4.Protocol)).AsBytes(),
		nat.NewNATValueWithFlags(0 /* id */, 1 /* count */, 1 /* local */, 0, nat.NATFlgConsistentHash).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	// ICMP arriving at node 2
	bpfIfaceName = "MNP-2"

	skbMark = 0
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(icmpEncaped)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_REDIRECT))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		ipv4L := pktR.Layer(layers.LayerTypeIPv4)
		ipv4R := ipv4L.(*layers.IPv4)
		Expect(ipv4R.SrcIP.String()).To(Equal("69.69.69.69"))
		Expect(ipv4R.DstIP.String()).To(Equal(natIP.String()))

		ethL := pktR.Layer(layers.LayerTypeEthernet)
		Expect(ethL).NotTo(BeNil())
		ethR := ethL.(*layers.Ethernet)

		icmpL := pktR.Layer(layers.LayerTypeICMPv4)
		Expect(icmpL).NotTo(BeNil())
		icmpR := icmpL.(*layers.ICMPv4)

		payloadL := pktR.ApplicationLayer()
		Expect(payloadL).NotTo(BeNil())

		pkt := gopacket.NewSerializeBuffer()
		err = gopacket.SerializeLayers(pkt, gopacket.SerializeOptions{ComputeChecksums: true},
			ethR, ipv4R, icmpR, gopacket.Payload(payloadL.Payload()))
		Expect(err).NotTo(HaveOccurred())
		pktBytes := pkt.Bytes()

		Expect(res.dataOut).To(Equal(pktBytes))

		pktR = gopacket.NewPacket(payloadL.Payload(), layers.LayerTypeIPv4, gopacket.Default)
		fmt.Printf("ICMP = %+v\n", pktR)

		ipv4L = pktR.Layer(layers.LayerTypeIPv4)
		ipv4R = ipv4L.(*layers.IPv4)
		Expect(ipv4R.SrcIP.String()).To(Equal(natIP.String()))
		Expect(ipv4R.DstIP.String()).To(Equal(srcIP.String()))

		udpL := pktR.Layer(layers.LayerTypeUDP)
		Expect(udpL).NotTo(BeNil())
		udpR := udpL.(*layers.UDP)
		Expect(udpR.SrcPort).To(Equal(layers.UDPPort(natPort)))
		Expect(udpR.DstPort).To(Equal(layers.UDPPort(udpDefault.SrcPort)))

		recvPkt = res.dataOut
	})

	// Arriving at workload at node 2
	runBpfTest(t, "calico_to_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(recvPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		ipv4L := pktR.Layer(layers.LayerTypeIPv4)
		ipv4R := ipv4L.(*layers.IPv4)
		Expect(ipv4R.SrcIP.String()).To(Equal("69.69.69.69"))
		Expect(ipv4R.DstIP.String()).To(Equal(natIP.String()))

		payloadL := pktR.ApplicationLayer()
		Expect(payloadL).NotTo(BeNil())

		pktR = gopacket.NewPacket(payloadL.Payload(), layers.LayerTypeIPv4, gopacket.Default)
		fmt.Printf("ICMP = %+v\n", pktR)

		ipv4L = pktR.Layer(layers.LayerTypeIPv4)
		ipv4R = ipv4L.(*layers.IPv4)
		Expect(ipv4R.SrcIP.String()).To(Equal(natIP.String()))
		Expect(ipv4R.DstIP.String()).To(Equal(srcIP.String()))

		udpL := pktR.Layer(layers.LayerTypeUDP)
		Expect(udpL).NotTo(BeNil())
		udpR := udpL.(*layers.UDP)
		Expect(udpR.SrcPort).To(Equal(layers.UDPPort(natPort)))
		Expect(udpR.DstPort).To(Equal(layers.UDPPort(udpDefault.SrcPort)))
	})

	// TEST host-networked backend
	{
		resetCTMap(ctMap)

		var recvPkt []byte

		hostIP = node2ip
		skbMark = 0

		// we must know that the encaped packet src ip is from a known host
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

		// now we are at the node with local workload
		err = natMap.Update(
			nat.NewNATKey(net.IPv4(255, 255, 255, 255), uint16(udp.DstPort), uint8(ipv4.Protocol)).AsBytes(),
			nat.NewNATValueWithFlags( /* id */ 0 /* count */, 1 /* local */, 1 /* affinity t.o. */, 0, nat.NATFlgConsistentHash).AsBytes(),
		)
		Expect(err).NotTo(HaveOccurred())

		// make it point to the local host - host networked backend
		err = natBEMap.Update(
			nat.NewNATBackendKey(0, 0).AsBytes(),
			nat.NewNATBackendValue(node2ip, natPort).AsBytes(),
		)
		Expect(err).NotTo(HaveOccurred())

		// Build a maglev LUT and program each item to the BPF map.
		mglv := consistenthash.New(consistenthash.WithHash(fnv.New32(), fnv.New32()), consistenthash.WithPreferenceLength(31))
		mglv.AddBackend(chtypes.MockEndpoint{
			Ip:  node2ip.String(),
			Prt: natPort,
		})
		lut := mglv.Generate()
		for ordinal, ep := range lut {
			err = mgMap.Update(
				nat.NewConsistentHashBackendKey(ipv4.DstIP, uint16(udp.DstPort), uint8(ipv4.Protocol), uint32(ordinal)).AsBytes(),
				nat.NewNATBackendValue(net.ParseIP(ep.IP()), uint16(ep.Port())).AsBytes(),
			)
			Expect(err).NotTo(HaveOccurred())

		}

		// Arriving at node 2
		bpfIfaceName = "MNP-2"

		skbMark = 0
		runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
			res, err := bpfrun(encapedPktArrivesAtNode2)
			Expect(err).NotTo(HaveOccurred())
			Expect(res.Retval).To(Equal(resTC_ACT_REDIRECT))

			pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
			fmt.Printf("pktR = %+v\n", pktR)

			ipv4L := pktR.Layer(layers.LayerTypeIPv4)
			ipv4R := ipv4L.(*layers.IPv4)
			Expect(ipv4R.SrcIP.String()).To(Equal(ipv4.SrcIP.String()))
			Expect(ipv4R.DstIP.String()).To(Equal(node2ip.String()))

			udpL := pktR.Layer(layers.LayerTypeUDP)
			Expect(udpL).NotTo(BeNil())
			udpR := udpL.(*layers.UDP)
			Expect(udpR.SrcPort).To(Equal(layers.UDPPort(udp.SrcPort)))
			Expect(udpR.DstPort).To(Equal(layers.UDPPort(natPort)))

			ct, err := conntrack.LoadMapMem(ctMap)
			Expect(err).NotTo(HaveOccurred())

			ctKey := conntrack.NewKey(uint8(ipv4.Protocol),
				ipv4.DstIP, uint16(udp.DstPort), ipv4.SrcIP, uint16(udp.SrcPort))

			Expect(ct).Should(HaveKey(ctKey))
			ctr := ct[ctKey]
			Expect(ctr.Type()).To(Equal(conntrack.TypeNATForward))

			ctKey = ctr.ReverseNATKey().(conntrack.Key)
			Expect(ct).Should(HaveKey(ctKey))
			ctr = ct[ctKey]
			Expect(ctr.Type()).To(Equal(conntrack.TypeNATReverse))

			// Approved source side
			Expect(ctr.Data().A2B.Approved).To(BeTrue())
			// Dest not approved yet
			Expect(ctr.Data().B2A.Approved).NotTo(BeTrue())

			recvPkt = res.dataOut
		})

		dumpCTMap(ctMap)

		skbMark = 0

		// Response leaving workload at node 2
		runBpfTest(t, "calico_to_host_ep", nil, func(bpfrun bpfProgRunFn) {
			respPkt := udpResponseRaw(recvPkt)

			// Change the MAC addresses so that we can observe that the right
			// addresses were patched in.
			macUntouched := []byte{6, 5, 4, 3, 2, 1}
			copy(respPkt[:6], []byte{1, 2, 3, 4, 5, 6})
			copy(respPkt[6:12], macUntouched)

			res, err := bpfrun(respPkt)
			Expect(err).NotTo(HaveOccurred())
			Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

			pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
			fmt.Printf("pktR = %+v\n", pktR)

			ethL := pktR.Layer(layers.LayerTypeEthernet)
			Expect(ethL).NotTo(BeNil())
			ethR := ethL.(*layers.Ethernet)
			Expect(ethR).To(layersMatchFields(&layers.Ethernet{
				SrcMAC:       macUntouched, // Source is set by net stack and should not be touched.
				DstMAC:       macSrc,
				EthernetType: layers.EthernetTypeIPv4,
			}))

			ipv4L := pktR.Layer(layers.LayerTypeIPv4)
			Expect(ipv4L).NotTo(BeNil())
			ipv4R := ipv4L.(*layers.IPv4)
			Expect(ipv4R.SrcIP.String()).To(Equal(node2ip.String()))
			Expect(ipv4R.DstIP.String()).To(Equal(node1ip.String()))

			checkVxlan(pktR)
		}, withHostNetworked())
	}
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

	mgMap := nat.ConsistentHashMap()
	err = mgMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	natBEMap := nat.BackendMap()
	err = natBEMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	// local workload
	err = natMap.Update(
		nat.NewNATKey(ipv4.DstIP, uint16(udp.DstPort), uint8(ipv4.Protocol)).AsBytes(),
		nat.NewNATValueWithFlags(0 /* count */, 1 /* local */, 1, 0, nat.NATFlgConsistentHash).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	natIP := net.IPv4(8, 8, 8, 8)
	natPort := uint16(666)

	err = natBEMap.Update(
		nat.NewNATBackendKey(0, 0).AsBytes(),
		nat.NewNATBackendValue(natIP, natPort).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	// Build a maglev LUT and program each item to the BPF map.
	mglv := consistenthash.New(consistenthash.WithHash(fnv.New32(), fnv.New32()), consistenthash.WithPreferenceLength(31))
	mglv.AddBackend(chtypes.MockEndpoint{
		Ip:  natIP.String(),
		Prt: natPort,
	})
	lut := mglv.Generate()
	for ordinal, ep := range lut {
		err = mgMap.Update(
			nat.NewConsistentHashBackendKey(ipv4.DstIP, uint16(udp.DstPort), uint8(ipv4.Protocol), uint32(ordinal)).AsBytes(),
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
	Expect(v.Flags()).To(Equal(conntrack3.FlagExtLocal))

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

	// Response leaving workload at node 2
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

func TestMaglevNATNodePortMultiNIC(t *testing.T) {
	RegisterTestingT(t)

	bpfIfaceName = "MNPM1"
	defer func() { bpfIfaceName = "" }()

	_, ipv4, l4, payload, pktBytes, err := testPacketUDPDefaultNP(node1ip2)
	Expect(err).NotTo(HaveOccurred())
	udp := l4.(*layers.UDP)
	natMap := nat.FrontendMap()
	err = natMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	natBEMap := nat.BackendMap()
	err = natBEMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	mgMap := nat.ConsistentHashMap()
	err = mgMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	// NP for node1ip
	err = natMap.Update(
		nat.NewNATKey(node1ip, uint16(udp.DstPort), uint8(ipv4.Protocol)).AsBytes(),
		nat.NewNATValueWithFlags(0, 1, 0, 0, nat.NATFlgConsistentHash).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	// NP for node1ip2
	err = natMap.Update(
		nat.NewNATKey(node1ip2, uint16(udp.DstPort), uint8(ipv4.Protocol)).AsBytes(),
		nat.NewNATValueWithFlags(0, 1, 0, 0, nat.NATFlgConsistentHash).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	natIP := net.IPv4(8, 8, 8, 8)
	natPort := uint16(666)

	err = natBEMap.Update(
		nat.NewNATBackendKey(0, 0).AsBytes(),
		nat.NewNATBackendValue(natIP, natPort).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	// Build a maglev LUT and program each item to the BPF map.
	mglv := consistenthash.New(consistenthash.WithHash(fnv.New32(), fnv.New32()), consistenthash.WithPreferenceLength(31))
	mglv.AddBackend(chtypes.MockEndpoint{
		Ip:  natIP.String(),
		Prt: natPort,
	})
	lut := mglv.Generate()
	for ordinal, ep := range lut {
		err = mgMap.Update(
			nat.NewConsistentHashBackendKey(ipv4.DstIP, uint16(udp.DstPort), uint8(ipv4.Protocol), uint32(ordinal)).AsBytes(),
			nat.NewNATBackendValue(net.ParseIP(ep.IP()), uint16(ep.Port())).AsBytes(),
		)
		Expect(err).NotTo(HaveOccurred())
	}

	node2wCIDR := net.IPNet{
		IP:   natIP,
		Mask: net.IPv4Mask(255, 255, 255, 0),
	}

	ctMap := conntrack.Map()
	err = ctMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())
	resetCTMap(ctMap) // ensure it is clean

	var encapedPkt []byte

	hostIP = node1ip
	skbMark = 0

	// Setup routing
	rtMap := routes.Map()
	err = rtMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())
	defer resetRTMap(rtMap)
	err = rtMap.Update(
		routes.NewKey(ip.CIDRFromIPNet(&node2wCIDR).(ip.V4CIDR)).AsBytes(),
		routes.NewValueWithNextHop(routes.FlagsRemoteWorkload|routes.FlagInIPAMPool,
			ip.FromNetIP(node2ip).(ip.V4Addr)).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())
	err = rtMap.Update(
		routes.NewKey(ip.CIDRFromIPNet(&node1CIDR).(ip.V4CIDR)).AsBytes(),
		routes.NewValue(routes.FlagsLocalHost).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())
	dumpRTMap(rtMap)

	// Arriving at node 1 through 10.10.2.x
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

		checkVxlanEncap(pktR, false, ipv4, udp, payload)

		encapedPkt = res.dataOut

		ct, err := conntrack.LoadMapMem(ctMap)
		Expect(err).NotTo(HaveOccurred())

		ctKey := conntrack.NewKey(uint8(ipv4.Protocol),
			ipv4.SrcIP, uint16(udp.SrcPort), ipv4.DstIP, uint16(udp.DstPort))

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

	dumpCTMap(ctMap)

	expectMark(tcdefs.MarkSeenBypassForward)

	hostIP = node1ip
	var encapedGoPkt gopacket.Packet

	// Leaving node 1 through 10.10.0.x
	runBpfTest(t, "calico_to_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(encapedPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		ipv4L := pktR.Layer(layers.LayerTypeIPv4)
		Expect(ipv4L).NotTo(BeNil())
		ipv4R := ipv4L.(*layers.IPv4)
		Expect(ipv4R.SrcIP.String()).To(Equal(hostIP.String()))
		Expect(ipv4R.DstIP.String()).To(Equal(node2ip.String()))

		checkVxlanEncap(pktR, false, ipv4, udp, payload)

		encapedGoPkt = pktR
	})

	dumpCTMap(ctMap)

	// craft response packet - short-circuit the remote node side, tested in
	// TestNATNodePort()
	respPkt := encapedResponse(encapedGoPkt)

	var recvPkt []byte

	skbMark = 0
	// Response arriving at node 1 through 10.10.0.x
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		// Initially, blocked by the VXLAN source policing.
		res, err := bpfrun(respPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_SHOT))

		// Add the route for the remote node.  Should now be allowed...
		err = rtMap.Update(
			routes.NewKey(ip.FromNetIP(node2ip).AsCIDR().(ip.V4CIDR)).AsBytes(),
			routes.NewValueWithNextHop(routes.FlagsRemoteHost, ip.FromNetIP(node2ip).(ip.V4Addr)).AsBytes(),
		)
		Expect(err).NotTo(HaveOccurred())
		res, err = bpfrun(respPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_REDIRECT))

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

		recvPkt = res.dataOut
	})

	dumpCTMap(ctMap)

	expectMark(tcdefs.MarkSeenBypassForward)

	// Response leaving to original source
	runBpfTest(t, "calico_to_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(recvPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_UNSPEC))

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		ct, err := conntrack.LoadMapMem(ctMap)
		Expect(err).NotTo(HaveOccurred())

		ctKey := conntrack.NewKey(uint8(ipv4.Protocol),
			ipv4.SrcIP, uint16(udp.SrcPort), ipv4.DstIP, uint16(udp.DstPort))

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

	dumpCTMap(ctMap)
}

func TestMaglevNATNodePortICMPTooBig(t *testing.T) {
	RegisterTestingT(t)

	_, ipv4, l4, _, pktBytes, err := testPacketV4(nil, nil, nil, make([]byte, natTunnelMTU))
	Expect(err).NotTo(HaveOccurred())
	udp := l4.(*layers.UDP)

	natMap := nat.FrontendMap()
	err = natMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	natBEMap := nat.BackendMap()
	err = natBEMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	err = natMap.Update(
		nat.NewNATKey(ipv4.DstIP, uint16(udp.DstPort), uint8(ipv4.Protocol)).AsBytes(),
		nat.NewNATValueWithFlags(0, 1, 0, 0, nat.NATFlgConsistentHash).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	natIP := net.IPv4(8, 8, 8, 8)
	natPort := uint16(666)

	err = natBEMap.Update(
		nat.NewNATBackendKey(0, 0).AsBytes(),
		nat.NewNATBackendValue(natIP, natPort).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	mgMap := nat.ConsistentHashMap()
	err = mgMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())

	// Build a maglev LUT and program each item to the BPF map.
	mglv := consistenthash.New(consistenthash.WithHash(fnv.New32(), fnv.New32()), consistenthash.WithPreferenceLength(31))
	mglv.AddBackend(chtypes.MockEndpoint{
		Ip:  natIP.String(),
		Prt: natPort,
	})
	lut := mglv.Generate()
	for ordinal, ep := range lut {
		err = mgMap.Update(
			nat.NewConsistentHashBackendKey(ipv4.DstIP, uint16(udp.DstPort), uint8(ipv4.Protocol), uint32(ordinal)).AsBytes(),
			nat.NewNATBackendValue(net.ParseIP(ep.IP()), uint16(ep.Port())).AsBytes(),
		)
		Expect(err).NotTo(HaveOccurred())
	}

	node2IP := net.IPv4(3, 3, 3, 3)
	node2wCIDR := net.IPNet{
		IP:   natIP,
		Mask: net.IPv4Mask(255, 255, 255, 0),
	}

	rtMap := routes.Map()
	err = rtMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())
	defer resetRTMap(rtMap)
	err = rtMap.Update(
		routes.NewKey(ip.CIDRFromIPNet(&node2wCIDR).(ip.V4CIDR)).AsBytes(),
		routes.NewValueWithNextHop(routes.FlagsRemoteWorkload|routes.FlagInIPAMPool,
			ip.FromNetIP(node2IP).(ip.V4Addr)).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	ctMap := conntrack.Map()
	err = ctMap.EnsureExists()
	Expect(err).NotTo(HaveOccurred())
	resetCTMap(ctMap) // ensure it is clean

	hostIP = node1ip
	skbMark = 0

	// Arriving at node but is rejected because of MTU, expect ICMP too big reply
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.RetvalStr()).To(Equal("TC_ACT_UNSPEC"), "expected program to return TC_ACT_UNSPEC")

		pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
		fmt.Printf("pktR = %+v\n", pktR)

		checkICMPTooBig(pktR, ipv4, udp, ipv4.DstIP, natTunnelMTU)
	})

	expectMark(tcdefs.MarkSeenBypassForward)

	// clean up
	resetCTMap(ctMap)
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
