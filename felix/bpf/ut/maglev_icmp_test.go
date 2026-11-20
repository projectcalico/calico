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
	"fmt"
	"hash/fnv"
	"net"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/bpf/conntrack"
	"github.com/projectcalico/calico/felix/bpf/consistenthash"
	chtypes "github.com/projectcalico/calico/felix/bpf/consistenthash/test"
	"github.com/projectcalico/calico/felix/bpf/nat"
	"github.com/projectcalico/calico/felix/bpf/routes"
	"github.com/projectcalico/calico/felix/ip"
)

// An ICMP error for a Maglev VIP can be ECMP-hashed to a node that never saw
// the flow. That node holds no CT entry, but must still deliver the error to
// the backend the flow uses.

var (
	maglevICMPServiceIP = net.IPv4(172, 16, 1, 1).To4()
	maglevICMPRouterIP  = net.IPv4(192, 168, 99, 1).To4()
)

const (
	maglevICMPServicePort = uint16(5678)
	icmpDestUnreach       = uint8(3)
	icmpFragNeeded        = uint8(4)
)

type maglevICMPBackend struct {
	ip   net.IP
	port uint16
}

func setupMaglevICMPService(flags uint32, backends ...maglevICMPBackend) {
	err := natMap.Update(
		nat.NewNATKey(maglevICMPServiceIP, maglevICMPServicePort, uint8(layers.IPProtocolTCP)).AsBytes(),
		nat.NewNATValueWithFlags(maglevSvcID, uint32(len(backends)), 0, 0, flags).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	mglv := consistenthash.New(int(maglevTestM), fnv.New32(), fnv.New32())
	for _, be := range backends {
		mglv.AddBackend(chtypes.MockEndpoint{Ip: be.ip.String(), Prt: be.port})
	}
	for ordinal, ep := range mglv.Generate() {
		err = maglevMap.Update(
			nat.NewMaglevBackendKey(maglevSvcID, uint32(ordinal)).AsBytes(),
			nat.NewNATBackendValue(net.ParseIP(ep.IP()), uint16(ep.Port())).AsBytes(),
		)
		Expect(err).NotTo(HaveOccurred())
	}
}

func addMaglevICMPRoute(cidr net.IPNet, val routes.Value) {
	err := rtMap.Update(routes.NewKey(ip.CIDRFromIPNet(&cidr).(ip.V4CIDR)).AsBytes(), val.AsBytes())
	Expect(err).NotTo(HaveOccurred())
}

// maglevFragNeeded is what a router on the return path sends when the
// backend's reply (VIP -> client) does not fit the next hop.
func maglevFragNeeded(clientPort uint16) []byte {
	inner := *ipv4Default
	inner.SrcIP = maglevICMPServiceIP
	inner.DstIP = srcIP
	inner.Protocol = layers.IPProtocolTCP
	innerTCP := &layers.TCP{
		SrcPort:    layers.TCPPort(maglevICMPServicePort),
		DstPort:    layers.TCPPort(clientPort),
		ACK:        true,
		DataOffset: 5,
	}
	return makeICMPErrorFrom(maglevICMPRouterIP, &inner, innerTCP, icmpDestUnreach, icmpFragNeeded)
}

func expectCTMapEmpty() {
	ct, err := conntrack.LoadMapMem(ctMap)
	Expect(err).NotTo(HaveOccurred())
	Expect(ct).To(BeEmpty())
}

func TestMaglevICMPErrorWithoutCTFollowsFlowToRemoteBackend(t *testing.T) {
	RegisterTestingT(t)

	defer resetBPFMaps()
	resetBPFMaps()
	hostIP = node3ip
	skbMark = 0
	bpfIfaceName = "MICr"
	defer func() { bpfIfaceName = "" }()

	backendOnNode1 := maglevICMPBackend{net.IPv4(8, 8, 8, 8).To4(), 666}
	backendOnNode2 := maglevICMPBackend{net.IPv4(9, 9, 9, 9).To4(), 777}
	setupMaglevICMPService(nat.NATFlgMaglev, backendOnNode1, backendOnNode2)

	addMaglevICMPRoute(net.IPNet{IP: backendOnNode1.ip, Mask: net.CIDRMask(24, 32)},
		routes.NewValueWithNextHop(routes.FlagsRemoteWorkload|routes.FlagInIPAMPool, ip.FromNetIP(node1ip).(ip.V4Addr)))
	addMaglevICMPRoute(net.IPNet{IP: backendOnNode2.ip, Mask: net.CIDRMask(24, 32)},
		routes.NewValueWithNextHop(routes.FlagsRemoteWorkload|routes.FlagInIPAMPool, ip.FromNetIP(node2ip).(ip.V4Addr)))
	addMaglevICMPRoute(node1CIDR, routes.NewValue(routes.FlagsRemoteHost))
	addMaglevICMPRoute(node2CIDR, routes.NewValue(routes.FlagsRemoteHost))
	addMaglevICMPRoute(node3CIDR, routes.NewValue(routes.FlagsLocalHost))

	// With two backends, a hash over the wrong tuple orientation still picks
	// the right node about half the time, so check enough flows that a match
	// by chance is negligible.
	seenNodes := map[string]bool{}
	for clientPort := uint16(40000); clientPort < 40012; clientPort++ {
		_, _, _, _, synBytes, err := testPacketTCPV4WithPayload(maglevICMPServiceIP, clientPort, maglevICMPServicePort, true, nil)
		Expect(err).NotTo(HaveOccurred())

		var flowNode string
		runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
			res, err := bpfrun(synBytes)
			Expect(err).NotTo(HaveOccurred())
			Expect(retvalToStr[res.Retval]).To(Equal(retvalToStr[resTC_ACT_REDIRECT]))
			pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
			flowNode = pktR.Layer(layers.LayerTypeIPv4).(*layers.IPv4).DstIP.String()
		})
		seenNodes[flowNode] = true

		// The error lands on a node that never saw the flow.
		resetCTMap(ctMap)
		skbMark = 0

		icmpBytes := maglevFragNeeded(clientPort)
		runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
			res, err := bpfrun(icmpBytes)
			Expect(err).NotTo(HaveOccurred())
			Expect(retvalToStr[res.Retval]).To(Equal(retvalToStr[resTC_ACT_REDIRECT]))

			pktR := gopacket.NewPacket(res.dataOut, layers.LayerTypeEthernet, gopacket.Default)
			fmt.Printf("pktR = %+v\n", pktR)
			outer := pktR.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
			Expect(outer.SrcIP.String()).To(Equal(hostIP.String()))
			Expect(outer.DstIP.String()).To(Equal(flowNode),
				fmt.Sprintf("client port %d: ICMP error sent to a different node than its flow", clientPort))

			// The backend's node holds the CT entry and does the NAT, so the
			// error travels unmodified.
			inner := checkVxlan(pktR)
			innerIP := inner.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
			Expect(innerIP.SrcIP.String()).To(Equal(maglevICMPRouterIP.String()))
			Expect(innerIP.DstIP.String()).To(Equal(maglevICMPServiceIP.String()))
			Expect(inner.Layer(layers.LayerTypeICMPv4)).NotTo(BeNil())
		})

		expectCTMapEmpty()
		skbMark = 0
	}
	Expect(seenNodes).To(HaveLen(2), "test flows should exercise both backends")
}

func TestMaglevICMPErrorWithoutCTLocalBackendUnchanged(t *testing.T) {
	RegisterTestingT(t)

	defer resetBPFMaps()
	resetBPFMaps()
	hostIP = node1ip
	skbMark = 0
	bpfIfaceName = "MICl"
	defer func() { bpfIfaceName = "" }()

	backend := maglevICMPBackend{net.IPv4(8, 8, 8, 8).To4(), 666}
	setupMaglevICMPService(nat.NATFlgMaglev, backend)

	addMaglevICMPRoute(net.IPNet{IP: backend.ip, Mask: net.CIDRMask(32, 32)},
		routes.NewValueWithIfIndex(routes.FlagsLocalWorkload|routes.FlagInIPAMPool, 1))
	addMaglevICMPRoute(node1CIDR, routes.NewValue(routes.FlagsLocalHost))

	// A real flow to a local backend would have a CT entry here, so the error
	// must not be delivered to the pod on the strength of the LUT alone.
	icmpBytes := maglevFragNeeded(40000)
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(icmpBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(retvalToStr[res.Retval]).To(Equal(retvalToStr[resTC_ACT_UNSPEC]))
		Expect(res.dataOut).To(Equal(icmpBytes))
	})

	expectCTMapEmpty()
}

func TestICMPErrorWithoutCTNonMaglevServiceUnchanged(t *testing.T) {
	RegisterTestingT(t)

	defer resetBPFMaps()
	resetBPFMaps()
	hostIP = node1ip
	skbMark = 0
	bpfIfaceName = "MICn"
	defer func() { bpfIfaceName = "" }()

	backend := maglevICMPBackend{net.IPv4(8, 8, 8, 8).To4(), 666}
	setupMaglevICMPService(0, backend)
	addMaglevICMPRoute(node1CIDR, routes.NewValue(routes.FlagsLocalHost))

	icmpBytes := maglevFragNeeded(40000)
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(icmpBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(retvalToStr[res.Retval]).To(Equal(retvalToStr[resTC_ACT_UNSPEC]))
		Expect(res.dataOut).To(Equal(icmpBytes))
	})

	expectCTMapEmpty()
}

func TestMaglevICMPErrorForwardedToBackendNodeKeepsFlowTunnel(t *testing.T) {
	RegisterTestingT(t)

	defer resetBPFMaps()
	resetBPFMaps()
	skbMark = 0
	defer func() { bpfIfaceName = "" }()

	backend := maglevICMPBackend{net.IPv4(8, 8, 8, 8).To4(), 666}
	backendCIDR := net.IPNet{IP: backend.ip, Mask: net.CIDRMask(32, 32)}
	setupMaglevICMPService(nat.NATFlgMaglev, backend)

	ingressRoutes := func(local net.IPNet) {
		resetRTMap(rtMap)
		addMaglevICMPRoute(backendCIDR,
			routes.NewValueWithNextHop(routes.FlagsRemoteWorkload|routes.FlagInIPAMPool, ip.FromNetIP(node2ip).(ip.V4Addr)))
		for _, cidr := range []net.IPNet{node1CIDR, node2CIDR, node3CIDR} {
			flags := routes.FlagsRemoteHost
			if cidr.String() == local.String() {
				flags = routes.FlagsLocalHost
			}
			addMaglevICMPRoute(cidr, routes.NewValue(flags))
		}
	}

	clientPort := uint16(40000)
	_, _, _, _, synBytes, err := testPacketTCPV4WithPayload(maglevICMPServiceIP, clientPort, maglevICMPServicePort, true, nil)
	Expect(err).NotTo(HaveOccurred())

	// The flow ingresses on node 3.
	hostIP = node3ip
	bpfIfaceName = "MICf3"
	ingressRoutes(node3CIDR)
	var encapSYN []byte
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(synBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(retvalToStr[res.Retval]).To(Equal(retvalToStr[resTC_ACT_REDIRECT]))
		encapSYN = res.dataOut
	})

	// The ICMP error for it lands on node 1.
	resetCTMap(ctMap)
	skbMark = 0
	hostIP = node1ip
	bpfIfaceName = "MICf1"
	ingressRoutes(node1CIDR)
	var encapICMP []byte
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(maglevFragNeeded(clientPort))
		Expect(err).NotTo(HaveOccurred())
		Expect(retvalToStr[res.Retval]).To(Equal(retvalToStr[resTC_ACT_REDIRECT]))
		encapICMP = res.dataOut
	})

	// Node 2 hosts the backend and learns the flow from node 3's tunnel.
	resetCTMap(ctMap)
	resetRTMap(rtMap)
	skbMark = 0
	hostIP = node2ip
	bpfIfaceName = "MICf2"
	addMaglevICMPRoute(backendCIDR, routes.NewValueWithIfIndex(routes.FlagsLocalWorkload|routes.FlagInIPAMPool, 1))
	addMaglevICMPRoute(node1CIDR, routes.NewValue(routes.FlagsRemoteHost))
	addMaglevICMPRoute(node2CIDR, routes.NewValue(routes.FlagsLocalHost))
	addMaglevICMPRoute(node3CIDR, routes.NewValue(routes.FlagsRemoteHost))

	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(encapSYN)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).NotTo(Equal(resTC_ACT_SHOT))
	})

	revKey := conntrack.NewKey(uint8(layers.IPProtocolTCP), srcIP.To4(), clientPort, backend.ip, backend.port)
	expectFlowTunnel := func() {
		ct, err := conntrack.LoadMapMem(ctMap)
		Expect(err).NotTo(HaveOccurred())
		Expect(ct).To(HaveKey(revKey))
		Expect(ct[revKey].Data().TunIP.String()).To(Equal(node3ip.String()))
	}
	expectFlowTunnel()

	skbMark = 0
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(encapICMP)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).NotTo(Equal(resTC_ACT_SHOT))
		checkICMP(res.dataOut, maglevICMPRouterIP, backend.ip, backend.ip, srcIP,
			layers.IPProtocolTCP, backend.port, clientPort)
	})

	// The flow's replies must still go back through node 3.
	expectFlowTunnel()
}

// The new path never handles an error that lands on the backend's node
// directly: that node's CT entry delivers it.
func TestMaglevICMPErrorDirectToBackendNodeDeliveredByCT(t *testing.T) {
	RegisterTestingT(t)

	defer resetBPFMaps()
	resetBPFMaps()
	skbMark = 0
	defer func() { bpfIfaceName = "" }()

	backend := maglevICMPBackend{net.IPv4(8, 8, 8, 8).To4(), 666}
	backendCIDR := net.IPNet{IP: backend.ip, Mask: net.CIDRMask(32, 32)}
	setupMaglevICMPService(nat.NATFlgMaglev, backend)

	clientPort := uint16(40000)
	_, _, _, _, synBytes, err := testPacketTCPV4WithPayload(maglevICMPServiceIP, clientPort, maglevICMPServicePort, true, nil)
	Expect(err).NotTo(HaveOccurred())

	// The flow ingresses on node 3.
	hostIP = node3ip
	bpfIfaceName = "MICd3"
	resetRTMap(rtMap)
	addMaglevICMPRoute(backendCIDR,
		routes.NewValueWithNextHop(routes.FlagsRemoteWorkload|routes.FlagInIPAMPool, ip.FromNetIP(node2ip).(ip.V4Addr)))
	addMaglevICMPRoute(node2CIDR, routes.NewValue(routes.FlagsRemoteHost))
	addMaglevICMPRoute(node3CIDR, routes.NewValue(routes.FlagsLocalHost))
	var encapSYN []byte
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(synBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(retvalToStr[res.Retval]).To(Equal(retvalToStr[resTC_ACT_REDIRECT]))
		encapSYN = res.dataOut
	})

	// Node 2 hosts the backend and learns the flow from node 3's tunnel.
	resetCTMap(ctMap)
	resetRTMap(rtMap)
	skbMark = 0
	hostIP = node2ip
	bpfIfaceName = "MICd2"
	addMaglevICMPRoute(backendCIDR, routes.NewValueWithIfIndex(routes.FlagsLocalWorkload|routes.FlagInIPAMPool, 1))
	addMaglevICMPRoute(node2CIDR, routes.NewValue(routes.FlagsLocalHost))
	addMaglevICMPRoute(node3CIDR, routes.NewValue(routes.FlagsRemoteHost))
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(encapSYN)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).NotTo(Equal(resTC_ACT_SHOT))
	})
	ctBefore, err := conntrack.LoadMapMem(ctMap)
	Expect(err).NotTo(HaveOccurred())

	// The error reaches node 2 straight from the router, not through a tunnel.
	skbMark = 0
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(maglevFragNeeded(clientPort))
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).NotTo(Equal(resTC_ACT_SHOT))
		checkICMP(res.dataOut, maglevICMPRouterIP, backend.ip, backend.ip, srcIP,
			layers.IPProtocolTCP, backend.port, clientPort)
	})

	ctAfter, err := conntrack.LoadMapMem(ctMap)
	Expect(err).NotTo(HaveOccurred())
	Expect(ctAfter).To(HaveLen(len(ctBefore)))
}
