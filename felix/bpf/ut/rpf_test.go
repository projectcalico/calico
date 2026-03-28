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
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

// deleteDefaultRoutes removes only the default routes (0.0.0.0/0 or ::/0) for
// the given address family and returns a function that restores them. Without a
// default route, bpf_fib_lookup returns BPF_FIB_LKUP_RET_NOT_FWDED for IPs
// that don't match a more specific route.
func deleteDefaultRoutes(family int) func() {
	routes, err := netlink.RouteList(nil, family)
	if err != nil {
		log.WithError(err).Warn("Failed to list routes")
		return func() {}
	}

	var deleted []netlink.Route
	for i := range routes {
		// Default routes have nil or zero-length Dst.
		if routes[i].Dst == nil || routes[i].Dst.IP.IsUnspecified() {
			if err := netlink.RouteDel(&routes[i]); err != nil {
				log.WithError(err).WithField("route", routes[i]).Warn("Failed to delete default route")
			} else {
				deleted = append(deleted, routes[i])
			}
		}
	}

	return func() {
		for i := range deleted {
			if err := netlink.RouteAdd(&deleted[i]); err != nil {
				log.WithError(err).WithField("route", deleted[i]).Warn("Failed to restore default route")
			}
		}
	}
}

// runWithoutDefaultRoutes deletes default routes for the given family, runs fn,
// then restores them. The restore always runs even if fn panics.
func runWithoutDefaultRoutes(family int, fn func()) {
	restoreRoutes := deleteDefaultRoutes(family)
	defer restoreRoutes()
	fn()
}

func TestDHCPv4BypassesHEPRPF(t *testing.T) {
	RegisterTestingT(t)

	bpfIfaceName = "DHrpf"
	defer func() { bpfIfaceName = "" }()
	defer cleanUpMaps()

	hostIP = node1ip

	// DHCP server -> client (offer/ack): sport=67, dport=68
	// Use a random source IP that simulates an external DHCP server (e.g., AWS).
	dhcpServerIP := net.IPv4(172, 31, 0, 1).To4()
	ipHdr := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		SrcIP:    dhcpServerIP,
		DstIP:    node1ip,
		Protocol: layers.IPProtocolUDP,
	}
	udpHdr := &layers.UDP{
		SrcPort: 67,
		DstPort: 68,
	}

	_, _, _, _, pktBytes, err := testPacketV4(nil, ipHdr, udpHdr, nil)
	Expect(err).NotTo(HaveOccurred())

	resetCTMap(ctMap)
	defer resetCTMap(ctMap)

	skbMark = 0
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		runWithoutDefaultRoutes(netlink.FAMILY_V4, func() {
			res, err := bpfrun(pktBytes)
			Expect(err).NotTo(HaveOccurred())
			Expect(res.Retval).NotTo(Equal(resTC_ACT_SHOT),
				"DHCPv4 packet (sport=67, dport=68) should not be dropped by RPF")
		})
	}, withRPFEnforce("strict"))
}

func TestNonDHCPBlockedByHEPRPF(t *testing.T) {
	RegisterTestingT(t)

	bpfIfaceName = "NDrpf"
	defer func() { bpfIfaceName = "" }()
	defer cleanUpMaps()

	hostIP = node1ip

	// Regular UDP packet (not DHCP) from an unroutable source.
	unroutableIP := net.IPv4(172, 31, 0, 1).To4()
	ipHdr := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		SrcIP:    unroutableIP,
		DstIP:    node1ip,
		Protocol: layers.IPProtocolUDP,
	}
	udpHdr := &layers.UDP{
		SrcPort: 12345,
		DstPort: 5678,
	}

	_, _, _, _, pktBytes, err := testPacketV4(nil, ipHdr, udpHdr, nil)
	Expect(err).NotTo(HaveOccurred())

	resetCTMap(ctMap)
	defer resetCTMap(ctMap)

	skbMark = 0
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		runWithoutDefaultRoutes(netlink.FAMILY_V4, func() {
			res, err := bpfrun(pktBytes)
			Expect(err).NotTo(HaveOccurred())
			Expect(res.Retval).To(Equal(resTC_ACT_SHOT),
				"Non-DHCP packet from unroutable source should be dropped by RPF")
		})
	}, withRPFEnforce("strict"))
}

func TestDHCPv6LinkLocalBypassesHEPRPF(t *testing.T) {
	RegisterTestingT(t)

	bpfIfaceName = "D6rpf"
	defer func() { bpfIfaceName = "" }()
	defer cleanUpMaps()

	hostIP = node1ipV6

	// DHCPv6 uses link-local addresses. The existing ip_link_local check
	// in the NOT_FWDED path should allow these through.
	linkLocalSrc := net.ParseIP("fe80::1").To16()
	linkLocalDst := net.ParseIP("fe80::2").To16()
	ipHdr := &layers.IPv6{
		Version:    6,
		HopLimit:   64,
		SrcIP:      linkLocalSrc,
		DstIP:      linkLocalDst,
		NextHeader: layers.IPProtocolUDP,
	}
	udpHdr := &layers.UDP{
		SrcPort: 546,
		DstPort: 547,
	}

	_, _, _, _, pktBytes, err := testPacketV6(nil, ipHdr, udpHdr, nil)
	Expect(err).NotTo(HaveOccurred())

	resetCTMap(ctMapV6)
	defer resetCTMap(ctMapV6)

	skbMark = 0
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		runWithoutDefaultRoutes(netlink.FAMILY_V6, func() {
			res, err := bpfrun(pktBytes)
			Expect(err).NotTo(HaveOccurred())
			Expect(res.Retval).NotTo(Equal(resTC_ACT_SHOT),
				"DHCPv6 link-local packet should not be dropped by RPF")
		})
	}, withIPv6(), withRPFEnforce("strict"))
}

func TestNonLinkLocalV6BlockedByHEPRPF(t *testing.T) {
	RegisterTestingT(t)

	bpfIfaceName = "N6rpf"
	defer func() { bpfIfaceName = "" }()
	defer cleanUpMaps()

	hostIP = node1ipV6

	// Non-link-local source that has no route should be dropped.
	unroutableSrc := net.ParseIP("2001:db8::dead").To16()
	ipHdr := &layers.IPv6{
		Version:    6,
		HopLimit:   64,
		SrcIP:      unroutableSrc,
		DstIP:      node1ipV6,
		NextHeader: layers.IPProtocolUDP,
	}
	udpHdr := &layers.UDP{
		SrcPort: 12345,
		DstPort: 5678,
	}

	_, _, _, _, pktBytes, err := testPacketV6(nil, ipHdr, udpHdr, nil)
	Expect(err).NotTo(HaveOccurred())

	resetCTMap(ctMapV6)
	defer resetCTMap(ctMapV6)

	skbMark = 0
	runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
		runWithoutDefaultRoutes(netlink.FAMILY_V6, func() {
			res, err := bpfrun(pktBytes)
			Expect(err).NotTo(HaveOccurred())
			Expect(res.Retval).To(Equal(resTC_ACT_SHOT),
				"Non-link-local IPv6 packet from unroutable source should be dropped by RPF")
		})
	}, withIPv6(), withRPFEnforce("strict"))
}
