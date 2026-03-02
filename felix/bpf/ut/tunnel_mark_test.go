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

	. "github.com/onsi/gomega"
	"github.com/vishvananda/netlink"

	"github.com/projectcalico/calico/felix/bpf/conntrack"
	"github.com/projectcalico/calico/felix/bpf/routes"
	tcdefs "github.com/projectcalico/calico/felix/bpf/tc/defs"
	"github.com/projectcalico/calico/felix/ip"
)

func TestTunnelMarkSet(t *testing.T) {
	RegisterTestingT(t)

	bpfIfaceName = "TNL"
	defer func() { bpfIfaceName = "" }()
	defer cleanUpMaps()

	// Create a dummy device to simulate the tunnel device so bpf_fib_lookup
	// can resolve the destination and return an ifindex.
	dummy := createHostIf("tunl_test0")
	defer func() { _ = netlink.LinkDel(dummy) }()

	// Bring the device up (createHostIf sets the flag but we need the kernel
	// to actually transition it).
	err := netlink.LinkSetUp(dummy)
	Expect(err).NotTo(HaveOccurred())

	// Add a host route for the destination CIDR via the dummy device so
	// bpf_fib_lookup resolves it.
	destCIDR := &net.IPNet{
		IP:   net.IPv4(2, 2, 2, 0).To4(),
		Mask: net.IPv4Mask(255, 255, 255, 0),
	}
	err = netlink.RouteAdd(&netlink.Route{
		Dst:       destCIDR,
		LinkIndex: dummy.Attrs().Index,
	})
	Expect(err).NotTo(HaveOccurred())

	_, _, _, _, pktBytes, err := testPacketUDPDefault()
	Expect(err).NotTo(HaveOccurred())

	resetCTMap(ctMap) // ensure it is clean

	hostIP = node1ip

	// Insert a reverse route for the source workload.
	rtKey := routes.NewKey(srcV4CIDR).AsBytes()
	rtVal := routes.NewValueWithIfIndex(routes.FlagsLocalWorkload|routes.FlagInIPAMPool, 1).AsBytes()
	defer resetRTMap(rtMap)
	err = rtMap.Update(rtKey, rtVal)
	Expect(err).NotTo(HaveOccurred())

	// Insert route to the destination as a tunneled remote workload.
	err = rtMap.Update(
		routes.NewKey(ip.CIDRFromIPNet(destCIDR).(ip.V4CIDR)).AsBytes(),
		routes.NewValueWithNextHop(
			routes.FlagsRemoteWorkload|routes.FlagInIPAMPool|routes.FlagTunneled,
			ip.FromNetIP(node2ip).(ip.V4Addr),
		).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	skbMark = 0
	// Leaving workload — should set the tunnel key and mark.
	runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_REDIRECT))

		// Verify conntrack entry was created.
		ct, err := conntrack.LoadMapMem(ctMap)
		Expect(err).NotTo(HaveOccurred())
		Expect(ct).NotTo(BeEmpty())
	})

	expectMark(tcdefs.MarkSeenTunnelKeySet)
}
