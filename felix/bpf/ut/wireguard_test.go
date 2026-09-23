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

	"github.com/projectcalico/calico/felix/bpf/polprog"
	"github.com/projectcalico/calico/felix/bpf/routes"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/proto"
)

// Host-terminated traffic on a host interface is governed by host endpoint
// policy (HostNormalTiers with ForHostInterface set), not by the workload
// policy carried in Tiers. denyAllRulesHost (from failsafes_test.go) is the
// deny-all counterpart.
var allowAllRulesHost = &polprog.Rules{
	ForHostInterface: true,
	HostNormalTiers: []polprog.Tier{{
		Policies: []polprog.Policy{{
			Name:  "allow all",
			Rules: []polprog.Rule{{Rule: &proto.Rule{Action: "Allow"}}},
		}},
	}},
}

// WG_PORT is Calico's configured WireGuard port (default 51820), which also
// happens to be the stock WireGuard port. When a host endpoint sees traffic on
// that port to/from a known Calico host, it is fast-allowed so that a user's HEP
// policy cannot accidentally break the cluster's own host-to-host WireGuard mesh.
// Any other traffic on that port must fall through to policy rather than be
// dropped outright - it may belong to a user-managed WireGuard tunnel that is
// unrelated to Calico. See issue #12900.
func TestWireguardPortFromHEP(t *testing.T) {
	RegisterTestingT(t)
	defer resetBPFMaps()

	// The node terminates the WireGuard tunnel, so the packets are destined to
	// the local host on WG_PORT.
	err := rtMap.Update(
		routes.NewKey(ip.CIDRFromIPNet(&net.IPNet{IP: hostIP, Mask: net.CIDRMask(32, 32)}).(ip.V4CIDR)).AsBytes(),
		routes.NewValue(routes.FlagsLocalHost).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())

	wgPacket := func(src net.IP) []byte {
		ipv4 := *ipv4Default
		ipv4.SrcIP = src
		ipv4.DstIP = hostIP
		udp := &layers.UDP{SrcPort: layers.UDPPort(testWGPort), DstPort: layers.UDPPort(testWGPort)}
		_, _, _, _, pktBytes, err := testPacketV4(nil, &ipv4, udp, nil)
		Expect(err).NotTo(HaveOccurred())
		return pktBytes
	}

	// An allowed packet may end as TC_ACT_UNSPEC or, when the FIB forwards it,
	// TC_ACT_REDIRECT; only TC_ACT_SHOT means dropped. So we assert on
	// dropped-vs-not rather than the exact allow code.
	runWG := func(src net.IP, rules *polprog.Rules, dropped bool) {
		// Clear conntrack so each case is decided fresh, not by a CT entry
		// left behind by a previously-allowed run.
		resetCTMap(ctMap)
		skbMark = 0
		runBpfTest(t, "calico_from_host_ep", rules, func(bpfrun bpfProgRunFn) {
			res, err := bpfrun(wgPacket(src))
			Expect(err).NotTo(HaveOccurred())
			if dropped {
				Expect(res.Retval).To(Equal(resTC_ACT_SHOT))
			} else {
				Expect(res.Retval).NotTo(Equal(resTC_ACT_SHOT))
			}
		}, withWgPort(testWGPort))
	}

	// srcIP has no route: not a known Calico host. The packet must not be
	// dropped at parse - it falls through to host policy, which allows it here.
	t.Log("WG from unknown source, allow-all policy -> ALLOW (fall through to policy)")
	runWG(srcIP, allowAllRulesHost, false)

	// The same unknown-source packet must be governed by policy, so a deny
	// policy drops it. Combined with the allow-all case above, this confirms
	// the packet reaches policy rather than being decided at parse.
	t.Log("WG from unknown source, deny-all policy -> DROP (policy governs)")
	runWG(srcIP, &denyAllRulesHost, true)

	// node2ip is a known remote Calico host: the WG packet is fast-allowed and
	// bypasses policy, so even a deny-all policy does not drop it. This keeps
	// the cluster's own WireGuard mesh working regardless of HEP policy.
	t.Log("WG from known Calico host, deny-all policy -> ALLOW (fast path bypasses policy)")
	err = rtMap.Update(
		routes.NewKey(ip.CIDRFromIPNet(&net.IPNet{IP: node2ip, Mask: net.CIDRMask(32, 32)}).(ip.V4CIDR)).AsBytes(),
		routes.NewValue(routes.FlagsRemoteHost).AsBytes(),
	)
	Expect(err).NotTo(HaveOccurred())
	runWG(node2ip, &denyAllRulesHost, false)
}
