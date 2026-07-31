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
	"testing"

	"github.com/google/gopacket/layers"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/bpf/conntrack"
	"github.com/projectcalico/calico/felix/bpf/counters"
	"github.com/projectcalico/calico/felix/bpf/hook"
	"github.com/projectcalico/calico/felix/bpf/routes"
	tcdefs "github.com/projectcalico/calico/felix/bpf/tc/defs"
)

const (
	redirPeerProtoTCP = 6
	redirPeerSrcPort  = 54321
	redirPeerDstPort  = 7890
	// The harness runs every program as if attached to ifindex 1, and keys the
	// route and counter maps on it.
	redirPeerIfindex = 1
)

// testPacketTCPV4WithPayload does not exist on this branch, so build the
// segment directly. Only the SYN flag matters to what is under test.
func redirPeerTCPPacket(syn bool) []byte {
	tcp := &layers.TCP{
		SrcPort:    redirPeerSrcPort,
		DstPort:    redirPeerDstPort,
		SYN:        syn,
		DataOffset: 5,
	}

	_, _, _, _, pkt, err := testPacketV4(nil, nil, tcp, nil)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())

	return pkt
}

// bpf_redirect_peer hands the packet straight into the destination's network
// namespace, so the destination endpoint's program - and therefore its policy -
// never runs. That is only sound while ESTABLISHED_BYPASS really means "both
// endpoints approved their own leg".
//
// A host-endpoint program breaks that assumption. When it updates an entry for
// a packet that is already marked as seen it approves the leg facing away from
// the host, because it expects the endpoint on that side to be off-node. A
// packet on its way to a local workload can still reach a host endpoint: the
// destination's route is programmed asynchronously, so until it lands the FIB
// forwards the packet out of the node. The host endpoint then approves the
// local workload's leg on its behalf and the entry reads as fully approved
// before the workload has ever seen a packet.
//
// Withholding the peer redirect from SYNs keeps the destination in the path for
// every new connection, where its program forces policy.
func TestNoPeerRedirectForTCPSYN(t *testing.T) {
	RegisterTestingT(t)

	bpfIfaceName = "RPsyn"
	defer func() { bpfIfaceName = "" }()
	defer cleanUpMaps()

	hostIP = node1ip

	resetCTMap(ctMap)
	resetRTMap(rtMap)
	defer resetRTMap(rtMap)

	// srcIP:sport sorts below dstIP:dport, so src_lt_dest() puts the source on
	// the A side: A2B is the source's own leg, B2A the destination's.
	synPkt := redirPeerTCPPacket(true)
	ackPkt := redirPeerTCPPacket(false)

	ctKey := conntrack.NewKey(redirPeerProtoTCP, srcIP, redirPeerSrcPort, dstIP, redirPeerDstPort)

	// The source workload is local. The destination's route is deliberately
	// absent: this is the window in which its packets are still forwarded out
	// of the node.
	err := rtMap.Update(
		routes.NewKey(srcV4CIDR).AsBytes(),
		routes.NewValueWithIfIndex(routes.FlagsLocalWorkload|routes.FlagInIPAMPool, redirPeerIfindex).AsBytes())
	Expect(err).NotTo(HaveOccurred())

	t.Log("SYN from the source workload creates the entry")

	skbMark = 0
	runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(synPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_REDIRECT))

		ct, err := conntrack.LoadMapMem(ctMap)
		Expect(err).NotTo(HaveOccurred())
		Expect(ct).To(HaveKey(ctKey))
		Expect(ct[ctKey].Data().A2B.Approved).To(BeTrue())
		Expect(ct[ctKey].Data().B2A.Approved).To(BeFalse())
	}, withRedirectPeer())

	expectMark(tcdefs.MarkSeen)

	t.Log("the misrouted SYN reaches the host endpoint, which approves the destination's leg")

	runBpfTest(t, "calico_to_host_ep", nil, func(bpfrun bpfProgRunFn) {
		_, err := bpfrun(synPkt)
		Expect(err).NotTo(HaveOccurred())

		ct, err := conntrack.LoadMapMem(ctMap)
		Expect(err).NotTo(HaveOccurred())
		Expect(ct).To(HaveKey(ctKey))
		// Not being a workload interface, the host endpoint records the leg as
		// non-workload. The entry now reads as fully approved.
		Expect(ct[ctKey].Data().A2B.Approved).To(BeTrue())
		Expect(ct[ctKey].Data().B2A.Approved).To(BeTrue())
		Expect(ct[ctKey].Data().B2A.Workload).To(BeFalse())
	}, withRedirectPeer())

	// The destination's route lands. From here the source's program sees a
	// local workload and would take the peer redirect if the conntrack verdict
	// allowed it.
	err = rtMap.Update(
		routes.NewKey(dstV4CIDR).AsBytes(),
		routes.NewValueWithIfIndex(routes.FlagsLocalWorkload|routes.FlagInIPAMPool, redirPeerIfindex).AsBytes())
	Expect(err).NotTo(HaveOccurred())

	t.Log("the retransmitted SYN must not be peer-redirected")

	Expect(counters.Flush(countersMap, redirPeerIfindex, hook.Ingress)).NotTo(HaveOccurred())

	skbMark = 0
	runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		_, err := bpfrun(synPkt)
		Expect(err).NotTo(HaveOccurred())
	}, withRedirectPeer())

	c, err := counters.Read(countersMap, redirPeerIfindex, hook.Ingress)
	Expect(err).NotTo(HaveOccurred())
	Expect(c[counters.RedirectPeer]).To(BeZero(),
		"a TCP SYN redirected to the peer would skip the destination's policy")

	t.Log("a non-SYN packet on the same entry still takes the fast path")

	Expect(counters.Flush(countersMap, redirPeerIfindex, hook.Ingress)).NotTo(HaveOccurred())

	skbMark = 0
	runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(ackPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_REDIRECT))
	}, withRedirectPeer())

	c, err = counters.Read(countersMap, redirPeerIfindex, hook.Ingress)
	Expect(err).NotTo(HaveOccurred())
	Expect(c[counters.RedirectPeer]).To(BeNumerically("==", 1),
		"established traffic must still take the peer-redirect fast path")
}

// TestPoisonedLegDoesNotBypassDestinationPolicy covers the other half of the SYN
// detour: what the destination's program does once the packet reaches it. The
// conntrack entry says the flow is established and approved by both sides, but
// the SYN flag makes the program run policy anyway, so a deny still drops the
// packet.
//
// The entry itself is left as it was. The destination's program allows or drops
// on the strength of policy without rewriting the leg the host endpoint
// approved, so the entry keeps reading as fully approved either way.
func TestPoisonedLegDoesNotBypassDestinationPolicy(t *testing.T) {
	RegisterTestingT(t)

	bpfIfaceName = "RPpol"
	defer func() { bpfIfaceName = "" }()
	defer cleanUpMaps()

	hostIP = node1ip

	resetCTMap(ctMap)
	resetRTMap(rtMap)
	defer resetRTMap(rtMap)

	synPkt := redirPeerTCPPacket(true)

	ctKey := conntrack.NewKey(redirPeerProtoTCP, srcIP, redirPeerSrcPort, dstIP, redirPeerDstPort)

	err := rtMap.Update(
		routes.NewKey(srcV4CIDR).AsBytes(),
		routes.NewValueWithIfIndex(routes.FlagsLocalWorkload|routes.FlagInIPAMPool, redirPeerIfindex).AsBytes())
	Expect(err).NotTo(HaveOccurred())

	skbMark = 0
	runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(synPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_REDIRECT))
	}, withRedirectPeer())

	expectMark(tcdefs.MarkSeen)

	runBpfTest(t, "calico_to_host_ep", nil, func(bpfrun bpfProgRunFn) {
		_, err := bpfrun(synPkt)
		Expect(err).NotTo(HaveOccurred())
	}, withRedirectPeer())

	ct, err := conntrack.LoadMapMem(ctMap)
	Expect(err).NotTo(HaveOccurred())
	Expect(ct[ctKey].Data().A2B.Approved).To(BeTrue())
	Expect(ct[ctKey].Data().B2A.Approved).To(BeTrue())

	err = rtMap.Update(
		routes.NewKey(dstV4CIDR).AsBytes(),
		routes.NewValueWithIfIndex(routes.FlagsLocalWorkload|routes.FlagInIPAMPool, redirPeerIfindex).AsBytes())
	Expect(err).NotTo(HaveOccurred())

	t.Log("the destination's policy denies the SYN despite the approved entry")

	ctSaved := saveCTMap(ctMap)

	skbMark = tcdefs.MarkSeen
	runBpfTest(t, "calico_to_workload_ep", &denyAllRulesWorkloads, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(synPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(resTC_ACT_SHOT))
	}, withRedirectPeer())

	t.Log("and allows it when policy allows")

	restoreCTMap(ctMap, ctSaved)

	skbMark = tcdefs.MarkSeen
	runBpfTest(t, "calico_to_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(synPkt)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).NotTo(Equal(resTC_ACT_SHOT))
	}, withRedirectPeer())
}
