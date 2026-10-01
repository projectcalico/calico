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

	"github.com/gopacket/gopacket/layers"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/bpf/conntrack"
	"github.com/projectcalico/calico/felix/bpf/routes"
	tcdefs "github.com/projectcalico/calico/felix/bpf/tc/defs"
)

// These tests pin, per conntrack-writing program, which leg of a NORMAL entry
// gets its approved and workload bits set. The bits carry the entry's policy
// state: approved on a leg means "the policy of the endpoint on that side
// passed", and workload means "and that endpoint is a workload". Several
// verdicts consume them - the both-legs-approved check behind
// CALI_CT_ESTABLISHED_BYPASS, the per-leg check that sends an unapproved
// side's packets back through policy, and CT_RES_TO_WORKLOAD, which gates
// redirects. A site writing either bit on the wrong leg, or writing approved
// without workload for a workload endpoint, silently changes which flows can
// skip policy, so every writing site is pinned here.
//
// The writes happen in conntrack_create (conntrack.h): four create arms for a
// conntrack miss, keyed on the program type, and two update arms for a packet
// that carries the seen mark and hits an existing entry. The NAT-specific
// sites (the to-HEP source-port-collision arm and the from-HEP allow_return
// tunnel arm) write to NAT entries, which the BYPASS verdict does not consume;
// they are exercised by the NAT tests.
//
// All packets here are the default UDP packet, whose source sorts below its
// destination, so A2B is always the source's leg and B2A the destination's.

// ctAuditKey returns the entry key for the default UDP test packet.
func ctAuditKey(ipv4 *layers.IPv4, udp *layers.UDP) conntrack.Key {
	return conntrack.NewKey(uint8(ipv4.Protocol),
		ipv4.SrcIP, uint16(udp.SrcPort), ipv4.DstIP, uint16(udp.DstPort))
}

func ctAuditLoadEntry(k conntrack.Key) conntrack.Value {
	ct, err := conntrack.LoadMapMem(ctMap)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	ExpectWithOffset(1, ct).To(HaveKey(k))
	return ct[k]
}

func ctAuditExpectLegs(v conntrack.Value, srcApproved, srcWorkload, dstApproved, dstWorkload bool) {
	d := v.Data()
	ExpectWithOffset(1, d.A2B.Approved).To(Equal(srcApproved), "source leg approved")
	ExpectWithOffset(1, d.A2B.Workload).To(Equal(srcWorkload), "source leg workload")
	ExpectWithOffset(1, d.B2A.Approved).To(Equal(dstApproved), "destination leg approved")
	ExpectWithOffset(1, d.B2A.Workload).To(Equal(dstWorkload), "destination leg workload")
}

// TestCTApprovalOnCreate covers the create arms: a conntrack miss at each
// program type, policy allowing, so conntrack_create builds a fresh entry.
func TestCTApprovalOnCreate(t *testing.T) {
	RegisterTestingT(t)

	bpfIfaceName = "APcr"
	defer func() { bpfIfaceName = "" }()
	defer cleanUpMaps()

	hostIP = node1ip

	_, ipv4, l4, _, pktBytes, err := testPacketUDPDefault()
	Expect(err).NotTo(HaveOccurred())
	udp := l4.(*layers.UDP)
	ctKey := ctAuditKey(ipv4, udp)

	localWEP := routes.NewValueWithIfIndex(routes.FlagsLocalWorkload|routes.FlagInIPAMPool, 1).AsBytes()
	remoteWEP := routes.NewValue(routes.FlagsRemoteWorkload | routes.FlagInIPAMPool).AsBytes()
	localHost := routes.NewValue(routes.FlagsLocalHost).AsBytes()
	remoteHost := routes.NewValue(routes.FlagsRemoteHost).AsBytes()
	srcRT := routes.NewKey(srcV4CIDR).AsBytes()
	dstRT := routes.NewKey(dstV4CIDR).AsBytes()

	t.Run("from-WEP: pod egress", func(t *testing.T) {
		// The workload's own program approves the workload's leg and records
		// it as a workload approval.
		resetCTMap(ctMap)
		resetRTMap(rtMap)
		Expect(rtMap.Update(srcRT, localWEP)).NotTo(HaveOccurred())

		skbMark = 0
		runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
			_, err := bpfrun(pktBytes)
			Expect(err).NotTo(HaveOccurred())
			ctAuditExpectLegs(ctAuditLoadEntry(ctKey), true, true, false, false)
		})
	})

	t.Run("from-HEP: external client enters the node", func(t *testing.T) {
		// The host endpoint approves the external side's leg. That side is not
		// a workload, so the workload bit correctly stays clear.
		resetCTMap(ctMap)
		resetRTMap(rtMap)
		Expect(rtMap.Update(srcRT, remoteWEP)).NotTo(HaveOccurred())
		Expect(rtMap.Update(dstRT, localWEP)).NotTo(HaveOccurred())

		skbMark = 0
		runBpfTest(t, "calico_from_host_ep", nil, func(bpfrun bpfProgRunFn) {
			_, err := bpfrun(pktBytes)
			Expect(err).NotTo(HaveOccurred())
			ctAuditExpectLegs(ctAuditLoadEntry(ctKey), true, false, false, false)
		})
	})

	t.Run("to-WEP: host process to local pod", func(t *testing.T) {
		// The workload's own program approves the workload's leg as a workload approval.
		resetCTMap(ctMap)
		resetRTMap(rtMap)
		Expect(rtMap.Update(srcRT, localHost)).NotTo(HaveOccurred())
		Expect(rtMap.Update(dstRT, localWEP)).NotTo(HaveOccurred())

		skbMark = 0
		runBpfTest(t, "calico_to_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
			_, err := bpfrun(pktBytes)
			Expect(err).NotTo(HaveOccurred())
			ctAuditExpectLegs(ctAuditLoadEntry(ctKey), false, false, true, true)
		}, withFromHost())
	})

	t.Run("to-HEP: host process leaves the node", func(t *testing.T) {
		// Same CALI_F_FROM_HOST arm as above, run by the host endpoint: it
		// approves the external side's leg, which is not a workload, so here
		// the missing workload bit is the correct value.
		resetCTMap(ctMap)
		resetRTMap(rtMap)
		Expect(rtMap.Update(srcRT, localHost)).NotTo(HaveOccurred())
		Expect(rtMap.Update(dstRT, remoteHost)).NotTo(HaveOccurred())

		skbMark = tcdefs.MarkSeen
		runBpfTest(t, "calico_to_host_ep", nil, func(bpfrun bpfProgRunFn) {
			_, err := bpfrun(pktBytes)
			Expect(err).NotTo(HaveOccurred())
			ctAuditExpectLegs(ctAuditLoadEntry(ctKey), false, false, true, false)
		})
	})
}

// TestCTApprovalOnSeenUpdate covers the update arms: the packet carries the
// seen mark and hits an existing entry whose relevant leg is not approved, so
// the program goes back through policy and then updates the entry in place.
// The entry is planted with both legs blank so exactly one write shows up.
func TestCTApprovalOnSeenUpdate(t *testing.T) {
	RegisterTestingT(t)

	bpfIfaceName = "APup"
	defer func() { bpfIfaceName = "" }()
	defer cleanUpMaps()

	hostIP = node1ip

	_, ipv4, l4, _, pktBytes, err := testPacketUDPDefault()
	Expect(err).NotTo(HaveOccurred())
	udp := l4.(*layers.UDP)
	ctKey := ctAuditKey(ipv4, udp)

	localWEP := routes.NewValueWithIfIndex(routes.FlagsLocalWorkload|routes.FlagInIPAMPool, 1).AsBytes()
	remoteWEP := routes.NewValue(routes.FlagsRemoteWorkload | routes.FlagInIPAMPool).AsBytes()
	srcRT := routes.NewKey(srcV4CIDR).AsBytes()
	dstRT := routes.NewKey(dstV4CIDR).AsBytes()

	plantBlankEntry := func() {
		resetCTMap(ctMap)
		val := conntrack.NewValueNormal(0, 0, conntrack.Leg{}, conntrack.Leg{})
		Expect(ctMap.Update(ctKey.AsBytes(), val.AsBytes())).NotTo(HaveOccurred())
	}

	t.Run("to-WEP updates the destination leg as a workload approval", func(t *testing.T) {
		plantBlankEntry()
		resetRTMap(rtMap)
		Expect(rtMap.Update(srcRT, remoteWEP)).NotTo(HaveOccurred())
		Expect(rtMap.Update(dstRT, localWEP)).NotTo(HaveOccurred())

		skbMark = tcdefs.MarkSeen
		runBpfTest(t, "calico_to_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
			_, err := bpfrun(pktBytes)
			Expect(err).NotTo(HaveOccurred())
			ctAuditExpectLegs(ctAuditLoadEntry(ctKey), false, false, true, true)
		})
	})

	t.Run("to-HEP updates the destination leg as a non-workload approval", func(t *testing.T) {
		// The update arm approves the leg facing away from the host on the
		// assumption that the endpoint over there is off-node. It does not
		// consult the routes map: the write is the same here, where the
		// destination is a local workload, as for a genuinely external
		// destination. The entry then reads as fully approved even though the
		// workload's own program has never seen the flow - the state behind
		// the peer-redirect SYN detour, and the reason approved=1,workload=0
		// on a workload-destined leg is the fingerprint of a poisoned entry.
		plantBlankEntry()
		resetRTMap(rtMap)
		Expect(rtMap.Update(srcRT, localWEP)).NotTo(HaveOccurred())
		Expect(rtMap.Update(dstRT, localWEP)).NotTo(HaveOccurred())

		skbMark = tcdefs.MarkSeen
		runBpfTest(t, "calico_to_host_ep", nil, func(bpfrun bpfProgRunFn) {
			_, err := bpfrun(pktBytes)
			Expect(err).NotTo(HaveOccurred())
			ctAuditExpectLegs(ctAuditLoadEntry(ctKey), false, false, true, false)
		})
	})

	// The update arms also run in the packet-direction (TO_HOST) orientation,
	// where they approve the source's leg: a from-* program handling a packet
	// that already carries the seen mark. On the ingress attach points the
	// mark is always zero - the harness asserts as much - and the real-world
	// path into that orientation is a tunnel program handling a decapsulated
	// inner packet after the outer program marked it seen. Those programs are
	// not exposed as harness sections, so that orientation is pinned by the
	// tunnel FVs rather than here.
}
