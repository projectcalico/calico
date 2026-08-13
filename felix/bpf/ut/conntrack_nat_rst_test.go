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
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/gopacket/gopacket/layers"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/bpf/conntrack"
	"github.com/projectcalico/calico/felix/bpf/conntrack/timeouts"
	ctv4 "github.com/projectcalico/calico/felix/bpf/conntrack/v4"
	"github.com/projectcalico/calico/felix/bpf/maps"
	"github.com/projectcalico/calico/felix/bpf/routes"
)

// natRSTFixture stages the CT entry pair of a NAT'd flow: a connection opened
// by a local workload (srcIP) to a service (svcIP:svcPort) backed by a remote
// workload (dstIP:backendPort). All connection state lives on the reverse
// "tracking" entry; the forward entry is a stub holding the reverse key.
type natRSTFixture struct {
	fwdKey, revKey ctv4.Key
	ctMap          maps.Map
}

const (
	// natRSTIfIndex must match the BPF UT's default skb ifindex so the
	// workload RPF check (route iface vs skb iface) passes.
	natRSTIfIndex            = 1
	natRSTSrcPort     uint16 = 12377
	natRSTSvcPort     uint16 = 8080
	natRSTBackendPort uint16 = 8055
)

var natRSTSvcIP = net.IPv4(10, 101, 0, 10)

func (f natRSTFixture) fwdEntry() ctv4.ValueInterface {
	b, err := f.ctMap.Get(f.fwdKey.AsBytes())
	Expect(err).NotTo(HaveOccurred())
	return ctv4.ValueFromBytes(b)
}

func (f natRSTFixture) revEntry() ctv4.ValueInterface {
	b, err := f.ctMap.Get(f.revKey.AsBytes())
	Expect(err).NotTo(HaveOccurred())
	return ctv4.ValueFromBytes(b)
}

// setupNATRSTFixture installs the routes and the CT entry pair. revRSTSeen seeds
// the tracking entry's rst_seen timestamp (0 for a connection that has seen no
// RST).
func setupNATRSTFixture(t *testing.T, revRSTSeen uint64) natRSTFixture {
	rtKey := routes.NewKey(srcV4CIDR).AsBytes()
	rtVal := routes.NewValueWithIfIndex(routes.FlagsLocalWorkload|routes.FlagInIPAMPool, natRSTIfIndex).AsBytes()
	Expect(rtMap.Update(rtKey, rtVal)).NotTo(HaveOccurred())
	rtKey = routes.NewKey(dstV4CIDR).AsBytes()
	rtVal = routes.NewValueWithIfIndex(routes.FlagsRemoteWorkload|routes.FlagInIPAMPool, natRSTIfIndex).AsBytes()
	Expect(rtMap.Update(rtKey, rtVal)).NotTo(HaveOccurred())
	t.Cleanup(func() { resetRTMap(rtMap) })

	ctMap := conntrack.Map()
	Expect(ctMap.EnsureExists()).NotTo(HaveOccurred())
	resetCTMap(ctMap)
	t.Cleanup(func() { resetCTMap(ctMap) })

	f := natRSTFixture{
		fwdKey: ctv4.NewKey(6, srcIP, natRSTSrcPort, natRSTSvcIP, natRSTSvcPort),
		revKey: ctv4.NewKey(6, srcIP, natRSTSrcPort, dstIP, natRSTBackendPort),
		ctMap:  ctMap,
	}

	// The pod is the opener and carries the pod ifindex on its leg. Approved
	// must be set on both legs: from_wep is CALI_F_TO_HOST, so
	// calico_ct_lookup checks src_to_dst->approved and would otherwise return
	// CALI_CT_INVALID for these non-SYN packets and drop them before they
	// demonstrate anything.
	legA := ctv4.Leg{SynSeen: true, AckSeen: true, Approved: true, Opener: true, Ifindex: natRSTIfIndex}
	legB := ctv4.Leg{SynSeen: true, AckSeen: true, Approved: true}

	revVal := ctv4.NewValueNATReverse(time.Duration(0), 0, legA, legB,
		nil /* tunnelIP */, natRSTSvcIP /* origIP */, natRSTSvcPort)
	if revRSTSeen != 0 {
		vb := revVal.AsBytes()
		binary.LittleEndian.PutUint64(vb[ctv4.VoRSTSeen:ctv4.VoRSTSeen+8], revRSTSeen)
		Expect(ctMap.Update(f.revKey.AsBytes(), vb[:])).NotTo(HaveOccurred())
	} else {
		Expect(ctMap.Update(f.revKey.AsBytes(), revVal.AsBytes()[:])).NotTo(HaveOccurred())
	}

	fwdVal := ctv4.NewValueNATForward(time.Duration(0), 0, f.revKey)
	Expect(ctMap.Update(f.fwdKey.AsBytes(), fwdVal.AsBytes()[:])).NotTo(HaveOccurred())

	return f
}

// natRSTPacket builds a packet on the pre-DNAT tuple, i.e. one that hits the
// forward entry, with the given TCP flags.
func natRSTPacket(rst bool) []byte {
	ip := *ipv4Default
	ip.DstIP = natRSTSvcIP
	_, _, _, _, pkt, err := testPacketV4(nil, &ip, &layers.TCP{
		RST:        rst,
		ACK:        true,
		SrcPort:    layers.TCPPort(natRSTSrcPort),
		DstPort:    layers.TCPPort(natRSTSvcPort),
		DataOffset: 5,
	}, nil)
	Expect(err).NotTo(HaveOccurred())
	return pkt
}

// TestCTNatRSTHandling exercises TCP RST handling for a NAT'd flow in the
// client->service direction. That direction matches the forward entry, so the
// reverse direction is no substitute: it hits the tracking entry directly and
// behaves correctly regardless.
func TestCTNatRSTHandling(t *testing.T) {
	RegisterTestingT(t)

	bpfIfaceName = "NATrst"
	defer func() { bpfIfaceName = "" }()

	// runPkt replays pkt through from_wep. The retval check keeps a dropped
	// packet from making the assertions pass, or fail, for the wrong reason.
	runPkt := func(t *testing.T, f natRSTFixture, pkt []byte) {
		skbMark = 0
		runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
			res, err := bpfrun(pkt)
			Expect(err).NotTo(HaveOccurred())
			Expect(res.Retval).NotTo(Equal(resTC_ACT_SHOT))
		})
	}

	t.Run("an RST is recorded for the flow", func(t *testing.T) {
		RegisterTestingT(t)
		f := setupNATRSTFixture(t, 0)

		runPkt(t, f, natRSTPacket(true /* rst */))

		Expect(f.revEntry().RSTSeen()).NotTo(BeZero(),
			"the flow has no record of the RST; it is kept on the tracking entry, "+
				"which is where every reader looks")
		Expect(f.fwdEntry().RSTSeen()).To(BeZero(),
			"the forward entry is a stub — state written there is never read")
	})

	t.Run("a flow closed by an RST expires without waiting out the established timeout",
		func(t *testing.T) {
			RegisterTestingT(t)
			f := setupNATRSTFixture(t, 0)

			runPkt(t, f, natRSTPacket(true /* rst */))

			rev := f.revEntry()
			to := timeouts.DefaultTimeouts()

			// Three minutes after the RST, with no traffic since.
			reason, expired := conntrack.EntryExpired(to,
				rev.LastSeen()+int64(3*time.Minute), 6 /* TCP */, rev)
			Expect(expired).To(BeTrue(),
				"flow survived to the established timeout (%s); reason=%q",
				to.TCPEstablished, reason)

			// One minute in it is still inside the spurious-RST window: the
			// RST may yet turn out to have been bogus, so the flow has to stay.
			reason, expired = conntrack.EntryExpired(to,
				rev.LastSeen()+int64(time.Minute), 6, rev)
			Expect(expired).To(BeFalse(),
				"flow expired inside the 2-minute spurious-RST window; reason=%q", reason)
		})

	t.Run("a spurious RST is retracted once traffic continues", func(t *testing.T) {
		RegisterTestingT(t)

		// Backdate the RST so the two-minute window has already elapsed.
		// bpf_ktime_get_ns() counts from boot, so 1ns is effectively "at
		// boot"; the guard below catches a host up for less than that.
		f := setupNATRSTFixture(t, 1)
		Expect(f.revEntry().RSTSeen()).NotTo(BeZero())

		runPkt(t, f, natRSTPacket(false /* data, not rst */))

		Expect(f.revEntry().RSTSeen()).To(BeZero(),
			"traffic past the two-minute mark should have retracted the RST; the "+
				"verdict reads the tracking entry's timestamp, so a flow whose RST "+
				"was recorded elsewhere never reaches it")
	})
}
