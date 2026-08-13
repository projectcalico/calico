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

// A NAT'd (service) connection has two CT entries: a forward entry keyed on the
// pre-DNAT tuple, which is a stub holding only the reverse key, and a reverse
// "tracking" entry that holds all the connection state. Packets in the
// client->service direction hit the forward entry, so calico_ct_lookup runs with
// v = the stub and has to redirect its bookkeeping to the tracking entry.
//
// Expiry is decided solely from the tracking entry — cleanup.go looks the
// reverse entry up even when it is scanning the forward key — so RST state
// recorded on the stub is state nobody reads.
//
// natRSTFixture stages such a pair for a connection opened by a local workload
// (srcIP) to a service (svcIP:svcPort) backed by a remote workload
// (dstIP:backendPort), and returns accessors for the two entries.
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

// TestCTNatRSTRecordedOnTrackingEntry drives an RST in the client->service
// direction — a NAT_FWD hit — and requires the RST timestamp to land on the
// tracking entry, the only entry expiry consults.
func TestCTNatRSTRecordedOnTrackingEntry(t *testing.T) {
	RegisterTestingT(t)

	bpfIfaceName = "NATrst"
	defer func() { bpfIfaceName = "" }()

	f := setupNATRSTFixture(t, 0)

	skbMark = 0
	runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(natRSTPacket(true /* rst */))
		Expect(err).NotTo(HaveOccurred())
		// The RST must reach the conntrack path; if it were dropped the
		// assertions below would pass or fail for the wrong reason.
		Expect(res.Retval).NotTo(Equal(resTC_ACT_SHOT))
	})

	Expect(f.revEntry().RSTSeen()).NotTo(BeZero(),
		"RST arriving on the forward tuple must be recorded on the tracking entry, "+
			"which is the entry expiry is decided from")

	// The forward entry is a stub: nothing reads state written to it, so
	// writing the RST there is how the timestamp got lost.
	Expect(f.fwdEntry().RSTSeen()).To(BeZero(),
		"RST timestamp must not be written to the forward NAT stub")
}

// TestCTNatRSTClosedConnExpiresPromptly is the consequence of the above, checked
// against the production expiry predicate rather than restated: a connection
// closed by an RST from the client side must expire on the spurious-RST rule
// (~2 minutes without traffic), not fall through to TCPEstablished (1 hour).
func TestCTNatRSTClosedConnExpiresPromptly(t *testing.T) {
	RegisterTestingT(t)

	bpfIfaceName = "NATrstX"
	defer func() { bpfIfaceName = "" }()

	f := setupNATRSTFixture(t, 0)

	skbMark = 0
	runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(natRSTPacket(true /* rst */))
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).NotTo(Equal(resTC_ACT_SHOT))
	})

	rev := f.revEntry()
	to := timeouts.DefaultTimeouts()

	// Three minutes after the RST, with no traffic since.
	now := rev.LastSeen() + int64(3*time.Minute)
	reason, expired := conntrack.EntryExpired(to, now, 6 /* TCP */, rev)
	Expect(expired).To(BeTrue(),
		"an RST-closed connection should not survive to the established timeout (%s); reason=%q",
		to.TCPEstablished, reason)

	// One minute in it is still inside the spurious-RST window: the RST may
	// yet turn out to have been bogus, so the entry has to stay.
	reason, expired = conntrack.EntryExpired(to, rev.LastSeen()+int64(time.Minute), 6, rev)
	Expect(expired).To(BeFalse(),
		"entry expired inside the 2-minute spurious-RST window; reason=%q", reason)
}

// TestCTNatSpuriousRSTClearedOnTrackingEntry covers the other half of the
// spurious-RST logic on the same path: once traffic has continued for two
// minutes the dataplane concludes the RST was bogus and clears the timestamp. It
// has to clear it on the entry that carries it.
func TestCTNatSpuriousRSTClearedOnTrackingEntry(t *testing.T) {
	RegisterTestingT(t)

	bpfIfaceName = "NATrstC"
	defer func() { bpfIfaceName = "" }()

	// Backdate the RST so the two-minute window has already elapsed.
	// bpf_ktime_get_ns() counts from boot, so 1ns is effectively "at boot";
	// the guard below catches a host that has been up for less than that.
	f := setupNATRSTFixture(t, 1)
	Expect(f.revEntry().RSTSeen()).NotTo(BeZero())

	skbMark = 0
	runBpfTest(t, "calico_from_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(natRSTPacket(false /* data, not rst */))
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).NotTo(Equal(resTC_ACT_SHOT))
	})

	Expect(f.revEntry().RSTSeen()).To(BeZero(),
		"continued traffic past the two-minute mark must clear rst_seen on the "+
			"tracking entry; reading it from the forward stub means the branch never fires")
}
