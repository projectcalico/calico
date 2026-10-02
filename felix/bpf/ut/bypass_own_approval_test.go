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
	"github.com/projectcalico/calico/felix/bpf/counters"
	"github.com/projectcalico/calico/felix/bpf/hook"
	"github.com/projectcalico/calico/felix/bpf/routes"
	tcdefs "github.com/projectcalico/calico/felix/bpf/tc/defs"
)

// The counters entry appears on the first program run, so callers compare before and after.
func peerRedirects() uint64 {
	c, err := counters.Read(countersMap, redirPeerIfindex, hook.Ingress)
	if err != nil {
		return 0
	}
	return c[counters.RedirectPeer]
}

// Plants a UDP entry whose destination leg a host endpoint approved while the destination was remote.
func plantHEPApprovedUDPEntry(ctKey conntrack.Key, srcLeg conntrack.Leg, dstWorkload bool) {
	resetCTMap(ctMap)
	val := conntrack.NewValueNormal(0, 0, srcLeg, conntrack.Leg{Approved: true, Workload: dstWorkload})
	ExpectWithOffset(1, ctMap.Update(ctKey.AsBytes(), val.AsBytes())).NotTo(HaveOccurred())
}

// Neither the BYPASS mark nor a peer redirect may skip a local workload that has not approved its leg.
func TestBypassNeedsLocalWorkloadApproval(t *testing.T) {
	RegisterTestingT(t)

	bpfIfaceName = "BYPw"
	defer func() { bpfIfaceName = "" }()
	defer cleanUpMaps()

	hostIP = node1ip

	_, ipv4, l4, _, pktBytes, err := testPacketUDPDefault()
	Expect(err).NotTo(HaveOccurred())
	udp := l4.(*layers.UDP)
	ctKey := ctAuditKey(ipv4, udp)

	localWEP := routes.NewValueWithIfIndex(routes.FlagsLocalWorkload|routes.FlagInIPAMPool, redirPeerIfindex).AsBytes()
	remoteWEP := routes.NewValue(routes.FlagsRemoteWorkload | routes.FlagInIPAMPool).AsBytes()
	srcRT := routes.NewKey(srcV4CIDR).AsBytes()
	dstRT := routes.NewKey(dstV4CIDR).AsBytes()

	wepLeg := conntrack.Leg{Approved: true, Workload: true, Opener: true}
	hepLeg := conntrack.Leg{Approved: true, Opener: true}

	for _, c := range []struct {
		name        string
		section     string
		srcRoute    []byte
		srcLeg      conntrack.Leg
		dstRoute    []byte
		dstWorkload bool
		mark        uint32
		peerRedirs  int
	}{
		{"from-WEP, dest still remote", "calico_from_workload_ep", localWEP, wepLeg, remoteWEP, false, tcdefs.MarkSeenBypass, 0},
		{"from-WEP, dest now local, unapproved by it", "calico_from_workload_ep", localWEP, wepLeg, localWEP, false, tcdefs.MarkSeen, 0},
		{"from-WEP, dest local, approved by it", "calico_from_workload_ep", localWEP, wepLeg, localWEP, true, tcdefs.MarkSeenBypass, 1},
		{"from-HEP, dest now local, unapproved by it", "calico_from_host_ep", remoteWEP, hepLeg, localWEP, false, tcdefs.MarkSeen, 0},
		{"from-HEP, dest local, approved by it", "calico_from_host_ep", remoteWEP, hepLeg, localWEP, true, tcdefs.MarkSeenBypass, 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			resetRTMap(rtMap)
			Expect(rtMap.Update(srcRT, c.srcRoute)).NotTo(HaveOccurred())
			Expect(rtMap.Update(dstRT, c.dstRoute)).NotTo(HaveOccurred())
			plantHEPApprovedUDPEntry(ctKey, c.srcLeg, c.dstWorkload)
			redirsBefore := peerRedirects()

			skbMark = 0
			runBpfTest(t, c.section, rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
				res, err := bpfrun(pktBytes)
				Expect(err).NotTo(HaveOccurred())
				Expect(res.Retval).NotTo(Equal(resTC_ACT_SHOT))
			}, withRedirectPeer())

			Expect(skbMark).To(Equal(c.mark), "mark 0x%08x, want 0x%08x", skbMark, c.mark)
			Expect(peerRedirects() - redirsBefore).To(BeNumerically("==", c.peerRedirs))
		})
	}
}

// A host endpoint's approval of a local workload's leg does not skip that workload's policy.
func TestLocalWorkloadIgnoresHEPApproval(t *testing.T) {
	RegisterTestingT(t)

	bpfIfaceName = "BYPd"
	defer func() { bpfIfaceName = "" }()
	defer cleanUpMaps()

	hostIP = node1ip

	_, ipv4, l4, _, pktBytes, err := testPacketUDPDefault()
	Expect(err).NotTo(HaveOccurred())
	udp := l4.(*layers.UDP)
	ctKey := ctAuditKey(ipv4, udp)

	localWEP := routes.NewValueWithIfIndex(routes.FlagsLocalWorkload|routes.FlagInIPAMPool, 1).AsBytes()
	localHost := routes.NewValue(routes.FlagsLocalHost).AsBytes()
	remoteHost := routes.NewValue(routes.FlagsRemoteHost).AsBytes()
	srcRT := routes.NewKey(srcV4CIDR).AsBytes()
	dstRT := routes.NewKey(dstV4CIDR).AsBytes()

	wepLeg := conntrack.Leg{Approved: true, Workload: true, Opener: true}

	setup := func(srcRoute []byte, srcLeg conntrack.Leg) {
		resetRTMap(rtMap)
		Expect(rtMap.Update(srcRT, srcRoute)).NotTo(HaveOccurred())
		Expect(rtMap.Update(dstRT, localWEP)).NotTo(HaveOccurred())
		plantHEPApprovedUDPEntry(ctKey, srcLeg, false)
	}

	t.Run("from a local workload, policy denies", func(t *testing.T) {
		setup(localWEP, wepLeg)

		skbMark = tcdefs.MarkSeen
		runBpfTest(t, "calico_to_workload_ep", &denyAllRulesWorkloads, func(bpfrun bpfProgRunFn) {
			res, err := bpfrun(pktBytes)
			Expect(err).NotTo(HaveOccurred())
			Expect(res.Retval).To(Equal(resTC_ACT_SHOT))
		})
	})

	t.Run("from a local workload, policy allows and records the workload approval", func(t *testing.T) {
		setup(localWEP, wepLeg)

		skbMark = tcdefs.MarkSeen
		runBpfTest(t, "calico_to_workload_ep", rulesDefaultAllow, func(bpfrun bpfProgRunFn) {
			res, err := bpfrun(pktBytes)
			Expect(err).NotTo(HaveOccurred())
			Expect(res.Retval).NotTo(Equal(resTC_ACT_SHOT))
			d := ctAuditLoadEntry(ctKey).Data()
			Expect(d.B2A.Approved).To(BeTrue())
			Expect(d.B2A.Workload).To(BeTrue())
		})
	})

	// Unseen but remote, e.g. via an interface without Calico programs; withFromHost only waives the mark check.
	t.Run("unseen from a remote source, policy denies", func(t *testing.T) {
		setup(remoteHost, conntrack.Leg{Opener: true})

		skbMark = 0
		runBpfTest(t, "calico_to_workload_ep", &denyAllRulesWorkloads, func(bpfrun bpfProgRunFn) {
			res, err := bpfrun(pktBytes)
			Expect(err).NotTo(HaveOccurred())
			Expect(res.Retval).To(Equal(resTC_ACT_SHOT))
		}, withFromHost())
	})

	// Unseen host traffic to a local workload is always allowed, so the entry is used as is.
	t.Run("from a host process, accepted on the existing entry", func(t *testing.T) {
		setup(localHost, conntrack.Leg{Opener: true})

		skbMark = 0
		runBpfTest(t, "calico_to_workload_ep", &denyAllRulesWorkloads, func(bpfrun bpfProgRunFn) {
			res, err := bpfrun(pktBytes)
			Expect(err).NotTo(HaveOccurred())
			Expect(res.Retval).NotTo(Equal(resTC_ACT_SHOT))
			d := ctAuditLoadEntry(ctKey).Data()
			Expect(d.B2A.Approved).To(BeTrue())
			Expect(d.B2A.Workload).To(BeFalse())
		}, withFromHost())
	})
}
