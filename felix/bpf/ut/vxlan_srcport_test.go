// Project Calico BPF dataplane programs.
// Copyright (c) 2025 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

package ut_test

import (
	"testing"

	"github.com/gopacket/gopacket/layers"
	. "github.com/onsi/gomega"
)

// TestVXLANSrcPortRange verifies that, when VXLAN_PORT_MIN/MAX globals are set,
// the BPF code remaps the sport^dport hash into [min, max], and that with the
// range left at zero the raw hash is preserved (matching the historical
// behaviour).
func TestVXLANSrcPortRange(t *testing.T) {
	RegisterTestingT(t)

	_, _, l4, _, pktBytes, err := testPacketV4(nil, ipv4Default, nil, nil)
	Expect(err).NotTo(HaveOccurred())
	udp := l4.(*layers.UDP)

	hash := uint16(udp.SrcPort) ^ uint16(udp.DstPort)

	t.Run("no range (defaults)", func(t *testing.T) {
		RegisterTestingT(t)
		runBpfUnitTest(t, "vxlan_srcport_test.c", func(bpfrun bpfProgRunFn) {
			res, err := bpfrun(pktBytes)
			Expect(err).NotTo(HaveOccurred())
			Expect(uint16(res.Retval)).To(Equal(hash),
				"with no VXLAN port range configured the BPF code should return the raw sport^dport hash")
		})
	})

	t.Run("narrow range", func(t *testing.T) {
		RegisterTestingT(t)
		const min, max uint16 = 60000, 60010
		runBpfUnitTest(t, "vxlan_srcport_test.c", func(bpfrun bpfProgRunFn) {
			res, err := bpfrun(pktBytes)
			Expect(err).NotTo(HaveOccurred())
			port := uint16(res.Retval)
			Expect(port).To(BeNumerically(">=", min))
			Expect(port).To(BeNumerically("<=", max))
			expected := min + (hash % (max - min + 1))
			Expect(port).To(Equal(expected),
				"port should be min + hash%%(range) when both min and max are set")
		}, withVXLANPortRange(min, max))
	})

	t.Run("min==max (rejected by validator, BPF falls back to hash)", func(t *testing.T) {
		RegisterTestingT(t)
		const pinned uint16 = 4789
		runBpfUnitTest(t, "vxlan_srcport_test.c", func(bpfrun bpfProgRunFn) {
			res, err := bpfrun(pktBytes)
			Expect(err).NotTo(HaveOccurred())
			Expect(uint16(res.Retval)).To(Equal(hash),
				"min==max is rejected by Felix's config validator; "+
					"if a degenerate range reaches BPF the guard should fall "+
					"through to the raw hash rather than pinning to one port")
		}, withVXLANPortRange(pinned, pinned))
	})

	t.Run("invalid range (min>max) falls back to hash", func(t *testing.T) {
		RegisterTestingT(t)
		runBpfUnitTest(t, "vxlan_srcport_test.c", func(bpfrun bpfProgRunFn) {
			res, err := bpfrun(pktBytes)
			Expect(err).NotTo(HaveOccurred())
			Expect(uint16(res.Retval)).To(Equal(hash),
				"with max < min the BPF code should leave the hash unchanged")
		}, withVXLANPortRange(60010, 60000))
	})
}
