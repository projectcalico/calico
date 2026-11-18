// Project Calico BPF dataplane programs.
// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

package ut_test

import (
	"testing"

	"github.com/gopacket/gopacket/layers"
	. "github.com/onsi/gomega"
)

func TestVXLANSrcPortRange(t *testing.T) {
	for _, test := range []struct {
		name             string
		min, max         uint16
		srcPort, dstPort layers.UDPPort
		wantPort         int
	}{
		{name: "no range (defaults)", srcPort: 1234, dstPort: 5678, wantPort: 4860},
		{name: "narrow range", min: 60000, max: 60010, srcPort: 1234, dstPort: 5678, wantPort: 60009},
		{name: "range minimum", min: 60000, max: 60010, srcPort: 1234, dstPort: 1234, wantPort: 60000},
		{name: "range maximum", min: 60000, max: 60010, srcPort: 1234, dstPort: 1234 ^ 10, wantPort: 60010},
	} {
		t.Run(test.name, func(t *testing.T) {
			RegisterTestingT(t)

			_, _, _, _, pktBytes, err := testPacketV4(nil, ipv4Default, &layers.UDP{
				SrcPort: test.srcPort,
				DstPort: test.dstPort,
			}, nil)
			Expect(err).NotTo(HaveOccurred())

			runBpfUnitTest(t, "vxlan_srcport_test.c", func(bpfrun bpfProgRunFn) {
				res, err := bpfrun(pktBytes)
				Expect(err).NotTo(HaveOccurred())
				Expect(res.Retval).To(Equal(test.wantPort))
			}, withVXLANSrcPortRange(test.min, test.max), withSubtests(false))
		})
	}
}
