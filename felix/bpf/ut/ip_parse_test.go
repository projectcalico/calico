// Copyright (c) 2023 Tigera, Inc. All rights reserved.
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
)

func TestIPv4Parse(t *testing.T) {
	RegisterTestingT(t)

	ipHdr := *ipv4Default
	ipHdr.Options = []layers.IPv4Option{{
		OptionType:   123,
		OptionLength: 6,
		OptionData:   []byte{0xde, 0xad, 0xbe, 0xef},
	}}
	ipHdr.IHL += 2

	_, _, _, _, pktBytes, err := testPacketV4(nil, &ipHdr, nil, nil)
	Expect(err).NotTo(HaveOccurred())

	runBpfUnitTest(t, "ip_parse_test.c", func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(4))
	})
}

func TestIPv6Parse(t *testing.T) {
	RegisterTestingT(t)

	_, _, _, _, pktBytes, err := testPacketV6(nil, ipv6Default, nil, nil)
	Expect(err).NotTo(HaveOccurred())

	runBpfUnitTest(t, "ip_parse_test.c", func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(6))
	}, withIPv6())
}

func TestIPv6ParseOptsOne(t *testing.T) {
	RegisterTestingT(t)

	hop := &layers.IPv6HopByHop{}
	hop.NextHeader = layers.IPProtocolUDP

	/* from gopacket ip6_test.go */
	tlv := &layers.IPv6HopByHopOption{}
	tlv.OptionType = 0x01 //PadN
	tlv.OptionData = []byte{0x00, 0x00, 0x00, 0x00}
	hop.Options = append(hop.Options, tlv)

	_, _, _, _, pktBytes, err := testPacketV6(nil, ipv6Default, nil, nil, hop)
	Expect(err).NotTo(HaveOccurred())

	runBpfUnitTest(t, "ip_parse_test.c", func(bpfrun bpfProgRunFn) {
		res, err := bpfrun(pktBytes)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Retval).To(Equal(6))
	}, withIPv6())
}
