// Copyright (c) 2016-2025 Tigera, Inc. All rights reserved.
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

package nfnetlink

import (
	"net"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("ParseNflog", func() {
	Describe("Ipv6", func() {
		data := [...]byte{8, 0, 1, 0, 134, 221, 3, 0, 8, 0, 10, 0, 68, 82, 73, 0, 8, 0, 5, 0, 0, 0, 0, 3, 8, 0, 11, 0, 0, 0, 3, 232, 8, 0, 14, 0, 0, 0, 3, 232, 84, 0, 9, 0, 96, 15, 33, 48, 0, 40, 6, 64, 254, 128, 0, 0, 0, 0, 0, 0, 10, 0, 39, 255, 254, 134, 38, 162, 254, 128, 0, 0, 0, 0, 0, 0, 10, 0, 39, 255, 254, 215, 241, 163, 150, 125, 31, 64, 121, 172, 141, 35, 0, 0, 0, 0, 160, 2, 112, 128, 118, 211, 0, 0, 2, 4, 5, 160, 4, 2, 8, 10, 2, 59, 176, 73, 0, 0, 0, 0, 1, 3, 3, 7}
		It("should parse NFLOG packet with IPv6 payload without errors", func() {
			nflogPacket, err := parseNflog(data[:])
			Expect(err).To(BeNil())
			prefix := string(nflogPacket.Prefix.Prefix[:nflogPacket.Prefix.Len])
			Expect(prefix).To(Equal("DRI"))
			tuple := nflogPacket.Tuple
			Expect(net.IP(tuple.Src[:16]).String()).To(Equal("fe80::a00:27ff:fe86:26a2"))
			Expect(net.IP(tuple.Dst[:16]).String()).To(Equal("fe80::a00:27ff:fed7:f1a3"))
			// TCP
			Expect(tuple.Proto).To(Equal(6))
			// Dst port 8000
			Expect(tuple.L4Src.Port).To(Equal(38525))
			Expect(tuple.L4Dst.Port).To(Equal(8000))
		})
	})
})
