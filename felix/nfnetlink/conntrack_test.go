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
	"syscall"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/nfnetlink/nfnl"
)

var _ = Describe("Conntrack Entry DNAT", func() {
	var cte CtEntry
	var original_dnat, reply CtTuple

	BeforeEach(func() {
		original_dnat = CtTuple{
			Src:        [16]byte{1, 1, 1, 1},
			Dst:        [16]byte{3, 3, 3, 3},
			L3ProtoNum: 2048,
			ProtoNum:   6,
			L4Src: CtL4Src{
				Port: 12345,
			},
			L4Dst: CtL4Dst{
				Port: 80,
			},
		}
		reply = CtTuple{
			Src:        [16]byte{2, 2, 2, 2},
			Dst:        [16]byte{1, 1, 1, 1},
			L3ProtoNum: 2048,
			ProtoNum:   6,
			L4Src: CtL4Src{
				Port: 80,
			},
			L4Dst: CtL4Dst{
				Port: 12345,
			},
		}
		cte = CtEntry{
			OriginalTuple: original_dnat,
			ReplyTuple:    reply,
		}
	})
	Describe("Check DNAT", func() {
		BeforeEach(func() {
			cte.Status = cte.Status | nfnl.IPS_DST_NAT
		})
		It("should return true for DNAT check", func() {
			Expect(cte.IsDNAT()).To(Equal(true))
		})
		It("should return true for NAT check", func() {
			Expect(cte.IsNAT()).To(Equal(true))
		})
		It("should return false for SNAT check", func() {
			Expect(cte.IsSNAT()).To(Equal(false))
		})
		It("should return tuple after parsing DNAT info", func() {
			t, _ := cte.OriginalTuplePostDNAT()
			Expect(t.Src).To(Equal(reply.Dst))
			Expect(t.Dst).To(Equal(reply.Src))
			Expect(t.L3ProtoNum).To(Equal(original_dnat.L3ProtoNum))
			Expect(t.ProtoNum).To(Equal(original_dnat.ProtoNum))
			Expect(t.L4Src).To(Equal(original_dnat.L4Src))
			Expect(t.L4Dst).To(Equal(original_dnat.L4Dst))
		})

	})
})

var _ = Describe("Conntrack Entry Parsing", func() {
	Context("TCP", func() {
		data := [...]byte{52, 0, 1, 128, 20, 0, 1, 128, 8, 0, 1, 0, 10, 0, 2, 15, 8, 0, 2, 0, 216, 58, 217, 36, 28, 0, 2, 128, 5, 0, 1, 0, 6, 0, 0, 0, 6, 0, 2, 0, 236, 210, 0, 0, 6, 0, 3, 0, 0, 80, 0, 0, 52, 0, 2, 128, 20, 0, 1, 128, 8, 0, 1, 0, 216, 58, 217, 36, 8, 0, 2, 0, 10, 0, 2, 15, 28, 0, 2, 128, 5, 0, 1, 0, 6, 0, 0, 0, 6, 0, 2, 0, 0, 80, 0, 0, 6, 0, 3, 0, 236, 210, 0, 0, 8, 0, 3, 0, 0, 0, 1, 142, 8, 0, 7, 0, 0, 0, 0, 114, 28, 0, 9, 128, 12, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 9, 12, 0, 2, 0, 0, 0, 0, 0, 0, 0, 1, 202, 28, 0, 10, 128, 12, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 8, 12, 0, 2, 0, 0, 0, 0, 0, 0, 0, 46, 56, 48, 0, 4, 128, 44, 0, 1, 128, 5, 0, 1, 0, 7, 0, 0, 0, 5, 0, 2, 0, 0, 0, 0, 0, 5, 0, 3, 0, 0, 0, 0, 0, 6, 0, 4, 0, 39, 0, 0, 0, 6, 0, 5, 0, 32, 0, 0, 0, 8, 0, 8, 0, 0, 0, 0, 0, 8, 0, 12, 0, 182, 70, 136, 192, 8, 0, 11, 0, 0, 0, 0, 1}
		original := CtTuple{
			Src:        ipStrTo16Byte("10.0.2.15"),
			Dst:        ipStrTo16Byte("216.58.217.36"),
			L3ProtoNum: 2,
			ProtoNum:   6,
			L4Src: CtL4Src{
				Port: 60626,
			},
			L4Dst: CtL4Dst{
				Port: 80,
			},
		}
		reply := CtTuple{
			Src:        ipStrTo16Byte("216.58.217.36"),
			Dst:        ipStrTo16Byte("10.0.2.15"),
			L3ProtoNum: 2,
			ProtoNum:   6,
			L4Src: CtL4Src{
				Port: 80,
			},
			L4Dst: CtL4Dst{
				Port: 60626,
			},
		}
		orig_counters := CtCounters{
			Packets: 9,
			Bytes:   458,
		}
		reply_counters := CtCounters{
			Packets: 8,
			Bytes:   11832,
		}
		It("should parse conntrack entry correctly", func() {
			By("Parsing the byte array")
			ctentry, err := conntrackEntryFromNfAttrs(data[:], syscall.AF_INET)
			Expect(err).To(BeNil())

			By("checking the parsed conntrack is not NAT-ted")
			Expect(ctentry.IsDNAT()).To(Equal(false))
			Expect(ctentry.IsNAT()).To(Equal(false))
			Expect(ctentry.IsSNAT()).To(Equal(false))

			By("checking the fields of conntrack entry")
			Expect(ctentry.OriginalTuple).To(Equal(original))
			Expect(ctentry.ReplyTuple).To(Equal(reply))
			Expect(ctentry.OriginalCounters).To(Equal(orig_counters))
			Expect(ctentry.ReplyCounters).To(Equal(reply_counters))
			Expect(ctentry.ProtoInfo.State).To(Equal(nfnl.TCP_CONNTRACK_TIME_WAIT))
		})
	})
})

func BenchmarkConntrackEntryFromNfAttrs(b *testing.B) {
	// Setup
	data := [...]byte{52, 0, 1, 128, 20, 0, 1, 128, 8, 0, 1, 0, 10, 0, 2, 2, 8, 0, 2, 0, 10, 0, 2, 15, 28, 0, 2, 128, 5, 0, 1, 0, 6, 0, 0, 0, 6, 0, 2, 0, 207, 206, 0, 0, 6, 0, 3, 0, 0, 22, 0, 0, 52, 0, 2, 128, 20, 0, 1, 128, 8, 0, 1, 0, 10, 0, 2, 15, 8, 0, 2, 0, 10, 0, 2, 2, 28, 0, 2, 128, 5, 0, 1, 0, 6, 0, 0, 0, 6, 0, 2, 0, 0, 22, 0, 0, 6, 0, 3, 0, 207, 206, 0, 0, 8, 0, 3, 0, 0, 0, 1, 142, 8, 0, 7, 0, 0, 6, 145, 147, 48, 0, 4, 128, 44, 0, 1, 128, 5, 0, 1, 0, 3, 0, 0, 0, 5, 0, 2, 0, 0, 0, 0, 0, 5, 0, 3, 0, 0, 0, 0, 0, 6, 0, 4, 0, 32, 0, 0, 0, 6, 0, 5, 0, 32, 0, 0, 0, 8, 0, 8, 0, 0, 0, 0, 0, 8, 0, 12, 0, 186, 125, 96, 0, 8, 0, 11, 0, 0, 0, 0, 1}

	// Test
	b.ResetTimer()
	b.ReportAllocs()
	for n := 0; n < b.N; n++ {
		_, err := conntrackEntryFromNfAttrs(data[:], syscall.AF_INET)
		Expect(err).To(BeNil())
	}
}

func ipStrTo16Byte(ipStr string) [16]byte {
	addr := net.ParseIP(ipStr)
	var addrB [16]byte
	copy(addrB[:], addr.To16()[:16])
	return addrB
}
