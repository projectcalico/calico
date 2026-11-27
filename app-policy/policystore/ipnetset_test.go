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

package policystore

import (
	"testing"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/proto"
)

// A member with a longer prefix than the trie's bitmap node (/25 to /31 for IPv4, /121 to /127 for
// IPv6) hangs below that node, so a lookup must look past the node's bitmap of host addresses.
func TestIPNetLongPrefixMembers(t *testing.T) {
	for _, tc := range []struct {
		member string
		in     []string
		out    []string
	}{
		{"10.0.0.128/25", []string{"10.0.0.128", "10.0.0.200", "10.0.0.255"}, []string{"10.0.0.127", "10.0.1.200"}},
		{"10.0.0.128/28", []string{"10.0.0.128", "10.0.0.130", "10.0.0.143"}, []string{"10.0.0.127", "10.0.0.144"}},
		{"10.0.0.130/31", []string{"10.0.0.130", "10.0.0.131"}, []string{"10.0.0.129", "10.0.0.132"}},
		{"fd00::80/121", []string{"fd00::80", "fd00::c8", "fd00::ff"}, []string{"fd00::7f", "fd00::1:c8"}},
		{"fd00::82/127", []string{"fd00::82", "fd00::83"}, []string{"fd00::81", "fd00::84"}},
	} {
		t.Run(tc.member, func(t *testing.T) {
			RegisterTestingT(t)
			uut := NewIPSet(proto.IPSetUpdate_NET)
			uut.AddString(tc.member)
			for _, addr := range tc.in {
				Expect(uut.Contains(addr)).To(BeTrue(), "%s should be in %s", addr, tc.member)
			}
			for _, addr := range tc.out {
				Expect(uut.Contains(addr)).To(BeFalse(), "%s should not be in %s", addr, tc.member)
			}

			uut.RemoveString(tc.member)
			for _, addr := range tc.in {
				Expect(uut.Contains(addr)).To(BeFalse(), "%s after removing %s", addr, tc.member)
			}
			internals := uut.(ipNetSet)
			Expect(internals.v4.children).To(Equal([2]*trieNode{nil, nil}))
			Expect(internals.v6.children).To(Equal([2]*trieNode{nil, nil}))
		})
	}
}

// Host addresses and a longer prefix can share the bitmap node. Removing one kind of member must
// leave the other's addresses in the set.
func TestIPNetLongPrefixAndHostMembersOverlap(t *testing.T) {
	for _, tc := range []struct {
		name string
		// block is the bitmap node's own prefix and long a member below it. host is inside long,
		// otherHost is outside it, inLong is inside long but not a host member, and outside is
		// in block but in neither.
		block, long, host, otherHost, inLong, outside, hostLen string
	}{
		{"IPv4", "10.0.0.0/24", "10.0.0.128/28", "10.0.0.130", "10.0.0.5", "10.0.0.135", "10.0.0.200", "/32"},
		{"IPv6", "fd00::/120", "fd00::80/124", "fd00::82", "fd00::5", "fd00::87", "fd00::c8", "/128"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			RegisterTestingT(t)
			hostLen := tc.hostLen

			uut := NewIPSet(proto.IPSetUpdate_NET)
			uut.AddString(tc.block)
			uut.AddString(tc.long)
			uut.AddString(tc.host + hostLen)
			uut.AddString(tc.otherHost + hostLen)

			uut.RemoveString(tc.block)
			Expect(uut.Contains(tc.host)).To(BeTrue())
			Expect(uut.Contains(tc.inLong)).To(BeTrue())
			Expect(uut.Contains(tc.otherHost)).To(BeTrue())
			Expect(uut.Contains(tc.outside)).To(BeFalse())

			// The long prefix still covers the host address taken out of the bitmap.
			uut.RemoveString(tc.host + hostLen)
			Expect(uut.Contains(tc.host)).To(BeTrue())
			Expect(uut.Contains(tc.otherHost)).To(BeTrue())

			uut.AddString(tc.host + hostLen)
			uut.RemoveString(tc.long)
			Expect(uut.Contains(tc.host)).To(BeTrue())
			Expect(uut.Contains(tc.inLong)).To(BeFalse())
			Expect(uut.Contains(tc.otherHost)).To(BeTrue())

			uut.RemoveString(tc.host + hostLen)
			uut.RemoveString(tc.otherHost + hostLen)
			Expect(uut.Contains(tc.host)).To(BeFalse())
			Expect(uut.Contains(tc.otherHost)).To(BeFalse())
			internals := uut.(ipNetSet)
			Expect(internals.v4.children).To(Equal([2]*trieNode{nil, nil}))
			Expect(internals.v6.children).To(Equal([2]*trieNode{nil, nil}))
		})
	}
}

func BenchmarkIPNetSetContains(b *testing.B) {
	for _, tc := range []struct {
		name    string
		members []string
		addr    string
	}{
		{"HostMembers/Hit", []string{"10.0.0.5/32", "10.0.0.6/32", "10.0.1.7/32"}, "10.0.0.6"},
		{"HostMembers/Miss", []string{"10.0.0.5/32", "10.0.0.6/32", "10.0.1.7/32"}, "10.0.0.9"},
		{"ShortPrefix/Hit", []string{"10.0.0.0/16"}, "10.0.200.9"},
		{"LongPrefix/Hit", []string{"10.0.0.128/28", "10.0.0.5/32"}, "10.0.0.130"},
		{"LongPrefix/Miss", []string{"10.0.0.128/28", "10.0.0.5/32"}, "10.0.0.200"},
	} {
		b.Run(tc.name, func(b *testing.B) {
			s := NewIPSet(proto.IPSetUpdate_NET)
			for _, m := range tc.members {
				s.AddString(m)
			}
			b.ReportAllocs()
			for b.Loop() {
				s.Contains(tc.addr)
			}
		})
	}
}
