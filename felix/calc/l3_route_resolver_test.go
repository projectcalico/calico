// Copyright (c) 2022 Tigera, Inc. All rights reserved.

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

package calc

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/ip"
)

var _ = Describe("L3RouteResolver", func() {
	Describe("L3RouteResolver UTs", func() {
		var l3RR *L3RouteResolver
		var eventBuf *EventSequencer

		BeforeEach(func() {
			eventBuf = NewEventSequencer(nil)
			l3RR = NewL3RouteResolver("test-hostname", eventBuf, true, "CalicoIPAM")
		})

		It("onNodeUpdate should add entries to the correct IP version tries", func() {
			Expect(l3RR.trie.v4T).To(Equal(&ip.CIDRTrie{}))
			Expect(l3RR.trie.v6T).To(Equal(&ip.CIDRTrie{}))

			nodeInfo := &l3rrNodeInfo{
				V4Addr: ip.FromString("192.168.0.1").(ip.V4Addr),
				V6Addr: ip.FromString("dead:beef::1").(ip.V6Addr),
			}

			l3RR.onNodeUpdate("nodeName1", nodeInfo)

			ri := RouteInfo{}
			ri.Host.NodeNames = []string{"nodeName1"}

			expectedV4T := &ip.CIDRTrie{}
			cidrV4, _ := ip.CIDRFromString("192.168.0.1/32")
			expectedV4T.Update(cidrV4, ri)
			Expect(l3RR.trie.v4T).To(Equal(expectedV4T))

			expectedV6T := &ip.CIDRTrie{}
			cidrV6, _ := ip.CIDRFromString("dead:beef::1/128")
			expectedV6T.Update(cidrV6, ri)
			Expect(l3RR.trie.v6T).To(Equal(expectedV6T))
		})
	})
	Describe("l3rrNodeInfo UTs", func() {
		It("should not return empty IP addresses in AddressesAsCIDRs()", func() {
			var (
				emptyV4Addr ip.V4Addr
				emptyV6Addr ip.V6Addr
			)
			info := l3rrNodeInfo{
				V4Addr: emptyV4Addr,
				V6Addr: emptyV6Addr,
			}
			Expect(info.AddressesAsCIDRs()).To(Equal([]ip.CIDR{}))
		})
	})
})
