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
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/encap"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
)

var _ = Describe("L3RouteResolver", func() {
	Describe("L3RouteResolver UTs", func() {
		var l3RR *L3RouteResolver
		var eventBuf rtEventsMock

		BeforeEach(func() {
			eventBuf = make(rtEventsMock, 100)
			l3RR = NewL3RouteResolver("test-hostname", eventBuf, true, "CalicoIPAM")
			l3RR.OnAlive = func() {}
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

		It("should add crossSubnet routes in pure V6 env", func() {
			cidr, _ := ip.CIDRFromString("dead:beef::/122")
			ipnet := net.IPNet{IPNet: cidr.ToIPNet()}
			v1Pool := model.IPPool{
				CIDR:      ipnet,
				VXLANMode: encap.CrossSubnet,
			}

			l3RR.OnPoolUpdate(api.Update{
				KVPair: model.KVPair{
					Key:   model.IPPoolKey{CIDR: v1Pool.CIDR},
					Value: &v1Pool,
				},
			})

			cidr, _ = ip.CIDRFromString("abcd:eeee::/32")
			nodeInfo := &l3rrNodeInfo{
				V6Addr:      ip.FromString("abcd:eeee::1").(ip.V6Addr),
				V6CIDR:      cidr.(ip.V6CIDR),
				VXLANV6Addr: ip.FromString("abcd:0000::1").(ip.V6Addr),
			}

			l3RR.onNodeUpdate("test-hostname", nodeInfo)

			cidr, _ = ip.CIDRFromString("abcd:ffff::/32")
			nodeInfo = &l3rrNodeInfo{
				V6Addr:      ip.FromString("abcd:ffff::1").(ip.V6Addr),
				V6CIDR:      cidr.(ip.V6CIDR),
				VXLANV6Addr: ip.FromString("abcd:0001::1").(ip.V6Addr),
			}

			l3RR.onNodeUpdate("nodeName1", nodeInfo)

			cidr, _ = ip.CIDRFromString("dead:beef::1/122")

			l3RR.OnWorkloadUpdate(api.Update{
				KVPair: model.KVPair{
					Key: model.WorkloadEndpointKey{
						Hostname:   "test-hostname",
						WorkloadID: "w1",
						EndpointID: "ep1",
					},
					Value: &model.WorkloadEndpoint{
						Name:     "w1",
						IPv6Nets: []net.IPNet{{IPNet: cidr.ToIPNet()}},
					},
				},
			})

			// drain all route updates
		drainLoop:
			for {
				select {
				case <-eventBuf:
				default:
					break drainLoop
				}
			}

			cidr, _ = ip.CIDRFromString("dead:beef::2/122")

			l3RR.OnWorkloadUpdate(api.Update{
				KVPair: model.KVPair{
					Key: model.WorkloadEndpointKey{
						Hostname:   "nodeName1",
						WorkloadID: "w2",
						EndpointID: "ep2",
					},
					Value: &model.WorkloadEndpoint{
						Name:     "w2",
						IPv6Nets: []net.IPNet{{IPNet: cidr.ToIPNet()}},
					},
				},
			})

			rt := (<-eventBuf).(*proto.RouteUpdate)
			Expect(rt.Types).To(Equal(proto.RouteType_REMOTE_WORKLOAD))
			Expect(rt.SameSubnet).NotTo(BeTrue())
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
		It("should consider VXLANV6Addr in Equal() method", func() {
			info1 := l3rrNodeInfo{
				VXLANV6Addr: ip.FromString("dead:beef::1"),
			}
			info2 := l3rrNodeInfo{
				VXLANV6Addr: ip.FromString("dead:beef::2"),
			}
			Expect(info1.Equal(info1)).To(BeTrue())
			Expect(info1.Equal(info2)).To(BeFalse())
		})
		It("should consider WireguardV6Addr in Equal() method", func() {
			info1 := l3rrNodeInfo{
				WireguardV6Addr: ip.FromString("dead:beef::1"),
			}
			info2 := l3rrNodeInfo{
				WireguardV6Addr: ip.FromString("dead:beef::2"),
			}
			Expect(info1.Equal(info1)).To(BeTrue())
			Expect(info1.Equal(info2)).To(BeFalse())
		})
	})
})

type rtEventsMock chan any

func (m rtEventsMock) OnRouteUpdate(update *proto.RouteUpdate) {
	m <- update
}

func (m rtEventsMock) OnRouteRemove(dst string) {
	m <- dst
}
