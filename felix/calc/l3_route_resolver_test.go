// Copyright (c) 2022-2026 Tigera, Inc. All rights reserved.

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
	. "github.com/onsi/ginkgo/v2"
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
			l3RR = NewL3RouteResolver("test-hostname", eventBuf, "CalicoIPAM")
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
	Describe("tunnel IP within IPAM block", func() {
		var l3RR *L3RouteResolver
		var eventBuf rtEventsMock

		BeforeEach(func() {
			eventBuf = make(rtEventsMock, 100)
			l3RR = NewL3RouteResolver("local-host", eventBuf, "CalicoIPAM")
			l3RR.OnAlive = func() {}
		})

		drainEvents := func() []*proto.RouteUpdate {
			var routes []*proto.RouteUpdate
			for {
				select {
				case ev := <-eventBuf:
					if rt, ok := ev.(*proto.RouteUpdate); ok {
						routes = append(routes, rt)
					}
				default:
					return routes
				}
			}
		}

		findRoute := func(routes []*proto.RouteUpdate, dst string) *proto.RouteUpdate {
			for _, rt := range routes {
				if rt.Dst == dst {
					return rt
				}
			}
			return nil
		}

		// Set up a remote host with a VXLAN tunnel IP that falls within an IPAM block.
		// The tunnel IP 10.0.1.0 is the first address of the /29 block 10.0.1.0/29.
		// In production (KIND clusters), this causes the tunnel route to get REMOTE_WORKLOAD
		// OR'd in alongside REMOTE_TUNNEL, which triggers spurious /32 route programming.
		It("should not add REMOTE_WORKLOAD to a tunnel IP just because it falls within a block", func() {
			// Add the IP pool.
			poolCIDR, _ := ip.CIDRFromString("10.0.0.0/16")
			pool := model.IPPool{
				CIDR:      net.IPNet{IPNet: poolCIDR.ToIPNet()},
				VXLANMode: encap.Always,
			}
			l3RR.OnPoolUpdate(api.Update{
				KVPair: model.KVPair{
					Key:   model.IPPoolKey{CIDR: pool.CIDR},
					Value: &pool,
				},
			})
			drainEvents()

			// Add the IPAM block (10.0.1.0/29) with affinity to remote-host.
			remoteAffinity := "host:remote-host"
			blockCIDR := net.MustParseCIDR("10.0.1.0/29")
			l3RR.OnBlockUpdate(api.Update{
				KVPair: model.KVPair{
					Key: model.BlockKey{CIDR: blockCIDR},
					Value: &model.AllocationBlock{
						CIDR:        blockCIDR,
						Affinity:    &remoteAffinity,
						Allocations: make([]*int, 8),
						Unallocated: []int{0, 1, 2, 3, 4, 5, 6, 7},
					},
				},
			})
			drainEvents()

			// Add the remote host IP and VXLAN tunnel address via OnNodeUpdate +
			// a direct tunnel address update. The tunnel IP 10.0.1.0 falls within
			// the block 10.0.1.0/29.
			l3RR.onNodeUpdate("remote-host", &l3rrNodeInfo{
				V4Addr:    ip.FromString("192.168.0.2").(ip.V4Addr),
				VXLANAddr: ip.FromString("10.0.1.0"),
			})
			l3RR.flush()

			routes := drainEvents()

			// Find the tunnel route for 10.0.1.0/32.
			tunnelRoute := findRoute(routes, "10.0.1.0/32")
			Expect(tunnelRoute).NotTo(BeNil(), "expected a route for the tunnel IP 10.0.1.0/32")

			// The tunnel route should only have REMOTE_TUNNEL, not REMOTE_WORKLOAD.
			// If REMOTE_WORKLOAD is present, the route manager will incorrectly program
			// an extra /32 directly-connected route on the tunnel device.
			Expect(tunnelRoute.Types&proto.RouteType_REMOTE_TUNNEL).NotTo(BeZero(),
				"tunnel route should have REMOTE_TUNNEL type")
			Expect(tunnelRoute.Types&proto.RouteType_REMOTE_WORKLOAD).To(BeZero(),
				"tunnel route should NOT have REMOTE_WORKLOAD just because it falls within a block")
		})

		It("should add REMOTE_WORKLOAD to a tunnel IP in a /32 block", func() {
			// A dedicated tunnel pool with blockSize=32 creates /32 blocks for each
			// tunnel IP. In this case the block IS the tunnel IP, and the route manager
			// needs REMOTE_WORKLOAD to program the directly-connected /32 route.
			poolCIDR, _ := ip.CIDRFromString("10.0.0.0/16")
			pool := model.IPPool{
				CIDR:      net.IPNet{IPNet: poolCIDR.ToIPNet()},
				VXLANMode: encap.Always,
			}
			l3RR.OnPoolUpdate(api.Update{
				KVPair: model.KVPair{
					Key:   model.IPPoolKey{CIDR: pool.CIDR},
					Value: &pool,
				},
			})
			drainEvents()

			// Add a /32 IPAM block at the same CIDR as the tunnel IP.
			remoteAffinity := "host:remote-host"
			blockCIDR := net.MustParseCIDR("10.0.1.0/32")
			l3RR.OnBlockUpdate(api.Update{
				KVPair: model.KVPair{
					Key: model.BlockKey{CIDR: blockCIDR},
					Value: &model.AllocationBlock{
						CIDR:        blockCIDR,
						Affinity:    &remoteAffinity,
						Allocations: make([]*int, 1),
						Unallocated: []int{0},
					},
				},
			})
			drainEvents()

			l3RR.onNodeUpdate("remote-host", &l3rrNodeInfo{
				V4Addr:    ip.FromString("192.168.0.2").(ip.V4Addr),
				VXLANAddr: ip.FromString("10.0.1.0"),
			})
			l3RR.flush()

			routes := drainEvents()

			tunnelRoute := findRoute(routes, "10.0.1.0/32")
			Expect(tunnelRoute).NotTo(BeNil(), "expected a route for the tunnel IP 10.0.1.0/32")

			// With a /32 block, the tunnel route should have BOTH types so the route
			// manager programs a directly-connected route.
			Expect(tunnelRoute.Types&proto.RouteType_REMOTE_TUNNEL).NotTo(BeZero(),
				"tunnel route should have REMOTE_TUNNEL type")
			Expect(tunnelRoute.Types&proto.RouteType_REMOTE_WORKLOAD).NotTo(BeZero(),
				"tunnel route in /32 block should have REMOTE_WORKLOAD")
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
		It("should not panic on nil addresses in AddressesAsCIDRs()", func() {
			// Test for issue #11384: SIGSEGV on null address
			// When ExternalIP is empty, a nil ip.Addr can end up in the Addresses slice.
			// The nil check should prevent a panic when AsCIDR() is called.
			info := l3rrNodeInfo{
				Addresses: []ip.Addr{nil, ip.FromString("192.168.0.1"), nil},
			}
			cidrs := info.AddressesAsCIDRs()
			Expect(cidrs).To(HaveLen(1))
			Expect(cidrs[0].String()).To(Equal("192.168.0.1/32"))
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
