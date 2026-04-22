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

package intdataplane

import (
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/mdlayher/arp"
	"github.com/mdlayher/ethernet"
	"github.com/mdlayher/ndp"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/ipv6"

	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

// --- Mock netlink (only used for updateHostIfaceCIDRs / AddrList) ---

type mockNetlinkForProxyNeigh struct {
	netlinkshimStub
	links      map[string]*netlink.Dummy
	ifaceAddrs map[string][]netlink.Addr
}

type netlinkshimStub struct{}

func (s netlinkshimStub) LinkByName(name string) (netlink.Link, error) {
	return nil, fmt.Errorf("not found")
}
func (s netlinkshimStub) LinkList() ([]netlink.Link, error) { return nil, nil }
func (s netlinkshimStub) LinkAdd(link netlink.Link) error   { return nil }
func (s netlinkshimStub) LinkDel(link netlink.Link) error   { return nil }
func (s netlinkshimStub) LinkSetMTU(link netlink.Link, mtu int) error {
	return nil
}
func (s netlinkshimStub) LinkSetUp(link netlink.Link) error { return nil }
func (s netlinkshimStub) RouteListFiltered(family int, filter *netlink.Route, filterMask uint64) ([]netlink.Route, error) {
	return nil, nil
}
func (s netlinkshimStub) RouteListFilteredIter(family int, filter *netlink.Route, filterMask uint64, f func(netlink.Route) (cont bool)) error {
	return nil
}
func (s netlinkshimStub) RouteAdd(route *netlink.Route) error     { return nil }
func (s netlinkshimStub) RouteReplace(route *netlink.Route) error { return nil }
func (s netlinkshimStub) RouteDel(route *netlink.Route) error     { return nil }
func (s netlinkshimStub) AddrList(link netlink.Link, family int) ([]netlink.Addr, error) {
	return nil, nil
}
func (s netlinkshimStub) AddrAdd(link netlink.Link, addr *netlink.Addr) error { return nil }
func (s netlinkshimStub) AddrDel(link netlink.Link, addr *netlink.Addr) error { return nil }
func (s netlinkshimStub) RuleList(family int) ([]netlink.Rule, error)         { return nil, nil }
func (s netlinkshimStub) RuleAdd(rule *netlink.Rule) error                    { return nil }
func (s netlinkshimStub) RuleDel(rule *netlink.Rule) error                    { return nil }
func (s netlinkshimStub) Delete()                                             {}
func (s netlinkshimStub) NeighAdd(neigh *netlink.Neigh) error                 { return nil }
func (s netlinkshimStub) NeighList(linkIndex, family int) ([]netlink.Neigh, error) {
	return nil, nil
}
func (s netlinkshimStub) NeighSet(a *netlink.Neigh) error         { return nil }
func (s netlinkshimStub) NeighDel(a *netlink.Neigh) error         { return nil }
func (s netlinkshimStub) SetSocketTimeout(to time.Duration) error { return nil }
func (s netlinkshimStub) SetStrictCheck(b bool) error             { return nil }

func newMockNetlinkForProxyNeigh() *mockNetlinkForProxyNeigh {
	return &mockNetlinkForProxyNeigh{
		links: map[string]*netlink.Dummy{
			"eth0": {LinkAttrs: netlink.LinkAttrs{Index: 1, Name: "eth0"}},
			"eth1": {LinkAttrs: netlink.LinkAttrs{Index: 2, Name: "eth1"}},
		},
		ifaceAddrs: make(map[string][]netlink.Addr),
	}
}

func (m *mockNetlinkForProxyNeigh) LinkByName(name string) (netlink.Link, error) {
	if link, ok := m.links[name]; ok {
		return link, nil
	}
	return nil, fmt.Errorf("unknown network %s", name)
}

func (m *mockNetlinkForProxyNeigh) AddrList(link netlink.Link, family int) ([]netlink.Addr, error) {
	name := link.Attrs().Name
	if addrs, ok := m.ifaceAddrs[name]; ok {
		return addrs, nil
	}
	return nil, nil
}

func (m *mockNetlinkForProxyNeigh) setIfaceAddr(name, cidr string) {
	ip, ipnet, _ := net.ParseCIDR(cidr)
	if ip != nil {
		ipnet.IP = ip
	}
	m.ifaceAddrs[name] = []netlink.Addr{{IPNet: ipnet}}
}

// --- Mock ARP client ---

type mockARPClient struct {
	mu     sync.Mutex
	reads  chan *arp.Packet
	writes []arpWrite
	hwAddr net.HardwareAddr
	closed bool
}

type arpWrite struct {
	packet *arp.Packet
	dest   net.HardwareAddr
}

func newMockARPClient(hwAddr net.HardwareAddr) *mockARPClient {
	return &mockARPClient{
		reads:  make(chan *arp.Packet, 10),
		hwAddr: hwAddr,
	}
}

func (c *mockARPClient) Read() (*arp.Packet, *ethernet.Frame, error) {
	pkt, ok := <-c.reads
	if !ok {
		return nil, nil, fmt.Errorf("closed")
	}
	return pkt, nil, nil
}

func (c *mockARPClient) Reply(req *arp.Packet, hwAddr net.HardwareAddr, ip netip.Addr) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	pkt, _ := arp.NewPacket(arp.OperationReply, hwAddr, ip, req.SenderHardwareAddr, req.SenderIP)
	c.writes = append(c.writes, arpWrite{packet: pkt, dest: req.SenderHardwareAddr})
	return nil
}

func (c *mockARPClient) WriteTo(p *arp.Packet, addr net.HardwareAddr) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes = append(c.writes, arpWrite{packet: p, dest: addr})
	return nil
}

func (c *mockARPClient) SetReadDeadline(t time.Time) error { return nil }

func (c *mockARPClient) Close() error {
	c.closed = true
	close(c.reads)
	return nil
}

func (c *mockARPClient) getWrites() []arpWrite {
	c.mu.Lock()
	defer c.mu.Unlock()
	result := make([]arpWrite, len(c.writes))
	copy(result, c.writes)
	return result
}

func (c *mockARPClient) resetWrites() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes = nil
}

// --- Mock NDP conn ---

type mockNDPConn struct {
	mu     sync.Mutex
	reads  chan ndp.Message
	writes []ndpWrite
	closed bool
}

type ndpWrite struct {
	msg ndp.Message
	dst netip.Addr
}

func newMockNDPConn() *mockNDPConn {
	return &mockNDPConn{
		reads: make(chan ndp.Message, 10),
	}
}

func (c *mockNDPConn) ReadFrom() (ndp.Message, *ipv6.ControlMessage, netip.Addr, error) {
	msg, ok := <-c.reads
	if !ok {
		return nil, nil, netip.Addr{}, fmt.Errorf("closed")
	}
	return msg, nil, netip.MustParseAddr("fe80::1"), nil
}

func (c *mockNDPConn) WriteTo(m ndp.Message, cm *ipv6.ControlMessage, dst netip.Addr) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes = append(c.writes, ndpWrite{msg: m, dst: dst})
	return nil
}

func (c *mockNDPConn) SetReadDeadline(t time.Time) error { return nil }

func (c *mockNDPConn) Close() error {
	c.closed = true
	close(c.reads)
	return nil
}

func (c *mockNDPConn) getWrites() []ndpWrite {
	c.mu.Lock()
	defer c.mu.Unlock()
	result := make([]ndpWrite, len(c.writes))
	copy(result, c.writes)
	return result
}

// --- Test helpers ---

func newTestProxyNeighManager(nl *mockNetlinkForProxyNeigh, arpClients map[string]*mockARPClient) *proxyNeighManager {
	return newTestProxyNeighManagerWithHostname(nl, arpClients, "test-node")
}

func newTestProxyNeighManagerWithHostname(nl *mockNetlinkForProxyNeigh, arpClients map[string]*mockARPClient, hostname string) *proxyNeighManager {
	config := Config{
		Hostname: hostname,
		RulesConfig: rules.Config{
			WorkloadIfacePrefixes: []string{"cali"},
		},
	}
	af := func(ifaceName string) (arpClient, net.HardwareAddr, error) {
		if c, ok := arpClients[ifaceName]; ok {
			return c, c.hwAddr, nil
		}
		return nil, nil, fmt.Errorf("no mock for %s", ifaceName)
	}
	mgr := newProxyNeighManagerWithShims(config, 4, nl, af, nil)
	// Register a default no-encap pool covering the test subnet.
	sendNoEncapPool(mgr, "default-test-pool", "10.0.0.0/8")
	return mgr
}

func newTestProxyNDPManager(nl *mockNetlinkForProxyNeigh, ndpConns map[string]*mockNDPConn) *proxyNeighManager {
	config := Config{
		RulesConfig: rules.Config{
			WorkloadIfacePrefixes: []string{"cali"},
		},
	}
	nf := func(ifaceName string) (ndpConn, net.HardwareAddr, error) {
		if c, ok := ndpConns[ifaceName]; ok {
			return c, net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x06}, nil
		}
		return nil, nil, fmt.Errorf("no mock for %s", ifaceName)
	}
	mgr := newProxyNeighManagerWithShims(config, 6, nl, nil, nf)
	sendNoEncapPool(mgr, "default-test-pool-v6", "fd00::/8")
	return mgr
}

func sendNoEncapPool(mgr *proxyNeighManager, poolID, cidr string) {
	mgr.OnUpdate(&proto.IPAMPoolUpdate{
		Id: poolID,
		Pool: &proto.IPAMPool{
			Cidr:      cidr,
			IpipMode:  "Never",
			VxlanMode: "Never",
		},
	})
}

func sendIfaceAddrsUpdate(mgr *proxyNeighManager, name string, addrs ...string) {
	mgr.OnUpdate(&ifaceAddrsUpdate{
		Name:  name,
		Addrs: set.FromArray(addrs),
	})
}

func sendHostMetadata(mgr *proxyNeighManager, hostname, ipv4Addr string) {
	mgr.OnUpdate(&proto.HostMetadataV4V6Update{
		Hostname: hostname,
		Ipv4Addr: ipv4Addr,
	})
}

func proxyNeighWepUpdate(orchID, wlID, epID string, ipv4Nets ...string) *proto.WorkloadEndpointUpdate {
	return &proto.WorkloadEndpointUpdate{
		Id: &proto.WorkloadEndpointID{
			OrchestratorId: orchID,
			WorkloadId:     wlID,
			EndpointId:     epID,
		},
		Endpoint: &proto.WorkloadEndpoint{
			Ipv4Nets: ipv4Nets,
		},
	}
}

func proxyNeighWepRemove(orchID, wlID, epID string) *proto.WorkloadEndpointRemove {
	return &proto.WorkloadEndpointRemove{
		Id: &proto.WorkloadEndpointID{
			OrchestratorId: orchID,
			WorkloadId:     wlID,
			EndpointId:     epID,
		},
	}
}

func wepUpdateV6(orchID, wlID, epID string, ipv6Nets ...string) *proto.WorkloadEndpointUpdate {
	return &proto.WorkloadEndpointUpdate{
		Id: &proto.WorkloadEndpointID{
			OrchestratorId: orchID,
			WorkloadId:     wlID,
			EndpointId:     epID,
		},
		Endpoint: &proto.WorkloadEndpoint{
			Ipv6Nets: ipv6Nets,
		},
	}
}

func svcUpdate(name, namespace, svcType string, ingressIPs ...string) *proto.ServiceUpdate {
	return &proto.ServiceUpdate{
		Name:                   name,
		Namespace:              namespace,
		Type:                   svcType,
		LoadbalancerIngressIps: ingressIPs,
	}
}

// getDesiredIPs returns the desired IP set for an interface from the manager's listener.
func getDesiredIPs(mgr *proxyNeighManager, ifaceName string) desiredIPSet {
	l, ok := mgr.listeners[ifaceName]
	if !ok {
		return nil
	}
	d := l.desired.Load()
	if d == nil {
		return nil
	}
	return *d
}

// --- Tests ---

var _ = Describe("Proxy neighbor manager (IPv4)", func() {
	var (
		mgr        *proxyNeighManager
		nl         *mockNetlinkForProxyNeigh
		arpClients map[string]*mockARPClient
	)

	BeforeEach(func() {
		nl = newMockNetlinkForProxyNeigh()
		arpClients = map[string]*mockARPClient{
			"eth0": newMockARPClient(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01}),
			"eth1": newMockARPClient(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02}),
		}
		mgr = newTestProxyNeighManager(nl, arpClients)
	})

	AfterEach(func() {
		mgr.cancel()
	})

	Describe("basic enable", func() {
		BeforeEach(func() {
			nl.setIfaceAddr("eth0", "10.0.0.1/24")
			sendIfaceAddrsUpdate(mgr, "eth0", "10.0.0.1")
			mgr.OnUpdate(proxyNeighWepUpdate("k8s", "default/pod1", "eth0", "10.0.0.50/32"))
			Expect(mgr.CompleteDeferredWork()).To(Succeed())
		})

		It("should have 10.0.0.50 in desired set for eth0", func() {
			desired := getDesiredIPs(mgr, "eth0")
			Expect(desired).To(HaveKey("10.0.0.50"))
		})

		It("should start a listener on eth0", func() {
			Expect(mgr.listeners).To(HaveKey("eth0"))
		})

		It("should send GARP for the new IP", func() {
			Eventually(func() int {
				return len(arpClients["eth0"].getWrites())
			}).Should(BeNumerically(">=", 1))
			writes := arpClients["eth0"].getWrites()
			Expect(writes[0].packet.TargetIP.String()).To(Equal("10.0.0.50"))
		})
	})

	Describe("workload removed", func() {
		BeforeEach(func() {
			nl.setIfaceAddr("eth0", "10.0.0.1/24")
			sendIfaceAddrsUpdate(mgr, "eth0", "10.0.0.1")
			mgr.OnUpdate(proxyNeighWepUpdate("k8s", "default/pod1", "eth0", "10.0.0.50/32"))
			Expect(mgr.CompleteDeferredWork()).To(Succeed())
			Expect(getDesiredIPs(mgr, "eth0")).To(HaveKey("10.0.0.50"))

			mgr.OnUpdate(proxyNeighWepRemove("k8s", "default/pod1", "eth0"))
			Expect(mgr.CompleteDeferredWork()).To(Succeed())
		})

		It("should remove the IP from the desired set", func() {
			// No interfaces should have any desired IPs, listener should be stopped.
			Expect(mgr.listeners).To(BeEmpty())
		})
	})

	Describe("multiple pods same interface", func() {
		BeforeEach(func() {
			nl.setIfaceAddr("eth0", "10.0.0.1/24")
			sendIfaceAddrsUpdate(mgr, "eth0", "10.0.0.1")
			mgr.OnUpdate(proxyNeighWepUpdate("k8s", "default/pod1", "eth0", "10.0.0.50/32"))
			mgr.OnUpdate(proxyNeighWepUpdate("k8s", "default/pod2", "eth0", "10.0.0.51/32"))
			Expect(mgr.CompleteDeferredWork()).To(Succeed())
		})

		It("should have both IPs in the desired set", func() {
			desired := getDesiredIPs(mgr, "eth0")
			Expect(desired).To(HaveKey("10.0.0.50"))
			Expect(desired).To(HaveKey("10.0.0.51"))
		})
	})

	Describe("no match - pod outside any host subnet", func() {
		BeforeEach(func() {
			nl.setIfaceAddr("eth0", "10.0.0.1/24")
			sendIfaceAddrsUpdate(mgr, "eth0", "10.0.0.1")
			mgr.OnUpdate(proxyNeighWepUpdate("k8s", "default/pod1", "eth0", "192.168.1.50/32"))
			Expect(mgr.CompleteDeferredWork()).To(Succeed())
		})

		It("should not start any listeners", func() {
			Expect(mgr.listeners).To(BeEmpty())
		})
	})

	Describe("workload interface filtered", func() {
		BeforeEach(func() {
			nl.setIfaceAddr("eth0", "10.0.0.1/24")
			sendIfaceAddrsUpdate(mgr, "cali12345", "10.0.0.1")
			mgr.OnUpdate(proxyNeighWepUpdate("k8s", "default/pod1", "eth0", "10.0.0.50/32"))
			Expect(mgr.CompleteDeferredWork()).To(Succeed())
		})

		It("should not track cali interfaces", func() {
			Expect(mgr.hostIfaceToCIDRs).ToNot(HaveKey("cali12345"))
		})
	})

	Describe("GARP not sent for existing IPs on second reconciliation", func() {
		BeforeEach(func() {
			nl.setIfaceAddr("eth0", "10.0.0.1/24")
			sendIfaceAddrsUpdate(mgr, "eth0", "10.0.0.1")
			mgr.OnUpdate(proxyNeighWepUpdate("k8s", "default/pod1", "eth0", "10.0.0.50/32"))
			Expect(mgr.CompleteDeferredWork()).To(Succeed())

			// Reset writes and trigger another reconciliation.
			arpClients["eth0"].resetWrites()
			mgr.dirty = true
			Expect(mgr.CompleteDeferredWork()).To(Succeed())
		})

		It("should not send GARP again", func() {
			Consistently(func() int {
				return len(arpClients["eth0"].getWrites())
			}).Should(Equal(0))
		})
	})

	Describe("interface removed", func() {
		BeforeEach(func() {
			nl.setIfaceAddr("eth0", "10.0.0.1/24")
			sendIfaceAddrsUpdate(mgr, "eth0", "10.0.0.1")
			mgr.OnUpdate(proxyNeighWepUpdate("k8s", "default/pod1", "eth0", "10.0.0.50/32"))
			Expect(mgr.CompleteDeferredWork()).To(Succeed())
			Expect(mgr.listeners).To(HaveKey("eth0"))

			// Interface removed.
			mgr.OnUpdate(&ifaceAddrsUpdate{Name: "eth0", Addrs: nil})
			Expect(mgr.CompleteDeferredWork()).To(Succeed())
		})

		It("should stop the listener", func() {
			Expect(mgr.listeners).ToNot(HaveKey("eth0"))
		})
	})

	Describe("encapsulated pool filtered", func() {
		BeforeEach(func() {
			nl.setIfaceAddr("eth0", "10.0.0.1/24")
			sendIfaceAddrsUpdate(mgr, "eth0", "10.0.0.1")
			// Remove the default no-encap pool and add a VXLAN pool.
			mgr.OnUpdate(&proto.IPAMPoolRemove{Id: "default-test-pool"})
			mgr.OnUpdate(&proto.IPAMPoolUpdate{
				Id: "vxlan-pool",
				Pool: &proto.IPAMPool{
					Cidr:      "10.0.0.0/8",
					VxlanMode: "Always",
				},
			})
			mgr.OnUpdate(proxyNeighWepUpdate("k8s", "default/pod1", "eth0", "10.0.0.50/32"))
			Expect(mgr.CompleteDeferredWork()).To(Succeed())
		})

		It("should not respond for IPs in encapsulated pools", func() {
			Expect(mgr.listeners).To(BeEmpty())
		})
	})
})

var _ = Describe("Proxy neighbor manager - LoadBalancer IPs", func() {
	var (
		mgr        *proxyNeighManager
		nl         *mockNetlinkForProxyNeigh
		arpClients map[string]*mockARPClient
	)

	// With nodes ["node-a","node-b","node-c"], HRW (Rendezvous) hashing selects:
	//   "10.0.0.100" -> node-c
	//   "10.0.0.101" -> node-b
	//   "10.0.0.102" -> node-a

	setupThreeNodes := func(mgr *proxyNeighManager) {
		sendHostMetadata(mgr, "node-a", "1.1.1.1")
		sendHostMetadata(mgr, "node-b", "1.1.1.2")
		sendHostMetadata(mgr, "node-c", "1.1.1.3")
	}

	Describe("LB IP on selected node", func() {
		BeforeEach(func() {
			nl = newMockNetlinkForProxyNeigh()
			arpClients = map[string]*mockARPClient{
				"eth0": newMockARPClient(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01}),
			}
			mgr = newTestProxyNeighManagerWithHostname(nl, arpClients, "node-c")
			setupThreeNodes(mgr)
			nl.setIfaceAddr("eth0", "10.0.0.1/24")
			sendIfaceAddrsUpdate(mgr, "eth0", "10.0.0.1")
			mgr.OnUpdate(svcUpdate("my-svc", "default", "LoadBalancer", "10.0.0.100"))
			Expect(mgr.CompleteDeferredWork()).To(Succeed())
		})

		AfterEach(func() { mgr.cancel() })

		It("should have the LB IP in desired set", func() {
			desired := getDesiredIPs(mgr, "eth0")
			Expect(desired).To(HaveKey("10.0.0.100"))
		})

		It("should send GARP for LB VIP", func() {
			Eventually(func() int {
				return len(arpClients["eth0"].getWrites())
			}).Should(BeNumerically(">=", 1))
		})
	})

	Describe("LB IP on non-selected node", func() {
		BeforeEach(func() {
			nl = newMockNetlinkForProxyNeigh()
			arpClients = map[string]*mockARPClient{
				"eth0": newMockARPClient(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01}),
			}
			mgr = newTestProxyNeighManagerWithHostname(nl, arpClients, "node-a")
			setupThreeNodes(mgr)
			nl.setIfaceAddr("eth0", "10.0.0.1/24")
			sendIfaceAddrsUpdate(mgr, "eth0", "10.0.0.1")
			mgr.OnUpdate(svcUpdate("my-svc", "default", "LoadBalancer", "10.0.0.100"))
			Expect(mgr.CompleteDeferredWork()).To(Succeed())
		})

		AfterEach(func() { mgr.cancel() })

		It("should not have any desired IPs", func() {
			Expect(mgr.listeners).To(BeEmpty())
		})
	})

	Describe("selectNodeForIP deterministic", func() {
		It("should be deterministic", func() {
			nl = newMockNetlinkForProxyNeigh()
			arpClients = map[string]*mockARPClient{}
			mgr = newTestProxyNeighManagerWithHostname(nl, arpClients, "node-c")
			setupThreeNodes(mgr)

			result1 := mgr.selectNodeForIP("10.0.0.100")
			result2 := mgr.selectNodeForIP("10.0.0.100")
			Expect(result1).To(Equal(result2))
			Expect(result1).To(BeTrue()) // node-c is selected for this IP
			mgr.cancel()
		})

		It("should return false with zero nodes", func() {
			nl = newMockNetlinkForProxyNeigh()
			arpClients = map[string]*mockARPClient{}
			mgr = newTestProxyNeighManagerWithHostname(nl, arpClients, "node-a")
			Expect(mgr.selectNodeForIP("10.0.0.100")).To(BeFalse())
			mgr.cancel()
		})
	})
})

var _ = Describe("Proxy NDP manager (IPv6)", func() {
	var (
		mgr      *proxyNeighManager
		nl       *mockNetlinkForProxyNeigh
		ndpConns map[string]*mockNDPConn
	)

	BeforeEach(func() {
		nl = newMockNetlinkForProxyNeigh()
		ndpConns = map[string]*mockNDPConn{
			"eth0": newMockNDPConn(),
		}
		mgr = newTestProxyNDPManager(nl, ndpConns)
	})

	AfterEach(func() {
		mgr.cancel()
	})

	Describe("basic IPv6 proxy NDP entry", func() {
		BeforeEach(func() {
			nl.setIfaceAddr("eth0", "fd00::1/64")
			sendIfaceAddrsUpdate(mgr, "eth0", "fd00::1")
			mgr.OnUpdate(wepUpdateV6("k8s", "default/pod1", "eth0", "fd00::50/128"))
			Expect(mgr.CompleteDeferredWork()).To(Succeed())
		})

		It("should have fd00::50 in desired set for eth0", func() {
			desired := getDesiredIPs(mgr, "eth0")
			Expect(desired).To(HaveKey("fd00::50"))
		})

		It("should start a listener", func() {
			Expect(mgr.listeners).To(HaveKey("eth0"))
		})

		It("should send unsolicited NA", func() {
			Eventually(func() int {
				return len(ndpConns["eth0"].getWrites())
			}).Should(BeNumerically(">=", 1))
			writes := ndpConns["eth0"].getWrites()
			na, ok := writes[0].msg.(*ndp.NeighborAdvertisement)
			Expect(ok).To(BeTrue())
			Expect(na.TargetAddress.String()).To(Equal("fd00::50"))
			Expect(na.Override).To(BeTrue())
		})
	})
})

var _ = Describe("Proxy neighbor manager - live migration", func() {
	var (
		mgr        *proxyNeighManager
		nl         *mockNetlinkForProxyNeigh
		arpClients map[string]*mockARPClient
	)

	BeforeEach(func() {
		nl = newMockNetlinkForProxyNeigh()
		arpClients = map[string]*mockARPClient{
			"eth0": newMockARPClient(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01}),
		}
		mgr = newTestProxyNeighManager(nl, arpClients)
		nl.setIfaceAddr("eth0", "10.0.0.1/24")
		sendIfaceAddrsUpdate(mgr, "eth0", "10.0.0.1")
	})

	AfterEach(func() {
		mgr.cancel()
	})

	It("should not respond for SOURCE migration role", func() {
		mgr.OnUpdate(&proto.WorkloadEndpointUpdate{
			Id: &proto.WorkloadEndpointID{
				OrchestratorId: "k8s",
				WorkloadId:     "default/pod1",
				EndpointId:     "eth0",
			},
			Endpoint: &proto.WorkloadEndpoint{
				Ipv4Nets:          []string{"10.0.0.50/32"},
				LiveMigrationRole: proto.LiveMigrationRole_SOURCE,
			},
		})
		Expect(mgr.CompleteDeferredWork()).To(Succeed())
		Expect(mgr.listeners).To(BeEmpty())
	})

	It("should respond for TARGET migration role", func() {
		mgr.OnUpdate(&proto.WorkloadEndpointUpdate{
			Id: &proto.WorkloadEndpointID{
				OrchestratorId: "k8s",
				WorkloadId:     "default/pod1",
				EndpointId:     "eth0",
			},
			Endpoint: &proto.WorkloadEndpoint{
				Ipv4Nets:          []string{"10.0.0.50/32"},
				LiveMigrationRole: proto.LiveMigrationRole_TARGET,
			},
		})
		Expect(mgr.CompleteDeferredWork()).To(Succeed())
		desired := getDesiredIPs(mgr, "eth0")
		Expect(desired).To(HaveKey("10.0.0.50"))
	})
})
