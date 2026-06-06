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

	"github.com/projectcalico/calico/felix/netlinkshim/mocknetlink"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

// testReadTimeout is the per-read deadline used by unit-test managers: small so
// a listener that loops on a read timeout (and teardown) is near-instant rather
// than waiting the production readDeadlineInterval.
const testReadTimeout = 10 * time.Millisecond

func newMockNetlinkForProxyNeigh() *mocknetlink.MockNetlinkDataplane {
	dp := mocknetlink.New()
	// ifindex 1 is reserved for "lo" by the shared mock, so number our
	// interfaces from 2 upwards.
	dp.AddIface(2, "eth0", true, true)
	dp.AddIface(3, "eth1", true, true)
	// Mark the handle "open" so the NetlinkOpen assertions in LinkByName /
	// AddrList pass (the manager is handed an already-opened handle).
	dp.NetlinkOpen = true
	return dp
}

// setIfaceAddr sets (replacing any existing) the address that AddrList reports
// for the named interface on the mock netlink dataplane.
func setIfaceAddr(nl *mocknetlink.MockNetlinkDataplane, name, cidr string) {
	ip, ipnet, _ := net.ParseCIDR(cidr)
	if ip != nil {
		ipnet.IP = ip
	}
	nl.NameToLink[name].Addrs = []netlink.Addr{{IPNet: ipnet}}
}

// readTimeoutError mimics the net.Error a real arp/ndp socket returns when its
// read deadline expires, so the mock listeners exercise the same
// timeout-then-recheck-context loop as production rather than blocking forever.
type readTimeoutError struct{}

func (readTimeoutError) Error() string   { return "read timeout" }
func (readTimeoutError) Timeout() bool   { return true }
func (readTimeoutError) Temporary() bool { return true }

// deadlineCh returns a channel that fires at deadline, or nil (blocks forever)
// when the deadline is unset — mirroring a socket with no read deadline set.
func deadlineCh(deadline time.Time) <-chan time.Time {
	if deadline.IsZero() {
		return nil
	}
	return time.After(time.Until(deadline))
}

// --- Mock ARP client ---

type mockARPClient struct {
	mu           sync.Mutex
	reads        chan *arp.Packet
	readErr      chan error
	writes       []arpWrite
	hwAddr       net.HardwareAddr
	readDeadline time.Time
	closed       bool
}

type arpWrite struct {
	packet *arp.Packet
	dest   net.HardwareAddr
}

func newMockARPClient(hwAddr net.HardwareAddr) *mockARPClient {
	return &mockARPClient{
		reads:   make(chan *arp.Packet, 10),
		readErr: make(chan error, 1),
		hwAddr:  hwAddr,
	}
}

func (c *mockARPClient) Read() (*arp.Packet, *ethernet.Frame, error) {
	select {
	case err := <-c.readErr:
		return nil, nil, err
	case pkt, ok := <-c.reads:
		if !ok {
			return nil, nil, fmt.Errorf("closed")
		}
		return pkt, nil, nil
	case <-deadlineCh(c.readDeadline):
		return nil, nil, readTimeoutError{}
	}
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

func (c *mockARPClient) SetReadDeadline(t time.Time) error {
	c.readDeadline = t
	return nil
}

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
	mu           sync.Mutex
	reads        chan ndpRead
	writes       []ndpWrite
	joinedGroups []netip.Addr
	leftGroups   []netip.Addr
	readDeadline time.Time
	closed       bool
}

type ndpWrite struct {
	msg ndp.Message
	dst netip.Addr
}

// ndpRead is an incoming NDP message plus the source address it arrived from,
// so tests can drive both unicast solicitations and :: DAD probes.
type ndpRead struct {
	msg ndp.Message
	src netip.Addr
}

func newMockNDPConn() *mockNDPConn {
	return &mockNDPConn{
		reads: make(chan ndpRead, 10),
	}
}

func (c *mockNDPConn) ReadFrom() (ndp.Message, *ipv6.ControlMessage, netip.Addr, error) {
	select {
	case r, ok := <-c.reads:
		if !ok {
			return nil, nil, netip.Addr{}, fmt.Errorf("closed")
		}
		return r.msg, nil, r.src, nil
	case <-deadlineCh(c.readDeadline):
		return nil, nil, netip.Addr{}, readTimeoutError{}
	}
}

func (c *mockNDPConn) WriteTo(m ndp.Message, cm *ipv6.ControlMessage, dst netip.Addr) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes = append(c.writes, ndpWrite{msg: m, dst: dst})
	return nil
}

func (c *mockNDPConn) JoinGroup(group netip.Addr) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.joinedGroups = append(c.joinedGroups, group)
	return nil
}

func (c *mockNDPConn) LeaveGroup(group netip.Addr) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.leftGroups = append(c.leftGroups, group)
	return nil
}

func (c *mockNDPConn) getJoinedGroups() []netip.Addr {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]netip.Addr, len(c.joinedGroups))
	copy(out, c.joinedGroups)
	return out
}

func (c *mockNDPConn) getLeftGroups() []netip.Addr {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]netip.Addr, len(c.leftGroups))
	copy(out, c.leftGroups)
	return out
}

func (c *mockNDPConn) SetReadDeadline(t time.Time) error {
	c.readDeadline = t
	return nil
}

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

func (c *mockNDPConn) resetWrites() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes = nil
}

// --- Test helpers ---

func newTestProxyNeighManager(nl *mocknetlink.MockNetlinkDataplane, arpClients map[string]*mockARPClient) *proxyNeighManager {
	return newTestProxyNeighManagerWithHostname(nl, arpClients, "test-node")
}

func newTestProxyNeighManagerWithHostname(nl *mocknetlink.MockNetlinkDataplane, arpClients map[string]*mockARPClient, hostname string) *proxyNeighManager {
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
	mgr := newProxyNeighManagerWithShims(config, 4, nl, af, nil, testReadTimeout)
	// Register a default no-encap pool covering the test subnet.
	sendNoEncapPool(mgr, "default-test-pool", "10.0.0.0/8")
	return mgr
}

// ndpTestHWAddr is the MAC the test NDP listener answers with.
var ndpTestHWAddr = net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x06}

func newTestProxyNDPManager(nl *mocknetlink.MockNetlinkDataplane, ndpConns map[string]*mockNDPConn) *proxyNeighManager {
	config := Config{
		RulesConfig: rules.Config{
			WorkloadIfacePrefixes: []string{"cali"},
		},
	}
	nf := func(ifaceName string) (ndpConn, net.HardwareAddr, error) {
		if c, ok := ndpConns[ifaceName]; ok {
			return c, ndpTestHWAddr, nil
		}
		return nil, nil, fmt.Errorf("no mock for %s", ifaceName)
	}
	mgr := newProxyNeighManagerWithShims(config, 6, nl, nil, nf, testReadTimeout)
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
	mgr.OnUpdate(&proto.HostMetadataUpdate{
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
func getDesiredIPs(mgr *proxyNeighManager, ifaceName string) set.Set[string] {
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

// injectARPRequest pushes an ARP "who-has targetIP" request (from senderHW /
// senderIP) onto the client's read channel, simulating a request arriving on
// the wire.
func (c *mockARPClient) injectARPRequest(senderHW net.HardwareAddr, senderIP, targetIP string) {
	pkt, err := arp.NewPacket(arp.OperationRequest, senderHW, netip.MustParseAddr(senderIP),
		make(net.HardwareAddr, 6), netip.MustParseAddr(targetIP))
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	c.reads <- pkt
}

// injectNS pushes an IPv6 Neighbor Solicitation for targetIP, arriving from src,
// onto the conn's read channel.
func (c *mockNDPConn) injectNS(src, targetIP string) {
	c.reads <- ndpRead{
		msg: &ndp.NeighborSolicitation{TargetAddress: netip.MustParseAddr(targetIP)},
		src: netip.MustParseAddr(src),
	}
}

// --- Tests ---

var _ = Describe("Proxy neighbor manager (IPv4)", func() {
	var (
		mgr        *proxyNeighManager
		nl         *mocknetlink.MockNetlinkDataplane
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
		mgr.Stop()
	})

	Describe("basic enable", func() {
		BeforeEach(func() {
			setIfaceAddr(nl, "eth0", "10.0.0.1/24")
			sendIfaceAddrsUpdate(mgr, "eth0", "10.0.0.1")
			mgr.OnUpdate(proxyNeighWepUpdate("k8s", "default/pod1", "eth0", "10.0.0.50/32"))
			Expect(mgr.CompleteDeferredWork()).To(Succeed())
		})

		It("should have 10.0.0.50 in desired set for eth0", func() {
			desired := getDesiredIPs(mgr, "eth0")
			Expect(desired.Contains("10.0.0.50")).To(BeTrue())
		})

		It("should start a listener on eth0", func() {
			Expect(mgr.listeners).To(HaveKey("eth0"))
		})

		It("should send a correct gratuitous ARP for the new IP", func() {
			Eventually(func() int {
				return len(arpClients["eth0"].getWrites())
			}).Should(Equal(1))
			garp := arpClients["eth0"].getWrites()[0]
			Expect(garp.packet.Operation).To(Equal(arp.OperationRequest))
			Expect(garp.packet.SenderHardwareAddr).To(Equal(arpClients["eth0"].hwAddr))
			Expect(garp.packet.SenderIP.String()).To(Equal("10.0.0.50"))
			Expect(garp.packet.TargetIP.String()).To(Equal("10.0.0.50"))
			Expect(garp.dest).To(Equal(ethernet.Broadcast))
		})
	})

	Describe("workload removed", func() {
		BeforeEach(func() {
			setIfaceAddr(nl, "eth0", "10.0.0.1/24")
			sendIfaceAddrsUpdate(mgr, "eth0", "10.0.0.1")
			mgr.OnUpdate(proxyNeighWepUpdate("k8s", "default/pod1", "eth0", "10.0.0.50/32"))
			Expect(mgr.CompleteDeferredWork()).To(Succeed())
			Expect(getDesiredIPs(mgr, "eth0").Contains("10.0.0.50")).To(BeTrue())

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
			setIfaceAddr(nl, "eth0", "10.0.0.1/24")
			sendIfaceAddrsUpdate(mgr, "eth0", "10.0.0.1")
			mgr.OnUpdate(proxyNeighWepUpdate("k8s", "default/pod1", "eth0", "10.0.0.50/32"))
			mgr.OnUpdate(proxyNeighWepUpdate("k8s", "default/pod2", "eth0", "10.0.0.51/32"))
			Expect(mgr.CompleteDeferredWork()).To(Succeed())
		})

		It("should have both IPs in the desired set", func() {
			desired := getDesiredIPs(mgr, "eth0")
			Expect(desired.Contains("10.0.0.50")).To(BeTrue())
			Expect(desired.Contains("10.0.0.51")).To(BeTrue())
		})
	})

	Describe("no match - pod outside any host subnet", func() {
		BeforeEach(func() {
			setIfaceAddr(nl, "eth0", "10.0.0.1/24")
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
			setIfaceAddr(nl, "eth0", "10.0.0.1/24")
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
			setIfaceAddr(nl, "eth0", "10.0.0.1/24")
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
			setIfaceAddr(nl, "eth0", "10.0.0.1/24")
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
			setIfaceAddr(nl, "eth0", "10.0.0.1/24")
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

	Describe("multiple interfaces", func() {
		BeforeEach(func() {
			setIfaceAddr(nl, "eth0", "10.0.0.1/24")
			setIfaceAddr(nl, "eth1", "10.1.0.1/24")
			sendIfaceAddrsUpdate(mgr, "eth0", "10.0.0.1")
			sendIfaceAddrsUpdate(mgr, "eth1", "10.1.0.1")
			// One pod in each host interface's subnet.
			mgr.OnUpdate(proxyNeighWepUpdate("k8s", "default/pod-a", "eth0", "10.0.0.50/32"))
			mgr.OnUpdate(proxyNeighWepUpdate("k8s", "default/pod-b", "eth0", "10.1.0.50/32"))
			Expect(mgr.CompleteDeferredWork()).To(Succeed())
		})

		It("starts a listener on each interface", func() {
			Expect(mgr.listeners).To(HaveKey("eth0"))
			Expect(mgr.listeners).To(HaveKey("eth1"))
		})

		It("assigns each pod IP only to the interface whose subnet contains it", func() {
			Expect(getDesiredIPs(mgr, "eth0").Contains("10.0.0.50")).To(BeTrue())
			Expect(getDesiredIPs(mgr, "eth0").Contains("10.1.0.50")).To(BeFalse())
			Expect(getDesiredIPs(mgr, "eth1").Contains("10.1.0.50")).To(BeTrue())
			Expect(getDesiredIPs(mgr, "eth1").Contains("10.0.0.50")).To(BeFalse())
		})

		It("answers ARP on each interface using that interface's own MAC", func() {
			requesterHW := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x99}
			arpClients["eth0"].resetWrites()
			arpClients["eth1"].resetWrites()

			arpClients["eth0"].injectARPRequest(requesterHW, "10.0.0.200", "10.0.0.50")
			arpClients["eth1"].injectARPRequest(requesterHW, "10.1.0.200", "10.1.0.50")

			Eventually(func() int { return len(arpClients["eth0"].getWrites()) }).Should(Equal(1))
			Eventually(func() int { return len(arpClients["eth1"].getWrites()) }).Should(Equal(1))

			eth0Reply := arpClients["eth0"].getWrites()[0]
			Expect(eth0Reply.packet.SenderHardwareAddr).To(Equal(arpClients["eth0"].hwAddr))
			Expect(eth0Reply.packet.SenderIP.String()).To(Equal("10.0.0.50"))

			eth1Reply := arpClients["eth1"].getWrites()[0]
			Expect(eth1Reply.packet.SenderHardwareAddr).To(Equal(arpClients["eth1"].hwAddr))
			Expect(eth1Reply.packet.SenderIP.String()).To(Equal("10.1.0.50"))
		})
	})

	Describe("answering ARP requests", func() {
		const ownedIP = "10.0.0.50"
		requesterHW := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x99}

		BeforeEach(func() {
			setIfaceAddr(nl, "eth0", "10.0.0.1/24")
			sendIfaceAddrsUpdate(mgr, "eth0", "10.0.0.1")
			mgr.OnUpdate(proxyNeighWepUpdate("k8s", "default/pod1", "eth0", ownedIP+"/32"))
			Expect(mgr.CompleteDeferredWork()).To(Succeed())
			Expect(getDesiredIPs(mgr, "eth0").Contains(ownedIP)).To(BeTrue())
			// Drop the gratuitous ARP sent on enable so we only observe replies.
			arpClients["eth0"].resetWrites()
		})

		It("replies to a request for an owned IP with the correct packet", func() {
			arpClients["eth0"].injectARPRequest(requesterHW, "10.0.0.200", ownedIP)

			Eventually(func() int { return len(arpClients["eth0"].getWrites()) }).Should(Equal(1))
			reply := arpClients["eth0"].getWrites()[0]
			Expect(reply.packet.Operation).To(Equal(arp.OperationReply))
			Expect(reply.packet.SenderHardwareAddr).To(Equal(arpClients["eth0"].hwAddr))
			Expect(reply.packet.SenderIP.String()).To(Equal(ownedIP))
			Expect(reply.packet.TargetHardwareAddr).To(Equal(requesterHW))
			Expect(reply.packet.TargetIP.String()).To(Equal("10.0.0.200"))
			Expect(reply.dest).To(Equal(requesterHW))
		})

		It("ignores a request for an IP it does not own", func() {
			// Send an un-owned request, then an owned one. The listener processes
			// them in order, so seeing exactly one reply — for the owned IP —
			// proves the un-owned request was read and ignored.
			arpClients["eth0"].injectARPRequest(requesterHW, "10.0.0.200", "10.0.0.99")
			arpClients["eth0"].injectARPRequest(requesterHW, "10.0.0.200", ownedIP)

			Eventually(func() int { return len(arpClients["eth0"].getWrites()) }).Should(Equal(1))
			Consistently(func() int { return len(arpClients["eth0"].getWrites()) }).Should(Equal(1))
			Expect(arpClients["eth0"].getWrites()[0].packet.SenderIP.String()).To(Equal(ownedIP))
		})

		It("ignores its own gratuitous ARP (sender MAC is the device's own)", func() {
			arpClients["eth0"].injectARPRequest(arpClients["eth0"].hwAddr, ownedIP, ownedIP)
			arpClients["eth0"].injectARPRequest(requesterHW, "10.0.0.200", ownedIP)

			Eventually(func() int { return len(arpClients["eth0"].getWrites()) }).Should(Equal(1))
			Consistently(func() int { return len(arpClients["eth0"].getWrites()) }).Should(Equal(1))
			Expect(arpClients["eth0"].getWrites()[0].packet.TargetHardwareAddr).To(Equal(requesterHW))
		})
	})
})

var _ = Describe("Proxy neighbor manager - LoadBalancer IPs", func() {

	It("is claimed by exactly one node, which answers and GARPs for it", func() {
		const vip = "10.0.0.100"
		answering := 0
		for _, host := range []string{"node-a", "node-b", "node-c"} {
			nl := newMockNetlinkForProxyNeigh()
			arpClients := map[string]*mockARPClient{
				"eth0": newMockARPClient(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01}),
			}
			mgr := newTestProxyNeighManagerWithHostname(nl, arpClients, host)
			sendHostMetadata(mgr, "node-a", "1.1.1.1")
			sendHostMetadata(mgr, "node-b", "1.1.1.2")
			sendHostMetadata(mgr, "node-c", "1.1.1.3")
			setIfaceAddr(nl, "eth0", "10.0.0.1/24")
			sendIfaceAddrsUpdate(mgr, "eth0", "10.0.0.1")
			mgr.OnUpdate(svcUpdate("my-svc", "default", "LoadBalancer", vip))
			Expect(mgr.CompleteDeferredWork()).To(Succeed())

			if d := getDesiredIPs(mgr, "eth0"); d != nil && d.Contains(vip) {
				answering++
				// The owning node announces the VIP with a gratuitous ARP.
				Eventually(func() int {
					return len(arpClients["eth0"].getWrites())
				}).Should(BeNumerically(">=", 1))
			} else {
				// Non-owning nodes don't open a listener for it at all.
				Expect(mgr.listeners).To(BeEmpty())
			}
			mgr.Stop()
		}
		Expect(answering).To(Equal(1)) // exactly one node owns the VIP
	})
})

var _ = Describe("Proxy NDP manager (IPv6)", func() {
	var (
		mgr      *proxyNeighManager
		nl       *mocknetlink.MockNetlinkDataplane
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
		mgr.Stop()
	})

	Describe("basic IPv6 proxy NDP entry", func() {
		BeforeEach(func() {
			setIfaceAddr(nl, "eth0", "fd00::1/64")
			sendIfaceAddrsUpdate(mgr, "eth0", "fd00::1")
			mgr.OnUpdate(wepUpdateV6("k8s", "default/pod1", "eth0", "fd00::50/128"))
			Expect(mgr.CompleteDeferredWork()).To(Succeed())
		})

		It("should have fd00::50 in desired set for eth0", func() {
			desired := getDesiredIPs(mgr, "eth0")
			Expect(desired.Contains("fd00::50")).To(BeTrue())
		})

		It("should start a listener", func() {
			Expect(mgr.listeners).To(HaveKey("eth0"))
		})

		It("should send a correct unsolicited NA", func() {
			Eventually(func() int {
				return len(ndpConns["eth0"].getWrites())
			}).Should(Equal(1))
			write := ndpConns["eth0"].getWrites()[0]
			na, ok := write.msg.(*ndp.NeighborAdvertisement)
			Expect(ok).To(BeTrue())
			Expect(na.TargetAddress.String()).To(Equal("fd00::50"))
			Expect(na.Override).To(BeTrue())
			Expect(na.Solicited).To(BeFalse()) // unsolicited
			// Sent to all-nodes multicast, carrying this interface's MAC.
			Expect(write.dst.String()).To(Equal("ff02::1"))
			Expect(na.Options).To(HaveLen(1))
			lla, ok := na.Options[0].(*ndp.LinkLayerAddress)
			Expect(ok).To(BeTrue())
			Expect(lla.Direction).To(Equal(ndp.Target))
			Expect(lla.Addr).To(Equal(ndpTestHWAddr))
		})

		It("joins the desired IP's solicited-node multicast group", func() {
			// Without joining this group the kernel never delivers Neighbor
			// Solicitations for the proxied IP to the listener, so it could
			// never answer them.
			want, err := ndp.SolicitedNodeMulticast(netip.MustParseAddr("fd00::50"))
			Expect(err).NotTo(HaveOccurred())
			Expect(ndpConns["eth0"].getJoinedGroups()).To(ContainElement(want))
		})

		It("leaves the solicited-node multicast group when the IP is no longer desired", func() {
			// Move the pod to a different host-subnet IP: fd00::50 drops out of
			// the desired set, so its group should be left.
			mgr.OnUpdate(wepUpdateV6("k8s", "default/pod1", "eth0", "fd00::51/128"))
			Expect(mgr.CompleteDeferredWork()).To(Succeed())
			Expect(getDesiredIPs(mgr, "eth0").Contains("fd00::50")).To(BeFalse())

			left, err := ndp.SolicitedNodeMulticast(netip.MustParseAddr("fd00::50"))
			Expect(err).NotTo(HaveOccurred())
			Expect(ndpConns["eth0"].getLeftGroups()).To(ContainElement(left))
		})
	})

	Describe("answering Neighbor Solicitations", func() {
		const ownedIP = "fd00::50"

		BeforeEach(func() {
			setIfaceAddr(nl, "eth0", "fd00::1/64")
			sendIfaceAddrsUpdate(mgr, "eth0", "fd00::1")
			mgr.OnUpdate(wepUpdateV6("k8s", "default/pod1", "eth0", ownedIP+"/128"))
			Expect(mgr.CompleteDeferredWork()).To(Succeed())
			Expect(getDesiredIPs(mgr, "eth0").Contains(ownedIP)).To(BeTrue())
			// Drop the unsolicited NA sent on enable so we only observe replies.
			ndpConns["eth0"].resetWrites()
		})

		It("replies to a unicast solicitation with a solicited NA", func() {
			ndpConns["eth0"].injectNS("fe80::1234", ownedIP)

			Eventually(func() int { return len(ndpConns["eth0"].getWrites()) }).Should(Equal(1))
			write := ndpConns["eth0"].getWrites()[0]
			na, ok := write.msg.(*ndp.NeighborAdvertisement)
			Expect(ok).To(BeTrue())
			Expect(na.TargetAddress.String()).To(Equal(ownedIP))
			Expect(na.Solicited).To(BeTrue())
			Expect(na.Override).To(BeTrue())
			Expect(write.dst.String()).To(Equal("fe80::1234")) // unicast back to the requester
			Expect(na.Options).To(HaveLen(1))
			lla, ok := na.Options[0].(*ndp.LinkLayerAddress)
			Expect(ok).To(BeTrue())
			Expect(lla.Addr).To(Equal(ndpTestHWAddr))
		})

		It("replies to a  Duplicate Address Detection probe (unspecified source) via all-nodes multicast", func() {
			// A solicitation from :: is Duplicate Address Detection; we can't
			// unicast back, so the NA goes to ff02::1 with the Solicited flag clear.
			ndpConns["eth0"].injectNS("::", ownedIP)

			Eventually(func() int { return len(ndpConns["eth0"].getWrites()) }).Should(Equal(1))
			write := ndpConns["eth0"].getWrites()[0]
			na, ok := write.msg.(*ndp.NeighborAdvertisement)
			Expect(ok).To(BeTrue())
			Expect(na.TargetAddress.String()).To(Equal(ownedIP))
			Expect(na.Solicited).To(BeFalse())
			Expect(write.dst.String()).To(Equal("ff02::1"))
		})

		It("ignores a solicitation for an IP it does not own", func() {
			ndpConns["eth0"].injectNS("fe80::1234", "fd00::99")
			ndpConns["eth0"].injectNS("fe80::1234", ownedIP)

			Eventually(func() int { return len(ndpConns["eth0"].getWrites()) }).Should(Equal(1))
			Consistently(func() int { return len(ndpConns["eth0"].getWrites()) }).Should(Equal(1))
			na, ok := ndpConns["eth0"].getWrites()[0].msg.(*ndp.NeighborAdvertisement)
			Expect(ok).To(BeTrue())
			Expect(na.TargetAddress.String()).To(Equal(ownedIP))
		})
	})
})

var _ = Describe("Proxy neighbor manager - live migration", func() {
	var (
		mgr        *proxyNeighManager
		nl         *mocknetlink.MockNetlinkDataplane
		arpClients map[string]*mockARPClient
	)

	BeforeEach(func() {
		nl = newMockNetlinkForProxyNeigh()
		arpClients = map[string]*mockARPClient{
			"eth0": newMockARPClient(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01}),
		}
		mgr = newTestProxyNeighManager(nl, arpClients)
		setIfaceAddr(nl, "eth0", "10.0.0.1/24")
		sendIfaceAddrsUpdate(mgr, "eth0", "10.0.0.1")
	})

	AfterEach(func() {
		mgr.Stop()
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

var _ = Describe("Proxy neighbor manager - listener recreation", func() {
	var (
		mgr     *proxyNeighManager
		nl      *mocknetlink.MockNetlinkDataplane
		created []*mockARPClient
	)

	BeforeEach(func() {
		nl = newMockNetlinkForProxyNeigh()
		created = nil
		config := Config{
			Hostname:    "test-node",
			RulesConfig: rules.Config{WorkloadIfacePrefixes: []string{"cali"}},
		}
		// Hand out a fresh mock each time a listener is (re)started, recording
		// them so the test can inject a failure into the first one and confirm a
		// second one gets created.
		af := func(ifaceName string) (arpClient, net.HardwareAddr, error) {
			c := newMockARPClient(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01})
			created = append(created, c)
			return c, c.hwAddr, nil
		}
		mgr = newProxyNeighManagerWithShims(config, 4, nl, af, nil, testReadTimeout)
		sendNoEncapPool(mgr, "default-test-pool", "10.0.0.0/8")
		setIfaceAddr(nl, "eth0", "10.0.0.1/24")
		sendIfaceAddrsUpdate(mgr, "eth0", "10.0.0.1")
		mgr.OnUpdate(proxyNeighWepUpdate("k8s", "default/pod1", "eth0", "10.0.0.50/32"))
		Expect(mgr.CompleteDeferredWork()).To(Succeed())
		Expect(mgr.listeners).To(HaveKey("eth0"))
		Expect(created).To(HaveLen(1))
	})

	AfterEach(func() { mgr.Stop() })

	It("recreates a listener after an unrecoverable read error", func() {
		first := mgr.listeners["eth0"]

		// Simulate a broken socket: a persistent, non-timeout read error.
		created[0].readErr <- fmt.Errorf("socket boom")

		// The listener goroutine flags itself failed and exits.
		Eventually(first.failed.Load).Should(BeTrue())

		// A plain reconcile - with nothing else having dirtied the manager -
		// must drop the failed listener and start a fresh one.
		Expect(mgr.CompleteDeferredWork()).To(Succeed())

		recreated := mgr.listeners["eth0"]
		Expect(recreated).ToNot(BeIdenticalTo(first))
		Expect(recreated.failed.Load()).To(BeFalse())
		Expect(created).To(HaveLen(2))
		// The fresh listener still answers for the pod IP.
		Expect(getDesiredIPs(mgr, "eth0").Contains("10.0.0.50")).To(BeTrue())
	})

	It("is a no-op when nothing is dirty and no listener has failed", func() {
		first := mgr.listeners["eth0"]
		Expect(mgr.CompleteDeferredWork()).To(Succeed())
		Expect(mgr.listeners["eth0"]).To(BeIdenticalTo(first))
		Expect(created).To(HaveLen(1))
	})
})
