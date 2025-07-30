// Copyright (c) 2017-2025 Tigera, Inc. All rights reserved.
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
	"context"
	"errors"
	"net"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	dpsets "github.com/projectcalico/calico/felix/dataplane/ipsets"
	"github.com/projectcalico/calico/felix/dataplane/linux/dataplanedefs"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/logutils"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/routetable"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

var _ = Describe("IPIPManager", func() {
	var (
		ipipMgr   *ipipManager
		rt        *mockRouteTable
		ipSets    *dpsets.MockIPSets
		dataplane *mockTunnelDataplane
	)

	const (
		externalCIDR = "10.10.10.0/24"
	)

	BeforeEach(func() {
		ipSets = dpsets.NewMockIPSets()
		rt = &mockRouteTable{
			currentRoutes: map[string][]routetable.Target{},
		}

		la := netlink.NewLinkAttrs()
		la.Name = "eth0"
		opRecorder := logutils.NewSummarizer("test")

		dataplane = &mockTunnelDataplane{
			links:          []netlink.Link{&mockLink{attrs: la}},
			tunnelLinkName: dataplanedefs.IPIPIfaceName,
		}
		ipipMgr = newIPIPManagerWithShims(
			ipSets, rt, dataplanedefs.IPIPIfaceName,
			4,
			1400,
			Config{
				MaxIPSetSize:       1024,
				Hostname:           "node1",
				ExternalNodesCidrs: []string{"10.10.10.0/24"},
				RulesConfig: rules.Config{
					IPIPTunnelAddress: net.ParseIP("192.168.0.1"),
				},
				ProgramClusterRoutes: true,
				DeviceRouteProtocol:  dataplanedefs.DefaultRouteProto,
			},
			opRecorder,
			dataplane,
		)
	})

	It("should configure tunnel properly", func() {
		ipipMgr.OnUpdate(&proto.HostMetadataUpdate{
			Hostname: "node1",
			Ipv4Addr: "172.0.0.2",
		})
		ipipMgr.routeMgr.OnParentDeviceUpdate("eth0")

		Expect(ipipMgr.routeMgr.parentDeviceAddr).NotTo(BeZero())
		Expect(ipipMgr.routeMgr.parentDevice).NotTo(BeEmpty())
		noEncapDev, err := ipipMgr.routeMgr.detectParentIface()
		Expect(err).NotTo(HaveOccurred())
		Expect(noEncapDev).NotTo(BeNil())

		link, addr, err := ipipMgr.device(noEncapDev)
		Expect(err).NotTo(HaveOccurred())
		Expect(link).NotTo(BeNil())
		Expect(addr).NotTo(BeZero())

		err = ipipMgr.routeMgr.configureTunnelDevice(link, addr, 1400, false)
		Expect(err).NotTo(HaveOccurred())

		Expect(noEncapDev).NotTo(BeNil())
		Expect(err).NotTo(HaveOccurred())

		Expect(dataplane.tunnelLink).ToNot(BeNil())
		Expect(dataplane.tunnelLinkAttrs.MTU).To(Equal(1400))
		Expect(dataplane.tunnelLinkAttrs.Flags).To(Equal(net.FlagUp))
		Expect(dataplane.addrs).To(HaveLen(1))
		Expect(dataplane.addrs[0].IP.String()).To(Equal("192.168.0.1"))

		dataplane.ResetCalls()
		err = ipipMgr.routeMgr.configureTunnelDevice(link, addr, 50, false)
		Expect(err).ToNot(HaveOccurred())
		Expect(dataplane.LinkAddCalled).To(BeFalse())
		Expect(dataplane.LinkSetUpCalled).To(BeFalse())
		Expect(dataplane.LinkSetMTUCalled).To(BeTrue())
		Expect(dataplane.tunnelLinkAttrs.MTU).To(Equal(50))
		Expect(dataplane.AddrUpdated).To(BeFalse())

		dataplane.ResetCalls()
		err = ipipMgr.routeMgr.configureTunnelDevice(link, addr, 1500, false)
		Expect(err).ToNot(HaveOccurred())
		Expect(dataplane.LinkAddCalled).To(BeFalse())
		Expect(dataplane.LinkSetUpCalled).To(BeFalse())
		Expect(dataplane.tunnelLinkAttrs.MTU).To(Equal(1500))
		Expect(dataplane.addrs).To(HaveLen(1))
		Expect(dataplane.addrs[0].IP.String()).To(Equal("192.168.0.1"))

		dataplane.ResetCalls()
		err = ipipMgr.routeMgr.configureTunnelDevice(link, "", 1500, false)
		Expect(err).To(HaveOccurred())
		Expect(dataplane.tunnelLink).ToNot(BeNil())
		Expect(dataplane.LinkAddCalled).To(BeFalse())
		Expect(dataplane.LinkSetUpCalled).To(BeFalse())
		Expect(dataplane.tunnelLinkAttrs.MTU).To(Equal(1500))
		Expect(dataplane.tunnelLinkAttrs.Flags).To(Equal(net.FlagUp))
		Expect(dataplane.addrs).To(HaveLen(1))
		Expect(dataplane.addrs[0].IP.String()).To(Equal("192.168.0.1"))
	})

	allHostsSet := func() set.Set[string] {
		logrus.Info(ipSets.Members)
		Expect(ipSets.Members).To(HaveLen(1))
		return ipSets.Members["all-hosts-net"]
	}

	It("should handle IPSet updates correctly", func() {
		By("checking the the IP set is not created until first call to CompleteDeferredWork()")
		Expect(ipSets.AddOrReplaceCalled).To(BeFalse())
		err := ipipMgr.CompleteDeferredWork()
		Expect(err).ToNot(HaveOccurred())
		Expect(ipSets.AddOrReplaceCalled).To(BeTrue())

		By("adding host1")
		ipipMgr.OnUpdate(&proto.HostMetadataUpdate{
			Hostname: "host1",
			Ipv4Addr: "10.0.0.1",
		})
		err = ipipMgr.CompleteDeferredWork()
		Expect(err).ToNot(HaveOccurred())
		Expect(allHostsSet()).To(Equal(set.From("10.0.0.1", externalCIDR)))

		By("adding host2")
		ipipMgr.OnUpdate(&proto.HostMetadataUpdate{
			Hostname: "host2",
			Ipv4Addr: "10.0.0.2",
		})
		err = ipipMgr.CompleteDeferredWork()
		Expect(err).ToNot(HaveOccurred())
		Expect(allHostsSet()).To(Equal(set.From("10.0.0.1", "10.0.0.2", externalCIDR)))

		By("testing tolerance for duplicate ip")
		ipipMgr.OnUpdate(&proto.HostMetadataUpdate{
			Hostname: "host3",
			Ipv4Addr: "10.0.0.2",
		})
		err = ipipMgr.CompleteDeferredWork()
		Expect(err).ToNot(HaveOccurred())
		Expect(allHostsSet()).To(Equal(set.From("10.0.0.1", "10.0.0.2", externalCIDR)))

		By("removing the duplicate ip should keep the ip")
		ipipMgr.OnUpdate(&proto.HostMetadataRemove{
			Hostname: "host3",
		})
		err = ipipMgr.CompleteDeferredWork()
		Expect(err).ToNot(HaveOccurred())
		Expect(allHostsSet()).To(Equal(set.From("10.0.0.1", "10.0.0.2", externalCIDR)))

		By("removing the initial copy of ip")
		ipipMgr.OnUpdate(&proto.HostMetadataRemove{
			Hostname: "host2",
		})
		err = ipipMgr.CompleteDeferredWork()
		Expect(err).ToNot(HaveOccurred())
		Expect(allHostsSet()).To(Equal(set.From("10.0.0.1", externalCIDR)))

		By("adding/removing a duplicate IP in one batch")
		ipipMgr.OnUpdate(&proto.HostMetadataUpdate{
			Hostname: "host2",
			Ipv4Addr: "10.0.0.1",
		})
		ipipMgr.OnUpdate(&proto.HostMetadataRemove{
			Hostname: "host2",
		})
		err = ipipMgr.CompleteDeferredWork()
		Expect(err).ToNot(HaveOccurred())
		Expect(allHostsSet()).To(Equal(set.From("10.0.0.1", externalCIDR)))

		By("changing ip of host1")
		ipipMgr.OnUpdate(&proto.HostMetadataUpdate{
			Hostname: "host1",
			Ipv4Addr: "10.0.0.2",
		})
		err = ipipMgr.CompleteDeferredWork()
		Expect(err).ToNot(HaveOccurred())
		Expect(allHostsSet()).To(Equal(set.From("10.0.0.2", externalCIDR)))

		By("sending a no-op batch")
		ipSets.AddOrReplaceCalled = false
		err = ipipMgr.CompleteDeferredWork()
		Expect(err).ToNot(HaveOccurred())
		Expect(ipSets.AddOrReplaceCalled).To(BeFalse())
		Expect(allHostsSet()).To(Equal(set.From("10.0.0.2", externalCIDR)))
	})

	It("successfully adds a route to the noEncap interface", func() {
		ipipMgr.OnUpdate(&proto.HostMetadataUpdate{
			Hostname: "node1",
			Ipv4Addr: "172.0.0.2",
		})
		ipipMgr.OnUpdate(&proto.HostMetadataUpdate{
			Hostname: "node2",
			Ipv4Addr: "172.0.2.2",
		})

		ipipMgr.routeMgr.OnParentDeviceUpdate("eth0")

		Expect(ipipMgr.routeMgr.parentDeviceAddr).NotTo(BeZero())
		Expect(ipipMgr.routeMgr.parentDevice).NotTo(BeEmpty())
		noEncapDev, err := ipipMgr.routeMgr.detectParentIface()
		Expect(err).NotTo(HaveOccurred())
		Expect(noEncapDev).NotTo(BeNil())

		link, addr, err := ipipMgr.device(noEncapDev)
		Expect(err).NotTo(HaveOccurred())
		Expect(link).NotTo(BeNil())
		Expect(addr).NotTo(BeZero())

		err = ipipMgr.routeMgr.configureTunnelDevice(link, addr, 50, false)
		Expect(err).NotTo(HaveOccurred())

		Expect(noEncapDev).NotTo(BeNil())
		Expect(err).NotTo(HaveOccurred())

		ipipMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_REMOTE_WORKLOAD,
			IpPoolType:  proto.IPPoolType_IPIP,
			Dst:         "192.168.0.3/26",
			DstNodeName: "node2",
			DstNodeIp:   "172.0.2.2",
			SameSubnet:  true,
		})

		ipipMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_REMOTE_WORKLOAD,
			IpPoolType:  proto.IPPoolType_IPIP,
			Dst:         "192.168.0.2/26",
			DstNodeName: "node2",
			DstNodeIp:   "172.0.2.2",
		})

		ipipMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_LOCAL_WORKLOAD,
			IpPoolType:  proto.IPPoolType_IPIP,
			Dst:         "192.168.0.100/26",
			DstNodeName: "node1",
			DstNodeIp:   "172.0.0.2",
			SameSubnet:  true,
		})

		// Borrowed /32 should not be programmed as blackhole.
		ipipMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_LOCAL_WORKLOAD,
			IpPoolType:  proto.IPPoolType_IPIP,
			Dst:         "192.168.0.10/32",
			DstNodeName: "node1",
			DstNodeIp:   "172.0.0.2",
			SameSubnet:  true,
		})

		Expect(rt.currentRoutes[dataplanedefs.IPIPIfaceName]).To(HaveLen(0))
		Expect(rt.currentRoutes[routetable.InterfaceNone]).To(HaveLen(0))

		err = ipipMgr.CompleteDeferredWork()

		Expect(err).NotTo(HaveOccurred())
		Expect(rt.currentRoutes[dataplanedefs.IPIPIfaceName]).To(HaveLen(1))
		Expect(rt.currentRoutes[routetable.InterfaceNone]).To(HaveLen(1))
		Expect(rt.currentRoutes["eth0"]).NotTo(BeNil())
	})

	It("should fall back to programming tunneled routes if the noEncap device is not known", func() {
		dataDeviceC := make(chan string)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go ipipMgr.keepIPIPDeviceInSync(ctx, 1400, false, 1*time.Second, dataDeviceC)

		By("Sending another node's route.")
		ipipMgr.OnUpdate(&proto.HostMetadataUpdate{
			Hostname: "node2",
			Ipv4Addr: "10.0.0.2",
		})
		ipipMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_REMOTE_WORKLOAD,
			IpPoolType:  proto.IPPoolType_IPIP,
			Dst:         "192.168.10.0/26",
			DstNodeName: "node2",
			DstNodeIp:   "10.0.0.2",
			SameSubnet:  true,
		})

		err := ipipMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())
		Expect(ipipMgr.routeMgr.routesDirty).To(BeFalse())
		Expect(rt.currentRoutes["eth0"]).To(HaveLen(0))
		Expect(rt.currentRoutes[dataplanedefs.IPIPIfaceName]).To(HaveLen(1))

		By("Sending another local node update.")
		ipipMgr.OnUpdate(&proto.HostMetadataUpdate{
			Hostname: "node1",
			Ipv4Addr: "172.0.0.2",
		})
		localAddr := ipipMgr.routeMgr.parentIfaceAddr()
		Expect(localAddr).NotTo(BeNil())

		// Note: no encap device name is sent after configuration so this receive
		// ensures we don't race.

		By("waiting")
		Eventually(dataDeviceC, "2s").Should(Receive(Equal("eth0")))
		ipipMgr.routeMgr.OnParentDeviceUpdate("eth0")

		Expect(rt.currentRoutes["eth0"]).To(HaveLen(0))
		err = ipipMgr.CompleteDeferredWork()

		Expect(err).NotTo(HaveOccurred())
		Expect(ipipMgr.routeMgr.routesDirty).To(BeFalse())
		Expect(rt.currentRoutes["eth0"]).To(HaveLen(1))
		Expect(rt.currentRoutes[dataplanedefs.IPIPIfaceName]).To(HaveLen(0))
	})

	It("should program routes for remote endpoints with borrowed IP addresses", func() {
		By("Sending host updates")
		ipipMgr.OnUpdate(&proto.HostMetadataUpdate{
			Hostname: "node1",
			Ipv4Addr: "172.0.0.2",
		})
		ipipMgr.OnUpdate(&proto.HostMetadataUpdate{
			Hostname: "node2",
			Ipv4Addr: "172.0.2.2",
		})

		By("Sending a borrowed tunnel IP address")
		ipipMgr.OnUpdate(&proto.RouteUpdate{
			Types:       proto.RouteType_REMOTE_TUNNEL,
			IpPoolType:  proto.IPPoolType_IPIP,
			Dst:         "10.0.1.1/32",
			DstNodeName: "node2",
			DstNodeIp:   "172.0.2.2",
			Borrowed:    true,
		})

		err := ipipMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		// Expect a directly connected route to the borrowed IP.
		Expect(rt.currentRoutes[dataplanedefs.IPIPIfaceName]).To(HaveLen(1))
		Expect(rt.currentRoutes[dataplanedefs.IPIPIfaceName][0]).To(Equal(
			routetable.Target{
				Type:     "onlink",
				CIDR:     ip.MustParseCIDROrIP("10.0.1.1/32"),
				GW:       ip.FromString("172.0.2.2"),
				Protocol: 80,
			}))

		// Delete the route.
		ipipMgr.OnUpdate(&proto.RouteRemove{
			Dst: "10.0.1.1/32",
		})

		err = ipipMgr.CompleteDeferredWork()
		Expect(err).NotTo(HaveOccurred())

		// Expect no routes.
		Expect(rt.currentRoutes[dataplanedefs.IPIPIfaceName]).To(HaveLen(0))
	})
})

const (
	mockedTunnelIndex = 6
)

var (
	notFound    = errors.New("not found")
	mockFailure = errors.New("mock failure")
)

type mockTunnelDataplane struct {
	tunnelLink      netlink.Link
	tunnelLinkAttrs *netlink.LinkAttrs
	tunnelLinkName  string
	addrs           []netlink.Addr

	LinkAddCalled    bool
	LinkSetMTUCalled bool
	LinkSetUpCalled  bool
	AddrUpdated      bool

	NumCalls    int
	ErrorAtCall int

	ipVersion uint8
	links     []netlink.Link
}

func (d *mockTunnelDataplane) ResetCalls() {
	d.LinkAddCalled = false
	d.LinkSetMTUCalled = false
	d.LinkSetUpCalled = false
	d.AddrUpdated = false
}

func (d *mockTunnelDataplane) incCallCount() error {
	d.NumCalls += 1
	if d.NumCalls == d.ErrorAtCall {
		logrus.Warn("Simulating an error due to call count")
		return mockFailure
	}
	return nil
}

func (d *mockTunnelDataplane) LinkByName(name string) (netlink.Link, error) {
	logrus.WithField("name", name).Info("LinkByName called")

	if err := d.incCallCount(); err != nil {
		return nil, err
	}

	Expect(name).To(Equal(d.tunnelLinkName))
	if d.tunnelLink == nil {
		return nil, notFound
	}
	return d.tunnelLink, nil
}

func (d *mockTunnelDataplane) LinkSetMTU(link netlink.Link, mtu int) error {
	d.LinkSetMTUCalled = true
	if err := d.incCallCount(); err != nil {
		return err
	}
	Expect(link.Attrs().Name).To(Equal(d.tunnelLinkName))
	d.tunnelLinkAttrs.MTU = mtu
	return nil
}

func (d *mockTunnelDataplane) LinkSetUp(link netlink.Link) error {
	d.LinkSetUpCalled = true
	if err := d.incCallCount(); err != nil {
		return err
	}
	Expect(link.Attrs().Name).To(Equal(d.tunnelLinkName))
	d.tunnelLinkAttrs.Flags |= net.FlagUp
	return nil
}

func (d *mockTunnelDataplane) AddrList(link netlink.Link, family int) ([]netlink.Addr, error) {
	if err := d.incCallCount(); err != nil {
		return nil, err
	}

	name := link.Attrs().Name
	Expect(name).Should(BeElementOf(d.tunnelLinkName, "eth0"))
	if name == "eth0" {
		if d.ipVersion == 6 {
			return []netlink.Addr{{
				IPNet: &net.IPNet{
					IP: net.ParseIP("fc00:10:96::2"),
				}},
			}, nil
		}
		return []netlink.Addr{{
			IPNet: &net.IPNet{
				IP: net.IPv4(172, 0, 0, 2),
			}},
		}, nil
	}
	return d.addrs, nil
}

func (d *mockTunnelDataplane) AddrAdd(link netlink.Link, addr *netlink.Addr) error {
	d.AddrUpdated = true
	if err := d.incCallCount(); err != nil {
		return err
	}
	Expect(d.addrs).NotTo(ContainElement(*addr))
	d.addrs = append(d.addrs, *addr)
	return nil
}

func (d *mockTunnelDataplane) AddrDel(link netlink.Link, addr *netlink.Addr) error {
	d.AddrUpdated = true
	if err := d.incCallCount(); err != nil {
		return err
	}
	Expect(d.addrs).To(HaveLen(1))
	Expect(d.addrs[0].IP.String()).To(Equal(addr.IP.String()))
	d.addrs = nil
	return nil
}

func (d *mockTunnelDataplane) LinkList() ([]netlink.Link, error) {
	return d.links, nil
}

func (d *mockTunnelDataplane) LinkAdd(l netlink.Link) error {
	d.LinkAddCalled = true
	if err := d.incCallCount(); err != nil {
		return err
	}
	Expect(l.Attrs().Name).To(Equal(d.tunnelLinkName))
	if d.tunnelLink == nil {
		logrus.Info("Creating tunnel link")
		l.Attrs().Index = mockedTunnelIndex
		d.tunnelLinkAttrs = l.Attrs()
		d.tunnelLink = l
	}
	return nil
}

func (d *mockTunnelDataplane) LinkDel(_ netlink.Link) error {
	return nil
}

type mockLink struct {
	attrs netlink.LinkAttrs
	typ   string
}

func (l *mockLink) Attrs() *netlink.LinkAttrs {
	return &l.attrs
}

func (l *mockLink) Type() string {
	if l.typ == "" {
		return "not implemented"
	}

	return l.typ
}
