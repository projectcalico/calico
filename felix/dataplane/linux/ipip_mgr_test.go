// Copyright (c) 2017-2023 Tigera, Inc. All rights reserved.
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
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"errors"
	"fmt"
	"net"

	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/projectcalico/calico/felix/dataplane/common"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/routetable"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

var (
	notFound    = errors.New("not found")
	mockFailure = errors.New("mock failure")
)

var _ = Describe("IpipMgr (tunnel configuration)", func() {
	var (
		ipipMgr      *ipipManager
		ipSets       *common.MockIPSets
		dataplane    *mockIPIPDataplane
		rt, brt, prt *mockRouteTable
	)

	ip, _, err := net.ParseCIDR("10.0.0.1/32")
	if err != nil {
		panic("Failed to parse test IP")
	}
	_, ipNet2, err := net.ParseCIDR("10.0.0.2/32")
	if err != nil {
		panic("Failed to parse test IP")
	}

	BeforeEach(func() {
		dataplane = &mockIPIPDataplane{}
		ipSets = common.NewMockIPSets()
		rt = &mockRouteTable{
			currentRoutes:   map[string][]routetable.Target{},
			currentL2Routes: map[string][]routetable.L2Target{},
		}
		brt = &mockRouteTable{
			currentRoutes:   map[string][]routetable.Target{},
			currentL2Routes: map[string][]routetable.L2Target{},
		}
		prt = &mockRouteTable{
			currentRoutes:   map[string][]routetable.Target{},
			currentL2Routes: map[string][]routetable.L2Target{},
		}
		ipipMgr = newIPIPManagerWithShim(
			ipSets, rt, brt, "tunl0",
			Config{
				MaxIPSetSize:       1024,
				Hostname:           "node1",
				ExternalNodesCidrs: nil,
			},
			&mockIPIPDataplane{},
			4,
			dataplane,
			func(interfacePrefixes []string, ipVersion uint8, vxlan bool, netlinkTimeout time.Duration,
				deviceRouteSourceAddress net.IP, deviceRouteProtocol netlink.RouteProtocol, removeExternalRoutes bool) routetable.RouteTableInterface {
				return prt
			},
		)
	})

	Describe("after calling configureIPIPDevice", func() {
		ip2, _, err := net.ParseCIDR("10.0.0.2/32")
		if err != nil {
			panic("Failed to parse test IP")
		}

		BeforeEach(func() {
			err = ipipMgr.configureIPIPDevice(1400, ip, false)
			Expect(err).ToNot(HaveOccurred())
		})

		It("should create the interface", func() {
			Expect(dataplane.tunnelLink).ToNot(BeNil())
		})
		It("should set the MTU", func() {
			Expect(dataplane.tunnelLinkAttrs.MTU).To(Equal(1400))
		})
		It("should set the interface UP", func() {
			Expect(dataplane.tunnelLinkAttrs.Flags).To(Equal(net.FlagUp))
		})
		It("should configure the address", func() {
			Expect(dataplane.addrs).To(HaveLen(1))
			Expect(dataplane.addrs[0].IP.String()).To(Equal("10.0.0.1"))
		})

		Describe("after second call with same params", func() {
			BeforeEach(func() {
				dataplane.ResetCalls()
				err := ipipMgr.configureIPIPDevice(1400, ip, false)
				Expect(err).ToNot(HaveOccurred())
			})
			It("should avoid creating the interface", func() {
				Expect(dataplane.RunCmdCalled).To(BeFalse())
			})
			It("should avoid setting the interface UP again", func() {
				Expect(dataplane.LinkSetUpCalled).To(BeFalse())
			})
			It("should avoid setting the MTU again", func() {
				Expect(dataplane.LinkSetMTUCalled).To(BeFalse())
			})
			It("should avoid setting the address again", func() {
				Expect(dataplane.AddrUpdated).To(BeFalse())
			})
		})

		Describe("after second call with different params", func() {
			BeforeEach(func() {
				dataplane.ResetCalls()
				err = ipipMgr.configureIPIPDevice(1500, ip2, false)
				Expect(err).ToNot(HaveOccurred())

			})
			It("should avoid creating the interface", func() {
				Expect(dataplane.RunCmdCalled).To(BeFalse())
			})
			It("should avoid setting the interface UP again", func() {
				Expect(dataplane.LinkSetUpCalled).To(BeFalse())
			})
			It("should set the MTU", func() {
				Expect(dataplane.tunnelLinkAttrs.MTU).To(Equal(1500))
			})
			It("should reconfigure the address", func() {
				Expect(dataplane.addrs).To(HaveLen(1))
				Expect(dataplane.addrs[0].IP.String()).To(Equal("10.0.0.2"))
			})
		})

		Describe("after second call with nil IP", func() {
			BeforeEach(func() {
				dataplane.ResetCalls()
				err := ipipMgr.configureIPIPDevice(1500, nil, false)
				Expect(err).ToNot(HaveOccurred())
			})
			It("should avoid creating the interface", func() {
				Expect(dataplane.RunCmdCalled).To(BeFalse())
			})
			It("should avoid setting the interface UP again", func() {
				Expect(dataplane.LinkSetUpCalled).To(BeFalse())
			})
			It("should set the MTU", func() {
				Expect(dataplane.tunnelLinkAttrs.MTU).To(Equal(1500))
			})
			It("should remove the address", func() {
				Expect(dataplane.addrs).To(HaveLen(0))
			})
		})
	})

	Describe("after calling configureIPIPDevice with no IP", func() {
		BeforeEach(func() {
			err := ipipMgr.configureIPIPDevice(1400, nil, false)
			Expect(err).ToNot(HaveOccurred())
		})

		It("should create the interface", func() {
			Expect(dataplane.tunnelLink).ToNot(BeNil())
		})
		It("should set the MTU", func() {
			Expect(dataplane.tunnelLinkAttrs.MTU).To(Equal(1400))
		})
		It("should set the interface UP", func() {
			Expect(dataplane.tunnelLinkAttrs.Flags).To(Equal(net.FlagUp))
		})
		It("should configure the address", func() {
			Expect(dataplane.addrs).To(HaveLen(0))
		})
	})

	// Cover the error cases.  We pass the error back up the stack, check that that happens
	// for all calls.
	const expNumCalls = 8
	It("a successful call should only call into dataplane expected number of times", func() {
		// This spec is a sanity-check that we've got the expNumCalls constant correct.
		err := ipipMgr.configureIPIPDevice(1400, ip, false)
		Expect(err).ToNot(HaveOccurred())
		Expect(dataplane.NumCalls).To(BeNumerically("==", expNumCalls))
	})
	for i := 1; i <= expNumCalls; i++ {
		if i == 1 {
			continue // First LinkByName failure is handled.
		}
		i := i
		Describe(fmt.Sprintf("with a failure after %v calls", i), func() {
			BeforeEach(func() {
				dataplane.ErrorAtCall = i
			})

			It("should return the error", func() {
				Expect(ipipMgr.configureIPIPDevice(1400, ip, false)).To(Equal(mockFailure))
			})

			Describe("with an IP to remove", func() {
				BeforeEach(func() {
					dataplane.addrs = append(dataplane.addrs,
						netlink.Addr{
							IPNet: ipNet2,
						})
				})
				It("should return the error", func() {
					Expect(ipipMgr.configureIPIPDevice(1400, ip, false)).To(Equal(mockFailure))
				})
			})
		})
	}
})

var _ = Describe("ipipManager IP set updates", func() {
	var (
		ipipMgr      *ipipManager
		ipSets       *common.MockIPSets
		dataplane    *mockIPIPDataplane
		rt, brt, prt *mockRouteTable
	)

	const (
		externalCIDR = "11.0.0.1/32"
	)

	BeforeEach(func() {
		dataplane = &mockIPIPDataplane{}
		ipSets = common.NewMockIPSets()
		rt = &mockRouteTable{
			currentRoutes:   map[string][]routetable.Target{},
			currentL2Routes: map[string][]routetable.L2Target{},
		}
		brt = &mockRouteTable{
			currentRoutes:   map[string][]routetable.Target{},
			currentL2Routes: map[string][]routetable.L2Target{},
		}
		prt = &mockRouteTable{
			currentRoutes:   map[string][]routetable.Target{},
			currentL2Routes: map[string][]routetable.L2Target{},
		}

		la := netlink.NewLinkAttrs()
		la.Name = "eth0"
		ipipMgr = newIPIPManagerWithShim(
			ipSets, rt, brt, "tunl0",
			Config{
				MaxIPSetSize:       1024,
				Hostname:           "node1",
				ExternalNodesCidrs: []string{externalCIDR},
			},
			&mockVXLANDataplane{
				links:     []netlink.Link{&mockLink{attrs: la}},
				ipVersion: 4,
			},
			4,
			dataplane,
			func(interfacePrefixes []string, ipVersion uint8, vxlan bool, netlinkTimeout time.Duration,
				deviceRouteSourceAddress net.IP, deviceRouteProtocol netlink.RouteProtocol, removeExternalRoutes bool) routetable.RouteTableInterface {
				return prt
			},
		)
		ipipMgr.setNoEncapRouteTable(prt)
		ipipMgr.OnUpdate(&proto.HostMetadataUpdate{
			Hostname: "node1",
			Ipv4Addr: "172.0.0.2",
		})
	})

	It("should not create the IP set until first call to CompleteDeferredWork()", func() {
		Expect(ipSets.AddOrReplaceCalled).To(BeFalse())
		err := ipipMgr.CompleteDeferredWork()
		Expect(err).ToNot(HaveOccurred())
		Expect(ipSets.AddOrReplaceCalled).To(BeTrue())
	})

	allHostsSet := func() set.Set[string] {
		log.Info(ipSets.Members)
		Expect(ipSets.Members).To(HaveLen(1))
		return ipSets.Members["all-hosts-net"]
	}

	Describe("after adding an IP for host1", func() {
		BeforeEach(func() {
			ipipMgr.OnUpdate(&proto.HostMetadataUpdate{
				Hostname: "node1",
				Ipv4Addr: "172.0.0.2",
			})
			err := ipipMgr.CompleteDeferredWork()
			Expect(err).ToNot(HaveOccurred())
		})

		It("should add host1's IP to the IP set", func() {
			Expect(allHostsSet()).To(Equal(set.From("172.0.0.2", externalCIDR)))
		})

		Describe("after adding an IP for host2", func() {
			BeforeEach(func() {
				ipipMgr.OnUpdate(&proto.HostMetadataUpdate{
					Hostname: "node2",
					Ipv4Addr: "10.0.0.2",
				})
				err := ipipMgr.CompleteDeferredWork()
				Expect(err).ToNot(HaveOccurred())
			})
			It("should add the IP to the IP set", func() {
				Expect(allHostsSet()).To(Equal(set.From("172.0.0.2", "10.0.0.2", externalCIDR)))
			})
		})

		Describe("after adding a duplicate IP", func() {
			BeforeEach(func() {
				ipipMgr.OnUpdate(&proto.HostMetadataUpdate{
					Hostname: "host2",
					Ipv4Addr: "172.0.0.2",
				})
				err := ipipMgr.CompleteDeferredWork()
				Expect(err).ToNot(HaveOccurred())
			})
			It("should tolerate the duplicate", func() {
				Expect(allHostsSet()).To(Equal(set.From("172.0.0.2", externalCIDR)))
			})

			Describe("after removing a duplicate IP", func() {
				BeforeEach(func() {
					ipipMgr.OnUpdate(&proto.HostMetadataRemove{
						Hostname: "host2",
					})
					err := ipipMgr.CompleteDeferredWork()
					Expect(err).ToNot(HaveOccurred())
				})
				It("should keep the IP in the IP set", func() {
					Expect(allHostsSet()).To(Equal(set.From("172.0.0.2", externalCIDR)))
				})

				Describe("after removing initial copy of IP", func() {
					BeforeEach(func() {
						ipipMgr.OnUpdate(&proto.HostMetadataRemove{
							Hostname: "node1",
						})
						err := ipipMgr.CompleteDeferredWork()
						Expect(err.Error()).To(Equal("local address not found, will defer adding routes"))
					})
					It("should remove the IP", func() {
						Expect(allHostsSet().Len()).To(Equal(1))
					})
				})
			})
		})

		Describe("after adding/removing a duplicate IP in one batch", func() {
			BeforeEach(func() {
				ipipMgr.OnUpdate(&proto.HostMetadataUpdate{
					Hostname: "host2",
					Ipv4Addr: "172.0.0.2",
				})
				ipipMgr.OnUpdate(&proto.HostMetadataRemove{
					Hostname: "host2",
				})
				err := ipipMgr.CompleteDeferredWork()
				Expect(err).ToNot(HaveOccurred())
			})
			It("should keep the IP in the IP set", func() {
				Expect(allHostsSet()).To(Equal(set.From("172.0.0.2", externalCIDR)))
			})
		})

		Describe("after changing IP for node1", func() {
			BeforeEach(func() {
				ipipMgr.OnUpdate(&proto.HostMetadataUpdate{
					Hostname: "node1",
					Ipv4Addr: "10.0.0.2",
				})
				err := ipipMgr.CompleteDeferredWork()
				Expect(err).ToNot(HaveOccurred())
			})
			It("should update the IP set", func() {
				Expect(allHostsSet()).To(Equal(set.From("10.0.0.2", externalCIDR)))
			})
		})

		Describe("after a no-op batch", func() {
			BeforeEach(func() {
				ipSets.AddOrReplaceCalled = false
				err := ipipMgr.CompleteDeferredWork()
				Expect(err).ToNot(HaveOccurred())
			})
			It("shouldn't rewrite the IP set", func() {
				Expect(ipSets.AddOrReplaceCalled).To(BeFalse())
			})
		})
	})
})

var _ = Describe("IPIPManager", func() {
	var manager *ipipManager
	var rt, brt, prt *mockRouteTable
	var dataplane *mockIPIPDataplane
	var ipSets *common.MockIPSets

	BeforeEach(func() {
		dataplane = &mockIPIPDataplane{}
		ipSets = common.NewMockIPSets()
		rt = &mockRouteTable{
			currentRoutes:   map[string][]routetable.Target{},
			currentL2Routes: map[string][]routetable.L2Target{},
		}
		brt = &mockRouteTable{
			currentRoutes:   map[string][]routetable.Target{},
			currentL2Routes: map[string][]routetable.L2Target{},
		}
		prt = &mockRouteTable{
			currentRoutes:   map[string][]routetable.Target{},
			currentL2Routes: map[string][]routetable.L2Target{},
		}

		la := netlink.NewLinkAttrs()
		la.Name = "eth0"
		manager = newIPIPManagerWithShim(
			ipSets, rt, brt, "tunl0",
			Config{
				MaxIPSetSize:       1024,
				Hostname:           "node1",
				ExternalNodesCidrs: []string{"10.0.0.0/24"},
				RulesConfig: rules.Config{
					IPIPTunnelAddress: net.ParseIP("192.168.0.1"),
				},
			},
			&mockVXLANDataplane{
				links:     []netlink.Link{&mockLink{attrs: la}},
				ipVersion: 4,
			},
			4,
			dataplane,
			func(interfacePrefixes []string, ipVersion uint8, vxlan bool, netlinkTimeout time.Duration,
				deviceRouteSourceAddress net.IP, deviceRouteProtocol netlink.RouteProtocol, removeExternalRoutes bool) routetable.RouteTableInterface {
				return prt
			},
		)
	})

	It("successfully adds a route to the parent interface", func() {
		manager.OnUpdate(&proto.HostMetadataUpdate{
			Hostname: "node1",
			Ipv4Addr: "172.0.0.2",
		})
		manager.OnUpdate(&proto.HostMetadataUpdate{
			Hostname: "node2",
			Ipv4Addr: "172.0.12.1",
		})

		manager.noEncapRouteTable = prt

		err := manager.configureIPIPDevice(50, manager.dpConfig.RulesConfig.IPIPTunnelAddress)
		Expect(err).NotTo(HaveOccurred())

		Expect(manager.noEncapRouteTable).NotTo(BeNil())
		parent, err := manager.getParentInterface()

		Expect(parent).NotTo(BeNil())
		Expect(err).NotTo(HaveOccurred())

		manager.OnUpdate(&proto.RouteUpdate{
			Type:        proto.RouteType_REMOTE_WORKLOAD,
			IpPoolType:  proto.IPPoolType_IPIP,
			Dst:         "172.0.0.1/26",
			DstNodeName: "node2",
			DstNodeIp:   "172.8.8.8",
			SameSubnet:  true,
		})

		manager.OnUpdate(&proto.RouteUpdate{
			Type:        proto.RouteType_REMOTE_WORKLOAD,
			IpPoolType:  proto.IPPoolType_IPIP,
			Dst:         "172.0.0.2/26",
			DstNodeName: "node2",
			DstNodeIp:   "172.8.8.8",
		})

		manager.OnUpdate(&proto.RouteUpdate{
			Type:        proto.RouteType_LOCAL_WORKLOAD,
			IpPoolType:  proto.IPPoolType_IPIP,
			Dst:         "172.0.0.0/26",
			DstNodeName: "node0",
			DstNodeIp:   "172.8.8.8",
			SameSubnet:  true,
		})

		// Borrowed /32 should not be programmed as blackhole.
		manager.OnUpdate(&proto.RouteUpdate{
			Type:        proto.RouteType_LOCAL_WORKLOAD,
			IpPoolType:  proto.IPPoolType_IPIP,
			Dst:         "172.0.0.1/32",
			DstNodeName: "node1",
			DstNodeIp:   "172.8.8.7",
			SameSubnet:  true,
		})

		Expect(rt.currentRoutes["tunl0"]).To(HaveLen(0))
		Expect(brt.currentRoutes[routetable.InterfaceNone]).To(HaveLen(0))

		err = manager.CompleteDeferredWork()

		Expect(err).NotTo(HaveOccurred())
		Expect(rt.currentRoutes["tunl0"]).To(HaveLen(1))
		Expect(brt.currentRoutes[routetable.InterfaceNone]).To(HaveLen(1))
		Expect(prt.currentRoutes["eth0"]).NotTo(BeNil())
	})

	It("adds the route to the default table on next try when the parent route table is not immediately found", func() {
		go manager.KeepIPIPDeviceInSync(1400, manager.dpConfig.RulesConfig.IPIPTunnelAddress)
		manager.OnUpdate(&proto.HostMetadataUpdate{
			Hostname: "node2",
			Ipv4Addr: "172.0.12.1/32",
		})

		manager.OnUpdate(&proto.RouteUpdate{
			Type:        proto.RouteType_REMOTE_WORKLOAD,
			IpPoolType:  proto.IPPoolType_IPIP,
			Dst:         "172.0.0.1/26",
			DstNodeName: "node2",
			DstNodeIp:   "172.8.8.8",
			SameSubnet:  true,
		})

		err := manager.CompleteDeferredWork()

		Expect(err).NotTo(BeNil())
		Expect(err.Error()).To(Equal("no encap route table not set, will defer adding routes"))
		Expect(manager.routesDirty).To(BeTrue())

		manager.OnUpdate(&proto.HostMetadataUpdate{
			Hostname: "node1",
			Ipv4Addr: "172.0.0.2",
		})

		time.Sleep(2 * time.Second)

		err = manager.configureIPIPDevice(50, manager.dpConfig.RulesConfig.IPIPTunnelAddress)
		Expect(err).NotTo(HaveOccurred())

		Expect(prt.currentRoutes["eth0"]).To(HaveLen(0))
		err = manager.CompleteDeferredWork()

		Expect(err).NotTo(HaveOccurred())
		Expect(manager.routesDirty).To(BeFalse())
		Expect(prt.currentRoutes["eth0"]).To(HaveLen(1))
	})
})

type mockIPIPDataplane struct {
	tunnelLink      *mockLink
	tunnelLinkAttrs *netlink.LinkAttrs
	addrs           []netlink.Addr

	RunCmdCalled     bool
	LinkSetMTUCalled bool
	LinkSetUpCalled  bool
	AddrUpdated      bool

	NumCalls    int
	ErrorAtCall int

	links []netlink.Link
}

func (d *mockIPIPDataplane) ResetCalls() {
	d.RunCmdCalled = false
	d.LinkSetMTUCalled = false
	d.LinkSetUpCalled = false
	d.AddrUpdated = false
}

func (d *mockIPIPDataplane) incCallCount() error {
	d.NumCalls += 1
	if d.NumCalls == d.ErrorAtCall {
		log.Warn("Simulating an error due to call count")
		return mockFailure
	}
	return nil
}

func (d *mockIPIPDataplane) LinkByName(name string) (netlink.Link, error) {
	log.WithField("name", name).Info("LinkByName called")

	if err := d.incCallCount(); err != nil {
		return nil, err
	}

	Expect(name).To(Equal("tunl0"))
	if d.tunnelLink == nil {
		return nil, notFound
	}
	return d.tunnelLink, nil
}

func (d *mockIPIPDataplane) LinkSetMTU(link netlink.Link, mtu int) error {
	d.LinkSetMTUCalled = true
	if err := d.incCallCount(); err != nil {
		return err
	}
	Expect(link.Attrs().Name).To(Equal("tunl0"))
	d.tunnelLinkAttrs.MTU = mtu
	return nil
}

func (d *mockIPIPDataplane) LinkSetUp(link netlink.Link) error {
	d.LinkSetUpCalled = true
	if err := d.incCallCount(); err != nil {
		return err
	}
	Expect(link.Attrs().Name).To(Equal("tunl0"))
	d.tunnelLinkAttrs.Flags |= net.FlagUp
	return nil
}

func (d *mockIPIPDataplane) AddrList(link netlink.Link, family int) ([]netlink.Addr, error) {
	if err := d.incCallCount(); err != nil {
		return nil, err
	}

	Expect(link.Attrs().Name).To(Equal("tunl0"))
	return d.addrs, nil
}

func (d *mockIPIPDataplane) AddrAdd(link netlink.Link, addr *netlink.Addr) error {
	d.AddrUpdated = true
	if err := d.incCallCount(); err != nil {
		return err
	}
	Expect(d.addrs).NotTo(ContainElement(*addr))
	d.addrs = append(d.addrs, *addr)
	return nil
}

func (d *mockIPIPDataplane) AddrDel(link netlink.Link, addr *netlink.Addr) error {
	d.AddrUpdated = true
	if err := d.incCallCount(); err != nil {
		return err
	}
	Expect(d.addrs).To(HaveLen(1))
	Expect(d.addrs[0].IP.String()).To(Equal(addr.IP.String()))
	d.addrs = nil
	return nil
}

func (d *mockIPIPDataplane) LinkList() ([]netlink.Link, error) {
	return d.links, nil
}

func (d *mockIPIPDataplane) LinkAdd(_ netlink.Link) error {
	return nil
}

func (d *mockIPIPDataplane) LinkDel(_ netlink.Link) error {
	return nil
}

func (d *mockIPIPDataplane) RunCmd(name string, args ...string) error {
	d.RunCmdCalled = true
	if err := d.incCallCount(); err != nil {
		return err
	}
	log.WithFields(log.Fields{"name": name, "args": args}).Info("RunCmd called")
	Expect(name).To(Equal("ip"))
	Expect(args).To(Equal([]string{"tunnel", "add", "tunl0", "mode", "ipip"}))

	if d.tunnelLink == nil {
		log.Info("Creating tunnel link")
		link := &mockLink{}
		link.attrs.Name = "tunl0"
		d.tunnelLinkAttrs = &link.attrs
		d.tunnelLink = link
	}
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
