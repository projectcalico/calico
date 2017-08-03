// Copyright (c) 2017 Tigera, Inc. All rights reserved.
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
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"errors"
	"fmt"
	"net"

	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/projectcalico/felix/proto"
	"github.com/projectcalico/libcalico-go/lib/set"
)

var (
	notFound    = errors.New("not found")
	mockFailure = errors.New("mock failure")
)

var _ = Describe("IpipMgr (tunnel configuration)", func() {
	var (
		ipipMgr   *ipipManager
		ipSets    *mockIPSets
		dataplane *mockIPIPDataplane
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
		ipSets = newMockIPSets()
		ipipMgr = newIPIPManagerWithShim(ipSets, 1024, dataplane)
	})

	Describe("after calling configureIPIPDevice", func() {
		ip2, _, err := net.ParseCIDR("10.0.0.2/32")
		if err != nil {
			panic("Failed to parse test IP")
		}

		BeforeEach(func() {
			ipipMgr.configureIPIPDevice(1400, ip)
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
				ipipMgr.configureIPIPDevice(1400, ip)
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
				ipipMgr.configureIPIPDevice(1500, ip2)
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
				ipipMgr.configureIPIPDevice(1500, nil)
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
			ipipMgr.configureIPIPDevice(1400, nil)
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
		ipipMgr.configureIPIPDevice(1400, ip)
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
				Expect(ipipMgr.configureIPIPDevice(1400, ip)).To(Equal(mockFailure))
			})

			Describe("with an IP to remove", func() {
				BeforeEach(func() {
					dataplane.addrs = append(dataplane.addrs,
						netlink.Addr{
							IPNet: ipNet2,
						})
				})
				It("should return the error", func() {
					Expect(ipipMgr.configureIPIPDevice(1400, ip)).To(Equal(mockFailure))
				})
			})
		})
	}
})

var _ = Describe("ipipManager IP set updates", func() {
	var (
		ipipMgr   *ipipManager
		ipSets    *mockIPSets
		dataplane *mockIPIPDataplane
	)

	BeforeEach(func() {
		dataplane = &mockIPIPDataplane{}
		ipSets = newMockIPSets()
		ipipMgr = newIPIPManagerWithShim(ipSets, 1024, dataplane)
	})

	It("should not create the IP set until first call to CompleteDeferredWork()", func() {
		Expect(ipSets.AddOrReplaceCalled).To(BeFalse())
		ipipMgr.CompleteDeferredWork()
		Expect(ipSets.AddOrReplaceCalled).To(BeTrue())
	})

	allHostsSet := func() set.Set {
		Expect(ipSets.Members).To(HaveLen(1))
		return ipSets.Members["all-hosts"]
	}

	Describe("after adding an IP for host1", func() {
		BeforeEach(func() {
			ipipMgr.OnUpdate(&proto.HostMetadataUpdate{
				Hostname: "host1",
				Ipv4Addr: "10.0.0.1",
			})
			ipipMgr.CompleteDeferredWork()
		})

		It("should add host1's IP to the IP set", func() {
			Expect(allHostsSet()).To(Equal(set.From("10.0.0.1")))
		})

		Describe("after adding an IP for host2", func() {
			BeforeEach(func() {
				ipipMgr.OnUpdate(&proto.HostMetadataUpdate{
					Hostname: "host2",
					Ipv4Addr: "10.0.0.2",
				})
				ipipMgr.CompleteDeferredWork()
			})
			It("should add the IP to the IP set", func() {
				Expect(allHostsSet()).To(Equal(set.From("10.0.0.1", "10.0.0.2")))
			})
		})

		Describe("after adding a duplicate IP", func() {
			BeforeEach(func() {
				ipipMgr.OnUpdate(&proto.HostMetadataUpdate{
					Hostname: "host2",
					Ipv4Addr: "10.0.0.1",
				})
				ipipMgr.CompleteDeferredWork()
			})
			It("should tolerate the duplicate", func() {
				Expect(allHostsSet()).To(Equal(set.From("10.0.0.1")))
			})

			Describe("after removing a duplicate IP", func() {
				BeforeEach(func() {
					ipipMgr.OnUpdate(&proto.HostMetadataRemove{
						Hostname: "host2",
					})
					ipipMgr.CompleteDeferredWork()
				})
				It("should keep the IP in the IP set", func() {
					Expect(allHostsSet()).To(Equal(set.From("10.0.0.1")))
				})

				Describe("after removing initial copy of IP", func() {
					BeforeEach(func() {
						ipipMgr.OnUpdate(&proto.HostMetadataRemove{
							Hostname: "host1",
						})
						ipipMgr.CompleteDeferredWork()
					})
					It("should remove the IP", func() {
						Expect(allHostsSet().Len()).To(BeZero())
					})
				})
			})
		})

		Describe("after adding/removing a duplicate IP in one batch", func() {
			BeforeEach(func() {
				ipipMgr.OnUpdate(&proto.HostMetadataUpdate{
					Hostname: "host2",
					Ipv4Addr: "10.0.0.1",
				})
				ipipMgr.OnUpdate(&proto.HostMetadataRemove{
					Hostname: "host2",
				})
				ipipMgr.CompleteDeferredWork()
			})
			It("should keep the IP in the IP set", func() {
				Expect(allHostsSet()).To(Equal(set.From("10.0.0.1")))
			})
		})

		Describe("after changing IP for host1", func() {
			BeforeEach(func() {
				ipipMgr.OnUpdate(&proto.HostMetadataUpdate{
					Hostname: "host1",
					Ipv4Addr: "10.0.0.2",
				})
				ipipMgr.CompleteDeferredWork()
			})
			It("should update the IP set", func() {
				Expect(allHostsSet()).To(Equal(set.From("10.0.0.2")))
			})
		})

		Describe("after a no-op batch", func() {
			BeforeEach(func() {
				ipSets.AddOrReplaceCalled = false
				ipipMgr.CompleteDeferredWork()
			})
			It("shouldn't rewrite the IP set", func() {
				Expect(ipSets.AddOrReplaceCalled).To(BeFalse())
			})
		})
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
}

func (l *mockLink) Attrs() *netlink.LinkAttrs {
	return &l.attrs
}

func (l *mockLink) Type() string {
	return "not implemented"
}
