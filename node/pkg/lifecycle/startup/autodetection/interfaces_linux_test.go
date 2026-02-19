// Copyright (c) 2021 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package autodetection

import (
	"errors"
	"net"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/vishvananda/netlink"
)

type getInterfacesTestCase struct {
	getInterfaces       func() ([]net.Interface, error)
	expectFound         bool
	expectInterfaceName string
}

var _ = DescribeTable("GetInterfaces",
	func(tc getInterfacesTestCase) {
		found, err := GetInterfaces(tc.getInterfaces, nil, DEFAULT_INTERFACES_TO_EXCLUDE, 4)
		Expect(err).NotTo(HaveOccurred())
		if tc.expectFound {
			Expect(found).NotTo(BeEmpty())
		} else {
			Expect(found).To(BeEmpty())
		}
		if name := tc.expectInterfaceName; name != "" {
			Expect(found[0].Name).To(Equal(name))
		}
	},
	Entry("default interface", getInterfacesTestCase{
		getInterfaces: net.Interfaces,
		expectFound:   true,
	}),
	Entry("should not skip ibmveth", getInterfacesTestCase{
		getInterfaces: func() ([]net.Interface, error) {
			return []net.Interface{{Index: 0, Name: "lo"}, {Index: 1, Name: "ibmvetha"}}, nil
		},
		expectFound:         true,
		expectInterfaceName: "ibmvetha",
	}),
	Entry("should skip veth", getInterfacesTestCase{
		getInterfaces: func() ([]net.Interface, error) {
			return []net.Interface{{Index: 0, Name: "veth123126312783"}}, nil
		},
	}),
	Entry("should skip vxlan.calico", getInterfacesTestCase{
		getInterfaces: func() ([]net.Interface, error) {
			return []net.Interface{{Index: 0, Name: "vxlan.calico"}}, nil
		},
		expectFound: false,
	}),
	Entry("should skip vxlan-v6.calico", getInterfacesTestCase{
		getInterfaces: func() ([]net.Interface, error) {
			return []net.Interface{{Index: 0, Name: "vxlan-v6.calico"}}, nil
		},
		expectFound: false,
	}),
	Entry("should skip wireguard.cali", getInterfacesTestCase{
		getInterfaces: func() ([]net.Interface, error) {
			return []net.Interface{{Index: 0, Name: "wireguard.cali"}}, nil
		},
		expectFound: false,
	}),
	Entry("should skip wg-v6.cali", getInterfacesTestCase{
		getInterfaces: func() ([]net.Interface, error) {
			return []net.Interface{{Index: 0, Name: "wg-v6.cali"}}, nil
		},
		expectFound: false,
	}),
	Entry("should skip nodelocaldns", getInterfacesTestCase{
		getInterfaces: func() ([]net.Interface, error) {
			return []net.Interface{{Index: 0, Name: "nodelocaldns"}}, nil
		},
		expectFound: false,
	}),
	Entry("should skip podman", getInterfacesTestCase{
		getInterfaces: func() ([]net.Interface, error) {
			return []net.Interface{{Index: 0, Name: "podman"}}, nil
		},
	}),
	Entry("should skip Docker network bridge", getInterfacesTestCase{
		getInterfaces: func() ([]net.Interface, error) {
			return []net.Interface{{Index: 0, Name: "br-1234deadbeaf"}}, nil
		},
	}),
)

var _ = Describe("getAllInterfaceAddrs", func() {
	It("should group addresses by interface index", func() {
		originalAddrList := netlinkAddrList
		defer func() { netlinkAddrList = originalAddrList }()

		netlinkAddrList = func(link netlink.Link, family int) ([]netlink.Addr, error) {
			return []netlink.Addr{
				{LinkIndex: 1, IPNet: &net.IPNet{IP: net.ParseIP("192.168.1.10"), Mask: net.CIDRMask(24, 32)}},
				{LinkIndex: 1, IPNet: &net.IPNet{IP: net.ParseIP("fe80::1"), Mask: net.CIDRMask(64, 128)}},
				{LinkIndex: 2, IPNet: &net.IPNet{IP: net.ParseIP("10.0.0.5"), Mask: net.CIDRMask(8, 32)}},
			}, nil
		}

		addrsByIndex, err := getAllInterfaceAddrs()
		Expect(err).NotTo(HaveOccurred())
		Expect(addrsByIndex).To(HaveLen(2))
		Expect(addrsByIndex[1]).To(HaveLen(2))
		Expect(addrsByIndex[2]).To(HaveLen(1))

		ipNet1 := addrsByIndex[1][0].(*net.IPNet)
		Expect(ipNet1.IP.String()).To(Equal("192.168.1.10"))

		ipNet2 := addrsByIndex[2][0].(*net.IPNet)
		Expect(ipNet2.IP.String()).To(Equal("10.0.0.5"))
	})

	It("should handle netlink errors", func() {
		originalAddrList := netlinkAddrList
		defer func() { netlinkAddrList = originalAddrList }()

		netlinkAddrList = func(link netlink.Link, family int) ([]netlink.Addr, error) {
			return nil, errors.New("netlink error")
		}

		_, err := getAllInterfaceAddrs()
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(Equal("netlink error"))
	})

	It("should handle empty address list", func() {
		originalAddrList := netlinkAddrList
		defer func() { netlinkAddrList = originalAddrList }()

		netlinkAddrList = func(link netlink.Link, family int) ([]netlink.Addr, error) {
			return []netlink.Addr{}, nil
		}

		addrsByIndex, err := getAllInterfaceAddrs()
		Expect(err).NotTo(HaveOccurred())
		Expect(addrsByIndex).To(HaveLen(0))
	})
})

var _ = Describe("GetInterfaces with netlink optimization", func() {
	It("should fall back to i.Addrs() when bulk fetch fails", func() {
		originalAddrList := netlinkAddrList
		defer func() { netlinkAddrList = originalAddrList }()

		// Force bulk fetch to fail
		netlinkAddrList = func(link netlink.Link, family int) ([]netlink.Addr, error) {
			return nil, errors.New("simulated netlink failure")
		}

		// Should still work via i.Addrs() fallback
		getInterfaces := func() ([]net.Interface, error) {
			return net.Interfaces()
		}

		_, err := GetInterfaces(getInterfaces, nil, DEFAULT_INTERFACES_TO_EXCLUDE, 4)
		Expect(err).NotTo(HaveOccurred())
		// Just verify no error occurs - the fallback worked
	})

	It("should use bulk-fetched addresses when available", func() {
		originalAddrList := netlinkAddrList
		defer func() { netlinkAddrList = originalAddrList }()

		// Mock netlink to return specific addresses
		netlinkAddrList = func(link netlink.Link, family int) ([]netlink.Addr, error) {
			return []netlink.Addr{
				{LinkIndex: 1, IPNet: &net.IPNet{IP: net.ParseIP("192.168.1.10"), Mask: net.CIDRMask(24, 32)}},
				{LinkIndex: 2, IPNet: &net.IPNet{IP: net.ParseIP("10.0.0.5"), Mask: net.CIDRMask(16, 32)}},
			}, nil
		}

		getInterfaces := func() ([]net.Interface, error) {
			return []net.Interface{
				{Index: 1, Name: "eth0"},
				{Index: 2, Name: "eth1"},
			}, nil
		}

		ifaces, err := GetInterfaces(getInterfaces, nil, nil, 4)
		Expect(err).NotTo(HaveOccurred())
		Expect(ifaces).To(HaveLen(2))

		// Verify addresses were attached correctly (reverse order due to loop)
		Expect(ifaces[0].Name).To(Equal("eth1"))
		Expect(ifaces[0].Cidrs).To(HaveLen(1))
		Expect(ifaces[0].Cidrs[0].IP.String()).To(Equal("10.0.0.5"))

		Expect(ifaces[1].Name).To(Equal("eth0"))
		Expect(ifaces[1].Cidrs).To(HaveLen(1))
		Expect(ifaces[1].Cidrs[0].IP.String()).To(Equal("192.168.1.10"))
	})
})
