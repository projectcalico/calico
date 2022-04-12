// Copyright (c) 2018,2021 Tigera, Inc. All rights reserved.

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

package allocateip

import (
	"context"
	"errors"
	"fmt"
	gnet "net"
	"os"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/node/pkg/calicoclient"

	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	libapi "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/backend"
	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

func setTunnelAddressForNode(tunnelType string, n *libapi.Node, addr string) {
	if tunnelType == ipam.AttributeTypeIPIP {
		n.Spec.BGP.IPv4IPIPTunnelAddr = addr
	} else if tunnelType == ipam.AttributeTypeVXLAN {
		n.Spec.IPv4VXLANTunnelAddr = addr
	} else if tunnelType == ipam.AttributeTypeVXLANV6 {
		n.Spec.IPv6VXLANTunnelAddr = addr
	} else if tunnelType == ipam.AttributeTypeWireguard {
		if addr != "" {
			n.Spec.Wireguard = &libapi.NodeWireguardSpec{
				InterfaceIPv4Address: addr,
			}
		} else {
			n.Spec.Wireguard = nil
		}
	} else {
		panic(fmt.Errorf("Unknown tunnelType, %s", tunnelType))
	}
}

func getEnsureCIDRAndExpectedAddrForIPVersion(ipVersion int) (pool1CIDR, pool1ExpectedAddr, pool2CIDR, pool2ExpectedAddr string) {
	switch ipVersion {
	case 4:
		pool1CIDR = "172.16.10.10/32"
		pool1ExpectedAddr = "172.16.10.10"
		pool2CIDR = "172.16.0.0/31"
		pool2ExpectedAddr = "172.16.0.1"
	case 6:
		pool1CIDR = "2001:db8:00:ff::/128"
		pool1ExpectedAddr = "2001:db8:0:ff::"
		pool2CIDR = "2001:db8::/127"
		pool2ExpectedAddr = "2001:db8::1"
	default:
		panic(fmt.Errorf("Invalid IP version %v", ipVersion))
	}

	return pool1CIDR, pool1ExpectedAddr, pool2CIDR, pool2ExpectedAddr
}

func getEnsureCIDRAndExpectedAddrForTunnelType(tunnelType string) (pool1CIDR, pool1ExpectedAddr, pool2CIDR, pool2ExpectedAddr string) {
	switch tunnelType {
	case ipam.AttributeTypeIPIP:
		fallthrough
	case ipam.AttributeTypeVXLAN:
		fallthrough
	case ipam.AttributeTypeWireguard:
		return getEnsureCIDRAndExpectedAddrForIPVersion(4)
	case ipam.AttributeTypeVXLANV6:
		return getEnsureCIDRAndExpectedAddrForIPVersion(6)
	default:
		panic(fmt.Errorf("Invalid tunnelType %v", tunnelType))
	}
}

func getRemoveCIDRAndAddrForIPVersion(ipVersion int) (poolCIDR, expectedAddr, allocationCIDR, allocationAddr string) {
	switch ipVersion {
	case 4:
		poolCIDR = "172.16.0.0/24"
		expectedAddr = "172.16.0.5"
		allocationCIDR = "172.16.0.1/32"
		allocationAddr = "172.16.0.1"
	case 6:
		poolCIDR = "2001:db8::/64"
		expectedAddr = "2001:db8::5"
		allocationCIDR = "2001:db8::1/128"
		allocationAddr = "2001:db8::1"
	default:
		panic(fmt.Errorf("Invalid IP version %v", ipVersion))
	}
	return poolCIDR, expectedAddr, allocationCIDR, allocationAddr
}

func getRemoveCIDRAndAddrForTunnelType(tunnelType string) (poolCIDR, expectedAddr, allocationCIDR, allocationAddr string) {
	switch tunnelType {
	case ipam.AttributeTypeIPIP:
		fallthrough
	case ipam.AttributeTypeVXLAN:
		fallthrough
	case ipam.AttributeTypeWireguard:
		return getRemoveCIDRAndAddrForIPVersion(4)
	case ipam.AttributeTypeVXLANV6:
		return getRemoveCIDRAndAddrForIPVersion(6)
	default:
		panic(fmt.Errorf("Invalid tunnelType %v", tunnelType))
	}
}

func expectTunnelAddressEmpty(c client.Interface, tunnelType string, nodeName string) {
	Expect(checkTunnelAddressEmpty(c, tunnelType, nodeName)).NotTo(HaveOccurred())
}

func checkTunnelAddressEmpty(c client.Interface, tunnelType string, nodeName string) error {
	ctx := context.Background()
	n, err := c.Nodes().Get(ctx, nodeName, options.GetOptions{})
	Expect(err).NotTo(HaveOccurred())

	var addr string
	if tunnelType == ipam.AttributeTypeIPIP {
		addr = n.Spec.BGP.IPv4IPIPTunnelAddr
	} else if tunnelType == ipam.AttributeTypeVXLAN {
		addr = n.Spec.IPv4VXLANTunnelAddr
	} else if tunnelType == ipam.AttributeTypeVXLANV6 {
		addr = n.Spec.IPv6VXLANTunnelAddr
	} else if tunnelType == ipam.AttributeTypeWireguard {
		if n.Spec.Wireguard != nil {
			addr = n.Spec.Wireguard.InterfaceIPv4Address
		}
	} else {
		panic(fmt.Errorf("Unknown tunnelType, %s", tunnelType))
	}
	if addr != "" {
		return fmt.Errorf("%s address is not empty: %s", tunnelType, addr)
	}
	return nil
}

func expectTunnelAddressForNode(c client.Interface, tunnelType string, nodeName string, addr string) {
	Expect(checkTunnelAddressForNode(c, tunnelType, nodeName, addr)).NotTo(HaveOccurred())
}

func checkTunnelAddressForNode(c client.Interface, tunnelType string, nodeName string, expected string) error {
	ctx := context.Background()
	n, err := c.Nodes().Get(ctx, nodeName, options.GetOptions{})
	Expect(err).NotTo(HaveOccurred())

	// Check the address in the node is as expected.
	var addr string
	if tunnelType == ipam.AttributeTypeIPIP {
		addr = n.Spec.BGP.IPv4IPIPTunnelAddr
	} else if tunnelType == ipam.AttributeTypeVXLAN {
		addr = n.Spec.IPv4VXLANTunnelAddr
	} else if tunnelType == ipam.AttributeTypeVXLANV6 {
		addr = n.Spec.IPv6VXLANTunnelAddr
	} else if tunnelType == ipam.AttributeTypeWireguard {
		if n.Spec.Wireguard != nil {
			addr = n.Spec.Wireguard.InterfaceIPv4Address
		}
	} else {
		panic(fmt.Errorf("Unknown tunnelType, %s", tunnelType))
	}
	if addr != expected {
		return fmt.Errorf("%s address is %s, not expected %s", tunnelType, addr, expected)
	}

	// Also check the assignment attributes for this IP match.
	attr, _, err := c.IPAM().GetAssignmentAttributes(ctx, net.IP{IP: gnet.ParseIP(expected)})
	if err != nil {
		return err
	} else if attr[ipam.AttributeNode] != nodeName {
		return fmt.Errorf("Unexpected node attribute %s, expected %s", attr[ipam.AttributeNode], nodeName)
	} else if attr[ipam.AttributeType] != tunnelType {
		return fmt.Errorf("Unexpected ipam type attribute %s, expected %s", attr[ipam.AttributeType], tunnelType)
	}

	return nil
}

var _ = Describe("FV tests", func() {
	// Set up logging.
	log.SetOutput(os.Stdout)
	log.SetFormatter(&logutils.Formatter{})
	log.AddHook(&logutils.ContextHook{})

	ctx := context.Background()
	cfg, _ := apiconfig.LoadClientConfigFromEnvironment()

	var c client.Interface
	BeforeEach(func() {
		// Clear out datastore
		be, err := backend.NewClient(*cfg)
		Expect(err).ToNot(HaveOccurred())
		err = be.Clean()
		Expect(err).ToNot(HaveOccurred())

		// Create a client.
		c, _ = client.New(*cfg)

		// Create an IPPool.
		_, err = c.IPPools().Create(ctx, makeIPPool("pool1", "172.16.0.0/16", 31, api.IPIPModeAlways, api.VXLANModeNever), options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())
	})

	It("should not leak addresses if the existing allocation has no attributes", func() {
		// Create an allocation which simulates an "old-style" allocation, prior to us
		// using handles and attributes to attach metadata.
		ipAddr, _, _ := net.ParseCIDR("172.16.0.1/32")
		nodename := "my-test-node"
		args := ipam.AssignIPArgs{
			IP:       *ipAddr,
			Hostname: nodename,
		}
		Expect(c.IPAM().AssignIP(ctx, args)).NotTo(HaveOccurred())

		// Create a Node object which uses that allocation.
		node := makeNode("192.168.0.1/24", "fdff:ffff:ffff:ffff:ffff::/80")
		node.Name = nodename
		node.Spec.BGP.IPv4IPIPTunnelAddr = "172.16.0.1"
		_, err := c.Nodes().Create(ctx, node, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		// Run the allocateip code.
		cfg, c := calicoclient.CreateClient()
		reconcileTunnelAddrs(nodename, cfg, c)

		// Assert that the node has the same IP on it.
		newNode, err := c.Nodes().Get(ctx, nodename, options.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(newNode.Spec.BGP).NotTo(BeNil())
		Expect(newNode.Spec.BGP.IPv4IPIPTunnelAddr).To(Equal("172.16.0.1"))

		// Assert that the IPAM allocation has been updated to include a handle and attributes.
		attrs, handle, err := c.IPAM().GetAssignmentAttributes(ctx, net.IP{IP: gnet.ParseIP("172.16.0.1")})
		Expect(err).NotTo(HaveOccurred())
		Expect(len(attrs)).To(Equal(2))
		Expect(handle).NotTo(BeNil())
		Expect(*handle).To(Equal("ipip-tunnel-addr-my-test-node"))
	})

	It("should not claim an address that has a handle but no attributes", func() {
		// This test covers a scenario where the node has an IP address in its spec,
		// but the IP has no attributes because it was assigned using an old version of Calico.
		// In this scenario, either the allocation in IPAM has a  handle - in which case it is a
		// WEP address - or the allocation has no handle, in which case it is a node tunnel addr.
		// For WEP addresses, we should leave them alone and just allocate a new tunnel addr.

		// Create an allocation which simulates an "old-style" allocation, prior to us
		// using attributes to attach metadata.
		ipAddr, _, _ := net.ParseCIDR("172.16.0.1/32")
		nodename := "my-test-node"
		wepHandle := "some-wep-handle"
		args := ipam.AssignIPArgs{
			IP:       *ipAddr,
			HandleID: &wepHandle,
			Hostname: nodename,
		}
		Expect(c.IPAM().AssignIP(ctx, args)).NotTo(HaveOccurred())

		// Create a Node object which uses that allocation.
		node := makeNode("192.168.0.1/24", "fdff:ffff:ffff:ffff:ffff::/80")
		node.Name = nodename
		node.Spec.BGP.IPv4IPIPTunnelAddr = "172.16.0.1"
		_, err := c.Nodes().Create(ctx, node, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		// Run the allocateip code.
		cfg, c := calicoclient.CreateClient()
		reconcileTunnelAddrs(nodename, cfg, c)

		// Assert that the node no longer has the same IP on it.
		newNode, err := c.Nodes().Get(ctx, nodename, options.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(newNode.Spec.BGP).NotTo(BeNil())
		Expect(newNode.Spec.BGP.IPv4IPIPTunnelAddr).NotTo(Equal("172.16.0.1"))

		// Try to parse the new address to make sure it's a valid IP.
		_, _, err = net.ParseCIDROrIP(newNode.Spec.BGP.IPv4IPIPTunnelAddr)
		Expect(err).NotTo(HaveOccurred())

		// Assert that the IPAM allocation for the original address is stil intact.
		_, handle, err := c.IPAM().GetAssignmentAttributes(ctx, net.IP{IP: gnet.ParseIP("172.16.0.1")})
		Expect(err).NotTo(HaveOccurred())
		Expect(handle).NotTo(BeNil())
		Expect(*handle).To(Equal("some-wep-handle"))
	})

	It("should release old IPAM addresses if they exist and the node has none", func() {
		// Create an allocation for this node in IPAM.
		ipAddr, _, _ := net.ParseCIDR("172.16.0.1/32")
		nodename := "my-test-node"
		handle, attrs := generateHandleAndAttributes(nodename, ipam.AttributeTypeIPIP)
		args := ipam.AssignIPArgs{
			IP:       *ipAddr,
			HandleID: &handle,
			Hostname: nodename,
			Attrs:    attrs,
		}
		Expect(c.IPAM().AssignIP(ctx, args)).NotTo(HaveOccurred())

		// Create a Node object which does NOT use that allocation. It should clean up
		// the old leaked address and assign a new one.
		node := makeNode("192.168.0.1/24", "fdff:ffff:ffff:ffff:ffff::/80")
		node.Name = nodename

		// We don't want an address on the node for this scenario.
		node.Spec.BGP.IPv4IPIPTunnelAddr = ""
		_, err := c.Nodes().Create(ctx, node, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		// Run the allocateip code.
		cfg, c := calicoclient.CreateClient()
		reconcileTunnelAddrs(nodename, cfg, c)

		// Assert that the node no longer has the same IP on it.
		newNode, err := c.Nodes().Get(ctx, nodename, options.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(newNode.Spec.BGP).NotTo(BeNil())

		// Try to parse the new address to make sure it's a valid IP.
		_, _, err = net.ParseCIDROrIP(newNode.Spec.BGP.IPv4IPIPTunnelAddr)
		Expect(err).NotTo(HaveOccurred())

		// Assert that the IPAM allocation for the original leaked address is gone.
		_, _, err = c.IPAM().GetAssignmentAttributes(ctx, net.IP{IP: gnet.ParseIP("172.16.0.1")})
		Expect(err).To(HaveOccurred())

		// Assert that exactly one address exists for the node and that it matches the node.
		ips, err := c.IPAM().IPsByHandle(ctx, handle)
		Expect(err).NotTo(HaveOccurred())
		Expect(len(ips)).To(Equal(1))
		Expect(newNode.Spec.BGP.IPv4IPIPTunnelAddr).To(Equal(ips[0].String()))
	})

	It("should release old IPAM addresses if they exist and the node has a different address", func() {
		// Create an allocation for this node in IPAM.
		ipAddr, _, _ := net.ParseCIDR("172.16.0.1/32")
		nodename := "my-test-node"
		handle, attrs := generateHandleAndAttributes(nodename, ipam.AttributeTypeIPIP)
		args := ipam.AssignIPArgs{
			IP:       *ipAddr,
			HandleID: &handle,
			Hostname: nodename,
			Attrs:    attrs,
		}
		Expect(c.IPAM().AssignIP(ctx, args)).NotTo(HaveOccurred())

		// Create a Node object which does NOT use that allocation. It should clean up
		// the old leaked address and assign a new one.
		node := makeNode("192.168.0.1/24", "fdff:ffff:ffff:ffff:ffff::/80")
		node.Name = nodename

		// Put a different address on the node.
		node.Spec.BGP.IPv4IPIPTunnelAddr = "172.16.0.5"
		_, err := c.Nodes().Create(ctx, node, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		// Run the allocateip code.
		cfg, c := calicoclient.CreateClient()
		reconcileTunnelAddrs(nodename, cfg, c)

		// Assert that the node no longer has the same IP on it.
		newNode, err := c.Nodes().Get(ctx, nodename, options.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(newNode.Spec.BGP).NotTo(BeNil())

		// Try to parse the new address to make sure it's a valid IP.
		_, _, err = net.ParseCIDROrIP(newNode.Spec.BGP.IPv4IPIPTunnelAddr)
		Expect(err).NotTo(HaveOccurred())

		// Assert that the IPAM allocation for the original leaked address is gone.
		_, _, err = c.IPAM().GetAssignmentAttributes(ctx, net.IP{IP: gnet.ParseIP("172.16.0.1")})
		Expect(err).To(HaveOccurred())

		// Assert that exactly one address exists for the node and that it matches the node.
		ips, err := c.IPAM().IPsByHandle(ctx, handle)
		Expect(err).NotTo(HaveOccurred())
		Expect(len(ips)).To(Equal(1))
		Expect(newNode.Spec.BGP.IPv4IPIPTunnelAddr).To(Equal(ips[0].String()))
	})
})

var _ = Describe("ensureHostTunnelAddress", func() {
	log.SetOutput(os.Stdout)
	// Set log formatting.
	log.SetFormatter(&logutils.Formatter{})
	// Install a hook that adds file and line number information.
	log.AddHook(&logutils.ContextHook{})

	ctx := context.Background()
	cfg, _ := apiconfig.LoadClientConfigFromEnvironment()

	wepAttr := map[string]string{}

	var c client.Interface
	var be bapi.Client
	BeforeEach(func() {
		// Clear out datastore
		var err error
		be, err = backend.NewClient(*cfg)
		Expect(err).ToNot(HaveOccurred())
		err = be.Clean()
		Expect(err).ToNot(HaveOccurred())

		//create client.
		c, _ = client.New(*cfg)

		pool1CIDR, _, pool2CIDR, _ := getEnsureCIDRAndExpectedAddrForIPVersion(4)

		//create IPPool which has only one ip available.
		_, err = c.IPPools().Create(ctx, makeIPPool("pool1-v4", pool1CIDR, 32, api.IPIPModeAlways, api.VXLANModeNever), options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		// create IPPool which has only two ips available.
		_, err = c.IPPools().Create(ctx, makeIPPool("pool2-v4", pool2CIDR, 31, api.IPIPModeAlways, api.VXLANModeNever), options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		// Pre-allocate a WEP ip on 172.16.0.0. This will force tunnel address to use 172.16.0.1
		handle := "myhandle"
		wepAttr = map[string]string{
			ipam.AttributeNode: "test.node",
			ipam.AttributeType: ipam.AttributePod,
		}
		err = c.IPAM().AssignIP(ctx, ipam.AssignIPArgs{
			IP:       net.IP{IP: gnet.ParseIP("172.16.0.0")},
			Hostname: "test.node",
			HandleID: &handle,
			Attrs:    wepAttr,
		})
		Expect(err).NotTo(HaveOccurred())

		//TODO: enable when libcalico-go validator no longer gives an error for VXLAN IPv6 IPPools
		// pool1CIDR, _, pool2CIDR, _ = getEnsureCIDRAndExpectedAddrForIPVersion(6)

		//create IPPool which has only one ip available.
		//TODO: enable when libcalico-go validator no longer gives an error for VXLAN IPv6 IPPools
		// _, err = c.IPPools().Create(ctx, makeIPPool("pool1-v6", pool1CIDR, 128, api.IPIPModeNever, api.VXLANModeAlways), options.SetOptions{})
		// Expect(err).NotTo(HaveOccurred())

		//create IPPool which has only two ips available.
		//TODO: enable when libcalico-go validator no longer gives an error for VXLAN IPv6 IPPools
		// _, err = c.IPPools().Create(ctx, makeIPPool("pool2-v6", pool2CIDR, 127, api.IPIPModeNever, api.VXLANModeAlways), options.SetOptions{})
		// Expect(err).NotTo(HaveOccurred())

		// Pre-allocate a WEP ip on 2001:db8::0. This will force tunnel address to use 2001:db8::1
		//TODO: enable when libcalico-go validator no longer gives an error for VXLAN IPv6 IPPools
		// wepAttr = map[string]string{
		// 	ipam.AttributeNode: "test.node",
		// 	ipam.AttributeType: ipam.AttributePod,
		// }
		// err = c.IPAM().AssignIP(ctx, ipam.AssignIPArgs{
		// 	IP:       net.IP{IP: gnet.ParseIP("2001:db8::0")},
		// 	Hostname: "test.node",
		// 	HandleID: &handle,
		// 	Attrs:    wepAttr,
		// })
		// Expect(err).NotTo(HaveOccurred())
	})

	DescribeTable("should add tunnel address to node", func(tunnelType string) {
		node := makeNode("192.168.0.1/24", "fdff:ffff:ffff:ffff:ffff::/80")
		node.Name = "test.node"

		_, err := c.Nodes().Create(ctx, node, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		_, _, cidr, expectedAddr := getEnsureCIDRAndExpectedAddrForTunnelType(tunnelType)

		_, ipnet, _ := net.ParseCIDR(cidr)
		ensureHostTunnelAddress(ctx, c, node.Name, []net.IPNet{*ipnet}, tunnelType)
		expectTunnelAddressForNode(c, tunnelType, node.Name, expectedAddr)
	},
		Entry("IPIP", ipam.AttributeTypeIPIP),
		Entry("VXLAN", ipam.AttributeTypeVXLAN),
		Entry("Wireguard", ipam.AttributeTypeWireguard),
		//TODO: enable when libcalico-go validator no longer gives an error for VXLAN IPv6 IPPools
		XEntry("VXLAN-v6", ipam.AttributeTypeVXLANV6),
	)

	DescribeTable("should add tunnel address to node without BGP Spec or Wireguard Spec", func(tunnelType string) {
		node := makeNode("192.168.0.1/24", "fdff:ffff:ffff:ffff:ffff::/80")
		node.Name = "test.node"
		node.Spec.BGP = nil
		node.Spec.Wireguard = nil

		_, err := c.Nodes().Create(ctx, node, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		_, _, cidr, expectedAddr := getEnsureCIDRAndExpectedAddrForTunnelType(tunnelType)

		_, ipnet, _ := net.ParseCIDR(cidr)
		ensureHostTunnelAddress(ctx, c, node.Name, []net.IPNet{*ipnet}, tunnelType)
		expectTunnelAddressForNode(c, tunnelType, node.Name, expectedAddr)
	},
		Entry("IPIP", ipam.AttributeTypeIPIP),
		Entry("VXLAN", ipam.AttributeTypeVXLAN),
		Entry("Wireguard", ipam.AttributeTypeWireguard),
		//TODO: enable when libcalico-go validator no longer gives an error for VXLAN IPv6 IPPools
		XEntry("VXLAN-v6", ipam.AttributeTypeVXLANV6),
	)

	DescribeTable("should release old tunnel address and assign new one on ippool update", func(tunnelType string) {
		node := makeNode("192.168.0.1/24", "fdff:ffff:ffff:ffff:ffff::/80")
		node.Name = "test.node"

		_, err := c.Nodes().Create(ctx, node, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		cidr1, expectedAddr1, cidr2, expectedAddr2 := getEnsureCIDRAndExpectedAddrForTunnelType(tunnelType)

		_, ipnet, _ := net.ParseCIDR(cidr1)
		ensureHostTunnelAddress(ctx, c, node.Name, []net.IPNet{*ipnet}, tunnelType)
		expectTunnelAddressForNode(c, tunnelType, node.Name, expectedAddr1)

		// Simulate a node restart and ippool update.
		_, ipnet, _ = net.ParseCIDR(cidr2)
		ensureHostTunnelAddress(ctx, c, node.Name, []net.IPNet{*ipnet}, tunnelType)

		// Check old address
		// Verify 172.16.10.10 has been released.
		_, _, err = c.IPAM().GetAssignmentAttributes(ctx, net.IP{IP: gnet.ParseIP(expectedAddr1)})
		Expect(err).To(BeAssignableToTypeOf(cerrors.ErrorResourceDoesNotExist{}))

		// Check new address has been assigned in pool1.
		expectTunnelAddressForNode(c, tunnelType, node.Name, expectedAddr2)
	},
		Entry("IPIP", ipam.AttributeTypeIPIP),
		Entry("VXLAN", ipam.AttributeTypeVXLAN),
		Entry("Wireguard", ipam.AttributeTypeWireguard),
		//TODO: enable when libcalico-go validator no longer gives an error for VXLAN IPv6 IPPools
		XEntry("VXLAN-v6", ipam.AttributeTypeVXLANV6),
	)

	DescribeTable("should assign new tunnel address to node on ippool update if old address been occupied", func(tunnelType string) {
		node := makeNode("192.168.0.1/24", "fdff:ffff:ffff:ffff:ffff::/80")
		node.Name = "test.node"

		_, expectedAddr1, cidr2, expectedAddr2 := getEnsureCIDRAndExpectedAddrForTunnelType(tunnelType)

		setTunnelAddressForNode(tunnelType, node, expectedAddr1)

		_, err := c.Nodes().Create(ctx, node, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		// Pre-allocate a WEP ip on 172.16.10.10.
		handle := "myhandle"
		wepIp := gnet.ParseIP(expectedAddr1)
		err = c.IPAM().AssignIP(ctx, ipam.AssignIPArgs{
			IP:       net.IP{IP: wepIp},
			Hostname: "another.node",
			HandleID: &handle,
			Attrs:    wepAttr,
		})
		Expect(err).NotTo(HaveOccurred())

		_, ipnet, _ := net.ParseCIDR(cidr2)
		ensureHostTunnelAddress(ctx, c, node.Name, []net.IPNet{*ipnet}, tunnelType)

		// Check old address.
		// Verify 172.16.10.10 has not been touched.
		attr, _, err := c.IPAM().GetAssignmentAttributes(ctx, net.IP{IP: gnet.ParseIP(expectedAddr1)})
		Expect(err).NotTo(HaveOccurred())
		Expect(attr).To(Equal(wepAttr))

		// Check new address has been assigned.
		expectTunnelAddressForNode(c, tunnelType, node.Name, expectedAddr2)
	},
		Entry("IPIP", ipam.AttributeTypeIPIP),
		Entry("VXLAN", ipam.AttributeTypeVXLAN),
		Entry("Wireguard", ipam.AttributeTypeWireguard),
		//TODO: enable when libcalico-go validator no longer gives an error for VXLAN IPv6 IPPools
		XEntry("VXLAN-v6", ipam.AttributeTypeVXLANV6),
	)

	DescribeTable("should assign new tunnel address and do nothing if node restarts", func(tunnelType string) {
		node := makeNode("192.168.0.1/24", "fdff:ffff:ffff:ffff:ffff::/80")
		node.Name = "test.node"

		_, err := c.Nodes().Create(ctx, node, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		_, _, cidr2, expectedAddr2 := getEnsureCIDRAndExpectedAddrForTunnelType(tunnelType)

		_, ipnet, _ := net.ParseCIDR(cidr2)
		ensureHostTunnelAddress(ctx, c, node.Name, []net.IPNet{*ipnet}, tunnelType)
		expectTunnelAddressForNode(c, tunnelType, node.Name, expectedAddr2)

		// Now we have a wep IP allocated at 172.16.0.0 and tunnel ip allocated at 172.16.0.1.
		// Release wep IP and call ensureHostTunnelAddress again. Tunnel ip should not be changed.
		err = c.IPAM().ReleaseByHandle(ctx, "myhandle")
		Expect(err).NotTo(HaveOccurred())

		ensureHostTunnelAddress(ctx, c, node.Name, []net.IPNet{*ipnet}, tunnelType)
		expectTunnelAddressForNode(c, tunnelType, node.Name, expectedAddr2)
	},
		Entry("IPIP", ipam.AttributeTypeIPIP),
		Entry("VXLAN", ipam.AttributeTypeVXLAN),
		Entry("Wireguard", ipam.AttributeTypeWireguard),
		//TODO: enable when libcalico-go validator no longer gives an error for VXLAN IPv6 IPPools
		XEntry("VXLAN-v6", ipam.AttributeTypeVXLANV6),
	)

	DescribeTable("should assign new tunnel address to node on unassigned address", func(tunnelType string) {
		node := makeNode("192.168.0.1/24", "fdff:ffff:ffff:ffff:ffff::/80")
		node.Name = "test.node"

		_, _, cidr2, expectedAddr2 := getEnsureCIDRAndExpectedAddrForTunnelType(tunnelType)
		setTunnelAddressForNode(tunnelType, node, expectedAddr2)

		_, err := c.Nodes().Create(ctx, node, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		// Verify 172.16.0.1 is not properly assigned to tunnel address.
		_, _, err = c.IPAM().GetAssignmentAttributes(ctx, net.IP{IP: gnet.ParseIP(expectedAddr2)})
		Expect(err).To(BeAssignableToTypeOf(cerrors.ErrorResourceDoesNotExist{}))

		_, ipnet, _ := net.ParseCIDR(cidr2)
		ensureHostTunnelAddress(ctx, c, node.Name, []net.IPNet{*ipnet}, tunnelType)
		expectTunnelAddressForNode(c, tunnelType, node.Name, expectedAddr2)
	},
		Entry("IPIP", ipam.AttributeTypeIPIP),
		Entry("VXLAN", ipam.AttributeTypeVXLAN),
		Entry("Wireguard", ipam.AttributeTypeWireguard),
		//TODO: enable when libcalico-go validator no longer gives an error for VXLAN IPv6 IPPools
		XEntry("VXLAN-v6", ipam.AttributeTypeVXLANV6),
	)

	DescribeTable("should assign new tunnel address to node on pre-allocated address", func(tunnelType string) {
		node := makeNode("192.168.0.1/24", "fdff:ffff:ffff:ffff:ffff::/80")
		node.Name = "test.node"

		var expectedAddr1 string
		switch tunnelType {
		case ipam.AttributeTypeIPIP:
			fallthrough
		case ipam.AttributeTypeVXLAN:
			fallthrough
		case ipam.AttributeTypeWireguard:
			expectedAddr1 = "172.16.0.0"
		case ipam.AttributeTypeVXLANV6:
			expectedAddr1 = "2001:db8::0"
		default:
			panic(fmt.Errorf("Invalid tunnelType %v", tunnelType))
		}

		_, _, cidr2, expectedAddr2 := getEnsureCIDRAndExpectedAddrForTunnelType(tunnelType)
		setTunnelAddressForNode(tunnelType, node, expectedAddr1)

		_, err := c.Nodes().Create(ctx, node, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		_, ipnet, _ := net.ParseCIDR(cidr2)
		ensureHostTunnelAddress(ctx, c, node.Name, []net.IPNet{*ipnet}, tunnelType)
		expectTunnelAddressForNode(c, tunnelType, node.Name, expectedAddr2)

		// Verify 172.16.0.0 has not been released.
		attr, _, err := c.IPAM().GetAssignmentAttributes(ctx, net.IP{IP: gnet.ParseIP(expectedAddr1)})
		Expect(err).NotTo(HaveOccurred())
		Expect(attr).To(Equal(wepAttr))
	},
		Entry("IPIP", ipam.AttributeTypeIPIP),
		Entry("VXLAN", ipam.AttributeTypeVXLAN),
		Entry("Wireguard", ipam.AttributeTypeWireguard),
		//TODO: enable when libcalico-go validator no longer gives an error for VXLAN IPv6 IPPools
		XEntry("VXLAN-v6", ipam.AttributeTypeVXLANV6),
	)

	DescribeTable("should panic on datastore errors", func(tunnelType string) {
		pa := newIPPoolErrorAccessor(cerrors.ErrorDatastoreError{Err: errors.New("mock datastore error"), Identifier: nil})
		cc := newShimClientWithPoolAccessor(c, be, pa)

		node := makeNode("192.168.0.1/24", "fdff:ffff:ffff:ffff:ffff::/80")
		node.Name = "test.node"

		_, _, cidr2, expectedAddr2 := getEnsureCIDRAndExpectedAddrForTunnelType(tunnelType)
		setTunnelAddressForNode(tunnelType, node, expectedAddr2)

		_, err := cc.Nodes().Create(ctx, node, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		_, ipnet, _ := net.ParseCIDR(cidr2)

		defer func() {
			if err := recover(); err == nil {
				Fail("Panic didn't occur!")
			}
		}()
		ensureHostTunnelAddress(ctx, cc, node.Name, []net.IPNet{*ipnet}, tunnelType)
	},
		Entry("IPIP", ipam.AttributeTypeIPIP),
		Entry("VXLAN", ipam.AttributeTypeVXLAN),
		Entry("Wireguard", ipam.AttributeTypeWireguard),
		//TODO: enable when libcalico-go validator no longer gives an error for VXLAN IPv6 IPPools
		XEntry("VXLAN-v6", ipam.AttributeTypeVXLANV6),
	)
})

var _ = Describe("removeHostTunnelAddress", func() {
	log.SetOutput(os.Stdout)
	// Set log formatting.
	log.SetFormatter(&logutils.Formatter{})
	// Install a hook that adds file and line number information.
	log.AddHook(&logutils.ContextHook{})

	ctx := context.Background()
	cfg, _ := apiconfig.LoadClientConfigFromEnvironment()

	var c client.Interface
	BeforeEach(func() {
		// Clear out datastore
		be, err := backend.NewClient(*cfg)
		Expect(err).ToNot(HaveOccurred())
		err = be.Clean()
		Expect(err).ToNot(HaveOccurred())

		//create client and IPPools
		c, _ = client.New(*cfg)

		poolCIDR, _, _, _ := getRemoveCIDRAndAddrForIPVersion(4)
		_, err = c.IPPools().Create(ctx, makeIPPool("pool1-v4", poolCIDR, 26, api.IPIPModeAlways, api.VXLANModeNever), options.SetOptions{})
		Expect(err).ToNot(HaveOccurred())

		//TODO: enable when libcalico-go validator no longer gives an error for VXLAN IPv6 IPPools
		// poolCIDR, _, _, _ = getRemoveCIDRAndAddrForIPVersion(6)
		// _, err = c.IPPools().Create(ctx, makeIPPool("pool1-v6", poolCIDR, 122, api.IPIPModeNever, api.VXLANModeAlways), options.SetOptions{})
		// Expect(err).ToNot(HaveOccurred())
	})

	DescribeTable("should remove tunnel address from node", func(tunnelType string) {
		node := makeNode("192.168.0.1/24", "fdff:ffff:ffff:ffff:ffff::/80")
		node.Name = "test.node"

		_, expectedAddr, _, _ := getRemoveCIDRAndAddrForTunnelType(tunnelType)

		setTunnelAddressForNode(tunnelType, node, expectedAddr)

		_, err := c.Nodes().Create(ctx, node, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		removeHostTunnelAddr(ctx, c, node.Name, tunnelType)
		_, err = c.Nodes().Get(ctx, node.Name, options.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		expectTunnelAddressEmpty(c, tunnelType, node.Name)
	},
		Entry("IPIP", ipam.AttributeTypeIPIP),
		Entry("VXLAN", ipam.AttributeTypeVXLAN),
		Entry("Wireguard", ipam.AttributeTypeWireguard),
		//TODO: enable when libcalico-go validator no longer gives an error for VXLAN IPv6 IPPools
		XEntry("VXLAN-v6", ipam.AttributeTypeVXLANV6),
	)

	DescribeTable("should not panic on node without BGP Spec", func(tunnelType string) {
		node := makeNode("192.168.0.1/24", "fdff:ffff:ffff:ffff:ffff::/80")
		node.Name = "test.node"
		node.Spec.BGP = nil

		_, err := c.Nodes().Create(ctx, node, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		removeHostTunnelAddr(ctx, c, node.Name, tunnelType)
		n, err := c.Nodes().Get(ctx, node.Name, options.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(n.Spec.BGP).To(BeNil())
	},
		Entry("IPIP", ipam.AttributeTypeIPIP),
		Entry("VXLAN", ipam.AttributeTypeVXLAN),
		Entry("Wireguard", ipam.AttributeTypeWireguard),
		//TODO: enable when libcalico-go validator no longer gives an error for VXLAN IPv6 IPPools
		XEntry("VXLAN-v6", ipam.AttributeTypeVXLANV6),
	)

	DescribeTable("should release IP address allocations", func(tunnelType string) {
		_, _, allocationCIDR, allocationAddr := getRemoveCIDRAndAddrForTunnelType(tunnelType)
		// Create an allocation for this node in IPAM.
		ipAddr, _, _ := net.ParseCIDR(allocationCIDR)
		nodename := "my-test-node"
		handle, attrs := generateHandleAndAttributes(nodename, tunnelType)
		args := ipam.AssignIPArgs{
			IP:       *ipAddr,
			HandleID: &handle,
			Attrs:    attrs,
			Hostname: nodename,
		}
		Expect(c.IPAM().AssignIP(ctx, args)).NotTo(HaveOccurred())

		// Create a Node object which uses that allocation.
		node := makeNode("192.168.0.1/24", "fdff:ffff:ffff:ffff:ffff::/80")
		node.Name = nodename
		setTunnelAddressForNode(tunnelType, node, allocationAddr)
		_, err := c.Nodes().Create(ctx, node, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		// Remove the tunnel address.
		removeHostTunnelAddr(ctx, c, node.Name, tunnelType)

		// Assert that the IPAM allocation is gone.
		_, _, err = c.IPAM().GetAssignmentAttributes(ctx, net.IP{IP: gnet.ParseIP(allocationAddr)})
		Expect(err).To(HaveOccurred())
	},
		Entry("IPIP", ipam.AttributeTypeIPIP),
		Entry("VXLAN", ipam.AttributeTypeVXLAN),
		Entry("Wireguard", ipam.AttributeTypeWireguard),
		//TODO: enable when libcalico-go validator no longer gives an error for VXLAN IPv6 IPPools
		XEntry("VXLAN-v6", ipam.AttributeTypeVXLANV6),
	)

	DescribeTable("should release old-style IP address allocations", func(tunnelType string) {
		_, _, allocationCIDR, allocationAddr := getRemoveCIDRAndAddrForTunnelType(tunnelType)
		// Create an old-style allocation for this node in IPAM.
		ipAddr, _, _ := net.ParseCIDR(allocationCIDR)
		nodename := "my-test-node"
		args := ipam.AssignIPArgs{
			IP:       *ipAddr,
			Hostname: nodename,
		}
		Expect(c.IPAM().AssignIP(ctx, args)).NotTo(HaveOccurred())

		// Create a Node object which uses that allocation.
		node := makeNode("192.168.0.1/24", "fdff:ffff:ffff:ffff:ffff::/80")
		node.Name = nodename
		setTunnelAddressForNode(tunnelType, node, allocationAddr)
		_, err := c.Nodes().Create(ctx, node, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		// Remove the tunnel address.
		removeHostTunnelAddr(ctx, c, node.Name, tunnelType)

		// Assert that the IPAM allocation is gone.
		_, _, err = c.IPAM().GetAssignmentAttributes(ctx, net.IP{IP: gnet.ParseIP(allocationAddr)})
		Expect(err).To(HaveOccurred())
	},
		Entry("IPIP", ipam.AttributeTypeIPIP),
		Entry("VXLAN", ipam.AttributeTypeVXLAN),
		Entry("Wireguard", ipam.AttributeTypeWireguard),
		//TODO: enable when libcalico-go validator no longer gives an error for VXLAN IPv6 IPPools
		XEntry("VXLAN-v6", ipam.AttributeTypeVXLANV6),
	)

	DescribeTable("should not release old-style IP address allocations belonging to someone else", func(tunnelType string) {
		_, _, allocationCIDR, allocationAddr := getRemoveCIDRAndAddrForTunnelType(tunnelType)
		// Create an old-style allocation for this node in IPAM.
		ipAddr, _, _ := net.ParseCIDR(allocationCIDR)
		nodename := "my-test-node"
		handle := "some-handle"
		args := ipam.AssignIPArgs{
			IP:       *ipAddr,
			HandleID: &handle,
			Hostname: nodename,
		}
		Expect(c.IPAM().AssignIP(ctx, args)).NotTo(HaveOccurred())

		// Create a Node object which uses that allocation.
		node := makeNode("192.168.0.1/24", "fdff:ffff:ffff:ffff:ffff::/80")
		node.Name = nodename
		setTunnelAddressForNode(tunnelType, node, allocationAddr)
		_, err := c.Nodes().Create(ctx, node, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		// Remove the tunnel address.
		removeHostTunnelAddr(ctx, c, node.Name, tunnelType)

		// Assert that the IPAM allocation is gone.
		_, _, err = c.IPAM().GetAssignmentAttributes(ctx, net.IP{IP: gnet.ParseIP(allocationAddr)})
		Expect(err).NotTo(HaveOccurred())
	},
		Entry("IPIP", ipam.AttributeTypeIPIP),
		Entry("VXLAN", ipam.AttributeTypeVXLAN),
		Entry("Wireguard", ipam.AttributeTypeWireguard),
		//TODO: enable when libcalico-go validator no longer gives an error for VXLAN IPv6 IPPools
		XEntry("VXLAN-v6", ipam.AttributeTypeVXLANV6),
	)
})

var _ = Describe("Running as daemon", func() {
	log.SetOutput(os.Stdout)
	// Set log formatting.
	log.SetFormatter(&logutils.Formatter{})
	// Install a hook that adds file and line number information.
	log.AddHook(&logutils.ContextHook{})

	ctx := context.Background()
	cfg, _ := apiconfig.LoadClientConfigFromEnvironment()

	var c client.Interface
	var poolV4 *api.IPPool
	BeforeEach(func() {
		// Clear out datastore
		be, err := backend.NewClient(*cfg)
		Expect(err).ToNot(HaveOccurred())
		err = be.Clean()
		Expect(err).ToNot(HaveOccurred())

		// Create client and IPPool (IPIP)
		c, _ = client.New(*cfg)

		poolV4, err = c.IPPools().Create(ctx, makeIPPool("pool1-v4", "172.16.0.0/26", 26, api.IPIPModeAlways, api.VXLANModeNever), options.SetOptions{})
		Expect(err).ToNot(HaveOccurred())

		// Create /128 IPv6 IPPool so that there is only one address to be assigned
		//TODO: enable when libcalico-go validator no longer gives an error for VXLAN IPv6 IPPools
		// _, err = c.IPPools().Create(ctx, makeIPPool("pool1-v6", "2001:db8::/128", 128, api.IPIPModeNever, api.VXLANModeAlways), options.SetOptions{})
		// Expect(err).ToNot(HaveOccurred())
	})

	It("should handle adding and removing the tunnel IP after config updates", func() {
		node := makeNode("192.168.0.1/24", "fdff:ffff:ffff:ffff:ffff::/80")
		node.Name = "test.node"
		node.Status.WireguardPublicKey = "jlkVyQYooZYzI2wFfNhSZez5eWh44yfq1wKVjLvSXgY="
		node, err := c.Nodes().Create(ctx, node, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("starting the IP allocation daemon")
		done := make(chan struct{})
		completed := make(chan struct{})
		go func() {
			run("test.node", cfg, c, done)
			close(completed)
		}()

		// Wireguard is assigned first, then IPIP.  Note that this is an implementation detail rather than a requirement
		// and so this might change in future.
		By("waiting for wireguard and IPIP assignment")
		Eventually(func() error {
			return checkTunnelAddressForNode(c, ipam.AttributeTypeWireguard, "test.node", "172.16.0.0")
		}, "5s", "200ms").ShouldNot(HaveOccurred())
		Eventually(func() error { return checkTunnelAddressForNode(c, ipam.AttributeTypeIPIP, "test.node", "172.16.0.1") }, "5s", "200ms").ShouldNot(HaveOccurred())

		// Modify the IPv4 pool to be VXLAN.  The IPIP tunnel should be removed, and the VXLAN one should be assigned. The
		// wireguard IP should not change.
		By("changing from IPIP to VXLAN")
		poolV4.Spec.IPIPMode = api.IPIPModeNever
		poolV4.Spec.VXLANMode = api.VXLANModeAlways
		poolV4, err = c.IPPools().Update(ctx, poolV4, options.SetOptions{})
		Expect(err).ToNot(HaveOccurred())

		Eventually(func() error { return checkTunnelAddressEmpty(c, ipam.AttributeTypeIPIP, "test.node") }, "5s", "200ms").ShouldNot(HaveOccurred())
		Eventually(func() error { return checkTunnelAddressForNode(c, ipam.AttributeTypeVXLAN, "test.node", "172.16.0.2") }, "5s", "200ms").ShouldNot(HaveOccurred())
		expectTunnelAddressForNode(c, ipam.AttributeTypeWireguard, "test.node", "172.16.0.0")

		// Verify that IPv6 address is assigned from the only one available in the VXLAN IPv6 IPPool
		//TODO: enable when libcalico-go validator no longer gives an error for VXLAN IPv6 IPPools
		// expectTunnelAddressForNode(c, ipam.AttributeTypeVXLANV6, "test.node", "2001:db8::")

		// Modify the node so that the wireguard status has a different public key - the IP address should not change.
		By("changing the wireguard public key")
		node, err = c.Nodes().Get(ctx, node.Name, options.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		node.Status.WireguardPublicKey = "jlkVyQYooZYzI2wFfNhSZez5eWh44yfq1wKVjLvSXgX="
		_, err = c.Nodes().Update(ctx, node, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())
		Consistently(func() error {
			return checkTunnelAddressForNode(c, ipam.AttributeTypeWireguard, "test.node", "172.16.0.0")
		}, "2s", "200ms").ShouldNot(HaveOccurred())
		expectTunnelAddressEmpty(c, ipam.AttributeTypeIPIP, "test.node")
		expectTunnelAddressForNode(c, ipam.AttributeTypeVXLAN, "test.node", "172.16.0.2")

		// Modify the node so that there is no wireguard status. The  wireguardIP address should be removed.
		By("removing wireguard public key from node status")
		node, err = c.Nodes().Get(ctx, node.Name, options.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		node.Status.WireguardPublicKey = ""
		_, err = c.Nodes().Update(ctx, node, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		Eventually(func() error { return checkTunnelAddressEmpty(c, ipam.AttributeTypeWireguard, "test.node") }, "2s", "200ms").ShouldNot(HaveOccurred())
		expectTunnelAddressEmpty(c, ipam.AttributeTypeIPIP, "test.node")
		expectTunnelAddressForNode(c, ipam.AttributeTypeVXLAN, "test.node", "172.16.0.2")

		// Close the done channel to trigger completion.
		By("shutting down the daemon")
		close(done)
		Eventually(completed).Should(BeClosed(), "2s", "200ms")
	})
})

var _ = Describe("determineEnabledPoolCIDRs", func() {
	log.SetOutput(os.Stdout)
	// Set log formatting.
	log.SetFormatter(&logutils.Formatter{})
	// Install a hook that adds file and line number information.
	log.AddHook(&logutils.ContextHook{})

	Context("IPIP tests", func() {
		It("should match ip-pool-1 but not ip-pool-2", func() {
			// Mock out the node and ip pools
			n := libapi.Node{ObjectMeta: metav1.ObjectMeta{Name: "bee-node", Labels: map[string]string{"foo": "bar"}}}
			pl := api.IPPoolList{
				Items: []api.IPPool{
					{
						ObjectMeta: metav1.ObjectMeta{Name: "ip-pool-1"},
						Spec: api.IPPoolSpec{
							Disabled:     false,
							CIDR:         "172.0.0.0/9",
							NodeSelector: `foo == "bar"`,
							IPIPMode:     api.IPIPModeAlways,
						},
					}, {
						ObjectMeta: metav1.ObjectMeta{Name: "ip-pool-2"},
						Spec: api.IPPoolSpec{
							Disabled:     false,
							CIDR:         "172.128.0.0/9",
							NodeSelector: `foo != "bar"`,
							IPIPMode:     api.IPIPModeAlways,
						},
					}}}

			// Execute and test assertions.
			cidrs := determineEnabledPoolCIDRs(n, pl, ipam.AttributeTypeIPIP)
			_, cidr1, _ := net.ParseCIDR("172.0.0.1/9")
			_, cidr2, _ := net.ParseCIDR("172.128.0.1/9")
			Expect(cidrs).To(ContainElement(*cidr1))
			Expect(cidrs).ToNot(ContainElement(*cidr2))
		})
	})

	Context("IPv4 VXLAN tests", func() {
		It("should match ip-pool-1 but not ip-pool-2", func() {
			// Mock out the node and ip pools
			n := libapi.Node{ObjectMeta: metav1.ObjectMeta{Name: "bee-node", Labels: map[string]string{"foo": "bar"}}}
			pl := api.IPPoolList{
				Items: []api.IPPool{
					{
						ObjectMeta: metav1.ObjectMeta{Name: "ip-pool-1"},
						Spec: api.IPPoolSpec{
							Disabled:     false,
							CIDR:         "172.0.0.0/9",
							NodeSelector: `foo == "bar"`,
							VXLANMode:    api.VXLANModeAlways,
						},
					}, {
						ObjectMeta: metav1.ObjectMeta{Name: "ip-pool-2"},
						Spec: api.IPPoolSpec{
							Disabled:     false,
							CIDR:         "172.128.0.0/9",
							NodeSelector: `foo != "bar"`,
							VXLANMode:    api.VXLANModeAlways,
						},
					}}}

			// Execute and test assertions.
			cidrs := determineEnabledPoolCIDRs(n, pl, ipam.AttributeTypeVXLAN)
			_, cidr1, _ := net.ParseCIDR("172.0.0.1/9")
			_, cidr2, _ := net.ParseCIDR("172.128.0.1/9")
			Expect(cidrs).To(ContainElement(*cidr1))
			Expect(cidrs).ToNot(ContainElement(*cidr2))
		})
		It("should match ip-pool-1 but not ip-pool-2 for VXLANMode CrossSubnet", func() {
			// Mock out the node and ip pools
			n := libapi.Node{ObjectMeta: metav1.ObjectMeta{Name: "bee-node", Labels: map[string]string{"foo": "bar"}}}
			pl := api.IPPoolList{
				Items: []api.IPPool{
					{
						ObjectMeta: metav1.ObjectMeta{Name: "ip-pool-1"},
						Spec: api.IPPoolSpec{
							Disabled:     false,
							CIDR:         "172.0.0.0/9",
							NodeSelector: `foo == "bar"`,
							VXLANMode:    api.VXLANModeCrossSubnet,
						},
					}, {
						ObjectMeta: metav1.ObjectMeta{Name: "ip-pool-2"},
						Spec: api.IPPoolSpec{
							Disabled:     false,
							CIDR:         "172.128.0.0/9",
							NodeSelector: `foo != "bar"`,
							VXLANMode:    api.VXLANModeCrossSubnet,
						},
					}}}

			// Execute and test assertions.
			cidrs := determineEnabledPoolCIDRs(n, pl, ipam.AttributeTypeVXLAN)
			_, cidr1, _ := net.ParseCIDR("172.0.0.1/9")
			_, cidr2, _ := net.ParseCIDR("172.128.0.1/9")
			Expect(cidrs).To(ContainElement(*cidr1))
			Expect(cidrs).ToNot(ContainElement(*cidr2))
		})
	})

	//TODO: enable when libcalico-go validator no longer gives an error for VXLAN IPv6 IPPools
	XContext("IPv6 VXLAN tests", func() {
		It("should match ip-pool-1 but not ip-pool-2", func() {
			// Mock out the node and ip pools
			n := libapi.Node{ObjectMeta: metav1.ObjectMeta{Name: "bee-node", Labels: map[string]string{"foo": "bar"}}}
			pl := api.IPPoolList{
				Items: []api.IPPool{
					{
						ObjectMeta: metav1.ObjectMeta{Name: "ip-pool-1"},
						Spec: api.IPPoolSpec{
							Disabled:     false,
							CIDR:         "2001:db8::/64",
							NodeSelector: `foo == "bar"`,
							VXLANMode:    api.VXLANModeAlways,
						},
					}, {
						ObjectMeta: metav1.ObjectMeta{Name: "ip-pool-2"},
						Spec: api.IPPoolSpec{
							Disabled:     false,
							CIDR:         "2001:db8:00:ff::/64",
							NodeSelector: `foo != "bar"`,
							VXLANMode:    api.VXLANModeAlways,
						},
					}}}

			// Execute and test assertions.
			cidrs := determineEnabledPoolCIDRs(n, pl, ipam.AttributeTypeVXLANV6)
			_, cidr1, _ := net.ParseCIDR("2001:db8::1/64")
			_, cidr2, _ := net.ParseCIDR("2001:db8:00:ff::1/64")
			Expect(cidrs).To(ContainElement(*cidr1))
			Expect(cidrs).ToNot(ContainElement(*cidr2))
		})
		It("should match ip-pool-1 but not ip-pool-2 for VXLANMode CrossSubnet", func() {
			// Mock out the node and ip pools
			n := libapi.Node{ObjectMeta: metav1.ObjectMeta{Name: "bee-node", Labels: map[string]string{"foo": "bar"}}}
			pl := api.IPPoolList{
				Items: []api.IPPool{
					{
						ObjectMeta: metav1.ObjectMeta{Name: "ip-pool-1"},
						Spec: api.IPPoolSpec{
							Disabled:     false,
							CIDR:         "2001:db8::/64",
							NodeSelector: `foo == "bar"`,
							VXLANMode:    api.VXLANModeCrossSubnet,
						},
					}, {
						ObjectMeta: metav1.ObjectMeta{Name: "ip-pool-2"},
						Spec: api.IPPoolSpec{
							Disabled:     false,
							CIDR:         "2001:db8:00:ff::/64",
							NodeSelector: `foo != "bar"`,
							VXLANMode:    api.VXLANModeCrossSubnet,
						},
					}}}

			// Execute and test assertions.
			cidrs := determineEnabledPoolCIDRs(n, pl, ipam.AttributeTypeVXLANV6)
			_, cidr1, _ := net.ParseCIDR("2001:db8::1/64")
			_, cidr2, _ := net.ParseCIDR("2001:db8:00:ff::1/64")
			Expect(cidrs).To(ContainElement(*cidr1))
			Expect(cidrs).ToNot(ContainElement(*cidr2))
		})
	})

	Context("Wireguard tests", func() {
		It("node has public key - should match ip-pool-1 but not ip-pool-2", func() {
			// Mock out the node and ip pools
			n := libapi.Node{
				ObjectMeta: metav1.ObjectMeta{Name: "bee-node", Labels: map[string]string{"foo": "bar"}},
				Status:     libapi.NodeStatus{WireguardPublicKey: "abcde"},
			}
			pl := api.IPPoolList{
				Items: []api.IPPool{
					{
						ObjectMeta: metav1.ObjectMeta{Name: "ip-pool-1"},
						Spec: api.IPPoolSpec{
							Disabled:     false,
							CIDR:         "172.0.0.0/9",
							NodeSelector: `foo == "bar"`,
						},
					}, {
						ObjectMeta: metav1.ObjectMeta{Name: "ip-pool-2"},
						Spec: api.IPPoolSpec{
							Disabled:     false,
							CIDR:         "172.128.0.0/9",
							NodeSelector: `foo != "bar"`,
						},
					}}}

			// Execute and test assertions.
			cidrs := determineEnabledPoolCIDRs(n, pl, ipam.AttributeTypeWireguard)
			_, cidr1, _ := net.ParseCIDR("172.0.0.1/9")
			_, cidr2, _ := net.ParseCIDR("172.128.0.1/9")
			Expect(cidrs).To(ContainElement(*cidr1))
			Expect(cidrs).ToNot(ContainElement(*cidr2))
		})
		It("node has no public key - should match no pools", func() {
			// Mock out the node and ip pools
			n := libapi.Node{ObjectMeta: metav1.ObjectMeta{Name: "bee-node", Labels: map[string]string{"foo": "bar"}}}
			pl := api.IPPoolList{
				Items: []api.IPPool{
					{
						ObjectMeta: metav1.ObjectMeta{Name: "ip-pool-1"},
						Spec: api.IPPoolSpec{
							Disabled:     false,
							CIDR:         "172.0.0.0/9",
							NodeSelector: `foo == "bar"`,
						},
					}, {
						ObjectMeta: metav1.ObjectMeta{Name: "ip-pool-2"},
						Spec: api.IPPoolSpec{
							Disabled:     false,
							CIDR:         "172.128.0.0/9",
							NodeSelector: `foo != "bar"`,
						},
					}}}

			// Execute and test assertions.
			cidrs := determineEnabledPoolCIDRs(n, pl, ipam.AttributeTypeWireguard)
			Expect(cidrs).To(HaveLen(0))
		})
	})
})

// Mock ippool accessor for ipam to return any error provided.
type ipPoolErrorAccessor struct {
	err error
}

func newIPPoolErrorAccessor(err error) *ipPoolErrorAccessor {
	return &ipPoolErrorAccessor{err}
}

func (i *ipPoolErrorAccessor) GetEnabledPools(ipVersion int) ([]api.IPPool, error) {
	return nil, i.err
}

func (i *ipPoolErrorAccessor) GetAllPools() ([]api.IPPool, error) {
	return nil, i.err
}

// shimClient inherits a client interface with new ipam client.
type shimClient struct {
	client client.Interface // real client
	ic     ipam.Interface   // new ipam client
}

func (c shimClient) IPReservations() client.IPReservationInterface {
	return c.client.IPReservations()
}

func newShimClientWithPoolAccessor(c client.Interface, be bapi.Client, pool ipam.PoolAccessorInterface) shimClient {
	return shimClient{client: c, ic: ipam.NewIPAMClient(be, pool, c.IPReservations())}
}

// Nodes returns an interface for managing node resources.
func (c shimClient) Nodes() client.NodeInterface {
	return c.client.Nodes()
}

// NetworkPolicies returns an interface for managing policy resources.
func (c shimClient) NetworkPolicies() client.NetworkPolicyInterface {
	return c.client.NetworkPolicies()
}

// GlobalNetworkPolicies returns an interface for managing policy resources.
func (c shimClient) GlobalNetworkPolicies() client.GlobalNetworkPolicyInterface {
	return c.client.GlobalNetworkPolicies()
}

// IPPools returns an interface for managing IP pool resources.
func (c shimClient) IPPools() client.IPPoolInterface {
	return c.client.IPPools()
}

// Profiles returns an interface for managing profile resources.
func (c shimClient) Profiles() client.ProfileInterface {
	return c.client.Profiles()
}

// GlobalNetworkSets returns an interface for managing host endpoint resources.
func (c shimClient) GlobalNetworkSets() client.GlobalNetworkSetInterface {
	return c.client.GlobalNetworkSets()
}

// NetworkSets returns an interface for managing host endpoint resources.
func (c shimClient) NetworkSets() client.NetworkSetInterface {
	return c.client.NetworkSets()
}

// HostEndpoints returns an interface for managing host endpoint resources.
func (c shimClient) HostEndpoints() client.HostEndpointInterface {
	return c.client.HostEndpoints()
}

// WorkloadEndpoints returns an interface for managing workload endpoint resources.
func (c shimClient) WorkloadEndpoints() client.WorkloadEndpointInterface {
	return c.client.WorkloadEndpoints()
}

// BGPPeers returns an interface for managing BGP peer resources.
func (c shimClient) BGPPeers() client.BGPPeerInterface {
	return c.client.BGPPeers()
}

// IPAM returns an interface for managing IP address assignment and releasing.
func (c shimClient) IPAM() ipam.Interface {
	return c.ic
}

// BGPConfigurations returns an interface for managing the BGP configuration resources.
func (c shimClient) BGPConfigurations() client.BGPConfigurationInterface {
	return c.client.BGPConfigurations()
}

// FelixConfigurations returns an interface for managing the Felix configuration resources.
func (c shimClient) FelixConfigurations() client.FelixConfigurationInterface {
	return c.client.FelixConfigurations()
}

// ClusterInformation returns an interface for managing the cluster information resource.
func (c shimClient) ClusterInformation() client.ClusterInformationInterface {
	return c.client.ClusterInformation()
}

// KubeControllersConfiguration returns an interface for managing the Kubernetes controllers configuration resource.
func (c shimClient) KubeControllersConfiguration() client.KubeControllersConfigurationInterface {
	return c.client.KubeControllersConfiguration()
}

// CalicoNodeStatus returns an interface for managing the calico node status resource.
func (c shimClient) CalicoNodeStatus() client.CalicoNodeStatusInterface {
	return c.client.CalicoNodeStatus()
}

func (c shimClient) EnsureInitialized(ctx context.Context, calicoVersion, clusterType string) error {
	return nil
}
