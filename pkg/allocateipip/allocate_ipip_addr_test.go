// Copyright (c) 2018 Tigera, Inc. All rights reserved.

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

package allocateipip

import (
	"context"
	"os"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/libcalico-go/lib/apiconfig"
	api "github.com/projectcalico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/libcalico-go/lib/backend"
	client "github.com/projectcalico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/libcalico-go/lib/logutils"
	"github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/options"
)

// makeNode creates an api.Node with some BGPSpec info populated.
func makeNode(ipv4 string, ipv6 string) *api.Node {
	ip4, ip4net, _ := net.ParseCIDR(ipv4)
	ip4net.IP = ip4.IP

	ip6Addr := ""
	if ipv6 != "" {
		ip6, ip6net, _ := net.ParseCIDR(ipv6)
		// Guard against nil here in case we pass in an empty string for IPv6.
		if ip6 != nil {
			ip6net.IP = ip6.IP
		}
		ip6Addr = ip6net.String()
	}

	n := &api.Node{
		Spec: api.NodeSpec{
			BGP: &api.NodeBGPSpec{
				IPv4Address: ip4net.String(),
				IPv6Address: ip6Addr,
			},
		},
	}
	return n
}

func makeIPv4Pool(ipv4cidr string) *api.IPPool {
	return &api.IPPool{
		ObjectMeta: metav1.ObjectMeta{
			Name: "dont-care",
		},
		Spec: api.IPPoolSpec{
			CIDR:        ipv4cidr,
			NATOutgoing: true,
			IPIPMode:    api.IPIPModeAlways,
		},
	}
}

var _ = Describe("ensureHostTunnelAddress", func() {
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
		be, _ := backend.NewClient(*cfg)
		be.Clean()

		//create client and IPPool
		c, _ = client.New(*cfg)
		c.IPPools().Create(ctx, makeIPv4Pool("172.16.0.0/24"), options.SetOptions{})
	})

	It("should add tunnel address to node", func() {
		node := makeNode("192.168.0.1/24", "fdff:ffff:ffff:ffff:ffff::/80")
		node.Name = "test.node"

		_, err := c.Nodes().Create(ctx, node, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		_, ip4net, _ := net.ParseCIDR("172.16.0.0/24")
		ensureHostTunnelAddress(ctx, c, node.Name, []net.IPNet{*ip4net})
		n, err := c.Nodes().Get(ctx, node.Name, options.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(n.Spec.BGP.IPv4IPIPTunnelAddr).ToNot(Equal(""))
	})

	It("should add tunnel address to node without BGP Spec", func() {
		node := makeNode("192.168.0.1/24", "fdff:ffff:ffff:ffff:ffff::/80")
		node.Name = "test.node"
		node.Spec.BGP = nil

		_, err := c.Nodes().Create(ctx, node, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		_, ip4net, _ := net.ParseCIDR("172.16.0.0/24")
		ensureHostTunnelAddress(ctx, c, node.Name, []net.IPNet{*ip4net})
		n, err := c.Nodes().Get(ctx, node.Name, options.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(n.Spec.BGP.IPv4IPIPTunnelAddr).ToNot(Equal(""))
	})
})

var _ = Describe("removeHostTunnelAddr", func() {
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
		be, _ := backend.NewClient(*cfg)
		be.Clean()

		//create client and IPPool
		c, _ = client.New(*cfg)
		c.IPPools().Create(ctx, makeIPv4Pool("172.16.0.0/24"), options.SetOptions{})
	})

	It("should remove tunnel address from node", func() {
		node := makeNode("192.168.0.1/24", "fdff:ffff:ffff:ffff:ffff::/80")
		node.Name = "test.node"
		node.Spec.BGP.IPv4IPIPTunnelAddr = "172.16.0.5"

		_, err := c.Nodes().Create(ctx, node, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		removeHostTunnelAddr(ctx, c, node.Name)
		n, err := c.Nodes().Get(ctx, node.Name, options.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(n.Spec.BGP.IPv4IPIPTunnelAddr).To(Equal(""))
	})

	It("should not panic on node without BGP Spec", func() {
		node := makeNode("192.168.0.1/24", "fdff:ffff:ffff:ffff:ffff::/80")
		node.Name = "test.node"
		node.Spec.BGP = nil

		_, err := c.Nodes().Create(ctx, node, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		removeHostTunnelAddr(ctx, c, node.Name)
		n, err := c.Nodes().Get(ctx, node.Name, options.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(n.Spec.BGP).To(BeNil())
	})
})
