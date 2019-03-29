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

package allocateip

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

var _ = Describe("determineVXLANEnabledPoolCIDRs", func() {
	log.SetOutput(os.Stdout)
	// Set log formatting.
	log.SetFormatter(&logutils.Formatter{})
	// Install a hook that adds file and line number information.
	log.AddHook(&logutils.ContextHook{})

	It("should match ip-pool-1 but not ip-pool-2", func() {
		// Mock out the node and ip pools
		n := api.Node{ObjectMeta: metav1.ObjectMeta{Name: "bee-node", Labels: map[string]string{"foo": "bar"}}}
		pl := api.IPPoolList{
			Items: []api.IPPool{
				api.IPPool{
					ObjectMeta: metav1.ObjectMeta{Name: "ip-pool-1"},
					Spec: api.IPPoolSpec{
						Disabled:     false,
						CIDR:         "172.0.0.0/9",
						NodeSelector: `foo == "bar"`,
						VXLANMode:    api.VXLANModeAlways,
					},
				}, api.IPPool{
					ObjectMeta: metav1.ObjectMeta{Name: "ip-pool-2"},
					Spec: api.IPPoolSpec{
						Disabled:     false,
						CIDR:         "172.128.0.0/9",
						NodeSelector: `foo != "bar"`,
						VXLANMode:    api.VXLANModeAlways,
					},
				}}}

		// Execute and test assertions.
		cidrs := determineVXLANEnabledPoolCIDRs(n, pl)
		_, cidr1, _ := net.ParseCIDR("172.0.0.1/9")
		_, cidr2, _ := net.ParseCIDR("172.128.0.1/9")
		Expect(cidrs).To(ContainElement(*cidr1))
		Expect(cidrs).ToNot(ContainElement(*cidr2))
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

	var c client.Interface
	BeforeEach(func() {
		// Clear out datastore
		be, err := backend.NewClient(*cfg)
		Expect(err).ToNot(HaveOccurred())
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
		Expect(n.Spec.BGP.IPv4VXLANTunnelAddr).ToNot(Equal(""))
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
		Expect(n.Spec.BGP.IPv4VXLANTunnelAddr).ToNot(Equal(""))
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
		be, err := backend.NewClient(*cfg)
		Expect(err).ToNot(HaveOccurred())
		be.Clean()

		//create client and IPPool
		c, _ = client.New(*cfg)
		c.IPPools().Create(ctx, makeIPv4Pool("172.16.0.0/24"), options.SetOptions{})
	})

	It("should remove tunnel address from node", func() {
		node := makeNode("192.168.0.1/24", "fdff:ffff:ffff:ffff:ffff::/80")
		node.Name = "test.node"
		node.Spec.BGP.IPv4VXLANTunnelAddr = "172.16.0.5"

		_, err := c.Nodes().Create(ctx, node, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		removeHostTunnelAddr(ctx, c, node.Name)
		n, err := c.Nodes().Get(ctx, node.Name, options.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(n.Spec.BGP.IPv4VXLANTunnelAddr).To(Equal(""))
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
