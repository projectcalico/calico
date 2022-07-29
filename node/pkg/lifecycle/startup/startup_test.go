// Copyright (c) 2016,2021 Tigera, Inc. All rights reserved.

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

package startup

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	libapi "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/backend"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/names"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
	"github.com/projectcalico/calico/node/pkg/lifecycle/startup/autodetection"
	"github.com/projectcalico/calico/node/pkg/lifecycle/utils"
)

var exitCode int

func fakeExitFunction(ec int) {
	exitCode = ec
}

// makeNode creates an libapi.Node with some BGPSpec info populated.
func makeNode(ipv4 string, ipv6 string) *libapi.Node {
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

	n := &libapi.Node{
		Spec: libapi.NodeSpec{
			BGP: &libapi.NodeBGPSpec{
				IPv4Address: ip4net.String(),
				IPv6Address: ip6Addr,
			},
		},
	}
	return n
}

// makeK8sNode creates an v1.Node with some Addresses populated.
func makeK8sNode(ipv4 string, ipv6 string) *v1.Node {
	node := &v1.Node{
		Status: v1.NodeStatus{
			Addresses: []v1.NodeAddress{
				{Type: v1.NodeInternalIP, Address: ipv4},
				{Type: v1.NodeInternalIP, Address: ipv6},
			},
		},
	}
	return node
}

var _ = DescribeTable("Node IP detection failure cases",
	func(networkingBackend string, expectedExitCode int, rrCId string) {
		os.Setenv("CALICO_NETWORKING_BACKEND", networkingBackend)
		os.Setenv("IP", "none")
		os.Setenv("IP6", "")

		my_ec := 0
		oldExit := utils.GetExitFunction()
		exitFunction := func(ec int) { my_ec = ec }
		utils.SetExitFunction(exitFunction)
		defer utils.SetExitFunction(oldExit)

		// prologue for the main test.
		cfg, err := apiconfig.LoadClientConfigFromEnvironment()
		Expect(err).NotTo(HaveOccurred())
		c, err := client.New(*cfg)
		Expect(err).NotTo(HaveOccurred())

		node := libapi.Node{}
		if rrCId != "" {
			node.Spec.BGP = &libapi.NodeBGPSpec{RouteReflectorClusterID: rrCId}
		}

		_ = configureAndCheckIPAddressSubnets(context.Background(), c, &node, &v1.Node{})
		Expect(my_ec).To(Equal(expectedExitCode))
		if rrCId != "" {
			Expect(node.Spec.BGP).NotTo(BeNil())
		}
	},

	Entry("startup should terminate if IP is set to none and Calico is used for networking", "bird", 1, ""),
	Entry("startup should NOT terminate if IP is set to none and Calico is policy-only", "none", 0, ""),
	Entry("startup should NOT terminate and BGPSpec shouldn't be set to nil", "none", 0, "rrClusterID"),
)

var _ = Describe("Default IPv4 pool CIDR", func() {
	It("default pool must be valid", func() {
		_, _, err := net.ParseCIDR(DEFAULT_IPV4_POOL_CIDR)
		Expect(err).To(BeNil())
	})
})

var _ = Describe("Termination tests", func() {
	It("should have terminated", func() {
		exitCode = 0
		oldExit := utils.GetExitFunction()
		utils.SetExitFunction(fakeExitFunction)
		defer utils.SetExitFunction(oldExit)
		utils.Terminate()
		Expect(exitCode).To(Equal(1))
	})
})

type EnvItem struct {
	key   string
	value string
}

const (
	randomULAPool = "<random ULA pool>"
)

var (
	kubeadmConfig *v1.ConfigMap = &v1.ConfigMap{Data: map[string]string{"ClusterConfiguration": "podSubnet: 192.168.0.0/16"}}
	rancherState  *v1.ConfigMap = nil
)

var _ = Describe("FV tests against a real etcd", func() {
	RegisterFailHandler(Fail)
	ctx := context.Background()
	changedEnvVars := []string{
		"CALICO_IPV4POOL_CIDR", "CALICO_IPV6POOL_CIDR",
		"NO_DEFAULT_POOLS",
		"CALICO_IPV4POOL_IPIP",
		"CALICO_IPV4POOL_NAT_OUTGOING", "CALICO_IPV6POOL_NAT_OUTGOING",
		"IP", "CLUSTER_TYPE", "CALICO_K8S_NODE_REF", "CALICO_UNKNOWN_NODE_REF",
		"CALICO_IPV4POOL_BLOCK_SIZE", "CALICO_IPV6POOL_BLOCK_SIZE",
		"CALICO_IPV4POOL_NODE_SELECTOR", "CALICO_IPV6POOL_NODE_SELECTOR",
	}

	BeforeEach(func() {
		for _, envName := range changedEnvVars {
			os.Unsetenv(envName)
		}
	})
	AfterEach(func() {
		for _, envName := range changedEnvVars {
			os.Unsetenv(envName)
		}
	})

	DescribeTable("Test IP pool env variables",
		func(envList []EnvItem, expectedIPv4 string, expectedIPv6 string, expectIpv4IpipMode string, expectIpv4VXLANMode string, expectIpv6VXLANMode string, expectedIPV4NATOutgoing bool, expectedIPV6NATOutgoing bool, expectedIPv4BlockSize, expectedIPv6BlockSize int, expectedIPv4NodeSelector, expectedIPv6NodeSelector string, expectedIPv4DisableBGPExport, expectedIPv6DisableBGPExport bool) {
			// Create a new client.
			cfg, err := apiconfig.LoadClientConfigFromEnvironment()
			Expect(err).NotTo(HaveOccurred())

			c, err := client.New(*cfg)
			Expect(err).NotTo(HaveOccurred())

			be, err := backend.NewClient(*cfg)
			Expect(err).NotTo(HaveOccurred())
			err = be.Clean()
			Expect(err).NotTo(HaveOccurred())

			// Set the env variables specified.
			for _, env := range envList {
				os.Setenv(env.key, env.value)
			}
			defer func() {
				for _, env := range envList {
					os.Unsetenv(env.key)
				}
			}()

			poolList, err := c.IPPools().List(ctx, options.ListOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(poolList.Items).To(BeEmpty())

			// Run the UUT.
			configureIPPools(ctx, c, kubeadmConfig)

			// Get the IPPool list.
			poolList, err = c.IPPools().List(ctx, options.ListOptions{})
			Expect(err).NotTo(HaveOccurred())

			// Look through the pool for the expected data.
			foundv4Expected := false
			foundv6Expected := false

			for _, pool := range poolList.Items {
				if pool.Spec.CIDR == expectedIPv4 {
					foundv4Expected = true
				}
				if expectedIPv6 == randomULAPool {
					_, ipNet, err := net.ParseCIDR(pool.Spec.CIDR)
					Expect(err).NotTo(HaveOccurred(), "Pool had invalid CIDR: "+pool.Spec.CIDR)
					ones, bits := ipNet.Mask.Size()
					// The ULA pool should be 48 bits and have prefix fd00::/8.
					if ones == 48 && bits == 128 && ipNet.IP[0] == 0xfd {
						foundv6Expected = true
					}
				} else if pool.Spec.CIDR == expectedIPv6 {
					foundv6Expected = true
				}
				if _, cidr, _ := net.ParseCIDR(pool.Spec.CIDR); cidr.Version() == 6 {
					// Expect IPIP on IPv6 to be disabled

					Expect(pool.Spec.IPIPMode).To(Equal(api.IPIPModeNever))

					// off is not a real mode value but use it instead of empty string
					if expectIpv6VXLANMode == "Off" {
						Expect(pool.Spec.VXLANMode).To(Equal(api.VXLANModeNever))
					} else {
						Expect(pool.Spec.VXLANMode).To(Equal(api.VXLANMode(expectIpv6VXLANMode)))
					}

					Expect(pool.Spec.NATOutgoing).To(Equal(expectedIPV6NATOutgoing), "Expected IPv6 natOutgoing to be %t but was %t", expectedIPV6NATOutgoing, pool.Spec.NATOutgoing)

					Expect(pool.Spec.BlockSize).To(Equal(expectedIPv6BlockSize), "Expected IPv6 blocksize to be %d but was %d", expectedIPv6BlockSize, pool.Spec.BlockSize)

					Expect(pool.Spec.NodeSelector).To(Equal(expectedIPv6NodeSelector),
						"Expected IPv4 selector %s to be %s", pool.Spec.NodeSelector, expectedIPv6NodeSelector)

					Expect(pool.Spec.DisableBGPExport).To(Equal(expectedIPv6DisableBGPExport), "Expected IPv6 disableBGPExport to be %t but was %t", expectedIPv6DisableBGPExport, pool.Spec.DisableBGPExport)
				} else {
					// off is not a real mode value but use it instead of empty string
					if expectIpv4IpipMode == "Off" {
						Expect(pool.Spec.IPIPMode).To(Equal(api.IPIPModeNever))
					} else {
						Expect(pool.Spec.IPIPMode).To(Equal(api.IPIPMode(expectIpv4IpipMode)))
					}

					// off is not a real mode value but use it instead of empty string
					if expectIpv4VXLANMode == "Off" {
						Expect(pool.Spec.VXLANMode).To(Equal(api.VXLANModeNever))
					} else {
						Expect(pool.Spec.VXLANMode).To(Equal(api.VXLANMode(expectIpv4VXLANMode)))
					}

					Expect(pool.Spec.NATOutgoing).To(Equal(expectedIPV4NATOutgoing), "Expected IPv4 to be %t but was %t", expectedIPV4NATOutgoing, pool.Spec.NATOutgoing)

					Expect(pool.Spec.BlockSize).To(Equal(expectedIPv4BlockSize), "Expected IPv4 blocksize to be %d but was %d", expectedIPv4BlockSize, pool.Spec.BlockSize)

					Expect(pool.Spec.NodeSelector).To(Equal(expectedIPv4NodeSelector),
						"Expected IPv4 selector %s to be %s", pool.Spec.NodeSelector, expectedIPv4NodeSelector)

					Expect(pool.Spec.DisableBGPExport).To(Equal(expectedIPv4DisableBGPExport), "Expected IPv4 disableBGPExport to be %t but was %t", expectedIPv4DisableBGPExport, pool.Spec.DisableBGPExport)
				}
			}
			Expect(foundv4Expected).To(BeTrue(),
				"Expected %s to be in Pools", expectedIPv4)
			Expect(foundv6Expected).To(BeTrue(),
				"Expected %s to be in Pools", expectedIPv6)
		},

		Entry("No env variables set", []EnvItem{},
			"192.168.0.0/16", randomULAPool, "Off", "Off", "Off", true, false, 26, 122, "all()", "all()", false, false),
		Entry("IPv4 Pool env var set",
			[]EnvItem{{"CALICO_IPV4POOL_CIDR", "172.16.0.0/24"}},
			"172.16.0.0/24", randomULAPool, "Off", "Off", "Off", true, false, 26, 122, "all()", "all()", false, false),
		Entry("IPv6 Pool env var set",
			[]EnvItem{{"CALICO_IPV6POOL_CIDR", "fdff:ffff:ffff:ffff:ffff::/80"}},
			"192.168.0.0/16", "fdff:ffff:ffff:ffff:ffff::/80", "Off", "Off", "Off", true, false, 26, 122, "all()", "all()", false, false),
		Entry("Both IPv4 and IPv6 Pool env var set",
			[]EnvItem{
				{"CALICO_IPV4POOL_CIDR", "172.16.0.0/24"},
				{"CALICO_IPV6POOL_CIDR", "fdff:ffff:ffff:ffff:ffff::/80"},
			},
			"172.16.0.0/24", "fdff:ffff:ffff:ffff:ffff::/80", "Off", "Off", "Off", true, false, 26, 122, "all()", "all()", false, false),
		Entry("CALICO_IPV4POOL_IPIP set off", []EnvItem{{"CALICO_IPV4POOL_IPIP", "off"}},
			"192.168.0.0/16", randomULAPool, "Off", "Off", "Off", true, false, 26, 122, "all()", "all()", false, false),
		Entry("CALICO_IPV4POOL_IPIP set Off", []EnvItem{{"CALICO_IPV4POOL_IPIP", "Off"}},
			"192.168.0.0/16", randomULAPool, "Off", "Off", "Off", true, false, 26, 122, "all()", "all()", false, false),
		Entry("CALICO_IPV4POOL_IPIP set Never", []EnvItem{{"CALICO_IPV4POOL_IPIP", "Never"}},
			"192.168.0.0/16", randomULAPool, "Never", "Off", "Off", true, false, 26, 122, "all()", "all()", false, false),
		Entry("CALICO_IPV4POOL_IPIP set empty string", []EnvItem{{"CALICO_IPV4POOL_IPIP", ""}},
			"192.168.0.0/16", randomULAPool, "Off", "Off", "Off", true, false, 26, 122, "all()", "all()", false, false),
		Entry("CALICO_IPV4POOL_IPIP set always", []EnvItem{{"CALICO_IPV4POOL_IPIP", "always"}},
			"192.168.0.0/16", randomULAPool, "Always", "Off", "Off", true, false, 26, 122, "all()", "all()", false, false),
		Entry("CALICO_IPV4POOL_IPIP set Always", []EnvItem{{"CALICO_IPV4POOL_IPIP", "Always"}},
			"192.168.0.0/16", randomULAPool, "Always", "Off", "Off", true, false, 26, 122, "all()", "all()", false, false),
		Entry("CALICO_IPV4POOL_IPIP set cross-subnet", []EnvItem{{"CALICO_IPV4POOL_IPIP", "cross-subnet"}},
			"192.168.0.0/16", randomULAPool, "CrossSubnet", "Off", "Off", true, false, 26, 122, "all()", "all()", false, false),
		Entry("CALICO_IPV4POOL_IPIP set CrossSubnet", []EnvItem{{"CALICO_IPV4POOL_IPIP", "CrossSubnet"}},
			"192.168.0.0/16", randomULAPool, "CrossSubnet", "Off", "Off", true, false, 26, 122, "all()", "all()", false, false),
		Entry("CALICO_IPV4POOL_BLOCK_SIZE set 27", []EnvItem{{"CALICO_IPV4POOL_BLOCK_SIZE", "27"}},
			"192.168.0.0/16", randomULAPool, "Off", "Off", "Off", true, false, 27, 122, "all()", "all()", false, false),
		Entry("IPv6 Pool and IPIP set",
			[]EnvItem{
				{"CALICO_IPV6POOL_CIDR", "fdff:ffff:ffff:ffff:ffff::/80"},
				{"CALICO_IPV4POOL_IPIP", "always"},
			},
			"192.168.0.0/16", "fdff:ffff:ffff:ffff:ffff::/80", "Always", "Off", "Off", true, false, 26, 122, "all()", "all()", false, false),
		Entry("IPv6 NATOutgoing Set Enabled",
			[]EnvItem{
				{"CALICO_IPV6POOL_NAT_OUTGOING", "true"},
			},
			"192.168.0.0/16", randomULAPool, "Off", "Off", "Off", true, true, 26, 122, "all()", "all()", false, false),
		Entry("IPv6 NATOutgoing Set Disabled",
			[]EnvItem{
				{"CALICO_IPV6POOL_NAT_OUTGOING", "false"},
			},
			"192.168.0.0/16", randomULAPool, "Off", "Off", "Off", true, false, 26, 122, "all()", "all()", false, false),
		Entry("IPv4 NATOutgoing Set Disabled",
			[]EnvItem{
				{"CALICO_IPV4POOL_NAT_OUTGOING", "false"},
			},
			"192.168.0.0/16", randomULAPool, "Off", "Off", "Off", false, false, 26, 122, "all()", "all()", false, false),
		Entry("IPv6 NAT OUTGOING and IPV4 NAT OUTGOING SET",
			[]EnvItem{
				{"CALICO_IPV4POOL_NAT_OUTGOING", "false"},
				{"CALICO_IPV6POOL_NAT_OUTGOING", "true"},
			},
			"192.168.0.0/16", randomULAPool, "Off", "Off", "Off", false, true, 26, 122, "all()", "all()", false, false),
		Entry("CALICO_IPV6POOL_BLOCK_SIZE set 123", []EnvItem{{"CALICO_IPV6POOL_BLOCK_SIZE", "123"}},
			"192.168.0.0/16", randomULAPool, "Off", "Off", "Off", true, false, 26, 123, "all()", "all()", false, false),
		Entry("CALICO_IPV4POOL_NODE_SELECTOR set all()", []EnvItem{{"CALICO_IPV4POOL_NODE_SELECTOR", "all()"}},
			"192.168.0.0/16", randomULAPool, "Off", "Off", "Off", true, false, 26, 122, "all()", "all()", false, false),
		Entry("CALICO_IPV4POOL_NODE_SELECTOR set has(something)", []EnvItem{{"CALICO_IPV4POOL_NODE_SELECTOR", "key == 'something'"}},
			"192.168.0.0/16", randomULAPool, "Off", "Off", "Off", true, false, 26, 122, "key == 'something'", "all()", false, false),
		Entry("CALICO_IPV6POOL_NODE_SELECTOR set failed", []EnvItem{{"CALICO_IPV6POOL_NODE_SELECTOR", "has(something)"}},
			"192.168.0.0/16", randomULAPool, "Off", "Off", "Off", true, false, 26, 122, "all()", "has(something)", false, false),
		Entry("CALICO_IPV4POOL_VXLAN set off", []EnvItem{{"CALICO_IPV4POOL_VXLAN", "off"}},
			"192.168.0.0/16", randomULAPool, "Off", "Off", "Off", true, false, 26, 122, "all()", "all()", false, false),
		Entry("CALICO_IPV4POOL_VXLAN set Off", []EnvItem{{"CALICO_IPV4POOL_VXLAN", "Off"}},
			"192.168.0.0/16", randomULAPool, "Off", "Off", "Off", true, false, 26, 122, "all()", "all()", false, false),
		Entry("CALICO_IPV4POOL_VXLAN set Never", []EnvItem{{"CALICO_IPV4POOL_VXLAN", "Never"}},
			"192.168.0.0/16", randomULAPool, "Off", "Never", "Off", true, false, 26, 122, "all()", "all()", false, false),
		Entry("CALICO_IPV4POOL_VXLAN set empty string", []EnvItem{{"CALICO_IPV4POOL_VXLAN", ""}},
			"192.168.0.0/16", randomULAPool, "Off", "Off", "Off", true, false, 26, 122, "all()", "all()", false, false),
		Entry("CALICO_IPV4POOL_VXLAN set always", []EnvItem{{"CALICO_IPV4POOL_VXLAN", "always"}},
			"192.168.0.0/16", randomULAPool, "Off", "Always", "Off", true, false, 26, 122, "all()", "all()", false, false),
		Entry("CALICO_IPV4POOL_VXLAN set Always", []EnvItem{{"CALICO_IPV4POOL_VXLAN", "Always"}},
			"192.168.0.0/16", randomULAPool, "Off", "Always", "Off", true, false, 26, 122, "all()", "all()", false, false),
		Entry("CALICO_IPV4POOL_VXLAN set cross-subnet", []EnvItem{{"CALICO_IPV4POOL_VXLAN", "cross-subnet"}},
			"192.168.0.0/16", randomULAPool, "Off", "CrossSubnet", "Off", true, false, 26, 122, "all()", "all()", false, false),
		Entry("CALICO_IPV4POOL_VXLAN set CrossSubnet", []EnvItem{{"CALICO_IPV4POOL_VXLAN", "CrossSubnet"}},
			"192.168.0.0/16", randomULAPool, "Off", "CrossSubnet", "Off", true, false, 26, 122, "all()", "all()", false, false),
		// Reset CALICO_IPV4POOL_VXLAN here as well
		Entry("CALICO_IPV6POOL_VXLAN set off", []EnvItem{{"CALICO_IPV4POOL_VXLAN", "off"}, {"CALICO_IPV6POOL_VXLAN", "off"}},
			"192.168.0.0/16", randomULAPool, "Off", "Off", "Off", true, false, 26, 122, "all()", "all()", false, false),
		Entry("CALICO_IPV6POOL_VXLAN set Off", []EnvItem{{"CALICO_IPV6POOL_VXLAN", "Off"}},
			"192.168.0.0/16", randomULAPool, "Off", "Off", "Off", true, false, 26, 122, "all()", "all()", false, false),
		Entry("CALICO_IPV6POOL_VXLAN set Never", []EnvItem{{"CALICO_IPV6POOL_VXLAN", "Never"}},
			"192.168.0.0/16", randomULAPool, "Off", "Off", "Never", true, false, 26, 122, "all()", "all()", false, false),
		Entry("CALICO_IPV6POOL_VXLAN set empty string", []EnvItem{{"CALICO_IPV6POOL_VXLAN", ""}},
			"192.168.0.0/16", randomULAPool, "Off", "Off", "Off", true, false, 26, 122, "all()", "all()", false, false),
		Entry("CALICO_IPV6POOL_VXLAN set always", []EnvItem{{"CALICO_IPV6POOL_VXLAN", "always"}},
			"192.168.0.0/16", randomULAPool, "Off", "Off", "Always", true, false, 26, 122, "all()", "all()", false, false),
		Entry("CALICO_IPV6POOL_VXLAN set Always", []EnvItem{{"CALICO_IPV6POOL_VXLAN", "Always"}},
			"192.168.0.0/16", randomULAPool, "Off", "Off", "Always", true, false, 26, 122, "all()", "all()", false, false),
		Entry("CALICO_IPV6POOL_VXLAN set cross-subnet", []EnvItem{{"CALICO_IPV6POOL_VXLAN", "cross-subnet"}},
			"192.168.0.0/16", randomULAPool, "Off", "Off", "CrossSubnet", true, false, 26, 122, "all()", "all()", false, false),
		Entry("CALICO_IPV6POOL_VXLAN set CrossSubnet", []EnvItem{{"CALICO_IPV6POOL_VXLAN", "CrossSubnet"}},
			"192.168.0.0/16", randomULAPool, "Off", "Off", "CrossSubnet", true, false, 26, 122, "all()", "all()", false, false),
		Entry("CALICO_IPV4POOL_VXLAN and CALICO_IPV6POOL_VXLAN set CrossSubnet", []EnvItem{{"CALICO_IPV4POOL_VXLAN", "CrossSubnet"}, {"CALICO_IPV6POOL_VXLAN", "CrossSubnet"}},
			"192.168.0.0/16", randomULAPool, "Off", "CrossSubnet", "CrossSubnet", true, false, 26, 122, "all()", "all()", false, false),
		Entry("CALICO_IPV4POOL_VXLAN set CrossSubnet and CALICO_IPV6POOL_VXLAN set Always", []EnvItem{{"CALICO_IPV4POOL_VXLAN", "CrossSubnet"}, {"CALICO_IPV6POOL_VXLAN", "Always"}},
			"192.168.0.0/16", randomULAPool, "Off", "CrossSubnet", "Always", true, false, 26, 122, "all()", "all()", false, false),
		Entry("CALICO_IPV4POOL_DISABLE_BGP_EXPORT set true",
			[]EnvItem{{"CALICO_IPV4POOL_DISABLE_BGP_EXPORT", "true"}},
			"192.168.0.0/16", randomULAPool, "Off", "Off", "Off", true, false, 26, 122, "all()", "all()", true, false),
		Entry("CALICO_IPV6POOL_DISABLE_BGP_EXPORT set true",
			[]EnvItem{{"CALICO_IPV6POOL_CIDR", "fdff:ffff:ffff:ffff:ffff::/80"}, {"CALICO_IPV6POOL_DISABLE_BGP_EXPORT", "true"}},
			"192.168.0.0/16", "fdff:ffff:ffff:ffff:ffff::/80", "Off", "Off", "Off", true, false, 26, 122, "all()", "all()", false, true),
		Entry("CALICO_IPV4POOL_DISABLE_BGP_EXPORT and CALICO_IPV6POOL_DISABLE_BGP_EXPORT set true",
			[]EnvItem{{"CALICO_IPV6POOL_CIDR", "fdff:ffff:ffff:ffff:ffff::/80"}, {"CALICO_IPV4POOL_DISABLE_BGP_EXPORT", "true"}, {"CALICO_IPV6POOL_DISABLE_BGP_EXPORT", "true"}},
			"192.168.0.0/16", "fdff:ffff:ffff:ffff:ffff::/80", "Off", "Off", "Off", true, false, 26, 122, "all()", "all()", true, true),
		Entry("CALICO_IPV4POOL_DISABLE_BGP_EXPORT and CALICO_IPV6POOL_DISABLE_BGP_EXPORT set false",
			[]EnvItem{{"CALICO_IPV4POOL_DISABLE_BGP_EXPORT", "false"}, {"CALICO_IPV6POOL_DISABLE_BGP_EXPORT", "false"}},
			"192.168.0.0/16", randomULAPool, "Off", "Off", "Off", true, false, 26, 122, "all()", "all()", false, false),
	)

	It("should properly clear node IPs", func() {
		cfg, err := apiconfig.LoadClientConfigFromEnvironment()
		Expect(err).NotTo(HaveOccurred())
		c, err := client.New(*cfg)
		Expect(err).NotTo(HaveOccurred())

		node := makeNode("192.168.0.1/24", "fdff:ffff:ffff:ffff:ffff::/80")
		node.Name = "clearips.test.node"
		By("creating a Node with IPv4 and IPv6 addresses", func() {
			_, err = c.Nodes().Create(ctx, node, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())
		})

		var n *libapi.Node
		By("getting the Node", func() {
			n, err = c.Nodes().Get(ctx, node.Name, options.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(n).NotTo(BeNil())
			Expect(n.ResourceVersion).NotTo(Equal(""))
		})

		By("clearing the Node's IPv4 address", func() {
			clearNodeIPs(ctx, c, n, true, false)
			dn, err := c.Nodes().Get(ctx, node.Name, options.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(dn.Spec.BGP.IPv4Address).To(Equal(""))
			Expect(dn.Spec.BGP.IPv6Address).ToNot(Equal(""))
		})

		By("getting the Node", func() {
			n, err = c.Nodes().Get(ctx, node.Name, options.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(n).NotTo(BeNil())
			Expect(n.ResourceVersion).NotTo(Equal(""))
		})

		By("clearing the Node's IPv6 address", func() {
			clearNodeIPs(ctx, c, n, false, true)
			dn, err := c.Nodes().Get(ctx, node.Name, options.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(dn.Spec.BGP).To(BeNil())
		})
	})

	It("should properly handle NO_DEFAULT_POOLS env variable", func() {
		// Create clients for test.
		cfg, err := apiconfig.LoadClientConfigFromEnvironment()
		Expect(err).NotTo(HaveOccurred())
		c, err := client.New(*cfg)
		Expect(err).NotTo(HaveOccurred())
		be, err := backend.NewClient(*cfg)
		Expect(err).NotTo(HaveOccurred())

		err = be.Clean()
		Expect(err).NotTo(HaveOccurred())

		// Set the env variables specified.
		os.Setenv("NO_DEFAULT_POOLS", "true")

		// Run the UUT.
		configureIPPools(ctx, c, kubeadmConfig)

		// Get the IPPool list.
		poolList, err := c.IPPools().List(ctx, options.ListOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(poolList.Items).To(BeEmpty(), "Environment %#v", os.Environ())
	})

	DescribeTable("Test IP pool env variables that cause exit",
		func(envList []EnvItem) {
			my_ec := 0
			oldExit := utils.GetExitFunction()
			exitFunction := func(ec int) { my_ec = ec }
			utils.SetExitFunction(exitFunction)
			defer utils.SetExitFunction(oldExit)

			// Create a new client.
			cfg, err := apiconfig.LoadClientConfigFromEnvironment()
			Expect(err).NotTo(HaveOccurred())

			c, err := client.New(*cfg)
			Expect(err).NotTo(HaveOccurred())

			be, err := backend.NewClient(*cfg)
			Expect(err).NotTo(HaveOccurred())

			err = be.Clean()
			Expect(err).NotTo(HaveOccurred())

			// Set the env variables specified.
			for _, env := range envList {
				os.Setenv(env.key, env.value)
			}

			// Run the UUT.
			configureIPPools(ctx, c, kubeadmConfig)

			Expect(my_ec).To(Equal(1))
		},

		Entry("Bad IPv4 Pool CIDR", []EnvItem{{"CALICO_IPV4POOL_CIDR", "172.16.0.0a/24"}}),
		Entry("Too small IPv4 Pool CIDR", []EnvItem{{"CALICO_IPV4POOL_CIDR", "172.16.0.0/27"}}),
		Entry("Single IPv4 is too small for a pool CIDR", []EnvItem{{"CALICO_IPV4POOL_CIDR", "10.0.0.0/32"}}),
		Entry("Small IPv6 is too small for a pool CIDR", []EnvItem{{"CALICO_IPV6POOL_CIDR", "fd00::/123"}}),
		Entry("Bad IPv4 Pool with good IPv6 Pool env var set",
			[]EnvItem{
				{"CALICO_IPV4POOL_CIDR", "172.16.0.0a/24"},
				{"CALICO_IPV6POOL_CIDR", "fdff:ffff:ffff:ffff:ffff::/80"},
			}),
		Entry("Invalid Env Var combo",
			[]EnvItem{
				{"NO_DEFAULT_POOLS", "true"},
				{"CALICO_IPV4POOL_CIDR", "172.16.0.0/24"},
			}),
		Entry("Bad IPv4 Pool IPIP Mode", []EnvItem{{"CALICO_IPV4POOL_IPIP", "badVal"}}),
		Entry("v6 Address in IPv4 Pool CIDR",
			[]EnvItem{{"CALICO_IPV4POOL_CIDR", "fdff:ffff:ffff:ffff:ffff::/80"}}),
		Entry("v4 Address in IPv6 Pool CIDR",
			[]EnvItem{{"CALICO_IPV6POOL_CIDR", "172.16.0.0/24"}}),
		Entry("bad IPv4 node selector",
			[]EnvItem{{"CALICO_IPV4POOL_NODE_SELECTOR", "all(nothing)"}}),
		Entry("bad IPv6 node selector",
			[]EnvItem{{"CALICO_IPV6POOL_NODE_SELECTOR", "all(nothing)"}}),
		Entry("CALICO_IPV4POOL_BLOCK_SIZE set too small (19)", []EnvItem{{"CALICO_IPV4POOL_BLOCK_SIZE", "19"}}),
		Entry("CALICO_IPV4POOL_BLOCK_SIZE set too large (33)", []EnvItem{{"CALICO_IPV4POOL_BLOCK_SIZE", "33"}}),
		Entry("CALICO_IPV6POOL_BLOCK_SIZE set too small (115)", []EnvItem{{"CALICO_IPV6POOL_BLOCK_SIZE", "115"}}),
		Entry("CALICO_IPV6POOL_BLOCK_SIZE set too large (129)", []EnvItem{{"CALICO_IPV6POOL_BLOCK_SIZE", "129"}}),
	)

	Describe("Test we properly wait for the etcd datastore", func() {
		// Create a new client.
		cfg, err := apiconfig.LoadClientConfigFromEnvironment()
		It("should be able to load Calico client from ENV", func() {
			Expect(err).NotTo(HaveOccurred())
		})

		c, err := client.New(*cfg)
		It("should be able to create a new Calico client", func() {
			Expect(err).NotTo(HaveOccurred())
		})

		be, err := backend.NewClient(*cfg)
		It("should be able to create a new backend client", func() {
			Expect(err).NotTo(HaveOccurred())
		})

		err = be.Clean()
		It("should be able to clear the datastore", func() {
			Expect(err).NotTo(HaveOccurred())
		})

		// Wait for a connection.
		done := make(chan bool)
		go func() {
			// Wait for a connection.
			waitForConnection(ctx, c)

			// Once connected, indicate that we connected on the channel.
			done <- true
		}()

		// Wait for a done signal to indicate that we've connected to the datastore.
		// If we don't receive one in 5 seconds, then fail.
		count := 0
		for {
			select {
			case <-done:
				// Finished.  Success!
				return
			default:
				count++
				time.Sleep(1 * time.Second)
				if count > 5 {
					log.Fatal("Timed out waiting for datastore after 5 seconds")
				}
			}
		}
	})

	Describe("Test CLUSTER_TYPE env variable", func() {
		It("should support an empty env var", func() {
			// Create a new client.
			cfg, err := apiconfig.LoadClientConfigFromEnvironment()
			By("load Calico client from ENV", func() {
				Expect(err).NotTo(HaveOccurred())
			})

			c, err := client.New(*cfg)
			By("create a new Calico client", func() {
				Expect(err).NotTo(HaveOccurred())
			})

			be, err := backend.NewClient(*cfg)
			By("create a new backend client", func() {
				Expect(err).NotTo(HaveOccurred())
			})

			err = be.Clean()
			By("clear the datastore", func() {
				Expect(err).NotTo(HaveOccurred())
			})

			nodeName := utils.DetermineNodeName()
			node := getNode(ctx, c, nodeName)

			err = ensureDefaultConfig(ctx, cfg, c, node, OSTypeLinux, nil, nil)
			By("ensureDefaultConfig", func() {
				Expect(err).NotTo(HaveOccurred())
			})

			clusterInfo, err := c.ClusterInformation().Get(ctx, "default", options.GetOptions{})
			By("access the ClusterType", func() {
				Expect(err).NotTo(HaveOccurred())
			})

			By("being empty", func() {
				Expect(clusterInfo.Spec.ClusterType).To(Equal(""))
			})
		})

		It("should respect the env var", func() {
			// Create a new client.
			cfg, err := apiconfig.LoadClientConfigFromEnvironment()
			By("should be able to load Calico client from ENV", func() {
				Expect(err).NotTo(HaveOccurred())
			})

			c, err := client.New(*cfg)
			By("should be able to create a new Calico client", func() {
				Expect(err).NotTo(HaveOccurred())
			})

			be, err := backend.NewClient(*cfg)
			By("should be able to create a new backend client", func() {
				Expect(err).NotTo(HaveOccurred())
			})

			err = be.Clean()
			By("should be able to clear the datastore", func() {
				Expect(err).NotTo(HaveOccurred())
			})

			nodeName := utils.DetermineNodeName()
			node := getNode(ctx, c, nodeName)

			os.Setenv("CLUSTER_TYPE", "theType")

			localRancherState := &v1.ConfigMap{Data: map[string]string{"foo": "bar"}}
			err = ensureDefaultConfig(ctx, cfg, c, node, OSTypeWindows, kubeadmConfig, localRancherState)
			By("should be able to ensureDefaultConfig", func() {
				Expect(err).NotTo(HaveOccurred())
			})

			clusterInfo, err := c.ClusterInformation().Get(ctx, "default", options.GetOptions{})
			By("should be able to access the ClusterType", func() {
				Expect(err).NotTo(HaveOccurred())
			})

			By("should have the set value", func() {
				Expect(clusterInfo.Spec.ClusterType).To(Equal("theType,kubeadm,rancher,win"))
			})
		})

		It("should merge existing cluster type with the env var", func() {
			// Create a new client.
			cfg, err := apiconfig.LoadClientConfigFromEnvironment()
			By("load Calico client from ENV", func() {
				Expect(err).NotTo(HaveOccurred())
			})

			c, err := client.New(*cfg)
			By("create a new Calico client", func() {
				Expect(err).NotTo(HaveOccurred())
			})

			be, err := backend.NewClient(*cfg)
			By("create a new backend client", func() {
				Expect(err).NotTo(HaveOccurred())
			})

			err = be.Clean()
			By("clear the datastore", func() {
				Expect(err).NotTo(HaveOccurred())
			})

			nodeName := utils.DetermineNodeName()
			node := getNode(ctx, c, nodeName)

			clusterInfo := api.NewClusterInformation()
			clusterInfo.Name = "default"
			clusterInfo.Spec.ClusterType = "prePopulated"

			_, err = c.ClusterInformation().Create(ctx, clusterInfo, options.SetOptions{})
			Expect(err).ToNot(HaveOccurred())
			os.Setenv("CLUSTER_TYPE", "theType")

			err = ensureDefaultConfig(ctx, cfg, c, node, OSTypeLinux, kubeadmConfig, rancherState)
			By("ensureDefaultConfig", func() {
				Expect(err).NotTo(HaveOccurred())
			})

			clusterInfo, err = c.ClusterInformation().Get(ctx, "default", options.GetOptions{})
			By("access the ClusterType", func() {
				Expect(err).NotTo(HaveOccurred())
			})

			By("have the set value", func() {
				Expect(clusterInfo.Spec.ClusterType).To(ContainSubstring("theType"))
			})
			By("have the prepopulated value", func() {
				Expect(clusterInfo.Spec.ClusterType).To(ContainSubstring("prePopulated"))
			})
		})

		It("should append clusterType 'kdd' in KDD mode, with env var also set", func() {
			// Create Calico client with k8s backend.
			cfg, err := apiconfig.LoadClientConfigFromEnvironment()
			Expect(err).NotTo(HaveOccurred())
			cfg.Spec.DatastoreType = apiconfig.Kubernetes

			c, err := client.New(*cfg)
			By("create a new Calico client", func() {
				Expect(err).NotTo(HaveOccurred())
			})

			be, err := backend.NewClient(*cfg)
			By("create a new backend client", func() {
				Expect(err).NotTo(HaveOccurred())
			})

			err = be.Clean()
			By("clear the datastore", func() {
				Expect(err).NotTo(HaveOccurred())
			})

			nodeName := utils.DetermineNodeName()
			node := getNode(ctx, c, nodeName)

			clusterInfo := api.NewClusterInformation()
			clusterInfo.Name = "default"
			clusterInfo.Spec.ClusterType = "prePopulated"

			_, err = c.ClusterInformation().Create(ctx, clusterInfo, options.SetOptions{})
			Expect(err).ToNot(HaveOccurred())
			os.Setenv("CLUSTER_TYPE", "theType")

			err = ensureDefaultConfig(ctx, cfg, c, node, OSTypeLinux, kubeadmConfig, rancherState)
			By("ensureDefaultConfig", func() {
				Expect(err).NotTo(HaveOccurred())
			})

			clusterInfo, err = c.ClusterInformation().Get(ctx, "default", options.GetOptions{})
			By("access the ClusterType", func() {
				Expect(err).NotTo(HaveOccurred())
			})

			By("should have the set value", func() {
				Expect(clusterInfo.Spec.ClusterType).To(ContainSubstring("theType"))
			})
			By("should have the prepopulated value", func() {
				Expect(clusterInfo.Spec.ClusterType).To(ContainSubstring("prePopulated"))
			})
			By("should have 'kdd' appended at the end", func() {
				Expect(strings.HasSuffix(clusterInfo.Spec.ClusterType, ",kdd")).To(BeTrue())
			})
		})

		It("should set clusterType to 'kdd', with no env var", func() {
			// Create Calico client with k8s backend.
			cfg, err := apiconfig.LoadClientConfigFromEnvironment()
			Expect(err).NotTo(HaveOccurred())
			cfg.Spec.DatastoreType = apiconfig.Kubernetes

			c, err := client.New(*cfg)
			By("create a new Calico client", func() {
				Expect(err).NotTo(HaveOccurred())
			})

			be, err := backend.NewClient(*cfg)
			By("create a new backend client", func() {
				Expect(err).NotTo(HaveOccurred())
			})

			err = be.Clean()
			By("clear the datastore", func() {
				Expect(err).NotTo(HaveOccurred())
			})

			nodeName := utils.DetermineNodeName()
			node := getNode(ctx, c, nodeName)

			clusterInfo := api.NewClusterInformation()
			clusterInfo.Name = "default"

			_, err = c.ClusterInformation().Create(ctx, clusterInfo, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())
			os.Setenv("CLUSTER_TYPE", "")

			err = ensureDefaultConfig(ctx, cfg, c, node, OSTypeLinux, kubeadmConfig, rancherState)
			By("ensureDefaultConfig", func() {
				Expect(err).NotTo(HaveOccurred())
			})

			clusterInfo, err = c.ClusterInformation().Get(ctx, "default", options.GetOptions{})
			By("access the ClusterType", func() {
				Expect(err).NotTo(HaveOccurred())
			})

			By("having 'kdd' set", func() {
				Expect(clusterInfo.Spec.ClusterType).Should(Equal("kubeadm,kdd"))
			})
		})

		It("should handle same value in env var and cluster info", func() {
			// Create a new client.
			cfg, err := apiconfig.LoadClientConfigFromEnvironment()
			By("load Calico client from ENV", func() {
				Expect(err).NotTo(HaveOccurred())
			})

			c, err := client.New(*cfg)
			By("create a new Calico client", func() {
				Expect(err).NotTo(HaveOccurred())
			})

			be, err := backend.NewClient(*cfg)
			By("create a new backend client", func() {
				Expect(err).NotTo(HaveOccurred())
			})

			err = be.Clean()
			By("clear the datastore", func() {
				Expect(err).NotTo(HaveOccurred())
			})

			nodeName := utils.DetermineNodeName()
			node := getNode(ctx, c, nodeName)

			clusterInfo := api.NewClusterInformation()
			clusterInfo.Name = "default"
			clusterInfo.Spec.ClusterType = "type1,type2"

			_, err = c.ClusterInformation().Create(ctx, clusterInfo, options.SetOptions{})
			Expect(err).ToNot(HaveOccurred())
			os.Setenv("CLUSTER_TYPE", "type1,type1")

			err = ensureDefaultConfig(ctx, cfg, c, node, OSTypeLinux, kubeadmConfig, rancherState)
			By("ensureDefaultConfig", func() {
				Expect(err).NotTo(HaveOccurred())
			})

			clusterInfo, err = c.ClusterInformation().Get(ctx, "default", options.GetOptions{})
			By("access the ClusterType", func() {
				Expect(err).NotTo(HaveOccurred())
			})

			By("having instance of the expected value", func() {
				Expect(strings.Count(clusterInfo.Spec.ClusterType, "type1")).To(Equal(1), "Should only have one instance of type1, read '%s", clusterInfo.Spec.ClusterType)
			})
			By("having instance of the expected value", func() {
				Expect(strings.Count(clusterInfo.Spec.ClusterType, "type2")).To(Equal(1), "Should only have one instance of type1, read '%s", clusterInfo.Spec.ClusterType)
			})
		})

		Describe("Test OrchRef configuration", func() {
			DescribeTable("Should configure the OrchRef with the proper env var set", func(envs []EnvItem, expected libapi.OrchRef, isEqual bool) {
				node := &libapi.Node{}

				for _, env := range envs {
					os.Setenv(env.key, env.value)
				}

				configureNodeRef(node)
				// If we receive an invalid env var then none will be set.
				if len(node.Spec.OrchRefs) > 0 {
					ref := node.Spec.OrchRefs[0]
					Expect(ref == expected).To(Equal(isEqual))
				} else {
					Fail("OrchRefs slice was empty, expected at least one")
				}
			},

				Entry("valid single k8s env var", []EnvItem{{"CALICO_K8S_NODE_REF", "node1"}}, libapi.OrchRef{"node1", "k8s"}, true), // nolint: vet
			)

			It("Should not configure any OrchRefs when no valid env vars are passed", func() {
				os.Setenv("CALICO_UNKNOWN_NODE_REF", "node1")

				node := &libapi.Node{}
				configureNodeRef(node)

				Expect(node.Spec.OrchRefs).To(HaveLen(0))
			})
			It("Should not set an OrchRef if it is already set", func() {
				os.Setenv("CALICO_K8S_NODE_REF", "node1")

				node := &libapi.Node{}
				node.Spec.OrchRefs = append(node.Spec.OrchRefs, libapi.OrchRef{"node1", "k8s"}) // nolint: vet
				configureNodeRef(node)

				Expect(node.Spec.OrchRefs).To(HaveLen(1))
			})
		})
	})
})

var _ = Describe("UT for Node IP assignment and conflict checking.", func() {
	DescribeTable("Test variations on how IPs are detected.",
		func(node *libapi.Node, items []EnvItem, expected bool) {
			for _, item := range items {
				os.Setenv(item.key, item.value)
			}

			mockGetInterface := func([]string, []string, int) ([]autodetection.Interface, error) {
				return []autodetection.Interface{}, nil
			}

			check, err := configureIPsAndSubnets(node, &v1.Node{}, mockGetInterface)

			Expect(check).To(Equal(expected))
			Expect(err).NotTo(HaveOccurred())
		},

		Entry("Test with no \"IP\" env var set", &libapi.Node{}, []EnvItem{{"IP", ""}}, true),
		Entry("Test with \"IP\" env var set to IP", &libapi.Node{}, []EnvItem{{"IP", "192.168.1.10/24"}}, true),
		Entry("Test with \"IP\" env var set to IP and BGP spec populated with same IP", makeNode("192.168.1.10/24", ""), []EnvItem{{"IP", "192.168.1.10/24"}}, false),
		Entry("Test with \"IP\" env var set to IP and BGP spec populated with different IP", makeNode("192.168.1.10/24", ""), []EnvItem{{"IP", "192.168.1.11/24"}}, true),
		Entry("Test with no \"IP6\" env var set", &libapi.Node{}, []EnvItem{{"IP6", ""}}, true),
		Entry("Test with \"IP6\" env var set to IP", &libapi.Node{}, []EnvItem{{"IP6", "2001:db8:85a3:8d3:1319:8a2e:370:7348/32"}}, true),
		Entry("Test with \"IP6\" env var set to IP and BGP spec populated with same IP", makeNode("192.168.1.10/24", "2001:db8:85a3:8d3:1319:8a2e:370:7348/32"), []EnvItem{{"IP", "192.168.1.10/24"}, {"IP6", "2001:db8:85a3:8d3:1319:8a2e:370:7348/32"}}, false),
		Entry("Test with \"IP6\" env var set to IP and BGP spec populated with different IP", makeNode("192.168.1.10/24", "2001:db8:85a3:8d3:1319:8a2e:370:7348/32"), []EnvItem{{"IP", "192.168.1.10/24"}, {"IP6", "2001:db8:85a3:8d3:1319:8a2e:370:7349/32"}}, true),
	)
})

var _ = Describe("UT for autodetection method k8s-internal-ip", func() {
	DescribeTable("Test variations on k8s-internal-ip",
		func(node *libapi.Node, k8sNode *v1.Node, items []EnvItem, expected bool) {
			for _, item := range items {
				os.Setenv(item.key, item.value)
			}

			mockGetInterface := func([]string, []string, int) ([]autodetection.Interface, error) {
				return []autodetection.Interface{
					{Name: "eth1", Cidrs: []net.IPNet{net.MustParseCIDR("192.168.1.10/24"), net.MustParseCIDR("2001:db8:85a3:8d3:1319:8a2e:370:7348/128")}},
				}, nil
			}

			check, _ := configureIPsAndSubnets(node, k8sNode, mockGetInterface)

			Expect(check).To(Equal(expected))

			os.Unsetenv("IP")
			os.Unsetenv("IP_AUTODETECTION_METHOD")
		},

		Entry("Test with \"IP\" env = autodetect ,IP_AUTODETECTION_METHOD = k8s-internal-ip. k8snode = nil", &libapi.Node{}, nil, []EnvItem{{"IP", "autodetect"}, {"IP_AUTODETECTION_METHOD", "kubernetes-internal-ip"}}, false),
		Entry("Test with \"IP\" env = autodetect ,IP_AUTODETECTION_METHOD = k8s-internal-ip. k8snode = valid addr", &libapi.Node{}, makeK8sNode("192.168.1.10", "2001:db8:85a3:8d3:1319:8a2e:370:7348"), []EnvItem{{"IP", "autodetect"}, {"IP_AUTODETECTION_METHOD", "kubernetes-internal-ip"}}, true),
		Entry("Test with \"IP\" env = autodetect ,IP_AUTODETECTION_METHOD = k8s-internal-ip. k8snode = addr mismatch", &libapi.Node{}, makeK8sNode("192.168.1.1", "2001:db8:85a3:8d3:1319:8a2e:370:7349"), []EnvItem{{"IP", "autodetect"}, {"IP_AUTODETECTION_METHOD", "kubernetes-internal-ip"}}, false),
	)
})

var _ = Describe("UT for CIDR returned by IP address autodetection k8s-internal-ip method", func() {
	It("Verify that CIDR value returned using autodetection method k8s-internal-ip is not masked", func() {
		expectedV4Cidr := "192.168.1.10/24"
		expectedV6Cidr := "2001:db8:85a3:8d3:1319:8a2e:370:7348/64"
		mockGetInterface := func([]string, []string, int) ([]autodetection.Interface, error) {
			return []autodetection.Interface{
				{Name: "eth1", Cidrs: []net.IPNet{net.MustParseCIDR(expectedV4Cidr), net.MustParseCIDR("2001:db8:85a3:8d3:1319:8a2e:370:7348/64")}},
			}, nil
		}

		k8sNode := makeK8sNode("192.168.1.10", "2001:db8:85a3:8d3:1319:8a2e:370:7348")

		checkV4IPNet := autodetection.AutoDetectCIDR(autodetection.K8S_INTERNAL_IP, 4, k8sNode, mockGetInterface)
		checkV6IPNet := autodetection.AutoDetectCIDR(autodetection.K8S_INTERNAL_IP, 6, k8sNode, mockGetInterface)

		Expect(checkV4IPNet.String()).To(Equal(expectedV4Cidr))
		Expect(checkV6IPNet.String()).To(Equal(expectedV6Cidr))
	})
})

var _ = Describe("FV tests against K8s API server.", func() {
	It("should not throw an error when multiple Nodes configure the same global CRD value.", func() {
		ctx := context.Background()

		// How many Nodes we want to "create".
		numNodes := 10

		// Create a K8s client.
		kubeconfigPath := os.Getenv("KUBECONFIG")
		kcfg, err := clientcmd.BuildConfigFromFlags("", kubeconfigPath)
		if err != nil {
			Fail(fmt.Sprintf("Failed to create K8s config: %v", err))
		}
		cs, err := kubernetes.NewForConfig(kcfg)
		if err != nil {
			Fail(fmt.Sprintf("Could not create K8s client: %v", err))
		}

		// Create Calico client with k8s backend.
		cfg, err := apiconfig.LoadClientConfigFromEnvironment()
		Expect(err).NotTo(HaveOccurred())
		cfg.Spec.DatastoreType = apiconfig.Kubernetes

		c, err := client.New(*cfg)
		Expect(err).NotTo(HaveOccurred())

		// Create some Nodes using K8s client, Calico client does not support Node creation for KDD.
		for i := 0; i < numNodes; i++ {
			n := &v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: fmt.Sprintf("racenode%02d", i+1),
				},
			}
			_, err = cs.CoreV1().Nodes().Create(ctx, n, metav1.CreateOptions{})
			Expect(err).ToNot(HaveOccurred())
		}

		// Pull above Nodes using Calico client.
		nodes, err := c.Nodes().List(ctx, options.ListOptions{})
		if err != nil {
			Fail(fmt.Sprintf("Could not retrieve Nodes %v", err))
		}

		// Run ensureDefaultConfig against each of the Nodes using goroutines to simulate multiple Nodes coming online.
		var wg sync.WaitGroup
		errors := []error{}
		for _, node := range nodes.Items {
			wg.Add(1)
			go func(n libapi.Node) {
				defer wg.Done()
				err = ensureDefaultConfig(ctx, cfg, c, &n, OSTypeLinux, kubeadmConfig, rancherState)
				if err != nil {
					errors = append(errors, err)
				}
			}(node)
		}

		wg.Wait()

		// Verify all runs complete without error.
		Expect(len(errors)).To(Equal(0))

		// Clean up our Nodes.
		for _, node := range nodes.Items {
			err = cs.CoreV1().Nodes().Delete(ctx, node.Name, metav1.DeleteOptions{})
			Expect(err).ToNot(HaveOccurred())
		}
	})
})

var _ = Describe("UT for node name determination", func() {
	hn, _ := names.Hostname()
	DescribeTable("Test variations on how node names are detected.",
		func(nodenameEnv, hostnameEnv, expectedNodeName string) {
			if nodenameEnv != "" {
				os.Setenv("NODENAME", nodenameEnv)
			} else {
				os.Unsetenv("NODENAME")
			}
			if hostnameEnv != "" {
				os.Setenv("HOSTNAME", hostnameEnv)
			} else {
				os.Unsetenv("HOSTNAME")
			}
			nodeName := utils.DetermineNodeName()
			os.Unsetenv("NODENAME")
			os.Unsetenv("HOSTNAME")
			Expect(nodeName).To(Equal(expectedNodeName))
		},

		Entry("Valid NODENAME and valid HOSTNAME", "abc-def.ghi123", "foo1.bar2-baz3", "abc-def.ghi123"),
		Entry("Uppercase NODENAME and valid HOSTNAME (leaves uppercase)", "MyHostname-123", "valid.hostname", "MyHostname-123"),
		Entry("Whitespace NODENAME, valid HOSTNAME", "  ", "host123", "host123"),
		Entry("No NODENAME, uppercase HOSTNAME", "", "HOSTName", "hostname"),
		Entry("No NODENAME, no HOSTNAME", "", "", hn),
		Entry("Whitespace NODENAME and HOSTNAME", "  ", "  ", hn),
	)
})

var _ = Describe("UT for GenerateIPv6ULAPrefix", func() {
	It("should generate a different address each time", func() {
		seen := set.New[string]()
		for i := 0; i < 100; i++ {
			newAddr, err := GenerateIPv6ULAPrefix()
			Expect(err).NotTo(HaveOccurred())
			Expect(seen.Contains(newAddr)).To(BeFalse())
			seen.Add(newAddr)
		}
	})

	It("should generate a valid /48 CIDR", func() {
		cidrStr, err := GenerateIPv6ULAPrefix()
		Expect(err).NotTo(HaveOccurred())
		ip, ipNet, err := net.ParseCIDR(cidrStr)
		Expect(err).NotTo(HaveOccurred())
		Expect(ip.To4()).To(BeNil())
		Expect(ip.To16().String()).To(Equal(ip.String()))
		ones, bits := ipNet.Mask.Size()
		Expect(ones).To(Equal(48))
		Expect(bits).To(Equal(128))
		Expect([]byte(ip.IP)[0]).To(Equal(uint8(0xfd)))

		for _, b := range []byte(ip.IP)[1:] {
			if b != 0 {
				return
			}
		}
		Fail("random bits were all zeros")
	})
})

var _ = DescribeTable("UT for extractKubeadmCIDRs",
	func(cm *v1.ConfigMap, expectedIPv4 string, expectedIPv6 string, expectErr bool) {
		v4, v6, err := extractKubeadmCIDRs(cm)
		if expectErr {
			Expect(err).To(HaveOccurred())
		} else {
			Expect(err).ToNot(HaveOccurred())
		}
		Expect(v4).To(Equal(expectedIPv4))
		Expect(v6).To(Equal(expectedIPv6))
	},
	Entry("nil config map", nil, "", "", true),
	Entry("empty config map", &v1.ConfigMap{}, "", "", false),
	Entry("v4 only config map", &v1.ConfigMap{Data: map[string]string{"ClusterConfiguration": "podSubnet: 192.168.0.0/16"}}, "192.168.0.0/16", "", false),
	Entry("dual v4 config map", &v1.ConfigMap{Data: map[string]string{"ClusterConfiguration": "podSubnet: 192.168.0.0/16,10.10.0.0/16"}}, "192.168.0.0/16", "", false),
	Entry("v6 only config map", &v1.ConfigMap{Data: map[string]string{"ClusterConfiguration": "podSubnet: fdff:ffff:ffff:ffff:ffff::/80"}}, "", "fdff:ffff:ffff:ffff:ffff::/80", false),
	Entry("dual v6 config map", &v1.ConfigMap{Data: map[string]string{"ClusterConfiguration": "podSubnet: fdff:ffff:ffff:ffff:ffff::/80,fdff:ffff:ffff:ffff:ffff::/80"}}, "", "fdff:ffff:ffff:ffff:ffff::/80", false),
	Entry("dual-stack config map", &v1.ConfigMap{Data: map[string]string{"ClusterConfiguration": "podSubnet: 192.168.0.0/16,fdff:ffff:ffff:ffff:ffff::/80"}}, "192.168.0.0/16", "fdff:ffff:ffff:ffff:ffff::/80", false),

	Entry("full config map", &v1.ConfigMap{Data: map[string]string{
		`ClusterConfiguration`: `    apiServerCertSANs:
    - 35.223.231.224
    - 127.0.0.1
    apiServerExtraArgs:
      audit-log-path: /var/log/calico/audit/kube-audit.log
      audit-policy-file: /etc/kubernetes/pki/audit-policy.yaml
      authorization-mode: Node,RBAC
      basic-auth-file: /etc/kubernetes/pki/basic_auth.csv
    apiServerExtraVolumes:
    - hostPath: /var/log/calico/audit/
      mountPath: /var/log/calico/audit/
      name: calico-audit
      pathType: DirectoryOrCreate
      writable: true
    apiVersion: kubeadm.k8s.io/v1alpha3
    auditPolicy:
      logDir: /var/log/kubernetes/audit
      logMaxAge: 2
      path: ""
    certificatesDir: /etc/kubernetes/pki
    clusterName: kubernetes
    controlPlaneEndpoint: ""
    etcd:
      local:
        dataDir: /var/lib/etcd
        image: ""
    imageRepository: k8s.gcr.io
    kind: ClusterConfiguration
    kubernetesVersion: v1.12.7
    networking:
      dnsDomain: cluster.local
      podSubnet: 192.168.0.0/16
      serviceSubnet: 10.96.0.0/12
    unifiedControlPlaneImage: ""
  ClusterStatus: |
    apiEndpoints:
      rafael-cluster-1-kadm-ms:
        advertiseAddress: 10.128.0.73
        bindPort: 6443
    apiVersion: kubeadm.k8s.io/v1alpha3
    kind: ClusterStatus`,
	}}, "192.168.0.0/16", "", false),
)

var _ = Describe("UTs for monitor-addresses option", func() {
	It("poll-interval handles invalid values", func() {
		os.Setenv("AUTODETECT_POLL_INTERVAL", "foobar")
		Expect(getMonitorPollInterval()).To(Equal(DEFAULT_MONITOR_IP_POLL_INTERVAL))
	})
	It("poll-interval handles valid values", func() {
		os.Setenv("AUTODETECT_POLL_INTERVAL", "30m")
		Expect(getMonitorPollInterval()).To(Equal(30 * time.Minute))
	})
})

var _ = Describe("UT for IP and IP6", func() {
	DescribeTable("env IP is defined", func(ipv4Env string, version int, exceptValue string) {
		ipv4MockInterfaces := func([]string, []string, int) ([]autodetection.Interface, error) {
			return []autodetection.Interface{
				{Name: "eth1", Cidrs: []net.IPNet{net.MustParseCIDR("1.2.3.4/24")}},
			}, nil
		}
		ipv4CIDROrIP, _ := autodetection.GetLocalCIDR(ipv4Env, version, ipv4MockInterfaces)
		Expect(ipv4CIDROrIP).To(Equal(exceptValue))
	},
		Entry("get the local cidr", "1.2.3.4", 4, "1.2.3.4/24"),
		Entry("get the original cidr", "4.3.2.1/25", 4, "4.3.2.1/25"),
		Entry("get the original ip(v4)", "1.2.3.5", 4, "1.2.3.5"),
	)

	_ = DescribeTable("env IP6 is defined", func(ipv6Env string, version int, exceptValue string) {
		ipv6MockInterfaces := func([]string, []string, int) ([]autodetection.Interface, error) {
			return []autodetection.Interface{
				{Name: "eth1", Cidrs: []net.IPNet{net.MustParseCIDR("1:2:3:4::5/120")}},
			}, nil
		}
		ipv4CIDROrIP, _ := autodetection.GetLocalCIDR(ipv6Env, version, ipv6MockInterfaces)
		Expect(ipv4CIDROrIP).To(Equal(exceptValue))
	},
		Entry("get the local cidr", "1:2:3:4::5", 6, "1:2:3:4::5/120"),
		Entry("get the original cidr", "5:4:3:2::1/64", 6, "5:4:3:2::1/64"),
		Entry("get the original ip(v6)", "1:2:3:4::1111", 6, "1:2:3:4::1111"),
	)
})
