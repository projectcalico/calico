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
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	"github.com/projectcalico/calico/libcalico-go/lib/set"

	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	libapi "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/backend"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/names"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
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
		_ = configureAndCheckIPAddressSubnets(context.Background(), c, &node)
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

var _ = Describe("Non-etcd related tests", func() {

	Describe("Termination tests", func() {
		exitCode = 0
		Context("Test termination", func() {
			oldExit := utils.GetExitFunction()
			utils.SetExitFunction(fakeExitFunction)
			defer utils.SetExitFunction(oldExit)
			utils.Terminate()
			It("should have terminated", func() {
				Expect(exitCode).To(Equal(1))
			})
		})
	})
})

type EnvItem struct {
	key   string
	value string
}

const (
	randomULAPool = "<random ULA pool>"
)

var kubeadmConfig *v1.ConfigMap = &v1.ConfigMap{Data: map[string]string{"ClusterConfiguration": "podSubnet: 192.168.0.0/16"}}
var rancherState *v1.ConfigMap = nil

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
		func(envList []EnvItem, expectedIPv4 string, expectedIPv6 string, expectIpv4IpipMode string, expectedIPV4NATOutgoing bool, expectedIPV6NATOutgoing bool, expectedIPv4BlockSize, expectedIPv6BlockSize int, expectedIPv4NodeSelector, expectedIPv6NodeSelector string) {
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
			poolList, err := c.IPPools().List(ctx, options.ListOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(poolList.Items).To(BeEmpty())

			// Run the UUT.
			configureIPPools(ctx, c, kubeadmConfig)

			// Get the IPPool list.
			poolList, err = c.IPPools().List(ctx, options.ListOptions{})
			Expect(err).NotTo(HaveOccurred())
			log.Println("Get pool list returns: ", poolList.Items)

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

					Expect(pool.Spec.NATOutgoing).To(Equal(expectedIPV6NATOutgoing), "Expected IPv6 to be %t but was %t", expectedIPV6NATOutgoing, pool.Spec.NATOutgoing)

					Expect(pool.Spec.BlockSize).To(Equal(expectedIPv6BlockSize), "Expected IPv6 blocksize to be %d but was %d", expectedIPv6BlockSize, pool.Spec.BlockSize)

					Expect(pool.Spec.NodeSelector).To(Equal(expectedIPv6NodeSelector),
						"Expected IPv4 selector %s to be %s", pool.Spec.NodeSelector, expectedIPv6NodeSelector)
				} else {
					// off is not a real mode value but use it instead of empty string
					if expectIpv4IpipMode == "Off" {
						Expect(pool.Spec.IPIPMode).To(Equal(api.IPIPModeNever))
					} else {
						Expect(pool.Spec.IPIPMode).To(Equal(api.IPIPMode(expectIpv4IpipMode)))
					}

					Expect(pool.Spec.NATOutgoing).To(Equal(expectedIPV4NATOutgoing), "Expected IPv4 to be %t but was %t", expectedIPV4NATOutgoing, pool.Spec.NATOutgoing)

					Expect(pool.Spec.BlockSize).To(Equal(expectedIPv4BlockSize), "Expected IPv4 blocksize to be %d but was %d", expectedIPv4BlockSize, pool.Spec.BlockSize)

					Expect(pool.Spec.NodeSelector).To(Equal(expectedIPv4NodeSelector),
						"Expected IPv4 selector %s to be %s", pool.Spec.NodeSelector, expectedIPv4NodeSelector)
				}
			}
			Expect(foundv4Expected).To(BeTrue(),
				"Expected %s to be in Pools", expectedIPv4)
			Expect(foundv6Expected).To(BeTrue(),
				"Expected %s to be in Pools", expectedIPv6)
		},

		Entry("No env variables set", []EnvItem{},
			"192.168.0.0/16", randomULAPool, "Off", true, false, 26, 122, "all()", "all()"),
		Entry("IPv4 Pool env var set",
			[]EnvItem{{"CALICO_IPV4POOL_CIDR", "172.16.0.0/24"}},
			"172.16.0.0/24", randomULAPool, "Off", true, false, 26, 122, "all()", "all()"),
		Entry("IPv6 Pool env var set",
			[]EnvItem{{"CALICO_IPV6POOL_CIDR", "fdff:ffff:ffff:ffff:ffff::/80"}},
			"192.168.0.0/16", "fdff:ffff:ffff:ffff:ffff::/80", "Off", true, false, 26, 122, "all()", "all()"),
		Entry("Both IPv4 and IPv6 Pool env var set",
			[]EnvItem{
				{"CALICO_IPV4POOL_CIDR", "172.16.0.0/24"},
				{"CALICO_IPV6POOL_CIDR", "fdff:ffff:ffff:ffff:ffff::/80"},
			},
			"172.16.0.0/24", "fdff:ffff:ffff:ffff:ffff::/80", "Off", true, false, 26, 122, "all()", "all()"),
		Entry("CALICO_IPV4POOL_IPIP set off", []EnvItem{{"CALICO_IPV4POOL_IPIP", "off"}},
			"192.168.0.0/16", randomULAPool, "Off", true, false, 26, 122, "all()", "all()"),
		Entry("CALICO_IPV4POOL_IPIP set Off", []EnvItem{{"CALICO_IPV4POOL_IPIP", "Off"}},
			"192.168.0.0/16", randomULAPool, "Off", true, false, 26, 122, "all()", "all()"),
		Entry("CALICO_IPV4POOL_IPIP set Never", []EnvItem{{"CALICO_IPV4POOL_IPIP", "Never"}},
			"192.168.0.0/16", randomULAPool, "Never", true, false, 26, 122, "all()", "all()"),
		Entry("CALICO_IPV4POOL_IPIP set empty string", []EnvItem{{"CALICO_IPV4POOL_IPIP", ""}},
			"192.168.0.0/16", randomULAPool, "Off", true, false, 26, 122, "all()", "all()"),
		Entry("CALICO_IPV4POOL_IPIP set always", []EnvItem{{"CALICO_IPV4POOL_IPIP", "always"}},
			"192.168.0.0/16", randomULAPool, "Always", true, false, 26, 122, "all()", "all()"),
		Entry("CALICO_IPV4POOL_IPIP set Always", []EnvItem{{"CALICO_IPV4POOL_IPIP", "Always"}},
			"192.168.0.0/16", randomULAPool, "Always", true, false, 26, 122, "all()", "all()"),
		Entry("CALICO_IPV4POOL_IPIP set cross-subnet", []EnvItem{{"CALICO_IPV4POOL_IPIP", "cross-subnet"}},
			"192.168.0.0/16", randomULAPool, "CrossSubnet", true, false, 26, 122, "all()", "all()"),
		Entry("CALICO_IPV4POOL_IPIP set CrossSubnet", []EnvItem{{"CALICO_IPV4POOL_IPIP", "CrossSubnet"}},
			"192.168.0.0/16", randomULAPool, "CrossSubnet", true, false, 26, 122, "all()", "all()"),
		Entry("CALICO_IPV4POOL_BLOCK_SIZE set 27", []EnvItem{{"CALICO_IPV4POOL_BLOCK_SIZE", "27"}},
			"192.168.0.0/16", randomULAPool, "Off", true, false, 27, 122, "all()", "all()"),
		Entry("IPv6 Pool and IPIP set",
			[]EnvItem{
				{"CALICO_IPV6POOL_CIDR", "fdff:ffff:ffff:ffff:ffff::/80"},
				{"CALICO_IPV4POOL_IPIP", "always"},
			},
			"192.168.0.0/16", "fdff:ffff:ffff:ffff:ffff::/80", "Always", true, false, 26, 122, "all()", "all()"),
		Entry("IPv6 NATOutgoing Set Enabled",
			[]EnvItem{
				{"CALICO_IPV6POOL_NAT_OUTGOING", "true"}},
			"192.168.0.0/16", randomULAPool, "Off", true, true, 26, 122, "all()", "all()"),
		Entry("IPv6 NATOutgoing Set Disabled",
			[]EnvItem{
				{"CALICO_IPV6POOL_NAT_OUTGOING", "false"}},
			"192.168.0.0/16", randomULAPool, "Off", true, false, 26, 122, "all()", "all()"),
		Entry("IPv4 NATOutgoing Set Disabled",
			[]EnvItem{
				{"CALICO_IPV4POOL_NAT_OUTGOING", "false"}},
			"192.168.0.0/16", randomULAPool, "Off", false, false, 26, 122, "all()", "all()"),
		Entry("IPv6 NAT OUTGOING and IPV4 NAT OUTGOING SET",
			[]EnvItem{
				{"CALICO_IPV4POOL_NAT_OUTGOING", "false"},
				{"CALICO_IPV6POOL_NAT_OUTGOING", "true"},
			},
			"192.168.0.0/16", randomULAPool, "Off", false, true, 26, 122, "all()", "all()"),
		Entry("CALICO_IPV6POOL_BLOCK_SIZE set 123", []EnvItem{{"CALICO_IPV6POOL_BLOCK_SIZE", "123"}},
			"192.168.0.0/16", randomULAPool, "Off", true, false, 26, 123, "all()", "all()"),
		Entry("CALICO_IPV4POOL_NODE_SELECTOR set all()", []EnvItem{{"CALICO_IPV4POOL_NODE_SELECTOR", "all()"}},
			"192.168.0.0/16", randomULAPool, "Off", true, false, 26, 122, "all()", "all()"),
		Entry("CALICO_IPV4POOL_NODE_SELECTOR set has(something)", []EnvItem{{"CALICO_IPV4POOL_NODE_SELECTOR", "key == 'something'"}},
			"192.168.0.0/16", randomULAPool, "Off", true, false, 26, 122, "key == 'something'", "all()"),
		Entry("CALICO_IPV6POOL_NODE_SELECTOR set failed", []EnvItem{{"CALICO_IPV6POOL_NODE_SELECTOR", "has(something)"}},
			"192.168.0.0/16", randomULAPool, "Off", true, false, 26, 122, "all()", "has(something)"),
	)

	Describe("Test clearing of node IPs", func() {
		Context("clearing node IPs", func() {
			cfg, err := apiconfig.LoadClientConfigFromEnvironment()
			It("should be able to load Calico client from ENV", func() {
				Expect(err).NotTo(HaveOccurred())
			})

			c, err := client.New(*cfg)
			It("should be able to create a new Calico client", func() {
				Expect(err).NotTo(HaveOccurred())
			})

			node := makeNode("192.168.0.1/24", "fdff:ffff:ffff:ffff:ffff::/80")
			node.Name = "clearips.test.node"
			It("should create a Node with IPv4 and IPv6 addresses", func() {
				_, err = c.Nodes().Create(ctx, node, options.SetOptions{})
				Expect(err).NotTo(HaveOccurred())
			})

			var n *libapi.Node
			It("should get the Node", func() {
				n, err = c.Nodes().Get(ctx, node.Name, options.GetOptions{})
				Expect(err).NotTo(HaveOccurred())
				Expect(n).NotTo(BeNil())
				Expect(n.ResourceVersion).NotTo(Equal(""))
			})

			It("should clear the Node's IPv4 address", func() {
				clearNodeIPs(ctx, c, n, true, false)
				dn, err := c.Nodes().Get(ctx, node.Name, options.GetOptions{})
				Expect(err).NotTo(HaveOccurred())
				Expect(dn.Spec.BGP.IPv4Address).To(Equal(""))
				Expect(dn.Spec.BGP.IPv6Address).ToNot(Equal(""))
			})

			It("should get the Node", func() {
				n, err = c.Nodes().Get(ctx, node.Name, options.GetOptions{})
				Expect(err).NotTo(HaveOccurred())
				Expect(n).NotTo(BeNil())
				Expect(n.ResourceVersion).NotTo(Equal(""))
			})

			It("should clear the Node's IPv6 address", func() {
				clearNodeIPs(ctx, c, n, false, true)
				dn, err := c.Nodes().Get(ctx, node.Name, options.GetOptions{})
				Expect(err).NotTo(HaveOccurred())
				Expect(dn.Spec.BGP).To(BeNil())
			})
		})
	})

	Describe("Test NO_DEFAULT_POOLS env variable", func() {
		Context("Should have no pools defined", func() {
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

			// Set the env variables specified.
			os.Setenv("NO_DEFAULT_POOLS", "true")

			// Run the UUT.
			configureIPPools(ctx, c, kubeadmConfig)

			// Get the IPPool list.
			poolList, err := c.IPPools().List(ctx, options.ListOptions{})
			It("should be able to access the IP pool list", func() {
				Expect(err).NotTo(HaveOccurred())
			})
			log.Println("Get pool list returns: ", poolList.Items)

			It("should have no IP pools", func() {
				Expect(poolList.Items).To(BeEmpty(), "Environment %#v", os.Environ())
			})
		})
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
				log.Println("Connected to datastore")
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
		Context("With no env var, Cluster Type should be empty string", func() {
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

			nodeName := utils.DetermineNodeName()
			node := getNode(ctx, c, nodeName)

			err = ensureDefaultConfig(ctx, cfg, c, node, OSTypeLinux, nil, nil)
			It("should be able to ensureDefaultConfig", func() {
				Expect(err).NotTo(HaveOccurred())
			})

			clusterInfo, err := c.ClusterInformation().Get(ctx, "default", options.GetOptions{})
			It("should be able to access the ClusterType", func() {
				Expect(err).NotTo(HaveOccurred())
			})

			It("should be empty", func() {
				Expect(clusterInfo.Spec.ClusterType).To(Equal(""))
			})

		})
		Context("With env var set, Cluster Type should have that value", func() {
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

			nodeName := utils.DetermineNodeName()
			node := getNode(ctx, c, nodeName)

			os.Setenv("CLUSTER_TYPE", "theType")

			localRancherState := &v1.ConfigMap{Data: map[string]string{"foo": "bar"}}
			err = ensureDefaultConfig(ctx, cfg, c, node, OSTypeWindows, kubeadmConfig, localRancherState)
			It("should be able to ensureDefaultConfig", func() {
				Expect(err).NotTo(HaveOccurred())
			})

			clusterInfo, err := c.ClusterInformation().Get(ctx, "default", options.GetOptions{})
			It("should be able to access the ClusterType", func() {
				Expect(err).NotTo(HaveOccurred())
			})

			It("should have the set value", func() {
				Expect(clusterInfo.Spec.ClusterType).To(Equal("theType,kubeadm,rancher,win"))
			})
		})
		Context("With env var and Cluster Type prepopulated, Cluster Type should have both", func() {
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

			nodeName := utils.DetermineNodeName()
			node := getNode(ctx, c, nodeName)

			clusterInfo := api.NewClusterInformation()
			clusterInfo.Name = "default"
			clusterInfo.Spec.ClusterType = "prePopulated"

			_, err = c.ClusterInformation().Create(ctx, clusterInfo, options.SetOptions{})
			Expect(err).ToNot(HaveOccurred())
			os.Setenv("CLUSTER_TYPE", "theType")

			err = ensureDefaultConfig(ctx, cfg, c, node, OSTypeLinux, kubeadmConfig, rancherState)
			It("should be able to ensureDefaultConfig", func() {
				Expect(err).NotTo(HaveOccurred())
			})

			clusterInfo, err = c.ClusterInformation().Get(ctx, "default", options.GetOptions{})
			It("should be able to access the ClusterType", func() {
				Expect(err).NotTo(HaveOccurred())
			})

			It("should have the set value", func() {
				Expect(clusterInfo.Spec.ClusterType).To(ContainSubstring("theType"))
			})
			It("should have the prepopulated value", func() {
				Expect(clusterInfo.Spec.ClusterType).To(ContainSubstring("prePopulated"))
			})
		})

		Context("for KDD backend, with env var and Cluster Type prepopulated, Cluster Type should have 'kdd' appended", func() {
			// Create Calico client with k8s backend.
			cfg, err := apiconfig.LoadClientConfigFromEnvironment()
			It("should be able to load Calico client from ENV", func() {
				Expect(err).NotTo(HaveOccurred())
			})

			cfg.Spec = apiconfig.CalicoAPIConfigSpec{
				DatastoreType: apiconfig.Kubernetes,
				KubeConfig: apiconfig.KubeConfig{
					K8sAPIEndpoint:           "http://127.0.0.1:8080",
					K8sInsecureSkipTLSVerify: true,
				},
			}

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

			nodeName := utils.DetermineNodeName()
			node := getNode(ctx, c, nodeName)

			clusterInfo := api.NewClusterInformation()
			clusterInfo.Name = "default"
			clusterInfo.Spec.ClusterType = "prePopulated"

			_, err = c.ClusterInformation().Create(ctx, clusterInfo, options.SetOptions{})
			Expect(err).ToNot(HaveOccurred())
			os.Setenv("CLUSTER_TYPE", "theType")

			err = ensureDefaultConfig(ctx, cfg, c, node, OSTypeLinux, kubeadmConfig, rancherState)
			It("should be able to ensureDefaultConfig", func() {
				Expect(err).NotTo(HaveOccurred())
			})

			clusterInfo, err = c.ClusterInformation().Get(ctx, "default", options.GetOptions{})
			It("should be able to access the ClusterType", func() {
				Expect(err).NotTo(HaveOccurred())
			})

			It("should have the set value", func() {
				Expect(clusterInfo.Spec.ClusterType).To(ContainSubstring("theType"))
			})
			It("should have the prepopulated value", func() {
				Expect(clusterInfo.Spec.ClusterType).To(ContainSubstring("prePopulated"))
			})
			It("should have 'kdd' appended at the end", func() {
				Expect(strings.HasSuffix(clusterInfo.Spec.ClusterType, ",kdd")).To(BeTrue())
			})
		})

		Context("for KDD backend, with no env var and Cluster Type not prepopulated, Cluster Type should only have 'kdd'", func() {
			// Create Calico client with k8s backend.
			cfg, err := apiconfig.LoadClientConfigFromEnvironment()
			It("should be able to load Calico client from ENV", func() {
				Expect(err).NotTo(HaveOccurred())
			})

			cfg.Spec = apiconfig.CalicoAPIConfigSpec{
				DatastoreType: apiconfig.Kubernetes,
				KubeConfig: apiconfig.KubeConfig{
					K8sAPIEndpoint:           "http://127.0.0.1:8080",
					K8sInsecureSkipTLSVerify: true,
				},
			}

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

			nodeName := utils.DetermineNodeName()
			node := getNode(ctx, c, nodeName)

			clusterInfo := api.NewClusterInformation()
			clusterInfo.Name = "default"

			_, err = c.ClusterInformation().Create(ctx, clusterInfo, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())
			os.Setenv("CLUSTER_TYPE", "")

			err = ensureDefaultConfig(ctx, cfg, c, node, OSTypeLinux, kubeadmConfig, rancherState)
			It("should be able to ensureDefaultConfig", func() {
				Expect(err).NotTo(HaveOccurred())
			})

			clusterInfo, err = c.ClusterInformation().Get(ctx, "default", options.GetOptions{})
			It("should be able to access the ClusterType", func() {
				Expect(err).NotTo(HaveOccurred())
			})

			It("should only have 'kdd' set", func() {
				Expect(clusterInfo.Spec.ClusterType).Should(Equal("kubeadm,kdd"))
			})
		})

		Context("With the same entries in both sources", func() {
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

			nodeName := utils.DetermineNodeName()
			node := getNode(ctx, c, nodeName)

			clusterInfo := api.NewClusterInformation()
			clusterInfo.Name = "default"
			clusterInfo.Spec.ClusterType = "type1,type2"

			_, err = c.ClusterInformation().Create(ctx, clusterInfo, options.SetOptions{})
			Expect(err).ToNot(HaveOccurred())
			os.Setenv("CLUSTER_TYPE", "type1,type1")

			err = ensureDefaultConfig(ctx, cfg, c, node, OSTypeLinux, kubeadmConfig, rancherState)
			It("should be able to ensureDefaultConfig", func() {
				Expect(err).NotTo(HaveOccurred())
			})

			clusterInfo, err = c.ClusterInformation().Get(ctx, "default", options.GetOptions{})
			It("should be able to access the ClusterType", func() {
				Expect(err).NotTo(HaveOccurred())
			})

			It("should have only one instance of the expected value", func() {
				Expect(strings.Count(clusterInfo.Spec.ClusterType, "type1")).To(Equal(1), "Should only have one instance of type1, read '%s", clusterInfo.Spec.ClusterType)
			})
			It("should have only one instance of the expected value", func() {
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
				// If we receieve an invalid env var then none will be set.
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

			check, err := configureIPsAndSubnets(node)

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

var _ = Describe("FV tests against K8s API server.", func() {
	It("should not throw an error when multiple Nodes configure the same global CRD value.", func() {
		ctx := context.Background()

		// How many Nodes we want to "create".
		numNodes := 10

		// Create a K8s client.
		configOverrides := &clientcmd.ConfigOverrides{
			ClusterInfo: clientcmdapi.Cluster{
				Server:                "http://127.0.0.1:8080",
				InsecureSkipTLSVerify: true,
			},
		}

		kcfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(&clientcmd.ClientConfigLoadingRules{}, configOverrides).ClientConfig()
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

		cfg.Spec = apiconfig.CalicoAPIConfigSpec{
			DatastoreType: apiconfig.Kubernetes,
			KubeConfig: apiconfig.KubeConfig{
				K8sAPIEndpoint:           "http://127.0.0.1:8080",
				K8sInsecureSkipTLSVerify: true,
			},
		}

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
		seen := set.New()
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
    kind: ClusterStatus`}}, "192.168.0.0/16", "", false),
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
				{Name: "eth1", Cidrs: []net.IPNet{net.MustParseCIDR("1.2.3.4/24")}}}, nil
		}
		ipv4CIDROrIP, _ := getLocalCIDR(ipv4Env, version, ipv4MockInterfaces)
		Expect(ipv4CIDROrIP).To(Equal(exceptValue))
	},
		Entry("get the local cidr", "1.2.3.4", 4, "1.2.3.4/24"),
		Entry("get the original cidr", "4.3.2.1/25", 4, "4.3.2.1/25"),
		Entry("get the original ip(v4)", "1.2.3.5", 4, "1.2.3.5"),
	)

	var _ = DescribeTable("env IP6 is defined", func(ipv6Env string, version int, exceptValue string) {
		ipv6MockInterfaces := func([]string, []string, int) ([]autodetection.Interface, error) {
			return []autodetection.Interface{
				{Name: "eth1", Cidrs: []net.IPNet{net.MustParseCIDR("1:2:3:4::5/120")}}}, nil
		}
		ipv4CIDROrIP, _ := getLocalCIDR(ipv6Env, version, ipv6MockInterfaces)
		Expect(ipv4CIDROrIP).To(Equal(exceptValue))
	},
		Entry("get the local cidr", "1:2:3:4::5", 6, "1:2:3:4::5/120"),
		Entry("get the original cidr", "5:4:3:2::1/64", 6, "5:4:3:2::1/64"),
		Entry("get the original ip(v6)", "1:2:3:4::1111", 6, "1:2:3:4::1111"),
	)
})
