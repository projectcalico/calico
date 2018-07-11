// Copyright (c) 2016 Tigera, Inc. All rights reserved.

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
	"github.com/projectcalico/libcalico-go/lib/set"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	"github.com/projectcalico/libcalico-go/lib/apiconfig"
	api "github.com/projectcalico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/libcalico-go/lib/backend"
	client "github.com/projectcalico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/libcalico-go/lib/names"
	"github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/options"
)

var exitCode int

func fakeExitFunction(ec int) {
	exitCode = ec
}

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

var _ = Describe("Non-etcd related tests", func() {

	Describe("Termination tests", func() {
		exitCode = 0
		Context("Test termination", func() {
			oldExit := exitFunction
			exitFunction = fakeExitFunction
			defer func() { exitFunction = oldExit }()
			terminate()
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

var _ = Describe("FV tests against a real etcd", func() {
	ctx := context.Background()
	changedEnvVars := []string{"CALICO_IPV4POOL_CIDR", "CALICO_IPV6POOL_CIDR", "NO_DEFAULT_POOLS", "CALICO_IPV4POOL_IPIP", "CALICO_IPV6POOL_NAT_OUTGOING", "CALICO_IPV4POOL_NAT_OUTGOING", "IP", "CLUSTER_TYPE", "CALICO_K8S_NODE_REF", "CALICO_UNKNOWN_NODE_REF"}

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
		func(envList []EnvItem, expectedIPv4 string, expectedIPv6 string, expectIpv4IpipMode string, expectedIPV4NATOutgoing bool, expectedIPV6NATOutgoing bool) {
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
			Expect(poolList.Items).To(BeEmpty())

			// Run the UUT.
			configureIPPools(ctx, c)

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

				} else {
					// off is not a real mode value but use it instead of empty string
					if expectIpv4IpipMode == "Off" {
						Expect(pool.Spec.IPIPMode).To(Equal(api.IPIPModeNever))
					} else {
						Expect(pool.Spec.IPIPMode).To(Equal(api.IPIPMode(expectIpv4IpipMode)))
					}

					Expect(pool.Spec.NATOutgoing).To(Equal(expectedIPV4NATOutgoing), "Expected IPv4 to be %t but was %t", expectedIPV4NATOutgoing, pool.Spec.NATOutgoing)

				}
			}
			Expect(foundv4Expected).To(BeTrue(),
				"Expected %s to be in Pools", expectedIPv4)
			Expect(foundv6Expected).To(BeTrue(),
				"Expected %s to be in Pools", expectedIPv6)
		},

		Entry("No env variables set", []EnvItem{},
			"192.168.0.0/16", randomULAPool, "Off", true, false),
		Entry("IPv4 Pool env var set",
			[]EnvItem{{"CALICO_IPV4POOL_CIDR", "172.16.0.0/24"}},
			"172.16.0.0/24", randomULAPool, "Off", true, false),
		Entry("IPv6 Pool env var set",
			[]EnvItem{{"CALICO_IPV6POOL_CIDR", "fdff:ffff:ffff:ffff:ffff::/80"}},
			"192.168.0.0/16", "fdff:ffff:ffff:ffff:ffff::/80", "Off", true, false),
		Entry("Both IPv4 and IPv6 Pool env var set",
			[]EnvItem{
				{"CALICO_IPV4POOL_CIDR", "172.16.0.0/24"},
				{"CALICO_IPV6POOL_CIDR", "fdff:ffff:ffff:ffff:ffff::/80"},
			},
			"172.16.0.0/24", "fdff:ffff:ffff:ffff:ffff::/80", "Off", true, false),
		Entry("CALICO_IPV4POOL_IPIP set off", []EnvItem{{"CALICO_IPV4POOL_IPIP", "off"}},
			"192.168.0.0/16", randomULAPool, "Off", true, false),
		Entry("CALICO_IPV4POOL_IPIP set Off", []EnvItem{{"CALICO_IPV4POOL_IPIP", "Off"}},
			"192.168.0.0/16", randomULAPool, "Off", true, false),
		Entry("CALICO_IPV4POOL_IPIP set Never", []EnvItem{{"CALICO_IPV4POOL_IPIP", "Never"}},
			"192.168.0.0/16", randomULAPool, "Never", true, false),
		Entry("CALICO_IPV4POOL_IPIP set empty string", []EnvItem{{"CALICO_IPV4POOL_IPIP", ""}},
			"192.168.0.0/16", randomULAPool, "Off", true, false),
		Entry("CALICO_IPV4POOL_IPIP set always", []EnvItem{{"CALICO_IPV4POOL_IPIP", "always"}},
			"192.168.0.0/16", randomULAPool, "Always", true, false),
		Entry("CALICO_IPV4POOL_IPIP set Always", []EnvItem{{"CALICO_IPV4POOL_IPIP", "Always"}},
			"192.168.0.0/16", randomULAPool, "Always", true, false),
		Entry("CALICO_IPV4POOL_IPIP set cross-subnet", []EnvItem{{"CALICO_IPV4POOL_IPIP", "cross-subnet"}},
			"192.168.0.0/16", randomULAPool, "CrossSubnet", true, false),
		Entry("CALICO_IPV4POOL_IPIP set CrossSubnet", []EnvItem{{"CALICO_IPV4POOL_IPIP", "CrossSubnet"}},
			"192.168.0.0/16", randomULAPool, "CrossSubnet", true, false),
		Entry("IPv6 Pool and IPIP set",
			[]EnvItem{
				{"CALICO_IPV6POOL_CIDR", "fdff:ffff:ffff:ffff:ffff::/80"},
				{"CALICO_IPV4POOL_IPIP", "always"},
			},
			"192.168.0.0/16", "fdff:ffff:ffff:ffff:ffff::/80", "Always", true, false),
		Entry("IPv6 NATOutgoing Set Enabled",
			[]EnvItem{
				{"CALICO_IPV6POOL_NAT_OUTGOING", "true"}},
			"192.168.0.0/16", randomULAPool, "Off", true, true),
		Entry("IPv6 NATOutgoing Set Disabled",
			[]EnvItem{
				{"CALICO_IPV6POOL_NAT_OUTGOING", "false"}},
			"192.168.0.0/16", randomULAPool, "Off", true, false),
		Entry("IPv4 NATOutgoing Set Disabled",
			[]EnvItem{
				{"CALICO_IPV4POOL_NAT_OUTGOING", "false"}},
			"192.168.0.0/16", randomULAPool, "Off", false, false),
		Entry("IPv6 NAT OUTGOING and IPV4 NAT OUTGOING SET",
			[]EnvItem{
				{"CALICO_IPV4POOL_NAT_OUTGOING", "false"},
				{"CALICO_IPV6POOL_NAT_OUTGOING", "true"},
			},
			"192.168.0.0/16", randomULAPool, "Off", false, true),
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

			var n *api.Node
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
			configureIPPools(ctx, c)

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
			oldExit := exitFunction
			exitFunction = func(ec int) { my_ec = ec }
			defer func() { exitFunction = oldExit }()

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
			configureIPPools(ctx, c)

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

			nodeName := determineNodeName()
			node := getNode(ctx, c, nodeName)

			err = ensureDefaultConfig(ctx, cfg, c, node)
			It("should be able to ensureDefaultConfig", func() {
				Expect(err).NotTo(HaveOccurred())
			})

			clusterInfo, err := c.ClusterInformation().Get(ctx, "default", options.GetOptions{})
			It("should be able to access the ClusterType", func() {
				Expect(err).NotTo(HaveOccurred())
			})

			It("should be emtpy", func() {
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

			nodeName := determineNodeName()
			node := getNode(ctx, c, nodeName)

			os.Setenv("CLUSTER_TYPE", "theType")

			err = ensureDefaultConfig(ctx, cfg, c, node)
			It("should be able to ensureDefaultConfig", func() {
				Expect(err).NotTo(HaveOccurred())
			})

			clusterInfo, err := c.ClusterInformation().Get(ctx, "default", options.GetOptions{})
			It("should be able to access the ClusterType", func() {
				Expect(err).NotTo(HaveOccurred())
			})

			It("should have the set value", func() {
				Expect(clusterInfo.Spec.ClusterType).To(Equal("theType"))
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

			nodeName := determineNodeName()
			node := getNode(ctx, c, nodeName)

			clusterInfo := api.NewClusterInformation()
			clusterInfo.Name = "default"
			clusterInfo.Spec.ClusterType = "prePopulated"

			c.ClusterInformation().Create(ctx, clusterInfo, options.SetOptions{})
			os.Setenv("CLUSTER_TYPE", "theType")

			err = ensureDefaultConfig(ctx, cfg, c, node)
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

			nodeName := determineNodeName()
			node := getNode(ctx, c, nodeName)

			clusterInfo := api.NewClusterInformation()
			clusterInfo.Name = "default"
			clusterInfo.Spec.ClusterType = "prePopulated"

			c.ClusterInformation().Create(ctx, clusterInfo, options.SetOptions{})
			os.Setenv("CLUSTER_TYPE", "theType")

			err = ensureDefaultConfig(ctx, cfg, c, node)
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

			nodeName := determineNodeName()
			node := getNode(ctx, c, nodeName)

			clusterInfo := api.NewClusterInformation()
			clusterInfo.Name = "default"

			c.ClusterInformation().Create(ctx, clusterInfo, options.SetOptions{})
			os.Setenv("CLUSTER_TYPE", "")

			err = ensureDefaultConfig(ctx, cfg, c, node)
			It("should be able to ensureDefaultConfig", func() {
				Expect(err).NotTo(HaveOccurred())
			})

			clusterInfo, err = c.ClusterInformation().Get(ctx, "default", options.GetOptions{})
			It("should be able to access the ClusterType", func() {
				Expect(err).NotTo(HaveOccurred())
			})

			It("should only have 'kdd' set", func() {
				Expect(clusterInfo.Spec.ClusterType).Should(Equal("kdd"))
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

			nodeName := determineNodeName()
			node := getNode(ctx, c, nodeName)

			clusterInfo := api.NewClusterInformation()
			clusterInfo.Name = "default"
			clusterInfo.Spec.ClusterType = "type1,type2"

			c.ClusterInformation().Create(ctx, clusterInfo, options.SetOptions{})
			os.Setenv("CLUSTER_TYPE", "type1,type1")

			err = ensureDefaultConfig(ctx, cfg, c, node)
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
			DescribeTable("Should configure the OrchRef with the proper env var set", func(envs []EnvItem, expected api.OrchRef, isEqual bool) {
				node := &api.Node{}

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

				Entry("valid single k8s env var", []EnvItem{{"CALICO_K8S_NODE_REF", "node1"}}, api.OrchRef{"node1", "k8s"}, true),
			)

			It("Should not configure any OrchRefs when no valid env vars are passed", func() {
				os.Setenv("CALICO_UNKNOWN_NODE_REF", "node1")

				node := &api.Node{}
				configureNodeRef(node)

				Expect(node.Spec.OrchRefs).To(HaveLen(0))
			})
			It("Should not set an OrchRef if it is already set", func() {
				os.Setenv("CALICO_K8S_NODE_REF", "node1")

				node := &api.Node{}
				node.Spec.OrchRefs = append(node.Spec.OrchRefs, api.OrchRef{"node1", "k8s"})
				configureNodeRef(node)

				Expect(node.Spec.OrchRefs).To(HaveLen(1))
			})
		})

	})
})

var _ = Describe("UT for Node IP assignment and conflict checking.", func() {

	DescribeTable("Test variations on how IPs are detected.",
		func(node *api.Node, items []EnvItem, expected bool) {

			for _, item := range items {
				os.Setenv(item.key, item.value)
			}

			check, err := configureIPsAndSubnets(node)

			Expect(check).To(Equal(expected))
			Expect(err).NotTo(HaveOccurred())
		},

		Entry("Test with no \"IP\" env var set", &api.Node{}, []EnvItem{{"IP", ""}}, true),
		Entry("Test with \"IP\" env var set to IP", &api.Node{}, []EnvItem{{"IP", "192.168.1.10/24"}}, true),
		Entry("Test with \"IP\" env var set to IP and BGP spec populated with same IP", makeNode("192.168.1.10/24", ""), []EnvItem{{"IP", "192.168.1.10/24"}}, false),
		Entry("Test with \"IP\" env var set to IP and BGP spec populated with different IP", makeNode("192.168.1.10/24", ""), []EnvItem{{"IP", "192.168.1.11/24"}}, true),
		Entry("Test with no \"IP6\" env var set", &api.Node{}, []EnvItem{{"IP6", ""}}, true),
		Entry("Test with \"IP6\" env var set to IP", &api.Node{}, []EnvItem{{"IP6", "2001:db8:85a3:8d3:1319:8a2e:370:7348/32"}}, true),
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
		kNodes := []*v1.Node{}
		for i := 0; i < numNodes; i++ {
			n := &v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: fmt.Sprintf("raceNode%02d", i+1),
				},
			}
			kNodes = append(kNodes, n)
			cs.CoreV1().Nodes().Create(n)
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
			go func() {
				defer wg.Done()
				err = ensureDefaultConfig(ctx, cfg, c, &node)
				if err != nil {
					errors = append(errors, err)
				}
			}()
		}

		wg.Wait()

		// Verify all runs complete without error.
		Expect(len(errors)).To(Equal(0))

		// Clean up our Nodes.
		for _, node := range nodes.Items {
			cs.CoreV1().Nodes().Delete(node.Name, &metav1.DeleteOptions{})
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
			nodeName := determineNodeName()
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
