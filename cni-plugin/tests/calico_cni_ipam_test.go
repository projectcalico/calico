// Copyright (c) 2015-2020 Tigera, Inc. All rights reserved.

package main_test

import (
	"context"
	"fmt"
	"os"

	"github.com/containernetworking/cni/pkg/types"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	uuid "github.com/satori/go.uuid"

	"github.com/projectcalico/calico/cni-plugin/internal/pkg/testutils"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
	"github.com/projectcalico/calico/libcalico-go/lib/names"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

var plugin = "calico-ipam"
var defaultIPv4Pool = "192.168.0.0/16"

var _ = Describe("Calico IPAM Tests", func() {
	cniVersion := os.Getenv("CNI_SPEC_VERSION")
	calicoClient, err := client.NewFromEnv()
	Expect(err).NotTo(HaveOccurred())
	k8sClient := getKubernetesClient()

	var cid string
	BeforeEach(func() {
		testutils.WipeDatastore()
		testutils.MustCreateNewIPPool(calicoClient, defaultIPv4Pool, false, false, true)
		testutils.MustCreateNewIPPool(calicoClient, "fd80:24e2:f998:72d6::/64", false, false, true)

		// Create a unique container ID for each test.
		cid = uuid.NewV4().String()

		// Create the node for these tests. The IPAM code requires a corresponding Calico node to exist.
		var name string
		name, err = names.Hostname()
		Expect(err).NotTo(HaveOccurred())
		err = testutils.AddNode(calicoClient, k8sClient, name)
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		// Delete the node.
		name, err := names.Hostname()
		Expect(err).NotTo(HaveOccurred())
		err = testutils.DeleteNode(calicoClient, k8sClient, name)
		Expect(err).NotTo(HaveOccurred())
	})

	Describe("Run IPAM plugin", func() {
		DescribeTable("Request different numbers of IP addresses",
			func(expectedIPv4, expectedIPv6 bool, netconf string) {
				result, _, _ := testutils.RunIPAMPlugin(netconf, "ADD", "", cid, cniVersion)
				var ip4Mask, ip6Mask string

				for _, ip := range result.IPs {
					if ip.Address.IP.To4() != nil {
						ip4Mask = ip.Address.Mask.String()
					} else if ip.Address.IP.To16() != nil {
						ip6Mask = ip.Address.Mask.String()
					}
				}

				if expectedIPv4 {
					Expect(ip4Mask).Should(Equal("ffffffc0"))
				}

				if expectedIPv6 {
					Expect(ip6Mask).Should(Equal("ffffffffffffffffffffffffffffffc0"))
				}

				_, _, exitCode := testutils.RunIPAMPlugin(netconf, "DEL", "", cid, cniVersion)
				Expect(exitCode).Should(Equal(0))
			},

			Entry("IPAM with no configuration", true, false, fmt.Sprintf(`
            {
              "cniVersion": "%s",
              "name": "net1",
              "type": "calico",
              "etcd_endpoints": "http://%s:2379",
              "kubernetes": {
                  "kubeconfig": "/home/user/certs/kubeconfig"
              },
              "log_level": "debug",
              "datastore_type": "%s",
              "ipam": {
                "type": "%s"
              }
            }`, cniVersion, os.Getenv("ETCD_IP"), os.Getenv("DATASTORE_TYPE"), plugin)),
			Entry("IPAM with IPv4 (explicit)", true, false, fmt.Sprintf(`
            {
              "cniVersion": "%s",
              "name": "net1",
              "type": "calico",
              "etcd_endpoints": "http://%s:2379",
              "kubernetes": {
                 "kubeconfig": "/home/user/certs/kubeconfig"
                  },
              "datastore_type": "%s",
              "ipam": {
                "type": "%s",
                "assign_ipv4": "true"
              }
            }`, cniVersion, os.Getenv("ETCD_IP"), os.Getenv("DATASTORE_TYPE"), plugin)),
			Entry("IPAM with IPv6 only", false, true, fmt.Sprintf(`
            {
              "cniVersion": "%s",
              "name": "net1",
              "type": "calico",
              "etcd_endpoints": "http://%s:2379",
              "kubernetes": {
                 "kubeconfig": "/home/user/certs/kubeconfig"
              },
              "datastore_type": "%s",
              "ipam": {
                "type": "%s",
                "assign_ipv4": "false",
                "assign_ipv6": "true"
              }
            }`, cniVersion, os.Getenv("ETCD_IP"), os.Getenv("DATASTORE_TYPE"), plugin)),
			Entry("IPAM with IPv4 and IPv6", true, true, fmt.Sprintf(`
            {
              "cniVersion": "%s",
              "name": "net1",
              "type": "calico",
              "etcd_endpoints": "http://%s:2379",
              "kubernetes": {
                 "kubeconfig": "/home/user/certs/kubeconfig"
              },
              "datastore_type": "%s",
              "log_level": "debug",
              "ipam": {
                "type": "%s",
                "assign_ipv4": "true",
                "assign_ipv6": "true"
              }
            }`, cniVersion, os.Getenv("ETCD_IP"), os.Getenv("DATASTORE_TYPE"), plugin)),
		)
	})

	Describe("Run IPAM plugin - No partial assignments in dual stack", func() {
		Context("With no IPv4 pool", func() {
			It("Should not assign an IPv6 address in a dual stack configuration", func() {
				// Delete IPv6 pool.
				testutils.MustDeleteIPPool(calicoClient, "fd80:24e2:f998:72d6::/64")

				// Assign an IP to fill up the pool
				netconf := fmt.Sprintf(`
            {
              "cniVersion": "%s",
              "name": "net1",
              "type": "calico",
              "etcd_endpoints": "http://%s:2379",
              "kubernetes": {
                 "kubeconfig": "/home/user/certs/kubeconfig"
              },
              "datastore_type": "%s",
              "log_level": "debug",
              "ipam": {
                "type": "%s",
                "assign_ipv4": "true",
                "assign_ipv6": "true"
              }
            }`, cniVersion, os.Getenv("ETCD_IP"), os.Getenv("DATASTORE_TYPE"), plugin)
				_, _, _ = testutils.RunIPAMPlugin(netconf, "ADD", "", cid, cniVersion)

				// Attempt to assign both an IPv4 and IPv6 address
				result, _, _ := testutils.RunIPAMPlugin(netconf, "ADD", "", cid, cniVersion)
				Expect(result.IPs).To(HaveLen(0))

				// Clean up
				_, _, exitCode := testutils.RunIPAMPlugin(netconf, "DEL", "", cid, cniVersion)
				Expect(exitCode).Should(Equal(0))
				testutils.MustCreateNewIPPool(calicoClient, "fd80:24e2:f998:72d6::/64", false, false, true)
			})
		})

		Context("With no IPv6 pool", func() {
			It("Should not assign an IPv4 address in a dual stack configuration", func() {
				// Delete IPv4 pool.
				testutils.MustDeleteIPPool(calicoClient, defaultIPv4Pool)

				// Assign an IP to fill up the pool
				netconf := fmt.Sprintf(`
            {
              "cniVersion": "%s",
              "name": "net1",
              "type": "calico",
              "etcd_endpoints": "http://%s:2379",
              "kubernetes": {
                 "kubeconfig": "/home/user/certs/kubeconfig"
              },
              "datastore_type": "%s",
              "log_level": "debug",
              "ipam": {
                "type": "%s",
                "assign_ipv4": "true",
                "assign_ipv6": "true"
              }
            }`, cniVersion, os.Getenv("ETCD_IP"), os.Getenv("DATASTORE_TYPE"), plugin)
				_, _, _ = testutils.RunIPAMPlugin(netconf, "ADD", "", cid, cniVersion)

				// Attempt to assign both an IPv4 and IPv6 address
				result, _, _ := testutils.RunIPAMPlugin(netconf, "ADD", "", cid, cniVersion)
				Expect(result.IPs).To(HaveLen(0))

				// Clean up
				_, _, exitCode := testutils.RunIPAMPlugin(netconf, "DEL", "", cid, cniVersion)
				Expect(exitCode).Should(Equal(0))
				testutils.MustCreateNewIPPool(calicoClient, defaultIPv4Pool, false, false, true)
			})
		})
	})

	Describe("Run IPAM plugin - Verify IP Pools", func() {
		Context("Pass valid pools", func() {
			It("Uses the ipv4 pool", func() {
				netconf := fmt.Sprintf(`
                {
                  "cniVersion": "%s",
                  "name": "net1",
                  "type": "calico",
                  "etcd_endpoints": "http://%s:2379",
                  "kubernetes": {
                    "kubeconfig": "/home/user/certs/kubeconfig"
                    },
                  "datastore_type": "%s",
                  "ipam": {
                    "type": "%s",
                    "assign_ipv4": "true",
                    "ipv4_pools": [ "192.168.0.0/16" ]
                    }
                }`, cniVersion, os.Getenv("ETCD_IP"), os.Getenv("DATASTORE_TYPE"), plugin)
				result, _, _ := testutils.RunIPAMPlugin(netconf, "ADD", "", cid, cniVersion)
				Expect(len(result.IPs)).To(Equal(1))
				Expect(result.IPs[0].Address.IP.String()).Should(HavePrefix("192.168."))
			})
		})

		Context("Pass more than one pool", func() {
			It("Uses one of the ipv4 pools", func() {
				testutils.MustCreateNewIPPool(calicoClient, "192.169.1.0/24", false, false, true)
				netconf := fmt.Sprintf(`
                {
                      "cniVersion": "%s",
                      "name": "net1",
                      "type": "calico",
                      "etcd_endpoints": "http://%s:2379",
                        "kubernetes": {
                           "kubeconfig": "/home/user/certs/kubeconfig"
                      },
                      "datastore_type": "%s",
                      "ipam": {
                        "type": "%s",
                        "assign_ipv4": "true",
                        "ipv4_pools": [ "192.169.1.0/24", "192.168.0.0/16" ]
                      }
                }`, cniVersion, os.Getenv("ETCD_IP"), os.Getenv("DATASTORE_TYPE"), plugin)
				result, _, _ := testutils.RunIPAMPlugin(netconf, "ADD", "", cid, cniVersion)
				Expect(result.IPs[0].Address.IP.String()).Should(Or(HavePrefix("192.168."), HavePrefix("192.169.1")))
			})
		})

		Context("Disabled IP pool", func() {
			It("Never allocates from the disabled pool", func() {
				netconf := fmt.Sprintf(`
                {
                      "cniVersion": "%s",
                      "name": "net1",
                      "type": "calico",
                      "etcd_endpoints": "http://%s:2379",
                        "kubernetes": {
                         "kubeconfig": "/home/user/certs/kubeconfig"
                      },
                      "datastore_type": "%s",
                      "ipam": {
                        "type": "%s",
                        "assign_ipv4": "true"
                      }
                }`, cniVersion, os.Getenv("ETCD_IP"), os.Getenv("DATASTORE_TYPE"), plugin)

				// Get an allocation
				result, _, _ := testutils.RunIPAMPlugin(netconf, "ADD", "", cid, cniVersion)
				Expect(result.IPs[0].Address.IP.String()).Should(HavePrefix("192.168."))

				// Disable the currently enabled pool
				pool, err := calicoClient.IPPools().Get(context.Background(), "192-168-0-0-16", options.GetOptions{})
				Expect(err).ToNot(HaveOccurred())
				pool.Spec.Disabled = true
				_, err = calicoClient.IPPools().Update(context.Background(), pool, options.SetOptions{})
				Expect(err).ToNot(HaveOccurred())

				// Create new (enabled) pool
				testutils.MustCreateNewIPPool(calicoClient, "192.169.1.0/24", false, false, true)

				// Get an allocation then check that it is not from the disabled pool
				result, _, _ = testutils.RunIPAMPlugin(netconf, "ADD", "", cid, cniVersion)
				Expect(result.IPs[0].Address.IP.String()).Should(HavePrefix("192.169.1"))

				// Re-enable the the pool. We can't delete the node if the IP pool is disabled.
				// This is arguably a bug in the node deletion code...
				pool, err = calicoClient.IPPools().Get(context.Background(), "192-168-0-0-16", options.GetOptions{})
				Expect(err).ToNot(HaveOccurred())
				pool.Spec.Disabled = false
				_, err = calicoClient.IPPools().Update(context.Background(), pool, options.SetOptions{})
				Expect(err).ToNot(HaveOccurred())

			})
		})

		Context("Pass an invalid pool", func() {
			It("fails to get an IP", func() {
				// Put the bogus pool last in the array
				netconf := fmt.Sprintf(`
                    {
                      "cniVersion": "%s",
                      "name": "net1",
                      "type": "calico",
                      "etcd_endpoints": "http://%s:2379",
                        "kubernetes": {
                         "kubeconfig": "/home/user/certs/kubeconfig"
                      },
                      "datastore_type": "%s",
                      "ipam": {
                        "type": "%s",
                        "assign_ipv4": "true",
                        "ipv4_pools": [ "192.168.0.0/16", "192.169.1.0/24" ]
                      }
                    }`, cniVersion, os.Getenv("ETCD_IP"), os.Getenv("DATASTORE_TYPE"), plugin)
				_, err, _ := testutils.RunIPAMPlugin(netconf, "ADD", "", cid, cniVersion)
				Expect(err.Msg).Should(ContainSubstring("192.169.1.0/24) does not exist"))
			})

			It("fails to get an IP", func() {
				// Put the bogus pool first in the array
				netconf := fmt.Sprintf(`
                    {
                      "cniVersion": "%s",
                      "name": "net1",
                      "type": "calico",
                      "etcd_endpoints": "http://%s:2379",
                        "kubernetes": {
                         "kubeconfig": "/home/user/certs/kubeconfig"
                      },
                      "datastore_type": "%s",
                      "ipam": {
                        "type": "%s",
                        "assign_ipv4": "true",
                        "ipv4_pools": [ "192.168.0.0/16", "192.169.1.0/24" ]
                      }
                    }`, cniVersion, os.Getenv("ETCD_IP"), os.Getenv("DATASTORE_TYPE"), plugin)
				_, err, _ := testutils.RunIPAMPlugin(netconf, "ADD", "", cid, cniVersion)
				Expect(err.Msg).Should(ContainSubstring("192.169.1.0/24) does not exist"))
			})
		})

	})

	Describe("Requesting an explicit IP address", func() {
		netconf := fmt.Sprintf(`
                    {
                      "cniVersion": "%s",
                      "name": "net1",
                      "type": "calico",
                      "etcd_endpoints": "http://%s:2379",
                      "kubernetes": {
                        "kubeconfig": "/home/user/certs/kubeconfig"
                      },
                      "datastore_type": "%s",
                      "ipam": {
                        "type": "%s"
                      }
                    }`, cniVersion, os.Getenv("ETCD_IP"), os.Getenv("DATASTORE_TYPE"), plugin)
		Context("Pass explicit IP address", func() {
			It("Return the expected IP", func() {
				result, _, _ := testutils.RunIPAMPlugin(netconf, "ADD", "IP=192.168.123.123", cid, cniVersion)
				Expect(len(result.IPs)).Should(Equal(1))
				Expect(result.IPs[0].Address.String()).Should(Equal("192.168.123.123/32"))
			})
			It("Return the expected IP twice after deleting in the middle", func() {
				result, _, _ := testutils.RunIPAMPlugin(netconf, "ADD", "IP=192.168.123.123", cid, cniVersion)
				Expect(len(result.IPs)).Should(Equal(1))
				Expect(result.IPs[0].Address.String()).Should(Equal("192.168.123.123/32"))
				_, _, _ = testutils.RunIPAMPlugin(netconf, "DEL", "IP=192.168.123.123", cid, cniVersion)
				result, _, _ = testutils.RunIPAMPlugin(netconf, "ADD", "IP=192.168.123.123", cid, cniVersion)
				Expect(len(result.IPs)).Should(Equal(1))
				Expect(result.IPs[0].Address.String()).Should(Equal("192.168.123.123/32"))
			})
			It("Doesn't allow an explicit IP to be assigned twice", func() {
				result, _, _ := testutils.RunIPAMPlugin(netconf, "ADD", "IP=192.168.123.123", cid, cniVersion)
				Expect(len(result.IPs)).Should(Equal(1))
				Expect(result.IPs[0].Address.String()).Should(Equal("192.168.123.123/32"))
				_, _, exitCode := testutils.RunIPAMPlugin(netconf, "ADD", "IP=192.168.123.123", cid, cniVersion)
				Expect(exitCode).Should(BeNumerically(">", 0))
			})
		})
	})

	Describe("Run IPAM DEL", func() {
		netconf := fmt.Sprintf(`
                    {
                      "cniVersion": "%s",
                      "name": "net1",
                      "type": "calico",
                      "etcd_endpoints": "http://%s:2379",
                      "kubernetes": {
                        "kubeconfig": "/home/user/certs/kubeconfig"
                      },
                      "datastore_type": "%s",
                      "ipam": {
                        "type": "%s"
                      }
                    }`, cniVersion, os.Getenv("ETCD_IP"), os.Getenv("DATASTORE_TYPE"), plugin)

		It("should exit successfully even if no address exists", func() {
			_, _, exitCode := testutils.RunIPAMPlugin(netconf, "DEL", "IP=192.168.123.123", cid, cniVersion)
			Expect(exitCode).Should(Equal(0))
		})

		Context("when using old IPAM handle", func() {
			It("should remove the old handle", func() {
				// Create an IP using workload as the handle. This is the "old" way of
				// assigning IPs, prior to this PR:
				// https://github.com/projectcalico/cni-plugin/pull/446
				workload := cid
				assignArgs := ipam.AssignIPArgs{
					IP:       cnet.MustParseIP("192.168.123.123"),
					HandleID: &workload,
				}
				ctx := context.Background()
				err := calicoClient.IPAM().AssignIP(ctx, assignArgs)
				Expect(err).NotTo(HaveOccurred())

				// Verify the new IP was set.
				ips, err := calicoClient.IPAM().IPsByHandle(ctx, workload)
				Expect(err).NotTo(HaveOccurred())
				Expect(ips).To(HaveLen(1))

				// Call the IPAM plugin and assert that it properly cleans up the allocation.
				result, e, rc := testutils.RunIPAMPlugin(netconf, "DEL", "IP=192.168.123.123", cid, cniVersion)
				Expect(e).To(Equal(types.Error{}))
				Expect(rc).To(Equal(0))
				Expect(len(result.IPs)).Should(Equal(0))

				// Verify that the workload handle is gone.
				_, err = calicoClient.IPAM().IPsByHandle(ctx, workload)
				Expect(err).To(HaveOccurred())

				// Create an IP using the "new" style handleID composed of the
				// network name and containerID.
				handleID := fmt.Sprintf("net1.%s", cid)
				assignArgs = ipam.AssignIPArgs{
					IP:       cnet.MustParseIP("192.168.123.123"),
					HandleID: &handleID,
				}
				err = calicoClient.IPAM().AssignIP(ctx, assignArgs)
				Expect(err).NotTo(HaveOccurred())

				// Verify the new IP was set.
				ips, err = calicoClient.IPAM().IPsByHandle(ctx, handleID)
				Expect(err).NotTo(HaveOccurred())
				Expect(ips).To(HaveLen(1))

				// Remove the IP and handle.
				result, e, rc = testutils.RunIPAMPlugin(netconf, "DEL", "IP=192.168.123.123", cid, cniVersion)
				Expect(e).To(Equal(types.Error{}))
				Expect(rc).To(Equal(0))
				Expect(len(result.IPs)).Should(Equal(0))

				// Verify that the handleID is gone.
				_, err = calicoClient.IPAM().IPsByHandle(ctx, handleID)
				Expect(err).To(HaveOccurred())
			})
		})
	})
})
