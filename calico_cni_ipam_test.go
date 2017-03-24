package main_test

import (
	"fmt"
	"os"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	. "github.com/projectcalico/cni-plugin/test_utils"
	"github.com/projectcalico/libcalico-go/lib/testutils"
)

var plugin = "calico-ipam"

var _ = Describe("Calico IPAM Tests", func() {
	cniVersion := os.Getenv("CNI_SPEC_VERSION")

	BeforeEach(func() {
		WipeEtcd()
		testutils.CreateNewIPPool(*calicoClient, "192.168.0.0/16", false, false, true)
		testutils.CreateNewIPPool(*calicoClient, "fd80:24e2:f998:72d6::/64", false, false, true)
	})

	Describe("Run IPAM plugin", func() {
		Context("Do it", func() {
			DescribeTable("Request different numbers of IP addresses",
				func(expectedIPv4, expectedIPv6 bool, netconf string) {

					result, _, _ := RunIPAMPlugin(netconf, "ADD", "", cniVersion)
					var ip4Mask, ip6Mask string

					for _, ip := range result.IPs {
						if ip.Version == "4" {
							ip4Mask = ip.Address.Mask.String()
						} else if ip.Version == "6" {
							ip6Mask = ip.Address.Mask.String()
						}
					}

					if expectedIPv4 {
						Expect(ip4Mask).Should(Equal("ffffffff"))
					}

					if expectedIPv6 {
						Expect(ip6Mask).Should(Equal("ffffffffffffffffffffffffffffffff"))
					}

					_, _, exitCode := RunIPAMPlugin(netconf, "DEL", "", cniVersion)
					Expect(exitCode).Should(Equal(0))
				},
				Entry("IPAM with no configuration", true, false, fmt.Sprintf(`
			{
			  "cniVersion": "%s",
			  "name": "net1",
			  "type": "calico",
			  "etcd_endpoints": "http://%s:2379",
			  "ipam": {
			    "type": "%s"
			  }
			}`, cniVersion, os.Getenv("ETCD_IP"), plugin)),
				Entry("IPAM with IPv4 (explicit)", true, false, fmt.Sprintf(`
			{
			  "cniVersion": "%s",
			  "name": "net1",
			  "type": "calico",
			  "etcd_endpoints": "http://%s:2379",
			  "ipam": {
			    "type": "%s",
			    "assign_ipv4": "true"
			  }
			}`, cniVersion, os.Getenv("ETCD_IP"), plugin)),
				Entry("IPAM with IPv6 only", false, true, fmt.Sprintf(`
			{
			  "cniVersion": "%s",
			  "name": "net1",
			  "type": "calico",
			  "etcd_endpoints": "http://%s:2379",
			  "ipam": {
			    "type": "%s",
			    "assign_ipv4": "false",
			    "assign_ipv6": "true"
			  }
			}`, cniVersion, os.Getenv("ETCD_IP"), plugin)),
				Entry("IPAM with IPv4 and IPv6", true, true, fmt.Sprintf(`
			{
			  "cniVersion": "%s",
			  "name": "net1",
			  "type": "calico",
			  "etcd_endpoints": "http://%s:2379",
			  "ipam": {
			    "type": "%s",
			    "assign_ipv4": "true",
			    "assign_ipv6": "true"
			  }
			}`, cniVersion, os.Getenv("ETCD_IP"), plugin)),
			)
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
                  "ipam": {
                    "type": "%s",
                    "assign_ipv4": "true",
                    "ipv4_pools": [ "192.168.0.0/16" ]
                    }
                }`, cniVersion, os.Getenv("ETCD_IP"), plugin)
				result, _, _ := RunIPAMPlugin(netconf, "ADD", "", cniVersion)
				Expect(result.IPs[0].Address.IP.String()).Should(HavePrefix("192.168."))
			})
		})

		Context("Pass more than one pool", func() {
			It("Uses one of the ipv4 pools", func() {
				testutils.CreateNewIPPool(*calicoClient, "192.169.1.0/24", false, false, true)
				netconf := fmt.Sprintf(`
                {
                      "cniVersion": "%s",
                      "name": "net1",
                      "type": "calico",
                      "etcd_endpoints": "http://%s:2379",
                      "ipam": {
                        "type": "%s",
                        "assign_ipv4": "true",
                        "ipv4_pools": [ "192.169.1.0/24", "192.168.0.0/16" ]
                      }
                }`, cniVersion, os.Getenv("ETCD_IP"), plugin)
				result, _, _ := RunIPAMPlugin(netconf, "ADD", "", cniVersion)
				Expect(result.IPs[0].Address.IP.String()).Should(Or(HavePrefix("192.168."), HavePrefix("192.169.1")))
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
                      "ipam": {
                        "type": "%s",
                        "assign_ipv4": "true",
                        "ipv4_pools": [ "192.168.0.0/16", "192.169.1.0/24" ]
                      }
                    }`, cniVersion, os.Getenv("ETCD_IP"), plugin)
				_, error, _ := RunIPAMPlugin(netconf, "ADD", "", cniVersion)
				Expect(error.Msg).Should(ContainSubstring("192.169.1.0/24) does not exist"))
			})

			It("fails to get an IP", func() {
				// Put the bogus pool first in the array
				netconf := fmt.Sprintf(`
                    {
                      "cniVersion": "%s",
                      "name": "net1",
                      "type": "calico",
                      "etcd_endpoints": "http://%s:2379",
                      "ipam": {
                        "type": "%s",
                        "assign_ipv4": "true",
                        "ipv4_pools": [ "192.168.0.0/16", "192.169.1.0/24" ]
                      }
                    }`, cniVersion, os.Getenv("ETCD_IP"), plugin)
				_, error, _ := RunIPAMPlugin(netconf, "ADD", "", cniVersion)
				Expect(error.Msg).Should(ContainSubstring("192.169.1.0/24) does not exist"))
			})
		})

	})

	Describe("Run IPAM plugin", func() {
		netconf := fmt.Sprintf(`
					{
					  "cniVersion": "%s",
					  "name": "net1",
					  "type": "calico",
					  "etcd_endpoints": "http://%s:2379",
					  "ipam": {
					    "type": "%s"
					  }
					}`, cniVersion, os.Getenv("ETCD_IP"), plugin)
		Context("Pass explicit IP address", func() {
			It("Return the expected IP", func() {
				result, _, _ := RunIPAMPlugin(netconf, "ADD", "IP=192.168.123.123", cniVersion)
				Expect(len(result.IPs)).Should(Equal(1))
				Expect(result.IPs[0].Address.String()).Should(Equal("192.168.123.123/32"))
			})
			It("Return the expected IP twice after deleting in the middle", func() {
				result, _, _ := RunIPAMPlugin(netconf, "ADD", "IP=192.168.123.123", cniVersion)
				Expect(len(result.IPs)).Should(Equal(1))
				Expect(result.IPs[0].Address.String()).Should(Equal("192.168.123.123/32"))
				_, _, _ = RunIPAMPlugin(netconf, "DEL", "IP=192.168.123.123", cniVersion)
				result, _, _ = RunIPAMPlugin(netconf, "ADD", "IP=192.168.123.123", cniVersion)
				Expect(len(result.IPs)).Should(Equal(1))
				Expect(result.IPs[0].Address.String()).Should(Equal("192.168.123.123/32"))
			})
			It("Doesn't allow an explicit IP to be assigned twice", func() {
				result, _, _ := RunIPAMPlugin(netconf, "ADD", "IP=192.168.123.123", cniVersion)
				Expect(len(result.IPs)).Should(Equal(1))
				Expect(result.IPs[0].Address.String()).Should(Equal("192.168.123.123/32"))
				result, _, exitCode := RunIPAMPlugin(netconf, "ADD", "IP=192.168.123.123", cniVersion)
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
					  "ipam": {
					    "type": "%s"
					  }
					}`, cniVersion, os.Getenv("ETCD_IP"), plugin)

		It("should exit successfully even if no address exists", func() {
			_, _, exitCode := RunIPAMPlugin(netconf, "DEL", "IP=192.168.123.123", cniVersion)
			Expect(exitCode).Should(Equal(0))
		})
	})
})
