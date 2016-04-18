package main_test

import (
	"fmt"
	"os"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	. "github.com/projectcalico/calico-cni/test_utils"
)

var plugin = "calico-ipam"

var _ = Describe("Calico IPAM Tests", func() {
	BeforeEach(func() {
		Cmd(fmt.Sprintf("etcdctl --endpoints http://%s:2379 rm /calico --recursive | true", os.Getenv("ETCD_IP")))

		PreCreatePool("192.168.0.0/16")
		PreCreatePool("fd80:24e2:f998:72d6::/64")
	})

	Describe("Run IPAM plugin", func() {
		Context("Do it", func() {
			DescribeTable("Request different numbers of IP addresses",
				func(expectedIPv4, expectedIPv6 bool, netconf string) {

					result, _ := RunIPAMPlugin(netconf, "ADD", "")

					if expectedIPv4 {
						Expect(result.IP4.IP.Mask.String()).Should(Equal("ffffffff"))
					}

					if expectedIPv6 {
						Expect(result.IP6.IP.Mask.String()).Should(Equal("ffffffffffffffffffffffffffffffff"))
					}

					// I can't find any testable side effects for this
					_, _ = RunIPAMPlugin(netconf, "DEL", "")
				},
				Entry("IPAM with no configuration", true, false, fmt.Sprintf(`
			{
			  "name": "net1",
			  "type": "calico",
			  "etcd_endpoints": "http://%s:2379",
			  "ipam": {
			    "type": "%s"
			  }
			}`, os.Getenv("ETCD_IP"), plugin)),
				Entry("IPAM with IPv4 (explicit)", true, false, fmt.Sprintf(`
			{
			  "name": "net1",
			  "type": "calico",
			  "etcd_endpoints": "http://%s:2379",
			  "ipam": {
			    "type": "%s",
			    "assign_ipv4": "true"
			  }
			}`, os.Getenv("ETCD_IP"), plugin)),
				Entry("IPAM with IPv6 only", false, true, fmt.Sprintf(`
			{
			  "name": "net1",
			  "type": "calico",
			  "etcd_endpoints": "http://%s:2379",
			  "ipam": {
			    "type": "%s",
			    "assign_ipv4": "false",
			    "assign_ipv6": "true"
			  }
			}`, os.Getenv("ETCD_IP"), plugin)),
				Entry("IPAM with IPv4 and IPv6", true, true, fmt.Sprintf(`
			{
			  "name": "net1",
			  "type": "calico",
			  "etcd_endpoints": "http://%s:2379",
			  "ipam": {
			    "type": "%s",
			    "assign_ipv4": "true",
			    "assign_ipv6": "true"
			  }
			}`, os.Getenv("ETCD_IP"), plugin)),
			)
		})
	})

	Describe("Run IPAM plugin", func() {
		netconf := fmt.Sprintf(`
					{"name": "net1",
					  "type": "calico",
					  "etcd_endpoints": "http://%s:2379",
					  "ipam": {
					    "type": "%s"
					  }
					}`, os.Getenv("ETCD_IP"), plugin)
		Context("Pass explicit IP address", func() {
			It("Return the expected IP", func() {
				result, _ := RunIPAMPlugin(netconf, "ADD", "IP=192.168.123.123")
				Expect(result.IP4.IP.String()).Should(Equal("192.168.123.123/32"))
			})
			It("Return the expected IP twice after deleting in the middle", func() {
				result, _ := RunIPAMPlugin(netconf, "ADD", "IP=192.168.123.123")
				Expect(result.IP4.IP.String()).Should(Equal("192.168.123.123/32"))
				_, _ = RunIPAMPlugin(netconf, "DEL", "IP=192.168.123.123")
				result, _ = RunIPAMPlugin(netconf, "ADD", "IP=192.168.123.123")
				Expect(result.IP4.IP.String()).Should(Equal("192.168.123.123/32"))
			})
			It("Doesn't allow an explicit IP to be assigned twice", func() {
				result, _ := RunIPAMPlugin(netconf, "ADD", "IP=192.168.123.123")
				Expect(result.IP4.IP.String()).Should(Equal("192.168.123.123/32"))
				result, exitCode := RunIPAMPlugin(netconf, "ADD", "IP=192.168.123.123")
				Expect(exitCode).Should(BeNumerically(">", 0))
			})
		})
	})
})
