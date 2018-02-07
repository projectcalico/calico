package main_test

import (
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/containernetworking/cni/pkg/ns"
	"github.com/containernetworking/cni/pkg/types/current"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gexec"
	. "github.com/projectcalico/cni-plugin/test_utils"
	"github.com/projectcalico/cni-plugin/utils"
	"github.com/projectcalico/libcalico-go/lib/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/client"
	cnet "github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/testutils"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

// Some ideas for more tests
// Test that both etcd_endpoints and etcd_authity can be used
// Test k8s
// test bad network name
// badly formatted netconf
// vary the MTU
// Existing endpoint

var calicoClient *client.Client

func init() {
	var err error
	calicoClient, err = client.NewFromEnv()
	if err != nil {
		panic(err)
	}
}

var _ = Describe("CalicoCni", func() {
	hostname, _ := os.Hostname()
	BeforeEach(func() {
		WipeEtcd()
	})

	cniVersion := os.Getenv("CNI_SPEC_VERSION")

	Describe("Run Calico CNI plugin", func() {
		Context("using host-local IPAM", func() {

			netconf := fmt.Sprintf(`
			{
			  "cniVersion": "%s",
			  "name": "net1",
			  "type": "calico",
			  "etcd_endpoints": "http://%s:2379",
			  "ipam": {
			    "type": "host-local",
			    "subnet": "10.0.0.0/8"
			  }
			}`, cniVersion, os.Getenv("ETCD_IP"))

			It("successfully networks the namespace", func() {
				containerID, session, contVeth, contAddresses, contRoutes, contNs, err := CreateContainer(netconf, "", "")
				Expect(err).ShouldNot(HaveOccurred())
				Eventually(session).Should(gexec.Exit())

				result, err := GetResultForCurrent(session, cniVersion)
				if err != nil {
					log.Fatalf("Error getting result from the session: %v\n", err)
				}

				Expect(len(result.IPs)).Should(Equal(1))
				ip := result.IPs[0].Address.IP.String()
				result.IPs[0].Address.IP = result.IPs[0].Address.IP.To4() // Make sure the IP is respresented as 4 bytes
				Expect(result.IPs[0].Address.Mask.String()).Should(Equal("ffffffff"))

				// datastore things:
				// Profile is created with correct details
				profile, err := calicoClient.Profiles().Get(api.ProfileMetadata{Name: "net1"})
				Expect(err).ShouldNot(HaveOccurred())
				Expect(profile.Metadata.Tags).Should(ConsistOf("net1"))
				Expect(profile.Spec.EgressRules).Should(Equal([]api.Rule{{Action: "allow"}}))
				Expect(profile.Spec.IngressRules).Should(Equal([]api.Rule{{Action: "allow", Source: api.EntityRule{Tag: "net1"}}}))

				// The endpoint is created in etcd
				endpoints, err := calicoClient.WorkloadEndpoints().List(api.WorkloadEndpointMetadata{})
				Expect(err).ShouldNot(HaveOccurred())
				Expect(endpoints.Items).Should(HaveLen(1))

				// Set the Revision to nil since we can't assert it's exact value.
				endpoints.Items[0].Metadata.Revision = nil
				Expect(endpoints.Items[0].Metadata).Should(Equal(api.WorkloadEndpointMetadata{
					Node:             hostname,
					Name:             "eth0",
					Workload:         containerID,
					ActiveInstanceID: "",
					Orchestrator:     "cni",
				}))

				mac := contVeth.Attrs().HardwareAddr

				Expect(endpoints.Items[0].Spec).Should(Equal(api.WorkloadEndpointSpec{
					InterfaceName: fmt.Sprintf("cali%s", containerID),
					IPNetworks:    []cnet.IPNet{{result.IPs[0].Address}},
					MAC:           &cnet.MAC{HardwareAddr: mac},
					Profiles:      []string{"net1"},
				}))

				// Routes and interface on host - there's is nothing to assert on the routes since felix adds those.
				//fmt.Println(Cmd("ip link show")) // Useful for debugging
				hostVethName := "cali" + containerID[:utils.Min(11, len(containerID))] //"cali" + containerID

				hostVeth, err := netlink.LinkByName(hostVethName)
				Expect(err).ToNot(HaveOccurred())
				Expect(hostVeth.Attrs().Flags.String()).Should(ContainSubstring("up"))
				Expect(hostVeth.Attrs().MTU).Should(Equal(1500))
				Expect(hostVeth.Attrs().HardwareAddr.String()).Should(Equal("ee:ee:ee:ee:ee:ee"))

				// Assert hostVeth sysctl values are set to what we expect for IPv4.
				err = CheckSysctlValue(fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/proxy_arp", hostVethName), "1")
				Expect(err).ShouldNot(HaveOccurred())
				err = CheckSysctlValue(fmt.Sprintf("/proc/sys/net/ipv4/neigh/%s/proxy_delay", hostVethName), "0")
				Expect(err).ShouldNot(HaveOccurred())
				err = CheckSysctlValue(fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/forwarding", hostVethName), "1")
				Expect(err).ShouldNot(HaveOccurred())

				// Assert if the host side route is programmed correctly.
				hostRoutes, err := netlink.RouteList(hostVeth, syscall.AF_INET)
				Expect(err).ShouldNot(HaveOccurred())
				Expect(hostRoutes[0]).Should(Equal(netlink.Route{
					LinkIndex: hostVeth.Attrs().Index,
					Scope:     netlink.SCOPE_LINK,
					Dst:       &result.IPs[0].Address,
					Protocol:  syscall.RTPROT_BOOT,
					Table:     syscall.RT_TABLE_MAIN,
					Type:      syscall.RTN_UNICAST,
				}))

				// Routes and interface in netns
				Expect(contVeth.Attrs().Flags.String()).Should(ContainSubstring("up"))

				// Assume the first IP is the IPv4 address
				Expect(contAddresses[0].IP.String()).Should(Equal(ip))
				Expect(contRoutes).Should(SatisfyAll(ContainElement(netlink.Route{
					LinkIndex: contVeth.Attrs().Index,
					Gw:        net.IPv4(169, 254, 1, 1).To4(),
					Protocol:  syscall.RTPROT_BOOT,
					Table:     syscall.RT_TABLE_MAIN,
					Type:      syscall.RTN_UNICAST,
				}),
					ContainElement(netlink.Route{
						LinkIndex: contVeth.Attrs().Index,
						Scope:     netlink.SCOPE_LINK,
						Dst:       &net.IPNet{IP: net.IPv4(169, 254, 1, 1).To4(), Mask: net.CIDRMask(32, 32)},
						Protocol:  syscall.RTPROT_BOOT,
						Table:     syscall.RT_TABLE_MAIN,
						Type:      syscall.RTN_UNICAST,
					})))

				_, err = DeleteContainer(netconf, contNs.Path(), "")
				Expect(err).ShouldNot(HaveOccurred())

				// Make sure there are no endpoints anymore
				endpoints, err = calicoClient.WorkloadEndpoints().List(api.WorkloadEndpointMetadata{})
				Expect(err).ShouldNot(HaveOccurred())
				Expect(endpoints.Items).Should(HaveLen(0))

				// Make sure the interface has been removed from the namespace
				targetNs, _ := ns.GetNS(contNs.Path())
				err = targetNs.Do(func(_ ns.NetNS) error {
					_, err = netlink.LinkByName("eth0")
					return err
				})
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).Should(Equal("Link not found"))

				// Make sure the interface has been removed from the host
				_, err = netlink.LinkByName("cali" + containerID)
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).Should(Equal("Link not found"))

			})

			Context("when the same hostVeth exists", func() {
				It("successfully networks the namespace", func() {
					container_id := fmt.Sprintf("con%d", rand.Uint32())
					if err := CreateHostVeth(container_id, "", ""); err != nil {
						panic(err)
					}
					_, session, _, _, _, contNs, err := CreateContainerWithId(netconf, "", "", container_id)
					Expect(err).ShouldNot(HaveOccurred())
					Eventually(session).Should(gexec.Exit(0))

					_, err = DeleteContainerWithId(netconf, contNs.Path(), "", container_id)
					Expect(err).ShouldNot(HaveOccurred())
				})
			})
			Context("when the ready flag is not set", func() {
				It("should return error on Add", func() {
					kv, err := calicoClient.Backend.Apply(
						&model.KVPair{
							Key:   model.ReadyFlagKey{},
							Value: false,
						})
					Expect(err).ToNot(HaveOccurred(), fmt.Sprintf("%v", kv))
					_, session, _, _, _, _, err := CreateContainer(netconf, "", "")
					Expect(err).Should(HaveOccurred())
					Eventually(session).Should(gexec.Exit(1))
				})
			})
			Context("when the ready flag is not set", func() {
				It("should return error on DEL", func() {
					_, session, _, _, _, contNs, err := CreateContainerWithId(netconf, "", "", "dontcare")
					Expect(err).ShouldNot(HaveOccurred())
					Eventually(session).Should(gexec.Exit(0))

					kv, err := calicoClient.Backend.Apply(
						&model.KVPair{
							Key:   model.ReadyFlagKey{},
							Value: false,
						})
					Expect(err).ToNot(HaveOccurred(), fmt.Sprintf("%v", kv))
					exitCode, err := DeleteContainerWithId(netconf, contNs.Path(), "", "dontcare")
					Expect(err).ShouldNot(HaveOccurred())
					Expect(exitCode).Should(Equal(1))
				})
			})
		})
	})

	Describe("Run Calico CNI plugin", func() {
		Context("deprecate Hostname for nodename", func() {
			netconf := fmt.Sprintf(`
			{
			  "cniVersion": "%s",
			  "name": "net1",
			  "type": "calico",
			  "etcd_endpoints": "http://%s:2379",
			  "hostname": "namedHostname",
			  "ipam": {
			    "type": "host-local",
			    "subnet": "10.0.0.0/8"
			  }
			}`, cniVersion, os.Getenv("ETCD_IP"))

			It("has hostname even though deprecated", func() {
				containerID, session, _, _, _, contNs, err := CreateContainer(netconf, "", "")
				Expect(err).ShouldNot(HaveOccurred())
				Eventually(session).Should(gexec.Exit())

				result, err := GetResultForCurrent(session, cniVersion)
				if err != nil {
					log.Fatalf("Error getting result from the session: %v\n", err)
				}

				log.Printf("Unmarshalled result: %v\n", result)

				// The endpoint is created in etcd
				endpoints, err := calicoClient.WorkloadEndpoints().List(api.WorkloadEndpointMetadata{})
				Expect(err).ShouldNot(HaveOccurred())
				Expect(endpoints.Items).Should(HaveLen(1))

				// Set the Revision to nil since we can't assert it's exact value.
				endpoints.Items[0].Metadata.Revision = nil
				Expect(endpoints.Items[0].Metadata).Should(Equal(api.WorkloadEndpointMetadata{
					Node:             "namedHostname",
					Name:             "eth0",
					Workload:         containerID,
					ActiveInstanceID: "",
					Orchestrator:     "cni",
				}))

				_, err = DeleteContainer(netconf, contNs.Path(), "")
				Expect(err).ShouldNot(HaveOccurred())
			})
		})

		Context("Mesos Labels", func() {
			It("applies mesos labels", func() {
				netconf := fmt.Sprintf(`
				{
				  "cniVersion": "%s",
				  "name": "net1",
				  "type": "calico",
				  "etcd_endpoints": "http://%s:2379",
				  "hostname": "namedHostname",
				  "ipam": {
					"type": "host-local",
					"subnet": "10.0.0.0/8"
				  },
				  "args": {
					"org.apache.mesos": {
					  "network_info": {
						"labels": {
						  "labels": [
							{
							  "key": "k",
							  "value": "v"
							}
						  ]
						}
					  }
					}
				  }
				}`, cniVersion, os.Getenv("ETCD_IP"))

				containerID, session, _, _, _, contNs, err := CreateContainer(netconf, "", "")
				Expect(err).ShouldNot(HaveOccurred())
				Eventually(session).Should(gexec.Exit())

				result, err := GetResultForCurrent(session, cniVersion)
				if err != nil {
					log.Fatalf("Error getting result from the session: %v\n", err)
				}

				log.Printf("Unmarshalled result: %v\n", result)

				// The endpoint is created in etcd
				endpoints, err := calicoClient.WorkloadEndpoints().List(api.WorkloadEndpointMetadata{})
				Expect(err).ShouldNot(HaveOccurred())
				Expect(endpoints.Items).Should(HaveLen(1))

				// Set the Revision to nil since we can't assert it's exact value.
				endpoints.Items[0].Metadata.Revision = nil
				Expect(endpoints.Items[0].Metadata).Should(Equal(api.WorkloadEndpointMetadata{
					Node:             "namedHostname",
					Name:             "eth0",
					Workload:         containerID,
					ActiveInstanceID: "",
					Orchestrator:     "cni",
					Labels: map[string]string{
						"k": "v",
					},
				}))

				_, err = DeleteContainer(netconf, contNs.Path(), "")
				Expect(err).ShouldNot(HaveOccurred())
			})

			It("sanitizes mesos labels", func() {
				netconf := fmt.Sprintf(`
				{
				  "cniVersion": "%s",
				  "name": "net1",
				  "type": "calico",
				  "etcd_endpoints": "http://%s:2379",
				  "hostname": "namedHostname",
				  "ipam": {
					"type": "host-local",
					"subnet": "10.0.0.0/8"
				  },
				  "args": {
					"org.apache.mesos": {
					  "network_info": {
						"labels": {
						  "labels": [
							{
							  "key": "DCOS_SPACE",
							  "value": "/a/b/c"
							}
						  ]
						}
					  }
					}
				  }
				}`, cniVersion, os.Getenv("ETCD_IP"))

				containerID, session, _, _, _, contNs, err := CreateContainer(netconf, "", "")
				Expect(err).ShouldNot(HaveOccurred())
				Eventually(session).Should(gexec.Exit())

				result, err := GetResultForCurrent(session, cniVersion)
				if err != nil {
					log.Fatalf("Error getting result from the session: %v\n", err)
				}

				log.Printf("Unmarshalled result: %v\n", result)

				// The endpoint is created in etcd
				endpoints, err := calicoClient.WorkloadEndpoints().List(api.WorkloadEndpointMetadata{})
				Expect(err).ShouldNot(HaveOccurred())
				Expect(endpoints.Items).Should(HaveLen(1))

				// Set the Revision to nil since we can't assert it's exact value.
				endpoints.Items[0].Metadata.Revision = nil
				Expect(endpoints.Items[0].Metadata).Should(Equal(api.WorkloadEndpointMetadata{
					Node:             "namedHostname",
					Name:             "eth0",
					Workload:         containerID,
					ActiveInstanceID: "",
					Orchestrator:     "cni",
					Labels: map[string]string{
						"DCOS_SPACE": "a.b.c",
					},
				}))

				_, err = DeleteContainer(netconf, contNs.Path(), "")
				Expect(err).ShouldNot(HaveOccurred())
			})
		})
	})

	Describe("Run Calico CNI plugin", func() {
		Context("deprecate Hostname for nodename", func() {
			netconf := fmt.Sprintf(`
			{
			  "cniVersion": "%s",
			  "name": "net1",
			  "type": "calico",
			  "etcd_endpoints": "http://%s:2379",
			  "hostname": "namedHostname",
			  "nodename": "namedNodename",
			  "ipam": {
			    "type": "host-local",
			    "subnet": "10.0.0.0/8"
			  }
			}`, cniVersion, os.Getenv("ETCD_IP"))

			It("nodename takes precedence over hostname", func() {
				containerID, session, _, _, _, contNs, err := CreateContainer(netconf, "", "")
				Expect(err).ShouldNot(HaveOccurred())
				Eventually(session).Should(gexec.Exit())

				result, err := GetResultForCurrent(session, cniVersion)
				if err != nil {
					log.Fatalf("Error getting result from the session: %v\n", err)
				}

				log.Printf("Unmarshalled result: %v\n", result)

				// The endpoint is created in etcd
				endpoints, err := calicoClient.WorkloadEndpoints().List(api.WorkloadEndpointMetadata{})
				Expect(err).ShouldNot(HaveOccurred())
				Expect(endpoints.Items).Should(HaveLen(1))

				// Set the Revision to nil since we can't assert it's exact value.
				endpoints.Items[0].Metadata.Revision = nil
				Expect(endpoints.Items[0].Metadata).Should(Equal(api.WorkloadEndpointMetadata{
					Node:             "namedNodename",
					Name:             "eth0",
					Workload:         containerID,
					ActiveInstanceID: "",
					Orchestrator:     "cni",
				}))

				_, err = DeleteContainer(netconf, contNs.Path(), "")
				Expect(err).ShouldNot(HaveOccurred())
			})
		})
	})

	Describe("DEL", func() {
		netconf := fmt.Sprintf(`
		{
			"cniVersion": "%s",
			"name": "net1",
			"type": "calico",
			"etcd_endpoints": "http://%s:2379",
			"ipam": {
				"type": "host-local",
				"subnet": "10.0.0.0/8"
			}
		}`, cniVersion, os.Getenv("ETCD_IP"))

		Context("when it was never called for SetUP", func() {
			Context("and a namespace does exist", func() {
				It("exits with 'success' error code", func() {
					contNs, _, err := CreateContainerNamespace()
					Expect(err).ShouldNot(HaveOccurred())
					exitCode, err := DeleteContainer(netconf, contNs.Path(), "")
					Expect(err).ShouldNot(HaveOccurred())
					Expect(exitCode).To(Equal(0))
				})
			})

			Context("and no namespace exists", func() {
				It("exits with 'success' error code", func() {
					exitCode, err := DeleteContainer(netconf, "/not/a/real/path1234567890", "")
					Expect(err).ShouldNot(HaveOccurred())
					Expect(exitCode).To(Equal(0))
				})
			})
		})
	})

	Describe("after creating a container", func() {
		netconf := fmt.Sprintf(`
		{
		  "cniVersion": "%s",
		  "name": "net1",
		  "type": "calico",
		  "etcd_endpoints": "http://%s:2379",
		  "ipam": { "type": "calico-ipam" }
		}`, cniVersion, os.Getenv("ETCD_IP"))

		var containerID string
		var endpointSpec api.WorkloadEndpointSpec
		var contNs ns.NetNS
		var result *current.Result

		checkIPAMReservation := func() {
			// IPAM reservation should still be in place.
			handleID, _ := utils.GetHandleID("net1", containerID, containerID)
			ipamIPs, err := calicoClient.IPAM().IPsByHandle(handleID)
			ExpectWithOffset(1, err).NotTo(HaveOccurred())
			ExpectWithOffset(1, ipamIPs).To(HaveLen(1),
				"There should be an IPAM handle for endpoint")
			ExpectWithOffset(1, ipamIPs[0].To16()).To(ConsistOf(endpointSpec.IPNetworks[0].IP.To16()))
		}

		BeforeEach(func() {
			// Create a new ipPool.
			c, _ := client.NewFromEnv()
			testutils.CreateNewIPPool(*c, "10.0.0.0/24", false, false, true)

			var err error
			var session *gexec.Session
			log.WithField("netconf", netconf).Info("netconf")
			containerID, session, _, _, _, contNs, err = CreateContainer(netconf, "", "")
			Expect(err).ShouldNot(HaveOccurred())
			Eventually(session).Should(gexec.Exit())

			result, err = GetResultForCurrent(session, cniVersion)
			if err != nil {
				log.Fatalf("Error getting result from the session: %v\n", err)
			}

			log.Printf("Unmarshalled result from first ADD: %v\n", result)

			// The endpoint is created in etcd
			endpoints, err := calicoClient.WorkloadEndpoints().List(api.WorkloadEndpointMetadata{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(endpoints.Items).Should(HaveLen(1))

			// Set the Revision to nil since we can't assert it's exact value.
			endpoints.Items[0].Metadata.Revision = nil
			endpointSpec = endpoints.Items[0].Spec
			Expect(endpoints.Items[0].Metadata).Should(Equal(api.WorkloadEndpointMetadata{
				Node:             hostname,
				Name:             "eth0",
				Workload:         containerID,
				ActiveInstanceID: "",
				Orchestrator:     "cni",
			}))

			// IPAM reservation should have been created.
			checkIPAMReservation()
		})

		AfterEach(func() {
			_, err := DeleteContainer(netconf, contNs.Path(), "")
			Expect(err).ShouldNot(HaveOccurred())
		})

		It("a second ADD for the same container should be a no-op", func() {
			// Try to create the same container (so CNI receives the ADD for the same endpoint again)
			session, _, _, _, err := RunCNIPluginWithId(netconf, "", "", containerID, contNs)
			Expect(err).ShouldNot(HaveOccurred())
			Eventually(session).Should(gexec.Exit(0))

			resultSecondAdd, err := GetResultForCurrent(session, cniVersion)
			if err != nil {
				log.Fatalf("Error getting result from the session: %v\n", err)
			}

			log.Printf("Unmarshalled result from second ADD: %v\n", resultSecondAdd)
			Expect(resultSecondAdd).Should(Equal(result))

			// The endpoint is created in etcd
			endpoints, err := calicoClient.WorkloadEndpoints().List(api.WorkloadEndpointMetadata{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(endpoints.Items).Should(HaveLen(1))
			Expect(endpoints.Items[0].Spec.Profiles).To(ConsistOf("net1"))

			// IPAM reservation should still be in place.
			checkIPAMReservation()
		})

		It("a second ADD with new profile ID should append it", func() {
			// Try to create the same container (so CNI receives the ADD for the same endpoint again)
			tweaked := strings.Replace(netconf, "net1", "net2", 1)
			session, _, _, _, err := RunCNIPluginWithId(tweaked, "", "", containerID, contNs)
			Expect(err).ShouldNot(HaveOccurred())
			Eventually(session).Should(gexec.Exit(0))

			resultSecondAdd, err := GetResultForCurrent(session, cniVersion)
			if err != nil {
				log.Fatalf("Error getting result from the session: %v\n", err)
			}

			log.Printf("Unmarshalled result from second ADD: %v\n", resultSecondAdd)
			Expect(resultSecondAdd).Should(Equal(result))

			// The endpoint is created in etcd
			endpoints, err := calicoClient.WorkloadEndpoints().List(api.WorkloadEndpointMetadata{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(endpoints.Items).Should(HaveLen(1))
			Expect(endpoints.Items[0].Spec.Profiles).To(ConsistOf("net1", "net2"))

			// IPAM reservation should still be in place.
			checkIPAMReservation()
		})

		Context("with networking rigged to fail", func() {
			BeforeEach(func() {
				// To prevent the networking atempt from succeeding, rename the old veth.
				// This leaves a route and an eth0 in place that the plugin will struggle with.
				log.Info("Breaking networking for the created interface")
				hostVeth := endpointSpec.InterfaceName
				newName := strings.Replace(hostVeth, "cali", "sali", 1)
				output, err := exec.Command("ip", "link", "set", hostVeth, "down").CombinedOutput()
				Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Output: %s", output))
				output, err = exec.Command("ip", "link", "set", hostVeth, "name", newName).CombinedOutput()
				Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Output: %s", output))
				output, err = exec.Command("ip", "link", "set", newName, "up").CombinedOutput()
				Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Output: %s", output))
			})

			It("a second ADD for the same container should leave the datastore alone", func() {
				// Try to create the same container (so CNI receives the ADD for the same endpoint again)
				log.Info("Rerunning CNI plugin")
				session, _, _, _, err := RunCNIPluginWithId(netconf, "", "", containerID, contNs)
				Expect(err).ShouldNot(HaveOccurred())
				Eventually(session).Should(gexec.Exit(0))

				// IPAM reservation should still be in place.
				checkIPAMReservation()
			})
		})
	})

	Describe("SetupRoutes works fine when the route is already programmed", func() {
		Context("container route already exists on the host", func() {
			netconf := fmt.Sprintf(`
			{
			  "cniVersion": "%s",
			  "name": "net1",
			  "type": "calico",
			  "etcd_endpoints": "http://%s:2379",
			  "datastore_type": "%s",
			  "ipam": {
			    "type": "host-local",
			    "subnet": "10.0.0.0/8"
			  },
			  "log_level":"debug"
			}`, cniVersion, os.Getenv("ETCD_IP"), os.Getenv("DATASTORE_TYPE"))

			It("route setup should be resilient to existing route", func() {
				By("creating a CNI networked container, which should also install the container route in the host namespace")
				containerID, session, _, _, _, contNs, err := CreateContainerWithId(netconf, "", "", "meep1337")
				Expect(err).ShouldNot(HaveOccurred())
				Eventually(session).Should(gexec.Exit())

				// CNI plugin generates host side vEth name from containerID if used for "cni" orchestrator.
				hostVethName := "cali" + containerID[:utils.Min(11, len(containerID))] //"cali" + containerID
				hostVeth, err := netlink.LinkByName(hostVethName)
				Expect(err).ToNot(HaveOccurred())

				result, err := GetResultForCurrent(session, cniVersion)
				if err != nil {
					log.Fatalf("Error getting result from the session: %v\n", err)
				}

				log.Printf("Unmarshalled result: %v\n", result)

				By("setting up the same route CNI plugin installed in the initial run for the hostVeth")
				err = utils.SetupRoutes(hostVeth, result)
				Expect(err).NotTo(HaveOccurred())

				_, err = DeleteContainerWithId(netconf, contNs.Path(), "", containerID)
				Expect(err).ShouldNot(HaveOccurred())
			})
		})
	})
})
