// Copyright (c) 2015-2021 Tigera, Inc. All rights reserved.

package main_test

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"

	cniv1 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/plugins/pkg/ns"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/vishvananda/netlink"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/cni-plugin/internal/pkg/testutils"
	"github.com/projectcalico/calico/cni-plugin/internal/pkg/utils"
	grpc_dataplane "github.com/projectcalico/calico/cni-plugin/pkg/dataplane/grpc"
	"github.com/projectcalico/calico/cni-plugin/pkg/dataplane/grpc/proto"
	"github.com/projectcalico/calico/cni-plugin/pkg/dataplane/linux"
	libapiv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/names"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

var _ = Describe("CalicoCni", func() {
	hostname, _ := names.Hostname()
	ctx := context.Background()
	calicoClient, _ := client.NewFromEnv()

	BeforeEach(func() {
		if os.Getenv("DATASTORE_TYPE") == "kubernetes" {
			Skip("Don't run non-kubernetes test with Kubernetes Datastore")
		}
		testutils.WipeDatastore()
		// Create the node for these tests. The IPAM code requires a corresponding Calico node to exist.
		var err error
		n := libapiv3.NewNode()
		n.Name, err = names.Hostname()
		Expect(err).NotTo(HaveOccurred())
		_, err = calicoClient.Nodes().Create(context.Background(), n, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		if os.Getenv("DATASTORE_TYPE") == "kubernetes" {
			// no cleanup needed.
			return
		}

		// Delete the node.
		name, err := names.Hostname()
		Expect(err).NotTo(HaveOccurred())
		_, err = calicoClient.Nodes().Delete(context.Background(), name, options.DeleteOptions{})
		Expect(err).NotTo(HaveOccurred())
	})

	cniVersion := os.Getenv("CNI_SPEC_VERSION")

	Context("using host-local IPAM", func() {
		netconf := fmt.Sprintf(`
		{
		  "cniVersion": "%s",
		  "name": "net1",
		  "type": "calico",
		  "etcd_endpoints": "http://%s:2379",
		  "log_level": "info",
		  "nodename_file_optional": true,
		  "datastore_type": "%s",
		  "ipam": {
		    "type": "host-local",
		    "subnet": "10.0.0.0/8"
		  }
		}`, cniVersion, os.Getenv("ETCD_IP"), os.Getenv("DATASTORE_TYPE"))

		It("successfully networks the namespace", func() {
			containerID, result, contVeth, contAddresses, contRoutes, contNs, err := testutils.CreateContainerWithId(netconf, "", testutils.TEST_DEFAULT_NS, "", "abc123")
			Expect(err).ShouldNot(HaveOccurred())

			Expect(len(result.IPs)).Should(Equal(1))
			ip := result.IPs[0].Address.IP.String()
			result.IPs[0].Address.IP = result.IPs[0].Address.IP.To4() // Make sure the IP is respresented as 4 bytes
			Expect(result.IPs[0].Address.Mask.String()).Should(Equal("ffffffff"))

			// datastore things:
			// Profile is created with correct details
			profile, err := calicoClient.Profiles().Get(ctx, "net1", options.GetOptions{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(profile.Spec.LabelsToApply).Should(Equal(map[string]string{"net1": ""}))
			Expect(profile.Spec.Egress).Should(Equal([]apiv3.Rule{{Action: "Allow"}}))
			Expect(profile.Spec.Ingress).Should(Equal([]apiv3.Rule{{Action: "Allow", Source: apiv3.EntityRule{Selector: "has(net1)"}}}))

			// The endpoint is created in etcd
			endpoints, err := calicoClient.WorkloadEndpoints().List(ctx, options.ListOptions{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(endpoints.Items).Should(HaveLen(1))

			ids := names.WorkloadEndpointIdentifiers{
				Node:         hostname,
				Orchestrator: "cni",
				Endpoint:     "eth0",
				Pod:          "",
				ContainerID:  containerID,
			}

			wrkload, err := ids.CalculateWorkloadEndpointName(false)
			Expect(err).NotTo(HaveOccurred())

			Expect(endpoints.Items[0].Name).Should(Equal(wrkload))
			Expect(endpoints.Items[0].Namespace).Should(Equal(testutils.TEST_DEFAULT_NS))

			mac := contVeth.Attrs().HardwareAddr

			Expect(endpoints.Items[0].Spec).Should(Equal(libapiv3.WorkloadEndpointSpec{
				InterfaceName: fmt.Sprintf("cali%s", containerID),
				IPNetworks:    []string{result.IPs[0].Address.String()},
				MAC:           mac.String(),
				Profiles:      []string{"net1"},
				Node:          hostname,
				Endpoint:      "eth0",
				Workload:      "",
				ContainerID:   containerID,
				Orchestrator:  "cni",
			}))

			// Routes and interface on host - there's is nothing to assert on the routes since felix adds those.
			hostVethName := "cali" + containerID[:utils.Min(11, len(containerID))] //"cali" + containerID

			hostVeth, err := netlink.LinkByName(hostVethName)
			Expect(err).ToNot(HaveOccurred())
			Expect(hostVeth.Attrs().Flags.String()).Should(ContainSubstring("up"))
			Expect(hostVeth.Attrs().MTU).Should(Equal(1500))
			Expect(hostVeth.Attrs().HardwareAddr.String()).Should(Equal("ee:ee:ee:ee:ee:ee"))

			// Assert hostVeth sysctl values are set to what we expect for IPv4.
			err = testutils.CheckSysctlValue(fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/proxy_arp", hostVethName), "1")
			Expect(err).ShouldNot(HaveOccurred())
			err = testutils.CheckSysctlValue(fmt.Sprintf("/proc/sys/net/ipv4/neigh/%s/proxy_delay", hostVethName), "0")
			Expect(err).ShouldNot(HaveOccurred())
			err = testutils.CheckSysctlValue(fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/forwarding", hostVethName), "1")
			Expect(err).ShouldNot(HaveOccurred())

			// Assert the container sysctl values are set to what we expect for IPv4.
			targetNs, _ := ns.GetNS(contNs.Path())
			err = targetNs.Do(func(_ ns.NetNS) error {
				return testutils.CheckSysctlValue("/proc/sys/net/ipv4/ip_forward", "0")
			})
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
				Family:    syscall.AF_INET,
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
				Family:    syscall.AF_INET,
			}),
				ContainElement(netlink.Route{
					LinkIndex: contVeth.Attrs().Index,
					Scope:     netlink.SCOPE_LINK,
					Dst:       &net.IPNet{IP: net.IPv4(169, 254, 1, 1).To4(), Mask: net.CIDRMask(32, 32)},
					Protocol:  syscall.RTPROT_BOOT,
					Table:     syscall.RT_TABLE_MAIN,
					Type:      syscall.RTN_UNICAST,
					Family:    syscall.AF_INET,
				})))

			_, err = testutils.DeleteContainerWithId(netconf, contNs.Path(), "", testutils.TEST_DEFAULT_NS, containerID)
			Expect(err).ShouldNot(HaveOccurred())

			// Make sure there are no endpoints anymore
			endpoints, err = calicoClient.WorkloadEndpoints().List(ctx, options.ListOptions{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(endpoints.Items).Should(HaveLen(0))

			// Make sure the interface has been removed from the namespace
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
				containerID := fmt.Sprintf("con%d", rand.Uint32())
				if err := testutils.CreateHostVeth(containerID, "", "", hostname); err != nil {
					panic(err)
				}
				_, _, _, _, _, contNs, err := testutils.CreateContainerWithId(netconf, "", testutils.TEST_DEFAULT_NS, "", containerID)
				Expect(err).ShouldNot(HaveOccurred())

				_, err = testutils.DeleteContainerWithId(netconf, contNs.Path(), "", testutils.TEST_DEFAULT_NS, containerID)
				Expect(err).ShouldNot(HaveOccurred())
			})
		})

		Context("when ready flag is false", func() {
			It("errors when ADD is done", func() {
				ci, err := calicoClient.ClusterInformation().Get(ctx, "default", options.GetOptions{})
				Expect(err).ShouldNot(HaveOccurred())
				r := false
				ci.Spec.DatastoreReady = &r
				_, err = calicoClient.ClusterInformation().Update(ctx, ci, options.SetOptions{})
				Expect(err).ShouldNot(HaveOccurred())
				_, _, _, _, _, _, err = testutils.CreateContainer(netconf, "", testutils.TEST_DEFAULT_NS, "")
				Expect(err).Should(HaveOccurred())
			})

			It("errors when DEL is done", func() {
				_, _, _, _, _, contNs, err := testutils.CreateContainer(netconf, "", testutils.TEST_DEFAULT_NS, "")
				Expect(err).ShouldNot(HaveOccurred())

				ci, err := calicoClient.ClusterInformation().Get(ctx, "default", options.GetOptions{})
				Expect(err).ShouldNot(HaveOccurred())
				r := false
				ci.Spec.DatastoreReady = &r
				_, err = calicoClient.ClusterInformation().Update(ctx, ci, options.SetOptions{})
				Expect(err).ShouldNot(HaveOccurred())

				exitCode, err := testutils.DeleteContainer(netconf, contNs.Path(), "", testutils.TEST_DEFAULT_NS)
				Expect(err).ShouldNot(HaveOccurred())
				Expect(exitCode).ShouldNot(Equal(0))
			})
		})

		Context("when ready flag is missing", func() {
			It("errors when ADD is done", func() {
				_, err := calicoClient.ClusterInformation().Delete(ctx, "default", options.DeleteOptions{})
				Expect(err).ShouldNot(HaveOccurred())
				_, _, _, _, _, _, err = testutils.CreateContainer(netconf, "", testutils.TEST_DEFAULT_NS, "")
				Expect(err).Should(HaveOccurred())
			})

			It("errors when DEL is done", func() {
				_, _, _, _, _, contNs, err := testutils.CreateContainer(netconf, "", testutils.TEST_DEFAULT_NS, "")
				Expect(err).ShouldNot(HaveOccurred())

				_, err = calicoClient.ClusterInformation().Delete(ctx, "default", options.DeleteOptions{})
				Expect(err).ShouldNot(HaveOccurred())
				exitCode, err := testutils.DeleteContainer(netconf, contNs.Path(), "", testutils.TEST_DEFAULT_NS)
				Expect(err).ShouldNot(HaveOccurred())
				Expect(exitCode).ShouldNot(Equal(0))
			})
		})
	})

	Context("With IP forwarding enabled", func() {
		netconf := fmt.Sprintf(`
			{
			  "cniVersion": "%s",
			  "name": "net1",
			  "type": "calico",
			  "etcd_endpoints": "http://%s:2379",
			  "log_level": "info",
			  "nodename_file_optional": true,
			  "datastore_type": "%s",
			  "container_settings": {
			    "allow_ip_forwarding": true
			  },
			  "ipam": {
			    "type": "host-local",
			    "subnet": "10.0.0.0/8"
			  }
			}`, cniVersion, os.Getenv("ETCD_IP"), os.Getenv("DATASTORE_TYPE"))

		It("should enable IPv4 forwarding", func() {
			containerID := fmt.Sprintf("con%d", rand.Uint32())
			_, _, _, _, _, contNs, err := testutils.CreateContainerWithId(netconf, "", testutils.TEST_DEFAULT_NS, "", containerID)

			By("successfully networking the container", func() {
				Expect(err).ShouldNot(HaveOccurred())
			})

			By("asserting IPv4 forwarding is enabled", func() {
				targetNs, _ := ns.GetNS(contNs.Path())
				err = targetNs.Do(func(_ ns.NetNS) error {
					return testutils.CheckSysctlValue("/proc/sys/net/ipv4/ip_forward", "1")
				})
				Expect(err).ShouldNot(HaveOccurred())
			})

			By("tearing down the container", func() {
				_, err = testutils.DeleteContainerWithId(netconf, contNs.Path(), "", testutils.TEST_DEFAULT_NS, containerID)
				Expect(err).ShouldNot(HaveOccurred())
			})
		})
	})

	Context("With an invalid dataplane type", func() {
		netconf := fmt.Sprintf(`
			{
			  "cniVersion": "%s",
			  "name": "net1",
			  "type": "calico",
			  "etcd_endpoints": "http://%s:2379",
			  "log_level": "info",
			  "nodename_file_optional": true,
			  "datastore_type": "%s",
			  "ipam": {
			    "type": "host-local",
			    "subnet": "10.0.0.0/8"
			  },
			  "dataplane_options": {
			  	"type": "invalid-dataplane-type"
			  }
			}`, cniVersion, os.Getenv("ETCD_IP"), os.Getenv("DATASTORE_TYPE"))

		It("fails with an error", func() {
			_, _, _, _, _, _, err := testutils.CreateContainer(netconf, "", testutils.TEST_DEFAULT_NS, "")
			Expect(err).Should(HaveOccurred())
		})
	})

	Context("With a misconfigured gRPC dataplane", func() {
		netconf := fmt.Sprintf(`
			{
			  "cniVersion": "%s",
			  "name": "net1",
			  "type": "calico",
			  "etcd_endpoints": "http://%s:2379",
			  "log_level": "info",
			  "nodename_file_optional": true,
			  "datastore_type": "%s",
			  "ipam": {
			    "type": "host-local",
			    "subnet": "10.0.0.0/8"
			  },
			  "dataplane_options": {
			  	"type": "grpc",
			  	"socket": "unix:///tmp/xxxx-non-existent-dont-create-this-please.sock"
			  }
			}`, cniVersion, os.Getenv("ETCD_IP"), os.Getenv("DATASTORE_TYPE"))

		It("fails with an error", func() {
			_, _, _, _, _, _, err := testutils.CreateContainer(netconf, "", testutils.TEST_DEFAULT_NS, "")
			Expect(err).Should(HaveOccurred())
		})
	})

	Context("With a gRPC dataplane", func() {
		It("communicates with the dataplane", func(done Done) {
			var contNs ns.NetNS
			var grpcBackend *grpc_dataplane.TestServer
			var exitCode int
			var err error
			socket := fmt.Sprintf("/tmp/cni_grpc_dataplane_test%d.sock", rand.Uint32())
			netconf := fmt.Sprintf(`
				{
					"cniVersion": "%s",
					"name": "net1",
					"type": "calico",
					"etcd_endpoints": "http://%s:2379",
					"log_level": "info",
					"nodename_file_optional": true,
					"datastore_type": "%s",
					"ipam": {
			    		"type": "host-local",
			    		"subnet": "10.0.0.0/8"
					},
					"dataplane_options": {
			  			"type": "grpc",
			  			"socket": "unix://%s",
						"extra": "option"
					}
				}`, cniVersion, os.Getenv("ETCD_IP"), os.Getenv("DATASTORE_TYPE"), socket)

			grpcBackend, err = grpc_dataplane.StartTestServer(socket, true, "00:11:22:33:44:55")
			Expect(err).ShouldNot(HaveOccurred())
			Expect(grpcBackend).ShouldNot(Equal(nil))

			By("sending ADD requests to the gRPC backend")
			_, _, _, _, _, contNs, err = testutils.CreateContainer(netconf, "", testutils.TEST_DEFAULT_NS, "")
			Expect(err).ShouldNot(HaveOccurred())
			message := <-grpcBackend.Received
			addRequest, ok := message.(*proto.AddRequest)
			Expect(ok).Should(BeTrue())
			Expect(addRequest.Netns).Should(Equal(contNs.Path()))
			option, ok := addRequest.DataplaneOptions["extra"]
			Expect(ok).Should(BeTrue())
			Expect(option).Should(Equal("option"))
			Expect(len(addRequest.ContainerIps)).Should(BeNumerically(">=", 1))

			By("erroring if the backend fails to cleanup an interface")
			grpcBackend.SetResult(false)
			exitCode, err = testutils.DeleteContainer(netconf, contNs.Path(), "", testutils.TEST_DEFAULT_NS)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(exitCode).ShouldNot(Equal(0))
			message = <-grpcBackend.Received
			_, ok = message.(*proto.DelRequest)
			Expect(ok).Should(BeTrue())

			By("sending DEL requests to the gRPC backend")
			grpcBackend.SetResult(true)
			exitCode, err = testutils.DeleteContainer(netconf, contNs.Path(), "", testutils.TEST_DEFAULT_NS)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(exitCode).Should(Equal(0))
			message = <-grpcBackend.Received
			delRequest, ok := message.(*proto.DelRequest)
			Expect(ok).Should(BeTrue())
			Expect(delRequest.Netns).Should(Equal(contNs.Path()))
			option, ok = delRequest.DataplaneOptions["extra"]
			Expect(ok).Should(BeTrue())
			Expect(option).Should(Equal("option"))

			By("erroring if the backend fails to configure an interface")
			grpcBackend.SetResult(false)
			_, _, _, _, _, _, err = testutils.CreateContainer(netconf, "", testutils.TEST_DEFAULT_NS, "")
			Expect(err).Should(HaveOccurred())
			message = <-grpcBackend.Received
			_, ok = message.(*proto.AddRequest)
			Expect(ok).Should(BeTrue())

			grpcBackend.GracefulStop()
			err = syscall.Unlink(socket)
			if err != nil && !strings.Contains(err.Error(), "no such file or directory") {
				Expect(err).NotTo(HaveOccurred())
			}
			close(done)
		}, 30.0)
	})

	Context("deprecate hostname for nodename", func() {
		netconf := fmt.Sprintf(`
		{
		  "cniVersion": "%s",
		  "name": "net1",
		  "type": "calico",
		  "etcd_endpoints": "http://%s:2379",
		  "hostname": "named-hostname.somewhere",
		  "nodename_file_optional": true,
		  "datastore_type": "%s",
		  "ipam": {
		    "type": "host-local",
		    "subnet": "10.0.0.0/8"
		  }
		}`, cniVersion, os.Getenv("ETCD_IP"), os.Getenv("DATASTORE_TYPE"))

		It("has hostname even though deprecated", func() {
			containerID, _, _, _, _, contNs, err := testutils.CreateContainerWithId(netconf, "", testutils.TEST_DEFAULT_NS, "", "abcd1234")
			Expect(err).ShouldNot(HaveOccurred())

			// The endpoint is created in etcd
			endpoints, err := calicoClient.WorkloadEndpoints().List(ctx, options.ListOptions{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(endpoints.Items).Should(HaveLen(1))

			ids := names.WorkloadEndpointIdentifiers{
				Node:         "named-hostname.somewhere",
				Orchestrator: "cni",
				Endpoint:     "eth0",
				Pod:          "",
				ContainerID:  containerID,
			}

			wrkload, err := ids.CalculateWorkloadEndpointName(false)
			Expect(err).NotTo(HaveOccurred())

			Expect(endpoints.Items[0].Name).Should(Equal(wrkload))
			Expect(endpoints.Items[0].Namespace).Should(Equal(testutils.TEST_DEFAULT_NS))
			Expect(endpoints.Items[0].Spec.Node).Should(Equal("named-hostname.somewhere"))

			_, err = testutils.DeleteContainerWithId(netconf, contNs.Path(), "", testutils.TEST_DEFAULT_NS, containerID)
			Expect(err).ShouldNot(HaveOccurred())
		})

		netconf2 := fmt.Sprintf(`
		{
		  "cniVersion": "%s",
		  "name": "net1",
		  "type": "calico",
		  "etcd_endpoints": "http://%s:2379",
		  "hostname": "named-hostname",
		  "nodename": "named-nodename",
		  "nodename_file_optional": true,
		  "datastore_type": "%s",
		  "ipam": {
		    "type": "host-local",
		    "subnet": "10.0.0.0/8"
		  }
		}`, cniVersion, os.Getenv("ETCD_IP"), os.Getenv("DATASTORE_TYPE"))

		It("nodename takes precedence over hostname", func() {
			containerID, _, _, _, _, contNs, err := testutils.CreateContainerWithId(netconf2, "", testutils.TEST_DEFAULT_NS, "", "abcd")
			Expect(err).ShouldNot(HaveOccurred())

			// The endpoint is created in etcd
			endpoints, err := calicoClient.WorkloadEndpoints().List(ctx, options.ListOptions{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(endpoints.Items).Should(HaveLen(1))

			ids := names.WorkloadEndpointIdentifiers{
				Node:         "named-nodename",
				Orchestrator: "cni",
				Endpoint:     "eth0",
				Pod:          "",
				ContainerID:  containerID,
			}

			wrkload, err := ids.CalculateWorkloadEndpointName(false)
			Expect(err).NotTo(HaveOccurred())

			Expect(endpoints.Items[0].Name).Should(Equal(wrkload))
			Expect(endpoints.Items[0].Namespace).Should(Equal(testutils.TEST_DEFAULT_NS))

			Expect(endpoints.Items[0].Spec.Node).Should(Equal("named-nodename"))

			_, err = testutils.DeleteContainerWithId(netconf2, contNs.Path(), "", testutils.TEST_DEFAULT_NS, containerID)
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
			  "hostname": "named-hostname.somewhere",
		          "nodename_file_optional": true,
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
			containerID, _, _, _, _, contNs, err := testutils.CreateContainerWithId(netconf, "", testutils.TEST_DEFAULT_NS, "", "abcd1234")
			Expect(err).ShouldNot(HaveOccurred())

			// The endpoint is created in etcd
			endpoints, err := calicoClient.WorkloadEndpoints().List(ctx, options.ListOptions{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(endpoints.Items).Should(HaveLen(1))
			Expect(endpoints.Items[0].Labels["k"]).Should(Equal("v"))

			_, err = testutils.DeleteContainerWithId(netconf, contNs.Path(), "", testutils.TEST_DEFAULT_NS, containerID)
			Expect(err).ShouldNot(HaveOccurred())
		})

		It("sanitizes dcos label", func() {
			netconf := fmt.Sprintf(`
			{
			  "cniVersion": "%s",
			  "name": "net1",
			  "type": "calico",
			  "etcd_endpoints": "http://%s:2379",
			  "hostname": "named-hostname.somewhere",
		          "nodename_file_optional": true,
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
			containerID, _, _, _, _, contNs, err := testutils.CreateContainerWithId(netconf, "", testutils.TEST_DEFAULT_NS, "", "abcd1234")
			Expect(err).ShouldNot(HaveOccurred())

			// The endpoint is created in etcd
			endpoints, err := calicoClient.WorkloadEndpoints().List(ctx, options.ListOptions{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(endpoints.Items).Should(HaveLen(1))
			Expect(endpoints.Items[0].Labels["DCOS_SPACE"]).Should(Equal("a.b.c"))

			_, err = testutils.DeleteContainerWithId(netconf, contNs.Path(), "", testutils.TEST_DEFAULT_NS, containerID)
			Expect(err).ShouldNot(HaveOccurred())
		})
	})

	Context("feature flag processing", func() {
		It("errors if ip_addrs_no_ipam if not running kubernetes", func() {
			netconf := fmt.Sprintf(`
			{
				"cniVersion": "%s",
				"name": "net1",
				"type": "calico",
				"feature_control": {
					"ip_addrs_no_ipam": true
				},
				"etcd_endpoints": "http://%s:2379",
				"nodename": "named-nodename",
				"nodename_file_optional": true,
				"datastore_type": "%s",
				"ipam": {
					"type": "host-local",
					"subnet": "10.0.0.0/8"
				}
			}`, cniVersion, os.Getenv("ETCD_IP"), os.Getenv("DATASTORE_TYPE"))

			containerNs, containerId, err := testutils.CreateContainerNamespace()
			Expect(err).ToNot(HaveOccurred())

			_, _, _, _, err = testutils.RunCNIPluginWithId(netconf, "", testutils.K8S_TEST_NS, "", containerId, "", containerNs)
			Expect(err).To(HaveOccurred())
		})
	})

	Describe("DEL", func() {
		netconf := fmt.Sprintf(`
		{
			"cniVersion": "%s",
			"name": "net1",
			"type": "calico",
			"etcd_endpoints": "http://%s:2379",
			"nodename_file_optional": true,
			"datastore_type": "%s",
			"ipam": {
				"type": "host-local",
				"subnet": "10.0.0.0/8"
			}
		}`, cniVersion, os.Getenv("ETCD_IP"), os.Getenv("DATASTORE_TYPE"))

		Context("when it was never called for SetUP", func() {
			Context("and a namespace does exist", func() {
				It("exits with 'success' error code", func() {
					contNs, containerID, err := testutils.CreateContainerNamespace()
					Expect(err).ShouldNot(HaveOccurred())
					exitCode, err := testutils.DeleteContainerWithId(netconf, contNs.Path(), "", testutils.TEST_DEFAULT_NS, containerID)
					Expect(err).ShouldNot(HaveOccurred())
					Expect(exitCode).To(Equal(0))
				})
			})

			Context("and no namespace exists", func() {
				It("exits with 'success' error code", func() {
					exitCode, err := testutils.DeleteContainer(netconf, "/not/a/real/path1234567890", "", testutils.TEST_DEFAULT_NS)
					Expect(err).ShouldNot(HaveOccurred())
					Expect(exitCode).To(Equal(0))
				})
			})
		})
	})

	Describe("with calico-ipam enabled, after creating a container", func() {
		netconf := fmt.Sprintf(`
		{
		  "cniVersion": "%s",
		  "name": "net1",
		  "type": "calico",
		  "etcd_endpoints": "http://%s:2379",
		  "datastore_type": "%s",
		  "log_level": "info",
	          "nodename_file_optional": true,
		  "ipam": { "type": "calico-ipam" }
		}`, cniVersion, os.Getenv("ETCD_IP"), os.Getenv("DATASTORE_TYPE"))

		var containerID string
		var workloadName string
		var endpointSpec libapiv3.WorkloadEndpointSpec
		var contNs ns.NetNS
		var result *cniv1.Result

		checkIPAMReservation := func() {
			// IPAM reservation should still be in place.
			handleID := utils.GetHandleID("net1", containerID, workloadName)
			ipamIPs, err := calicoClient.IPAM().IPsByHandle(context.Background(), handleID)
			ExpectWithOffset(1, err).NotTo(HaveOccurred())
			ExpectWithOffset(1, ipamIPs).To(HaveLen(1),
				"There should be an IPAM handle for endpoint")
			ExpectWithOffset(1, ipamIPs[0].String()+"/32").To(Equal(endpointSpec.IPNetworks[0]))
		}

		BeforeEach(func() {
			// Create a new ipPool.
			testutils.MustCreateNewIPPool(calicoClient, "10.0.0.0/24", false, false, true)

			var err error
			containerID, result, _, _, _, contNs, err = testutils.CreateContainerWithId(netconf, "", testutils.TEST_DEFAULT_NS, "", "badbeef")
			Expect(err).ShouldNot(HaveOccurred())

			// The endpoint is created in etcd
			endpoints, err := calicoClient.WorkloadEndpoints().List(ctx, options.ListOptions{Namespace: "default"})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(endpoints.Items).To(HaveLen(1))

			ids := names.WorkloadEndpointIdentifiers{
				Node:         hostname,
				Orchestrator: "cni",
				Endpoint:     "eth0",
				Pod:          "",
				ContainerID:  containerID,
			}

			workloadName, err = ids.CalculateWorkloadEndpointName(false)
			Expect(err).NotTo(HaveOccurred())
			endpoint := endpoints.Items[0]
			Expect(endpoint.Name).Should(Equal(workloadName))
			endpointSpec = endpoint.Spec
			Expect(endpoint.Namespace).Should(Equal(testutils.TEST_DEFAULT_NS))
			Expect(endpoint.Spec.Node).Should(Equal(hostname))
			Expect(endpoint.Spec.Endpoint).Should(Equal("eth0"))
			Expect(endpoint.Spec.ContainerID).Should(Equal(containerID))
			Expect(endpoint.Spec.
				Orchestrator).Should(Equal("cni"))
			Expect(endpoint.Spec.Workload).Should(BeEmpty())

			// IPAM reservation should have been created.
			checkIPAMReservation()
		})

		AfterEach(func() {
			_, err := testutils.DeleteContainerWithId(
				netconf, contNs.Path(), "", testutils.TEST_DEFAULT_NS, containerID)
			Expect(err).ShouldNot(HaveOccurred())
		})

		It("a second ADD for the same container should be a no-op", func() {
			// Try to create the same container (so CNI receives the ADD for the same endpoint again)
			resultSecondAdd, _, _, _, err := testutils.RunCNIPluginWithId(netconf, "", testutils.TEST_DEFAULT_NS, "", containerID, "eth0", contNs)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(resultSecondAdd).Should(Equal(result))

			// The endpoint is created in etcd
			endpoints, err := calicoClient.WorkloadEndpoints().List(context.Background(), options.ListOptions{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(endpoints.Items).Should(HaveLen(1))
			Expect(endpoints.Items[0].Spec.Profiles).To(ConsistOf("net1"))

			// IPAM reservation should still be in place.
			checkIPAMReservation()
		})

		It("a second ADD with new profile ID should append it", func() {
			// Try to create the same container (so CNI receives the ADD for the same endpoint again)
			tweaked := strings.Replace(netconf, "net1", "net2", 1)
			resultSecondAdd, _, _, _, err := testutils.RunCNIPluginWithId(tweaked, "", "", "", containerID, "", contNs)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(resultSecondAdd).Should(Equal(result))

			// The endpoint is created in etcd
			endpoints, err := calicoClient.WorkloadEndpoints().List(context.Background(), options.ListOptions{})
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
				By("Breaking networking for the created interface")
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
				By("Running the CNI plugin a second time on the same container")
				_, _, _, _, err := testutils.RunCNIPluginWithId(netconf, "", "", "", containerID, "", contNs)
				Expect(err).ShouldNot(HaveOccurred())

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
			  "nodename_file_optional": true,
			  "log_level":"info"
			}`, cniVersion, os.Getenv("ETCD_IP"), os.Getenv("DATASTORE_TYPE"))

			It("route setup should be resilient to existing route", func() {
				By("creating a CNI networked container, which should also install the container route in the host namespace")
				containerID, result, _, _, _, contNs, err := testutils.CreateContainerWithId(netconf, "", testutils.TEST_DEFAULT_NS, "", "meep1337")
				Expect(err).ShouldNot(HaveOccurred())

				// CNI plugin generates host side vEth name from containerID if used for "cni" orchestrator.
				hostVethName := "cali" + containerID[:utils.Min(11, len(containerID))] //"cali" + containerID
				hostVeth, err := netlink.LinkByName(hostVethName)
				Expect(err).ToNot(HaveOccurred())

				By("setting up the same route CNI plugin installed in the initial run for the hostVeth")
				err = linux.SetupRoutes(hostVeth, result)
				Expect(err).NotTo(HaveOccurred())

				_, err = testutils.DeleteContainerWithId(netconf, contNs.Path(), "", testutils.TEST_DEFAULT_NS, containerID)
				Expect(err).ShouldNot(HaveOccurred())
			})
		})
	})

	Describe("testConnection tests", func() {

		It("successfully connects to the datastore", func(done Done) {
			netconf := fmt.Sprintf(`
{
  "cniVersion": "%s",
  "name": "net1",
  "type": "calico",
  "etcd_endpoints": "http://%s:2379",
  "log_level": "info",
  "nodename_file_optional": true,
  "datastore_type": "%s",
  "ipam": {
	"type": "host-local",
	"subnet": "10.0.0.0/8"
  }
}`, cniVersion, os.Getenv("ETCD_IP"), os.Getenv("DATASTORE_TYPE"))
			pluginPath := fmt.Sprintf("%s/%s", os.Getenv("BIN"), os.Getenv("PLUGIN"))
			c := exec.Command(pluginPath, "-t")
			stdin, err := c.StdinPipe()
			Expect(err).ToNot(HaveOccurred())

			go func() {
				defer stdin.Close()
				_, _ = io.WriteString(stdin, netconf)
			}()

			_, err = c.CombinedOutput()
			Expect(err).ToNot(HaveOccurred())
			close(done)
		}, 10)

		It("reports it cannot connect to the datastore", func(done Done) {
			// wrong port.
			netconf := fmt.Sprintf(`
{
  "cniVersion": "%s",
  "name": "net1",
  "type": "calico",
  "etcd_endpoints": "http://%s:2370",
  "log_level": "info",
  "nodename_file_optional": true,
  "datastore_type": "%s",
  "ipam": {
	"type": "host-local",
	"subnet": "10.0.0.0/8"
  }
}`, cniVersion, os.Getenv("ETCD_IP"), os.Getenv("DATASTORE_TYPE"))
			pluginPath := fmt.Sprintf("%s/%s", os.Getenv("BIN"), os.Getenv("PLUGIN"))
			c := exec.Command(pluginPath, "-t")
			stdin, err := c.StdinPipe()
			Expect(err).ToNot(HaveOccurred())

			go func() {
				defer stdin.Close()
				_, _ = io.WriteString(stdin, netconf)
			}()

			_, err = c.CombinedOutput()
			Expect(err).To(HaveOccurred())
			close(done)
		}, 10)

	})
})
