package main_test

import (
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/containernetworking/cni/pkg/ns"
	"github.com/containernetworking/cni/pkg/types/current"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gexec"
	. "github.com/projectcalico/cni-plugin/test_utils"
	"github.com/projectcalico/cni-plugin/utils"
	"github.com/projectcalico/libcalico-go/lib/api"
	"github.com/projectcalico/libcalico-go/lib/backend/k8s"
	"github.com/projectcalico/libcalico-go/lib/client"
	"github.com/projectcalico/libcalico-go/lib/logutils"
	cnet "github.com/projectcalico/libcalico-go/lib/net"
	"github.com/projectcalico/libcalico-go/lib/testutils"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/pkg/api/v1"
	"k8s.io/client-go/tools/clientcmd"
)

func init() {
	// Create a random seed
	rand.Seed(time.Now().UTC().UnixNano())
	log.SetFormatter(&logutils.Formatter{})
	log.AddHook(&logutils.ContextHook{})
	log.SetOutput(GinkgoWriter)
	log.SetLevel(log.DebugLevel)
}

var _ = Describe("CalicoCni", func() {
	hostname, _ := os.Hostname()
	BeforeEach(func() {
		WipeK8sPods()
		WipeEtcd()
	})

	Describe("Run Calico CNI plugin in K8s mode", func() {
		utils.ConfigureLogging("info")
		cniVersion := os.Getenv("CNI_SPEC_VERSION")

		Context("using host-local IPAM", func() {

			//TODO - set the netconfig
			netconf := fmt.Sprintf(`
			{
			  "cniVersion": "%s",
			  "name": "net1",
			  "type": "calico",
			  "etcd_endpoints": "http://%s:2379",
			  "ipam": {
			    "type": "host-local",
			    "subnet": "10.0.0.0/8"
			  },
			  "kubernetes": {
			    "k8s_api_root": "http://127.0.0.1:8080"
			  },
			  "policy": {"type": "k8s"},
			  "log_level":"info"
			}`, cniVersion, os.Getenv("ETCD_IP"))

			It("successfully networks the namespace", func() {
				config, err := clientcmd.DefaultClientConfig.ClientConfig()
				if err != nil {
					panic(err)
				}
				clientset, err := kubernetes.NewForConfig(config)

				if err != nil {
					panic(err)
				}

				name := fmt.Sprintf("run%d", rand.Uint32())
				interfaceName := k8s.VethNameForWorkload(fmt.Sprintf("%s.%s", K8S_TEST_NS, name))

				// Create a K8s pod w/o any special params
				_, err = clientset.Pods(K8S_TEST_NS).Create(&v1.Pod{
					ObjectMeta: metav1.ObjectMeta{Name: name},
					Spec: v1.PodSpec{Containers: []v1.Container{{
						Name:  fmt.Sprintf("container-%s", name),
						Image: "ignore",
					}}},
				})
				if err != nil {
					panic(err)
				}
				containerID, session, contVeth, contAddresses, contRoutes, contNs, err := CreateContainer(netconf, name, "")

				Expect(err).ShouldNot(HaveOccurred())
				Eventually(session).Should(gexec.Exit())

				result, err := GetResultForCurrent(session, cniVersion)
				if err != nil {
					log.Fatalf("Error getting result from the session: %v\n", err)
				}

				mac := contVeth.Attrs().HardwareAddr

				Expect(len(result.IPs)).Should(Equal(1))
				ip := result.IPs[0].Address.IP.String()
				result.IPs[0].Address.IP = result.IPs[0].Address.IP.To4() // Make sure the IP is respresented as 4 bytes
				Expect(result.IPs[0].Address.Mask.String()).Should(Equal("ffffffff"))

				// datastore things:
				// TODO Make sure the profile doesn't exist

				// The endpoint is created
				endpoints, err := calicoClient.WorkloadEndpoints().List(api.WorkloadEndpointMetadata{})
				Expect(err).ShouldNot(HaveOccurred())
				Expect(endpoints.Items).Should(HaveLen(1))

				// Set the Revision to nil since we can't assert its exact value.
				endpoints.Items[0].Metadata.Revision = nil
				Expect(endpoints.Items[0].Metadata).Should(Equal(api.WorkloadEndpointMetadata{
					Node:             hostname,
					Name:             "eth0",
					Workload:         fmt.Sprintf("test.%s", name),
					ActiveInstanceID: containerID,
					Orchestrator:     "k8s",
					Labels:           map[string]string{"calico/k8s_ns": "test"},
				}))
				Expect(endpoints.Items[0].Spec).Should(Equal(api.WorkloadEndpointSpec{
					InterfaceName: interfaceName,
					IPNetworks:    []cnet.IPNet{{result.IPs[0].Address}},
					MAC:           &cnet.MAC{HardwareAddr: mac},
					Profiles:      []string{"k8s_ns.test"},
				}))

				// Routes and interface on host - there's is nothing to assert on the routes since felix adds those.
				// fmt.Println(Cmd("ip link show")) // Useful for debugging
				hostVeth, err := netlink.LinkByName(interfaceName)
				Expect(err).ToNot(HaveOccurred())
				Expect(hostVeth.Attrs().Flags.String()).Should(ContainSubstring("up"))
				Expect(hostVeth.Attrs().MTU).Should(Equal(1500))

				// Assert hostVeth sysctl values are set to what we expect for IPv4.
				err = CheckSysctlValue(fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/proxy_arp", interfaceName), "1")
				Expect(err).ShouldNot(HaveOccurred())
				err = CheckSysctlValue(fmt.Sprintf("/proc/sys/net/ipv4/neigh/%s/proxy_delay", interfaceName), "0")
				Expect(err).ShouldNot(HaveOccurred())
				err = CheckSysctlValue(fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/forwarding", interfaceName), "1")
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
				Expect(contRoutes).Should(SatisfyAll(
					ContainElement(netlink.Route{
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

				_, err = DeleteContainer(netconf, contNs.Path(), name)
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
					config, err := clientcmd.DefaultClientConfig.ClientConfig()
					Expect(err).NotTo(HaveOccurred())

					clientset, err := kubernetes.NewForConfig(config)
					Expect(err).NotTo(HaveOccurred())

					name := fmt.Sprintf("run%d", rand.Uint32())

					// Create a K8s pod w/o any special params
					_, err = clientset.Pods(K8S_TEST_NS).Create(&v1.Pod{
						ObjectMeta: metav1.ObjectMeta{Name: name},
						Spec: v1.PodSpec{Containers: []v1.Container{{
							Name:  fmt.Sprintf("container-%s", name),
							Image: "ignore",
						}}},
					})
					Expect(err).NotTo(HaveOccurred())

					if err := CreateHostVeth("", name, K8S_TEST_NS); err != nil {
						panic(err)
					}
					_, session, _, _, _, contNs, err := CreateContainer(netconf, name, "")
					Expect(err).ShouldNot(HaveOccurred())
					Eventually(session).Should(gexec.Exit(0))

					_, err = DeleteContainer(netconf, contNs.Path(), name)
					Expect(err).ShouldNot(HaveOccurred())
				})
			})

			Context("using calico-ipam with ipPools annotation", func() {
				It("successfully assigns an IP address from the annotated ipPool", func() {
					netconfCalicoIPAM := fmt.Sprintf(`
				{
			      "cniVersion": "%s",
				  "name": "net2",
				  "type": "calico",
				  "etcd_endpoints": "http://%s:2379",
			 	  "ipam": {
			    	 "type": "calico-ipam"
			         },
					"kubernetes": {
					  "k8s_api_root": "http://127.0.0.1:8080"
					 },
					"policy": {"type": "k8s"},
					"log_level":"info"
				}`, cniVersion, os.Getenv("ETCD_IP"))

					// Create a new ipPool.
					ipPool := "172.16.0.0/16"
					c, _ := client.NewFromEnv()
					testutils.CreateNewIPPool(*c, ipPool, false, false, true)
					_, ipPoolCIDR, err := net.ParseCIDR(ipPool)
					Expect(err).NotTo(HaveOccurred())

					config, err := clientcmd.DefaultClientConfig.ClientConfig()
					Expect(err).NotTo(HaveOccurred())

					clientset, err := kubernetes.NewForConfig(config)
					Expect(err).NotTo(HaveOccurred())

					// Now create a K8s pod passing in an IP pool.
					name := fmt.Sprintf("run%d-pool", rand.Uint32())
					pod, err := clientset.Pods(K8S_TEST_NS).Create(&v1.Pod{
						ObjectMeta: metav1.ObjectMeta{
							Name: name,
							Annotations: map[string]string{
								"cni.projectcalico.org/ipv4pools": "[\"172.16.0.0/16\"]",
							},
						},
						Spec: v1.PodSpec{Containers: []v1.Container{{
							Name:  fmt.Sprintf("container-%s", name),
							Image: "ignore",
						}}},
					})
					Expect(err).NotTo(HaveOccurred())

					log.Infof("Created POD object: %v", pod)

					_, _, _, contAddresses, _, contNs, err := CreateContainer(netconfCalicoIPAM, name, "")
					Expect(err).NotTo(HaveOccurred())

					podIP := contAddresses[0].IP
					log.Infof("All container IPs: %v", contAddresses)
					log.Infof("Container got IP address: %s", podIP)
					Expect(ipPoolCIDR.Contains(podIP)).To(BeTrue())

					// Delete the container.
					_, err = DeleteContainer(netconfCalicoIPAM, contNs.Path(), name)
					Expect(err).ShouldNot(HaveOccurred())
				})
			})

			Context("using ipAddrsNoIpam annotation to assign IP address to a pod, bypassing IPAM", func() {
				It("should successfully assigns the annotated IP address", func() {
					netconfCalicoIPAM := fmt.Sprintf(`
				{
			      "cniVersion": "%s",
				  "name": "net3",
				  "type": "calico",
				  "etcd_endpoints": "http://%s:2379",
			 	  "ipam": {},
					"kubernetes": {
					  "k8s_api_root": "http://127.0.0.1:8080"
					 },
					"policy": {"type": "k8s"},
					"log_level":"info"
				}`, cniVersion, os.Getenv("ETCD_IP"))

					assignIP := net.IPv4(10, 0, 0, 1).To4()

					config, err := clientcmd.DefaultClientConfig.ClientConfig()
					Expect(err).NotTo(HaveOccurred())

					clientset, err := kubernetes.NewForConfig(config)
					Expect(err).NotTo(HaveOccurred())

					// Now create a K8s pod passing in an IP address.
					name := fmt.Sprintf("run%d-ip", rand.Uint32())
					pod, err := clientset.Pods(K8S_TEST_NS).Create(&v1.Pod{
						ObjectMeta: metav1.ObjectMeta{
							Name: name,
							Annotations: map[string]string{
								"cni.projectcalico.org/ipAddrsNoIpam": "[\"10.0.0.1\"]",
							},
						},
						Spec: v1.PodSpec{Containers: []v1.Container{{
							Name:  fmt.Sprintf("container-%s", name),
							Image: "ignore",
						}}},
					})
					Expect(err).NotTo(HaveOccurred())

					log.Infof("Created POD object: %v", pod)

					containerID, _, contVeth, contAddresses, _, contNs, err := CreateContainer(netconfCalicoIPAM, name, "")
					Expect(err).NotTo(HaveOccurred())
					mac := contVeth.Attrs().HardwareAddr

					podIP := contAddresses[0].IP
					log.Infof("All container IPs: %v", contAddresses)
					log.Infof("Container got IP address: %s", podIP)
					Expect(podIP).Should(Equal(assignIP))

					interfaceName := k8s.VethNameForWorkload(fmt.Sprintf("%s.%s", K8S_TEST_NS, name))

					// The endpoint is created
					endpoints, err := calicoClient.WorkloadEndpoints().List(api.WorkloadEndpointMetadata{})
					Expect(err).ShouldNot(HaveOccurred())
					Expect(endpoints.Items).Should(HaveLen(1))

					// Set the Revision to nil since we can't assert it's exact value.
					endpoints.Items[0].Metadata.Revision = nil
					Expect(endpoints.Items[0].Metadata).Should(Equal(api.WorkloadEndpointMetadata{
						Node:             hostname,
						Name:             "eth0",
						Workload:         fmt.Sprintf("test.%s", name),
						ActiveInstanceID: containerID,
						Orchestrator:     "k8s",
						Labels:           map[string]string{"calico/k8s_ns": "test"},
					}))
					Expect(endpoints.Items[0].Spec).Should(Equal(api.WorkloadEndpointSpec{
						InterfaceName: interfaceName,
						IPNetworks: []cnet.IPNet{{net.IPNet{
							IP:   assignIP,
							Mask: net.CIDRMask(32, 32),
						}}},
						MAC:      &cnet.MAC{HardwareAddr: mac},
						Profiles: []string{"k8s_ns.test"},
					}))

					// Delete the container.
					_, err = DeleteContainer(netconfCalicoIPAM, contNs.Path(), name)
					Expect(err).ShouldNot(HaveOccurred())
				})
			})

			Context("using ipAddrs annotation to assign IP address to a pod, through Calico IPAM", func() {

				It("should successfully assigns the annotated IP address", func() {
					netconfCalicoIPAM := fmt.Sprintf(`
				{
				  "cniVersion": "%s",
				  "name": "net4",
				  "type": "calico",
				  "etcd_endpoints": "http://%s:2379",
				  "ipam": {
					   "type": "calico-ipam",
					   "assign_ipv4": "true",
					   "assign_ipv6": "true"
				   },
					"kubernetes": {
					  "k8s_api_root": "http://127.0.0.1:8080"
					 },
					"policy": {"type": "k8s"},
					"log_level":"info"
				}`, cniVersion, os.Getenv("ETCD_IP"))

					assignIP := net.IPv4(20, 0, 0, 111).To4()

					// Create a new ipPool.
					ipPool := "20.0.0.0/24"
					c, _ := client.NewFromEnv()
					testutils.CreateNewIPPool(*c, ipPool, false, false, true)
					_, _, err := net.ParseCIDR(ipPool)
					Expect(err).NotTo(HaveOccurred())

					config, err := clientcmd.DefaultClientConfig.ClientConfig()
					Expect(err).NotTo(HaveOccurred())

					clientset, err := kubernetes.NewForConfig(config)
					Expect(err).NotTo(HaveOccurred())

					// Now create a K8s pod passing in an IP address.
					name := fmt.Sprintf("run%d-ip", rand.Uint32())
					pod, err := clientset.Pods(K8S_TEST_NS).Create(&v1.Pod{
						ObjectMeta: metav1.ObjectMeta{
							Name: name,
							Annotations: map[string]string{
								"cni.projectcalico.org/ipAddrs": "[\"20.0.0.111\"]",
							},
						},
						Spec: v1.PodSpec{Containers: []v1.Container{{
							Name:  fmt.Sprintf("container-%s", name),
							Image: "ignore",
						}}},
					})
					Expect(err).NotTo(HaveOccurred())

					log.Infof("Created POD object: %v", pod)

					containerID, _, contVeth, contAddresses, _, contNt, err := CreateContainer(netconfCalicoIPAM, name, "")
					Expect(err).NotTo(HaveOccurred())
					mac := contVeth.Attrs().HardwareAddr

					podIP := contAddresses[0].IP
					log.Infof("All container IPs: %v", contAddresses)
					log.Infof("Container got IP address: %s", podIP)
					Expect(podIP).Should(Equal(assignIP))

					interfaceName := k8s.VethNameForWorkload(fmt.Sprintf("%s.%s", K8S_TEST_NS, name))

					// Make sure WorkloadEndpoint is created and has the requested IP in the datastore.
					endpoints, err := calicoClient.WorkloadEndpoints().List(api.WorkloadEndpointMetadata{})
					Expect(err).ShouldNot(HaveOccurred())
					Expect(endpoints.Items).Should(HaveLen(1))

					// Set the Revision to nil since we can't assert it's exact value.
					endpoints.Items[0].Metadata.Revision = nil
					Expect(endpoints.Items[0].Metadata).Should(Equal(api.WorkloadEndpointMetadata{
						Node:             hostname,
						Name:             "eth0",
						Workload:         fmt.Sprintf("test.%s", name),
						ActiveInstanceID: containerID,
						Orchestrator:     "k8s",
						Labels:           map[string]string{"calico/k8s_ns": "test"},
					}))
					Expect(endpoints.Items[0].Spec).Should(Equal(api.WorkloadEndpointSpec{
						InterfaceName: interfaceName,
						IPNetworks: []cnet.IPNet{{net.IPNet{
							IP:   assignIP,
							Mask: net.CIDRMask(32, 32),
						}}},
						MAC:      &cnet.MAC{HardwareAddr: mac},
						Profiles: []string{"k8s_ns.test"},
					}))

					// Delete the container.
					_, err = DeleteContainer(netconfCalicoIPAM, contNt.Path(), name)
					Expect(err).ShouldNot(HaveOccurred())
				})
			})

			Context("using ipAddrs annotation to assign IP address to a pod, through Calico IPAM, without specifying cniVersion in CNI config", func() {
				It("should successfully assigns the annotated IP address", func() {
					netconfCalicoIPAM := fmt.Sprintf(`
				{
				  "name": "net5",
				  "type": "calico",
				  "etcd_endpoints": "http://%s:2379",
				  "ipam": {
					   "type": "calico-ipam",
					   "assign_ipv4": "true",
					   "assign_ipv6": "true"
				   },
					"kubernetes": {
					  "k8s_api_root": "http://127.0.0.1:8080"
					 },
					"policy": {"type": "k8s"},
					"log_level":"info"
				}`, os.Getenv("ETCD_IP"))

					assignIP := net.IPv4(20, 0, 0, 111).To4()

					// Create a new ipPool.
					ipPool := "20.0.0.0/24"
					c, _ := client.NewFromEnv()
					testutils.CreateNewIPPool(*c, ipPool, false, false, true)
					_, _, err := net.ParseCIDR(ipPool)
					Expect(err).NotTo(HaveOccurred())

					config, err := clientcmd.DefaultClientConfig.ClientConfig()
					Expect(err).NotTo(HaveOccurred())

					clientset, err := kubernetes.NewForConfig(config)
					Expect(err).NotTo(HaveOccurred())

					// Now create a K8s pod passing in an IP address.
					name := fmt.Sprintf("run%d-ip", rand.Uint32())
					pod, err := clientset.Pods(K8S_TEST_NS).Create(&v1.Pod{
						ObjectMeta: metav1.ObjectMeta{
							Name: name,
							Annotations: map[string]string{
								"cni.projectcalico.org/ipAddrs": "[\"20.0.0.111\"]",
							},
						},
						Spec: v1.PodSpec{Containers: []v1.Container{{
							Name:  fmt.Sprintf("container-%s", name),
							Image: "ignore",
						}}},
					})
					Expect(err).NotTo(HaveOccurred())

					log.Infof("Created POD object: %v", pod)

					containerID, _, contVeth, contAddresses, _, contNs, err := CreateContainer(netconfCalicoIPAM, name, "")
					Expect(err).NotTo(HaveOccurred())
					mac := contVeth.Attrs().HardwareAddr

					podIP := contAddresses[0].IP
					log.Infof("All container IPs: %v", contAddresses)
					log.Infof("Container got IP address: %s", podIP)
					Expect(podIP).Should(Equal(assignIP))

					interfaceName := k8s.VethNameForWorkload(fmt.Sprintf("%s.%s", K8S_TEST_NS, name))

					// Make sure WorkloadEndpoint is created and has the requested IP in the datastore.
					endpoints, err := calicoClient.WorkloadEndpoints().List(api.WorkloadEndpointMetadata{})
					Expect(err).ShouldNot(HaveOccurred())
					Expect(endpoints.Items).Should(HaveLen(1))

					// Set the Revision to nil since we can't assert it's exact value.
					endpoints.Items[0].Metadata.Revision = nil
					Expect(endpoints.Items[0].Metadata).Should(Equal(api.WorkloadEndpointMetadata{
						Node:             hostname,
						Name:             "eth0",
						Workload:         fmt.Sprintf("test.%s", name),
						ActiveInstanceID: containerID,
						Orchestrator:     "k8s",
						Labels:           map[string]string{"calico/k8s_ns": "test"},
					}))
					Expect(endpoints.Items[0].Spec).Should(Equal(api.WorkloadEndpointSpec{
						InterfaceName: interfaceName,
						IPNetworks: []cnet.IPNet{{net.IPNet{
							IP:   assignIP,
							Mask: net.CIDRMask(32, 32),
						}}},
						MAC:      &cnet.MAC{HardwareAddr: mac},
						Profiles: []string{"k8s_ns.test"},
					}))

					// Delete the container.
					_, err = DeleteContainer(netconfCalicoIPAM, contNs.Path(), name)
					Expect(err).ShouldNot(HaveOccurred())
				})
			})

			Context("Using host-local IPAM: request an IP then release it, and then request it again", func() {
				It("should successfully assign IP both times and successfully release it in the middle", func() {
					netconfHostLocalIPAM := fmt.Sprintf(`
				  {
					"cniVersion": "%s",
					"name": "net6",
					  "type": "calico",
					  "etcd_endpoints": "http://%s:2379",
					  "ipam": {
					    "type": "host-local",
						"subnet": "usePodCidr"
					  },
				   "kubernetes": {
				     "k8s_api_root": "http://127.0.0.1:8080"
			    	},
			   	  "policy": {"type": "k8s"},
				  "log_level":"info"
					}`, cniVersion, os.Getenv("ETCD_IP"))

					config, err := clientcmd.DefaultClientConfig.ClientConfig()
					Expect(err).NotTo(HaveOccurred())

					clientset, err := kubernetes.NewForConfig(config)
					Expect(err).NotTo(HaveOccurred())

					// Create a K8s Node object with PodCIDR and name equal to hostname.
					_, err = clientset.Nodes().Create(&v1.Node{
						ObjectMeta: metav1.ObjectMeta{Name: hostname},
						Spec: v1.NodeSpec{
							PodCIDR: "10.0.0.0/24",
						},
					})
					Expect(err).NotTo(HaveOccurred())

					By("Creating a pod with a specific IP address")
					name := fmt.Sprintf("run%d", rand.Uint32())
					_, err = clientset.Pods(K8S_TEST_NS).Create(&v1.Pod{
						ObjectMeta: metav1.ObjectMeta{Name: name},
						Spec: v1.PodSpec{Containers: []v1.Container{{
							Name:  fmt.Sprintf("container-%s", name),
							Image: "ignore",
						}},
							NodeName: hostname,
						},
					})
					Expect(err).NotTo(HaveOccurred())

					requestedIP := "10.0.0.42"
					expectedIP := net.IPv4(10, 0, 0, 42).To4()

					_, _, _, contAddresses, _, contNs, err := CreateContainer(netconfHostLocalIPAM, name, requestedIP)
					Expect(err).NotTo(HaveOccurred())

					podIP := contAddresses[0].IP
					log.Infof("All container IPs: %v", contAddresses)
					Expect(podIP).Should(Equal(expectedIP))

					By("Deleting the pod we created earlier")
					_, err = DeleteContainer(netconfHostLocalIPAM, contNs.Path(), name)
					Expect(err).ShouldNot(HaveOccurred())

					By("Creating a second pod with the same IP address as the first pod")
					name2 := fmt.Sprintf("run2%d", rand.Uint32())
					_, err = clientset.Pods(K8S_TEST_NS).Create(&v1.Pod{
						ObjectMeta: metav1.ObjectMeta{Name: name2},
						Spec: v1.PodSpec{Containers: []v1.Container{{
							Name:  fmt.Sprintf("container-%s", name2),
							Image: "ignore",
						}},
							NodeName: hostname,
						},
					})
					Expect(err).NotTo(HaveOccurred())

					_, _, _, contAddresses, _, contNs, err = CreateContainer(netconfHostLocalIPAM, name2, requestedIP)
					Expect(err).NotTo(HaveOccurred())

					pod2IP := contAddresses[0].IP
					log.Infof("All container IPs: %v", contAddresses)
					Expect(pod2IP).Should(Equal(expectedIP))
				})
			})

			// This specific test case is for an issue where k8s would send extra DELs being "aggressive". See: https://github.com/kubernetes/kubernetes/issues/44100
			Context("ADD a container with a ContainerID and DEL it with the same ContainerID then ADD a new container with a different ContainerID, and send a DEL for the old ContainerID", func() {
				It("Use different CNI_ContainerIDs to ADD and DEL the container", func() {
					netconf := fmt.Sprintf(`
				{
			      "cniVersion": "%s",
				  "name": "net7",
				  "type": "calico",
				  "etcd_endpoints": "http://%s:2379",
			 	  "ipam": {
			    	 "type": "calico-ipam"
			         },
					"kubernetes": {
					  "k8s_api_root": "http://127.0.0.1:8080"
					 },
					"policy": {"type": "k8s"},
					"log_level":"info"
				}`, cniVersion, os.Getenv("ETCD_IP"))

					// Create a new ipPool.
					ipPool := "10.0.0.0/24"
					c, _ := client.NewFromEnv()
					testutils.CreateNewIPPool(*c, ipPool, false, false, true)

					config, err := clientcmd.DefaultClientConfig.ClientConfig()
					Expect(err).NotTo(HaveOccurred())

					clientset, err := kubernetes.NewForConfig(config)
					Expect(err).NotTo(HaveOccurred())

					// Now create a K8s pod.
					name := fmt.Sprintf("run%d-pool", rand.Uint32())

					cniContainerIDX := "container-id-00X"
					cniContainerIDY := "container-id-00Y"

					pod, err := clientset.Pods(K8S_TEST_NS).Create(
						&v1.Pod{
							ObjectMeta: metav1.ObjectMeta{
								Name: name,
							},
							Spec: v1.PodSpec{Containers: []v1.Container{{
								Name:  fmt.Sprintf("container-%s", name),
								Image: "ignore",
							}}},
						})

					Expect(err).NotTo(HaveOccurred())

					log.Infof("Created POD object: %v", pod)

					// ADD the container with passing a CNI_ContainerID "X".
					_, session, _, _, _, contNs, err := CreateContainerWithId(netconf, name, "", cniContainerIDX)
					Expect(err).ShouldNot(HaveOccurred())
					Eventually(session).Should(gexec.Exit())

					result, err := GetResultForCurrent(session, cniVersion)
					if err != nil {
						log.Fatalf("Error getting result from the session: %v\n", err)
					}

					log.Printf("Unmarshaled result: %v\n", result)

					// Assert that the endpoint is created in the backend datastore with ContainerID "X".
					endpoints, err := calicoClient.WorkloadEndpoints().List(api.WorkloadEndpointMetadata{})
					Expect(err).ShouldNot(HaveOccurred())
					Expect(endpoints.Items).Should(HaveLen(1))

					// Set the Revision to nil since we can't assert it's exact value.
					endpoints.Items[0].Metadata.Revision = nil
					Expect(endpoints.Items[0].Metadata).Should(Equal(api.WorkloadEndpointMetadata{
						Node:             hostname,
						Name:             "eth0",
						Workload:         fmt.Sprintf("test.%s", name),
						ActiveInstanceID: cniContainerIDX,
						Orchestrator:     "k8s",
						Labels:           map[string]string{"calico/k8s_ns": "test"},
					}))

					// Delete the container with the CNI_ContainerID "X".
					exitCode, err := DeleteContainerWithId(netconf, contNs.Path(), name, cniContainerIDX)
					Expect(err).ShouldNot(HaveOccurred())
					Expect(exitCode).Should(Equal(0))

					// The endpoint for ContainerID "X" should not exist in the backend datastore.
					endpoints, err = calicoClient.WorkloadEndpoints().List(api.WorkloadEndpointMetadata{})
					Expect(err).ShouldNot(HaveOccurred())
					Expect(endpoints.Items).Should(HaveLen(0))

					// ADD a new container with passing a CNI_ContainerID "Y".
					_, session, _, _, _, contNs, err = CreateContainerWithId(netconf, name, "", cniContainerIDY)
					Expect(err).ShouldNot(HaveOccurred())
					Eventually(session).Should(gexec.Exit())

					result, err = GetResultForCurrent(session, cniVersion)
					if err != nil {
						log.Fatalf("Error getting result from the session: %v\n", err)
					}

					log.Printf("Unmarshaled result: %v\n", result)

					// Assert that the endpoint is created in the backend datastore with ContainerID "Y".
					endpoints, err = calicoClient.WorkloadEndpoints().List(api.WorkloadEndpointMetadata{})
					Expect(err).ShouldNot(HaveOccurred())
					Expect(endpoints.Items).Should(HaveLen(1))

					// Set the Revision to nil since we can't assert it's exact value.
					endpoints.Items[0].Metadata.Revision = nil
					Expect(endpoints.Items[0].Metadata).Should(Equal(api.WorkloadEndpointMetadata{
						Node:             hostname,
						Name:             "eth0",
						Workload:         fmt.Sprintf("test.%s", name),
						ActiveInstanceID: cniContainerIDY,
						Orchestrator:     "k8s",
						Labels:           map[string]string{"calico/k8s_ns": "test"},
					}))

					// Delete the container with the CNI_ContainerID "X" again.
					exitCode, err = DeleteContainerWithId(netconf, contNs.Path(), name, cniContainerIDX)
					Expect(err).ShouldNot(HaveOccurred())
					Expect(exitCode).Should(Equal(0))

					// Assert that the endpoint with ContainerID "Y" is still in the datastore.
					endpoints, err = calicoClient.WorkloadEndpoints().List(api.WorkloadEndpointMetadata{})
					Expect(err).ShouldNot(HaveOccurred())
					Expect(endpoints.Items).Should(HaveLen(1))

					// Set the Revision to nil since we can't assert it's exact value.
					endpoints.Items[0].Metadata.Revision = nil
					Expect(endpoints.Items[0].Metadata).Should(Equal(api.WorkloadEndpointMetadata{
						Node:             hostname,
						Name:             "eth0",
						Workload:         fmt.Sprintf("test.%s", name),
						ActiveInstanceID: cniContainerIDY,
						Orchestrator:     "k8s",
						Labels:           map[string]string{"calico/k8s_ns": "test"},
					}))

				})
			})

			// This specific test case is for an issue where k8s would send two ADDs with different container IDs for the same Pod.
			Context("Multiple ADD calls with different container IDs followed by DEL calls for stale container IDs", func() {
				It("Use different CNI_ContainerIDs to ADD and DEL the container", func() {
					netconf := fmt.Sprintf(`
				{
			      "cniVersion": "%s",
				  "name": "net7",
				  "type": "calico",
				  "etcd_endpoints": "http://%s:2379",
			 	  "ipam": {
			    	 "type": "calico-ipam"
			         },
					"kubernetes": {
					  "k8s_api_root": "http://127.0.0.1:8080"
					 },
					"policy": {"type": "k8s"},
					"log_level":"info"
				}`, cniVersion, os.Getenv("ETCD_IP"))

					// Create a new ipPool.
					ipPool := "10.0.0.0/24"
					c, _ := client.NewFromEnv()
					testutils.CreateNewIPPool(*c, ipPool, false, false, true)

					config, err := clientcmd.DefaultClientConfig.ClientConfig()
					Expect(err).NotTo(HaveOccurred())

					clientset, err := kubernetes.NewForConfig(config)
					Expect(err).NotTo(HaveOccurred())

					// Now create a K8s pod.
					name := fmt.Sprintf("run%d-pool", rand.Uint32())

					cniContainerIDX := "container-id-00X"
					cniContainerIDY := "container-id-00Y"

					pod, err := clientset.Pods(K8S_TEST_NS).Create(
						&v1.Pod{
							ObjectMeta: metav1.ObjectMeta{
								Name: name,
							},
							Spec: v1.PodSpec{Containers: []v1.Container{{
								Name:  fmt.Sprintf("container-%s", name),
								Image: "ignore",
							}}},
						})

					Expect(err).NotTo(HaveOccurred())

					log.Infof("Created POD object: %v", pod)

					// ADD the container with passing a CNI_CONTAINERID of "X".
					_, session, _, _, _, contNs, err := CreateContainerWithId(netconf, name, "", cniContainerIDX)
					Expect(err).ShouldNot(HaveOccurred())
					Eventually(session).Should(gexec.Exit())

					result, err := GetResultForCurrent(session, cniVersion)
					if err != nil {
						log.Fatalf("Error getting result from the session: %v\n", err)
					}
					log.Printf("Unmarshaled result: %v\n", result)

					// Assert that the endpoint is created in the backend datastore with ContainerID "X".
					endpoints, err := calicoClient.WorkloadEndpoints().List(api.WorkloadEndpointMetadata{})
					Expect(err).ShouldNot(HaveOccurred())
					Expect(endpoints.Items).Should(HaveLen(1))

					// Set the Revision to nil since we can't assert it's exact value.
					endpoints.Items[0].Metadata.Revision = nil
					Expect(endpoints.Items[0].Metadata).Should(Equal(api.WorkloadEndpointMetadata{
						Node:             hostname,
						Name:             "eth0",
						Workload:         fmt.Sprintf("test.%s", name),
						ActiveInstanceID: cniContainerIDX,
						Orchestrator:     "k8s",
						Labels:           map[string]string{"calico/k8s_ns": "test"},
					}))

					// ADD the container with passing a CNI_CONTAINERID of "Y"
					_, session, _, _, _, contNs, err = CreateContainerWithId(netconf, name, "", cniContainerIDY)
					Expect(err).ShouldNot(HaveOccurred())
					Eventually(session).Should(gexec.Exit())

					result, err = GetResultForCurrent(session, cniVersion)
					if err != nil {
						log.Fatalf("Error getting result from the session: %v\n", err)
					}
					log.Printf("Unmarshaled result: %v\n", result)

					// Assert that the endpoint is created in the backend datastore with ContainerID "Y".
					endpoints, err = calicoClient.WorkloadEndpoints().List(api.WorkloadEndpointMetadata{})
					Expect(err).ShouldNot(HaveOccurred())
					Expect(endpoints.Items).Should(HaveLen(1))

					// Set the Revision to nil since we can't assert it's exact value.
					endpoints.Items[0].Metadata.Revision = nil
					Expect(endpoints.Items[0].Metadata).Should(Equal(api.WorkloadEndpointMetadata{
						Node:             hostname,
						Name:             "eth0",
						Workload:         fmt.Sprintf("test.%s", name),
						ActiveInstanceID: cniContainerIDY,
						Orchestrator:     "k8s",
						Labels:           map[string]string{"calico/k8s_ns": "test"},
					}))

					// Delete the container with the CNI_CONTAINERID "X".
					exitCode, err := DeleteContainerWithId(netconf, contNs.Path(), name, cniContainerIDX)
					Expect(err).ShouldNot(HaveOccurred())
					Expect(exitCode).Should(Equal(0))

					// Assert that the endpoint in the backend datastore still has ContainerID "Y".
					endpoints, err = calicoClient.WorkloadEndpoints().List(api.WorkloadEndpointMetadata{})
					Expect(err).ShouldNot(HaveOccurred())
					Expect(endpoints.Items).Should(HaveLen(1))

					// Set the Revision to nil since we can't assert it's exact value.
					endpoints.Items[0].Metadata.Revision = nil
					Expect(endpoints.Items[0].Metadata).Should(Equal(api.WorkloadEndpointMetadata{
						Node:             hostname,
						Name:             "eth0",
						Workload:         fmt.Sprintf("test.%s", name),
						ActiveInstanceID: cniContainerIDY,
						Orchestrator:     "k8s",
						Labels:           map[string]string{"calico/k8s_ns": "test"},
					}))

					// Delete the container with the CNI_CONTAINERID "Y".
					exitCode, err = DeleteContainerWithId(netconf, contNs.Path(), name, cniContainerIDY)
					Expect(err).ShouldNot(HaveOccurred())
					Expect(exitCode).Should(Equal(0))

					// Assert that the endpoint in the backend datastore is now gone.
					endpoints, err = calicoClient.WorkloadEndpoints().List(api.WorkloadEndpointMetadata{})
					Expect(err).ShouldNot(HaveOccurred())
					Expect(endpoints.Items).Should(HaveLen(0))

				})
			})

			Context("after creating a pod", func() {
				netconf := fmt.Sprintf(`
					{
					  "cniVersion": "%s",
					  "name": "net8",
					  "type": "calico",
					  "etcd_endpoints": "http://%s:2379",
					  "ipam": {
						"type": "calico-ipam"
					  },
					  "kubernetes": {
						"k8s_api_root": "http://127.0.0.1:8080"
					  },
					  "policy": {"type": "k8s"},
					  "log_level":"info"
					}`,
					cniVersion,
					os.Getenv("ETCD_IP"),
				)

				var workloadName, containerID, name string
				var endpointSpec api.WorkloadEndpointSpec
				var contNs ns.NetNS
				var result *current.Result

				checkIPAMReservation := func() {
					// IPAM reservation should still be in place.
					handleID, _ := utils.GetHandleID("net8", containerID, containerID)
					ipamIPs, err := calicoClient.IPAM().IPsByHandle(handleID)
					ExpectWithOffset(0, err).NotTo(HaveOccurred())
					ExpectWithOffset(0, ipamIPs).To(HaveLen(1),
						"There should be an IPAM handle for endpoint")
					ExpectWithOffset(0, ipamIPs[0].To16()).To(ConsistOf(endpointSpec.IPNetworks[0].IP.To16()))
				}

				BeforeEach(func() {
					// Create a new ipPool.
					c, _ := client.NewFromEnv()
					testutils.CreateNewIPPool(*c, "10.0.0.0/24", false, false, true)

					config, err := clientcmd.DefaultClientConfig.ClientConfig()
					Expect(err).NotTo(HaveOccurred())

					clientset, err := kubernetes.NewForConfig(config)
					Expect(err).NotTo(HaveOccurred())

					// Now create a K8s pod.
					name = fmt.Sprintf("run%d-pool", rand.Uint32())

					pod, err := clientset.Pods(K8S_TEST_NS).Create(
						&v1.Pod{
							ObjectMeta: metav1.ObjectMeta{
								Name: name,
							},
							Spec: v1.PodSpec{Containers: []v1.Container{{
								Name:  fmt.Sprintf("container-%s", name),
								Image: "ignore",
							}}},
						})

					Expect(err).NotTo(HaveOccurred())

					log.Infof("Created POD object: %v", pod)
					var session *gexec.Session
					containerID, session, _, _, _, contNs, err = CreateContainer(netconf, name, "")
					Expect(err).ShouldNot(HaveOccurred())
					Eventually(session).Should(gexec.Exit(0))

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
					endpoint := endpoints.Items[0]
					endpoint.Metadata.Revision = nil
					workloadName = fmt.Sprintf("test.%s", name)
					Expect(endpoint.Metadata).Should(Equal(api.WorkloadEndpointMetadata{
						Node:             hostname,
						Name:             "eth0",
						Workload:         workloadName,
						ActiveInstanceID: containerID,
						Orchestrator:     "k8s",
						Labels:           map[string]string{"calico/k8s_ns": "test"},
					}))
					endpointSpec = endpoint.Spec
					Expect(endpointSpec.IPNetworks).To(HaveLen(1))

					checkIPAMReservation()
				})

				AfterEach(func() {
					_, err := DeleteContainer(netconf, contNs.Path(), "")
					Expect(err).ShouldNot(HaveOccurred())
				})

				It("a second ADD for the same container should work, assigning a new IP", func() {
					// Try to create the same pod with a new contaienr ID (so CNI receives the ADD for the same endpoint again)
					session, _, _, _, err := RunCNIPluginWithId(netconf, name, "", "new-container-id", contNs)
					Expect(err).NotTo(HaveOccurred())
					Eventually(session).Should(gexec.Exit(0))

					resultSecondAdd, err := GetResultForCurrent(session, cniVersion)
					Expect(err).NotTo(HaveOccurred())
					log.Printf("Unmarshalled result from second ADD: %v\n", resultSecondAdd)

					// The IP addresses shouldn't be the same, since we'll reassign one.
					Expect(resultSecondAdd.IPs).ShouldNot(Equal(result.IPs))

					// Otherwise, they should be the same.
					resultSecondAdd.IPs = nil
					result.IPs = nil
					Expect(resultSecondAdd).Should(Equal(result))

					// IPAM reservation should still be in place.
					checkIPAMReservation()
				})

				Context("with networking rigged to fail", func() {
					BeforeEach(func() {
						// To prevent the networking atempt from succeeding, rename the old veth.
						// This leaves a route and an eth0 in place that the plugin will struggle with.
						hostVeth := endpointSpec.InterfaceName
						newName := strings.Replace(hostVeth, "cali", "sali", 1)
						output, err := exec.Command("ip", "link", "set", hostVeth, "down").CombinedOutput()
						Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Output: %s", output))
						output, err = exec.Command("ip", "link", "set", hostVeth, "name", newName).CombinedOutput()
						Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Output: %s", output))
						output, err = exec.Command("ip", "link", "set", newName, "up").CombinedOutput()
						Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("Output: %s", output))
					})

					It("a second ADD should fail, but not clean up the original IPAM allocation", func() {
						// Try to create the same container (so CNI receives the ADD for the same endpoint again)
						// Use the same pod information but a different container ID to simulate the ADD.
						session, _, _, _, err := RunCNIPluginWithId(netconf, name, "", "new-container-id", contNs)
						Expect(err).ShouldNot(HaveOccurred())
						Eventually(session).Should(gexec.Exit(1))

						// IPAM reservation should still be in place.
						checkIPAMReservation()
					})
				})
			})

			Context("ask for more than 1 IPv4 addrs using ipAddrsNoIpam annotation to assign IP address to a pod, bypassing IPAM", func() {
				It("should return an error", func() {
					netconfCalicoIPAM := fmt.Sprintf(`
				{
			      "cniVersion": "%s",
				  "name": "net9",
				  "type": "calico",
				  "etcd_endpoints": "http://%s:2379",
			 	  "ipam": {},
					"kubernetes": {
					  "k8s_api_root": "http://127.0.0.1:8080"
					 },
					"policy": {"type": "k8s"},
					"log_level":"info"
				}`, cniVersion, os.Getenv("ETCD_IP"))

					config, err := clientcmd.DefaultClientConfig.ClientConfig()
					Expect(err).NotTo(HaveOccurred())

					clientset, err := kubernetes.NewForConfig(config)
					Expect(err).NotTo(HaveOccurred())

					// Now create a K8s pod passing in more than one IPv4 address.
					name := fmt.Sprintf("run%d-ip", rand.Uint32())
					pod, err := clientset.Pods(K8S_TEST_NS).Create(&v1.Pod{
						ObjectMeta: metav1.ObjectMeta{
							Name: name,
							Annotations: map[string]string{
								"cni.projectcalico.org/ipAddrsNoIpam": "[\"10.0.0.1\", \"10.0.0.2\"]",
							},
						},
						Spec: v1.PodSpec{Containers: []v1.Container{{
							Name:  fmt.Sprintf("container-%s", name),
							Image: "ignore",
						}}},
					})
					Expect(err).NotTo(HaveOccurred())

					log.Infof("Created POD object: %v", pod)

					_, _, _, _, _, contNs, err := CreateContainer(netconfCalicoIPAM, name, "")
					Expect(err).To(HaveOccurred())

					// Make sure the WorkloadEndpoint is not created in the datastore.
					endpoints, err := calicoClient.WorkloadEndpoints().List(api.WorkloadEndpointMetadata{})
					Expect(err).ShouldNot(HaveOccurred())
					Expect(endpoints.Items).Should(HaveLen(0))

					// Delete the container.
					_, err = DeleteContainer(netconfCalicoIPAM, contNs.Path(), name)
					Expect(err).ShouldNot(HaveOccurred())
				})
			})
		})
	})
})
