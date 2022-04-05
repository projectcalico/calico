// Copyright (c) 2018-2021 Tigera, Inc. All rights reserved.
//
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

package main_windows_test

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strings"
	"time"

	"github.com/projectcalico/calico/cni-plugin/pkg/dataplane/windows"

	"github.com/Microsoft/hcsshim"
	cniv1 "github.com/containernetworking/cni/pkg/types/100"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"

	"github.com/projectcalico/calico/cni-plugin/internal/pkg/testutils"
	"github.com/projectcalico/calico/cni-plugin/internal/pkg/utils"
	"github.com/projectcalico/calico/cni-plugin/pkg/k8s"
	"github.com/projectcalico/calico/cni-plugin/pkg/types"
	libapi "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	k8sconversion "github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/conversion"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/names"
	"github.com/projectcalico/calico/libcalico-go/lib/options"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func ensureNamespace(clientset *kubernetes.Clientset, name string) {
	ns := &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: name},
	}
	_, err := clientset.CoreV1().Namespaces().Create(context.Background(), ns, metav1.CreateOptions{})
	if errors.IsAlreadyExists(err) {
		return
	}
	Expect(err).NotTo(HaveOccurred())
}

func deleteNamespace(clientset *kubernetes.Clientset, name string) {
	err := clientset.CoreV1().Namespaces().Delete(context.Background(), name, metav1.DeleteOptions{})
	if err != nil {
		panic(err)
	}
}

func updateIPAMStrictAffinity(calicoClient client.Interface, enabled bool) {
	// Currently only Linux host is able to update IPAMConfig.
	// Use os override to fake a linux host.
	ctx := context.WithValue(context.Background(), "windowsHost", "linux")
	ipamConfig, err := calicoClient.IPAM().GetIPAMConfig(ctx)
	Expect(err).NotTo(HaveOccurred())

	ipamConfig.StrictAffinity = enabled

	err = calicoClient.IPAM().SetIPAMConfig(ctx, *ipamConfig)
	Expect(err).NotTo(HaveOccurred())
}

var _ = Describe("Kubernetes CNI tests", func() {
	var hostname string
	networkName := "calico-fv"
	var ctx context.Context
	var calicoClient client.Interface
	var err error
	BeforeSuite(func() {
		log.Infof("CONTAINER_RUNTIME=%v", os.Getenv("CONTAINER_RUNTIME"))

		//Clean-up Networks if left over in previous run
		hnsNetworkList, _ := hcsshim.HNSListNetworkRequest("GET", "", "")
		log.WithField("hnsNetworkList: ", hnsNetworkList).Infof("List of Network")
		for _, network := range hnsNetworkList {
			if strings.Contains(network.Name, networkName) {
				log.Infof("Removing network %s ", network.Name)
				_, err := network.Delete()
				Expect(err).NotTo(HaveOccurred())
			}
		}
		// Create a random seed
		rand.Seed(time.Now().UTC().UnixNano())
		hostname, _ = names.Hostname()
		ctx = context.Background()
		for i := 1; i <= 3; i++ {
			calicoClient, err = client.NewFromEnv()
			if err != nil {
				log.WithError(err).Errorf("Failed to create calico client (attempt %d)", i)
				continue
			}
			break
		}
		if err != nil {
			panic(err)
		}
	})

	BeforeEach(func() {
		testutils.WipeDatastore()

		if os.Getenv("DATASTORE_TYPE") != "kubernetes" {
			// Since we're not running the startup script, we need to create a Calico Node, as required by our
			// IPAM plugin.
			caliNode := libapi.NewNode()
			caliNode.Name = hostname
			caliNode, err := calicoClient.Nodes().Create(context.Background(), caliNode, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred(), "Failed to create Calico Node resource")
		}

		// Force StrictAffinity to be true, otherwise no IP allocation is possible.
		updateIPAMStrictAffinity(calicoClient, true)
	})

	cniVersion := os.Getenv("CNI_SPEC_VERSION")

	Context("l2bridge network::using host-local IPAM", func() {
		var nsName, name string
		var clientset *kubernetes.Clientset
		netconf := fmt.Sprintf(`
	   		{
	   			"cniVersion": "%s",
	   			"name": "%s",
	   			"type": "calico",
	   			"etcd_endpoints": "%s",
	   			"datastore_type": "%s",
	   			"windows_use_single_network":true,
	   			"ipam": {
	   				"type": "host-local",
	   				"subnet": "10.254.112.0/20"
	   			},
	   			"kubernetes": {
	   				"k8s_api_root": "%s",
					"kubeconfig": "C:\\k\\config"
	   			},
	   			"policy": {"type": "k8s"},
	   			"nodename_file_optional": true,
	   			"log_level":"debug"
	   		}`, cniVersion, networkName, os.Getenv("ETCD_ENDPOINTS"), os.Getenv("DATASTORE_TYPE"), os.Getenv("KUBERNETES_MASTER"))

		cleanup := func() {
			// Cleanup hns network
			hnsNetwork, _ := hcsshim.GetHNSNetworkByName(networkName)
			if hnsNetwork != nil {
				_, err := hnsNetwork.Delete()
				Expect(err).NotTo(HaveOccurred())
			}
			// Delete node
			_ = clientset.CoreV1().Nodes().Delete(context.Background(), hostname, metav1.DeleteOptions{})
		}

		BeforeEach(func() {
			testutils.WipeK8sPods(netconf)
			conf := types.NetConf{}
			if err := json.Unmarshal([]byte(netconf), &conf); err != nil {
				panic(err)
			}
			logger := log.WithFields(log.Fields{
				"Namespace": testutils.HnsNoneNs,
			})
			clientset, err = k8s.NewK8sClient(conf, logger)
			if err != nil {
				panic(err)
			}

			nsName = fmt.Sprintf("ns%d", rand.Uint32())
			name = fmt.Sprintf("run%d", rand.Uint32())
			cleanup()

			// Create namespace
			ensureNamespace(clientset, nsName)

			// Create a K8s Node object with PodCIDR and name equal to hostname.
			_, err = clientset.CoreV1().Nodes().Create(context.Background(), &v1.Node{
				ObjectMeta: metav1.ObjectMeta{Name: hostname},
				Spec: v1.NodeSpec{
					PodCIDR: "10.0.0.0/24",
				},
			}, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			// Create a K8s pod w/o any special params
			_, err = clientset.CoreV1().Pods(nsName).Create(context.Background(), &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: name},
				Spec: v1.PodSpec{
					Containers: []v1.Container{{
						Name:  name,
						Image: "ignore",
					}},
					NodeName: hostname,
				},
			}, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
		})

		AfterEach(func() {
			cleanup()
			// Delete namespace
			deleteNamespace(clientset, nsName)
		})

		It("successfully networks the namespace", func() {
			log.Infof("Creating container")
			containerID, result, contVeth, contAddresses, contRoutes, err := testutils.CreateContainer(netconf, name, testutils.HnsNoneNs, "", nsName)
			Expect(err).ShouldNot(HaveOccurred())
			defer func() {
				log.Infof("Container Delete  call")
				_, err = testutils.DeleteContainerWithId(netconf, name, testutils.HnsNoneNs, containerID, nsName)
				Expect(err).ShouldNot(HaveOccurred())

				// Make sure there are no endpoints anymore
				endpoints, err := calicoClient.WorkloadEndpoints().List(ctx, options.ListOptions{})
				Expect(err).ShouldNot(HaveOccurred())
				Expect(endpoints.Items).Should(HaveLen(0))
			}()
			log.Debugf("containerID :%v , result: %v ,icontVeth : %v , contAddresses : %v ,contRoutes : %v ", containerID, result, contVeth, contAddresses, contRoutes)

			Expect(len(result.IPs)).Should(Equal(1))
			ip := result.IPs[0].Address.IP.String()
			log.Debugf("ip is %v ", ip)
			result.IPs[0].Address.IP = result.IPs[0].Address.IP.To4() // Make sure the IP is respresented as 4 bytes
			Expect(result.IPs[0].Address.Mask.String()).Should(Equal("fffff000"))

			// datastore things:
			ids := names.WorkloadEndpointIdentifiers{
				Node:         hostname,
				Orchestrator: api.OrchestratorKubernetes,
				Endpoint:     "eth0",
				Pod:          name,
				ContainerID:  containerID,
			}

			wrkload, err := ids.CalculateWorkloadEndpointName(false)
			log.Debugf("workload endpoint: %v", wrkload)
			Expect(err).NotTo(HaveOccurred())

			// The endpoint is created
			endpoints, err := calicoClient.WorkloadEndpoints().List(ctx, options.ListOptions{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(endpoints.Items).Should(HaveLen(1))

			Expect(endpoints.Items[0].Name).Should(Equal(wrkload))
			Expect(endpoints.Items[0].Namespace).Should(Equal(nsName))
			Expect(endpoints.Items[0].Labels).Should(Equal(map[string]string{
				"projectcalico.org/namespace":      nsName,
				"projectcalico.org/orchestrator":   api.OrchestratorKubernetes,
				"projectcalico.org/serviceaccount": "default",
			}))
			Expect(endpoints.Items[0].Spec.Pod).Should(Equal(name))
			Expect(endpoints.Items[0].Spec.IPNetworks[0]).Should(Equal(result.IPs[0].Address.IP.String() + "/32"))
			Expect(endpoints.Items[0].Spec.Node).Should(Equal(hostname))
			Expect(endpoints.Items[0].Spec.Endpoint).Should(Equal("eth0"))
			Expect(endpoints.Items[0].Spec.Workload).Should(Equal(""))
			Expect(endpoints.Items[0].Spec.ContainerID).Should(Equal(containerID))
			Expect(endpoints.Items[0].Spec.Orchestrator).Should(Equal(api.OrchestratorKubernetes))

			// Ensure network is created
			hnsNetwork, err := hcsshim.GetHNSNetworkByName(networkName)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(hnsNetwork.Subnets[0].AddressPrefix).Should(Equal("10.254.112.0/20"))
			Expect(hnsNetwork.Subnets[0].GatewayAddress).Should(Equal("10.254.112.1"))
			Expect(hnsNetwork.Type).Should(Equal("L2Bridge"))

			// Ensure host and container endpoints are created
			hostEP, err := hcsshim.GetHNSEndpointByName("calico-fv_ep")
			Expect(err).ShouldNot(HaveOccurred())
			Expect(hostEP.GatewayAddress).Should(Equal("10.254.112.1"))
			Expect(hostEP.IPAddress.String()).Should(Equal("10.254.112.2"))
			Expect(hostEP.VirtualNetwork).Should(Equal(hnsNetwork.Id))
			Expect(hostEP.VirtualNetworkName).Should(Equal(hnsNetwork.Name))

			containerEP, err := hcsshim.GetHNSEndpointByName(containerID + "_calico-fv")
			Expect(containerEP.GatewayAddress).Should(Equal("10.254.112.2"))
			Expect(containerEP.IPAddress.String()).Should(Equal(ip))
			Expect(strings.ToUpper(containerEP.VirtualNetwork)).Should(Equal(strings.ToUpper(hnsNetwork.Id)))
			Expect(containerEP.VirtualNetworkName).Should(Equal(hnsNetwork.Name))
		})

		Context("when a named port is set", func() {
			It("it is added to the workload endpoint", func() {
				name := fmt.Sprintf("run%d", rand.Uint32())

				// Create a K8s pod w/o any special params
				_, err = clientset.CoreV1().Pods(nsName).Create(context.Background(), &v1.Pod{
					ObjectMeta: metav1.ObjectMeta{Name: name},
					Spec: v1.PodSpec{
						Containers: []v1.Container{{
							Name:  fmt.Sprintf("container-%s", name),
							Image: "ignore",
							Ports: []v1.ContainerPort{{
								Name:          "anamedport",
								ContainerPort: 555,
							}},
						}},
						NodeName: hostname,
					},
				}, metav1.CreateOptions{})
				defer clientset.CoreV1().Pods(nsName).Delete(context.Background(), name, metav1.DeleteOptions{})
				Expect(err).ShouldNot(HaveOccurred())

				containerID, result, contVeth, _, _, err := testutils.CreateContainer(netconf, name, testutils.HnsNoneNs, "", nsName)
				Expect(err).ShouldNot(HaveOccurred())
				defer func() {
					_, err = testutils.DeleteContainerWithId(netconf, name, testutils.HnsNoneNs, containerID, nsName)
					Expect(err).ShouldNot(HaveOccurred())

					// Make sure there are no endpoints anymore
					endpoints, err := calicoClient.WorkloadEndpoints().List(ctx, options.ListOptions{})
					Expect(err).ShouldNot(HaveOccurred())
					Expect(endpoints.Items).Should(HaveLen(0))
				}()
				log.Debugf("contVeth %v ", contVeth)
				log.Debugf("containerID %v ", containerID)
				log.Debugf("result %v ", result)
				Expect(len(result.IPs)).Should(Equal(1))
				result.IPs[0].Address.IP = result.IPs[0].Address.IP.To4() // Make sure the IP is respresented as 4 bytes
				Expect(result.IPs[0].Address.Mask.String()).Should(Equal("fffff000"))

				// datastore things:

				ids := names.WorkloadEndpointIdentifiers{
					Node:         hostname,
					Orchestrator: api.OrchestratorKubernetes,
					Endpoint:     "eth0",
					Pod:          name,
					ContainerID:  containerID,
				}

				wrkload, err := ids.CalculateWorkloadEndpointName(false)
				interfaceName := k8sconversion.NewConverter().VethNameForWorkload(nsName, name)
				Expect(err).NotTo(HaveOccurred())
				log.Debugf("interfaceName : %v", interfaceName)

				// The endpoint is created
				endpoints, err := calicoClient.WorkloadEndpoints().List(ctx, options.ListOptions{})
				Expect(err).ShouldNot(HaveOccurred())
				Expect(endpoints.Items).Should(HaveLen(1))
				log.Debugf("workload endpoints : %v", endpoints)

				Expect(endpoints.Items[0].Name).Should(Equal(wrkload))
				Expect(endpoints.Items[0].Namespace).Should(Equal(nsName))
				Expect(endpoints.Items[0].Labels).Should(Equal(map[string]string{
					"projectcalico.org/namespace":      nsName,
					"projectcalico.org/orchestrator":   api.OrchestratorKubernetes,
					"projectcalico.org/serviceaccount": "default",
				}))
				Expect(endpoints.Items[0].Spec.Pod).Should(Equal(name))
				Expect(endpoints.Items[0].Spec.InterfaceName).Should(Equal(interfaceName))
				Expect(endpoints.Items[0].Spec.Node).Should(Equal(hostname))
				Expect(endpoints.Items[0].Spec.Endpoint).Should(Equal("eth0"))
				Expect(endpoints.Items[0].Spec.ContainerID).Should(Equal(containerID))
				Expect(endpoints.Items[0].Spec.Orchestrator).Should(Equal(api.OrchestratorKubernetes))
				Expect(endpoints.Items[0].Spec.Ports).Should(Equal([]libapi.WorkloadEndpointPort{{
					Name:     "anamedport",
					Protocol: numorstring.ProtocolFromString("TCP"),
					Port:     555,
				}}))
			})

		})

		Context("when the same hostVeth exists", func() {
			It("successfully networks the namespace", func() {
				// Check if network exists, if not, create one
				hnsNetwork, err := testutils.CreateNetwork(netconf)
				Expect(err).ShouldNot(HaveOccurred())
				Expect(hnsNetwork.Subnets[0].AddressPrefix).Should(Equal("10.254.112.0/20"))
				Expect(hnsNetwork.Subnets[0].GatewayAddress).Should(Equal("10.254.112.1"))
				Expect(hnsNetwork.Type).Should(Equal("L2Bridge"))

				// Check for host endpoint, if doesn't exist, create endpoint
				hostEP, err := testutils.CreateEndpoint(hnsNetwork, netconf)
				Expect(err).ShouldNot(HaveOccurred())
				Expect(hostEP.GatewayAddress).Should(Equal("10.254.112.1"))
				Expect(hostEP.IPAddress.String()).Should(Equal("10.254.112.2"))
				Expect(hostEP.VirtualNetwork).Should(Equal(hnsNetwork.Id))
				Expect(hostEP.VirtualNetworkName).Should(Equal(hnsNetwork.Name))

				log.Infof("Creating container")
				containerID, result, contVeth, contAddresses, contRoutes, err := testutils.CreateContainer(netconf, name, testutils.HnsNoneNs, "", nsName)
				Expect(err).ShouldNot(HaveOccurred())
				defer func() {
					log.Infof("Container Delete  call")
					_, err := testutils.DeleteContainerWithId(netconf, name, testutils.HnsNoneNs, containerID, nsName)
					Expect(err).ShouldNot(HaveOccurred())

					// Make sure there are no endpoints anymore
					endpoints, err := calicoClient.WorkloadEndpoints().List(ctx, options.ListOptions{})
					Expect(err).ShouldNot(HaveOccurred())
					Expect(endpoints.Items).Should(HaveLen(0))
				}()
				log.Debugf("containerID :%v , result: %v ,icontVeth : %v , contAddresses : %v ,contRoutes : %v ", containerID, result, contVeth, contAddresses, contRoutes)

				Expect(len(result.IPs)).Should(Equal(1))
				ip := result.IPs[0].Address.IP.String()
				log.Debugf("ip is %v ", ip)
				result.IPs[0].Address.IP = result.IPs[0].Address.IP.To4() // Make sure the IP is respresented as 4 bytes
				Expect(result.IPs[0].Address.Mask.String()).Should(Equal("fffff000"))

				ids := names.WorkloadEndpointIdentifiers{
					Node:         hostname,
					Orchestrator: api.OrchestratorKubernetes,
					Endpoint:     "eth0",
					Pod:          name,
					ContainerID:  containerID,
				}

				wrkload, err := ids.CalculateWorkloadEndpointName(false)
				log.Debugf("workload endpoint: %v", wrkload)
				Expect(err).NotTo(HaveOccurred())

				// The endpoint is created
				endpoints, err := calicoClient.WorkloadEndpoints().List(ctx, options.ListOptions{})
				Expect(err).ShouldNot(HaveOccurred())
				Expect(endpoints.Items).Should(HaveLen(1))

				Expect(endpoints.Items[0].Name).Should(Equal(wrkload))
				Expect(endpoints.Items[0].Namespace).Should(Equal(nsName))
				Expect(endpoints.Items[0].Labels).Should(Equal(map[string]string{
					"projectcalico.org/namespace":      nsName,
					"projectcalico.org/orchestrator":   api.OrchestratorKubernetes,
					"projectcalico.org/serviceaccount": "default",
				}))
				Expect(endpoints.Items[0].Spec.Pod).Should(Equal(name))
				Expect(endpoints.Items[0].Spec.IPNetworks[0]).Should(Equal(result.IPs[0].Address.IP.String() + "/32"))
				Expect(endpoints.Items[0].Spec.Node).Should(Equal(hostname))
				Expect(endpoints.Items[0].Spec.Endpoint).Should(Equal("eth0"))
				Expect(endpoints.Items[0].Spec.Workload).Should(Equal(""))
				Expect(endpoints.Items[0].Spec.ContainerID).Should(Equal(containerID))
				Expect(endpoints.Items[0].Spec.Orchestrator).Should(Equal(api.OrchestratorKubernetes))

				// Ensure network is created
				hnsNetwork, err = hcsshim.GetHNSNetworkByName(networkName)
				Expect(err).ShouldNot(HaveOccurred())
				Expect(hnsNetwork.Subnets[0].AddressPrefix).Should(Equal("10.254.112.0/20"))
				Expect(hnsNetwork.Subnets[0].GatewayAddress).Should(Equal("10.254.112.1"))
				Expect(hnsNetwork.Type).Should(Equal("L2Bridge"))

				// Ensure host and container endpoints are created
				hostEP, err = hcsshim.GetHNSEndpointByName("calico-fv_ep")
				Expect(err).ShouldNot(HaveOccurred())
				Expect(hostEP.GatewayAddress).Should(Equal("10.254.112.1"))
				Expect(hostEP.IPAddress.String()).Should(Equal("10.254.112.2"))
				Expect(hostEP.VirtualNetwork).Should(Equal(hnsNetwork.Id))
				Expect(hostEP.VirtualNetworkName).Should(Equal(hnsNetwork.Name))

				containerEP, err := hcsshim.GetHNSEndpointByName(containerID + "_calico-fv")
				Expect(containerEP.GatewayAddress).Should(Equal("10.254.112.2"))
				Expect(containerEP.IPAddress.String()).Should(Equal(ip))
				Expect(strings.ToUpper(containerEP.VirtualNetwork)).Should(Equal(strings.ToUpper(hnsNetwork.Id)))
				Expect(containerEP.VirtualNetworkName).Should(Equal(hnsNetwork.Name))
			})
		})

		Context("after a pod has already been networked once", func() {
			It("an ADD for NETNS != \"none\" should return existing IP", func() {
				log.Infof("Creating container")
				containerID, result, contVeth, contAddresses, contRoutes, err := testutils.CreateContainer(netconf, name, testutils.HnsNoneNs, "", nsName)
				Expect(err).ShouldNot(HaveOccurred())
				defer func() {
					log.Infof("Container Delete  call")
					_, err := testutils.DeleteContainerWithId(netconf, name, testutils.HnsNoneNs, containerID, nsName)
					Expect(err).ShouldNot(HaveOccurred())

					// Make sure there are no endpoints anymore
					endpoints, err := calicoClient.WorkloadEndpoints().List(ctx, options.ListOptions{})
					Expect(err).ShouldNot(HaveOccurred())
					Expect(endpoints.Items).Should(HaveLen(0))
				}()
				log.Debugf("containerID :%v , result: %v ,icontVeth : %v , contAddresses : %v ,contRoutes : %v ", containerID, result, contVeth, contAddresses, contRoutes)

				Expect(err).ShouldNot(HaveOccurred())
				Expect(len(result.IPs)).Should(Equal(1))
				ip := result.IPs[0].Address.IP.String()
				log.Debugf("ip is %v ", ip)
				result.IPs[0].Address.IP = result.IPs[0].Address.IP.To4() // Make sure the IP is respresented as 4 bytes
				Expect(result.IPs[0].Address.Mask.String()).Should(Equal("fffff000"))

				// datastore things:
				ids := names.WorkloadEndpointIdentifiers{
					Node:         hostname,
					Orchestrator: api.OrchestratorKubernetes,
					Endpoint:     "eth0",
					Pod:          name,
					ContainerID:  containerID,
				}

				wrkload, err := ids.CalculateWorkloadEndpointName(false)
				log.Debugf("workload endpoint: %v", wrkload)
				Expect(err).NotTo(HaveOccurred())

				// The endpoint is created
				endpoints, err := calicoClient.WorkloadEndpoints().List(ctx, options.ListOptions{})
				Expect(err).ShouldNot(HaveOccurred())
				Expect(endpoints.Items).Should(HaveLen(1))

				Expect(endpoints.Items[0].Name).Should(Equal(wrkload))
				Expect(endpoints.Items[0].Namespace).Should(Equal(nsName))
				Expect(endpoints.Items[0].Labels).Should(Equal(map[string]string{
					"projectcalico.org/namespace":      nsName,
					"projectcalico.org/orchestrator":   api.OrchestratorKubernetes,
					"projectcalico.org/serviceaccount": "default",
				}))
				Expect(endpoints.Items[0].Spec.Pod).Should(Equal(name))
				Expect(endpoints.Items[0].Spec.IPNetworks[0]).Should(Equal(result.IPs[0].Address.IP.String() + "/32"))
				Expect(endpoints.Items[0].Spec.Node).Should(Equal(hostname))
				Expect(endpoints.Items[0].Spec.Endpoint).Should(Equal("eth0"))
				Expect(endpoints.Items[0].Spec.Workload).Should(Equal(""))
				Expect(endpoints.Items[0].Spec.ContainerID).Should(Equal(containerID))
				Expect(endpoints.Items[0].Spec.Orchestrator).Should(Equal(api.OrchestratorKubernetes))

				// Ensure network is created
				hnsNetwork, err := hcsshim.GetHNSNetworkByName(networkName)
				Expect(err).ShouldNot(HaveOccurred())
				Expect(hnsNetwork.Subnets[0].AddressPrefix).Should(Equal("10.254.112.0/20"))
				Expect(hnsNetwork.Subnets[0].GatewayAddress).Should(Equal("10.254.112.1"))
				Expect(hnsNetwork.Type).Should(Equal("L2Bridge"))

				// Ensure host and container endpoints are created
				hostEP, err := hcsshim.GetHNSEndpointByName("calico-fv_ep")
				Expect(err).ShouldNot(HaveOccurred())
				Expect(hostEP.GatewayAddress).Should(Equal("10.254.112.1"))
				Expect(hostEP.IPAddress.String()).Should(Equal("10.254.112.2"))
				Expect(hostEP.VirtualNetwork).Should(Equal(hnsNetwork.Id))
				Expect(hostEP.VirtualNetworkName).Should(Equal(hnsNetwork.Name))

				containerEP, err := hcsshim.GetHNSEndpointByName(containerID + "_calico-fv")
				Expect(containerEP.GatewayAddress).Should(Equal("10.254.112.2"))
				Expect(containerEP.IPAddress.String()).Should(Equal(ip))
				Expect(strings.ToUpper(containerEP.VirtualNetwork)).Should(Equal(strings.ToUpper(hnsNetwork.Id)))
				Expect(containerEP.VirtualNetworkName).Should(Equal(hnsNetwork.Name))

				netns := fmt.Sprintf("container:%v", containerID)
				result2, _, _, _, err := testutils.RunCNIPluginWithId(netconf, name, netns, ip, containerID, "", nsName)
				Expect(err).ShouldNot(HaveOccurred())
				Expect(len(result2.IPs)).Should(Equal(1))
				ip2 := result2.IPs[0].Address.IP.String()
				Expect(ip2).Should(Equal(ip))

			})
		})

		Context("With pod not networked", func() {
			It("an ADD for NETNS != \"none\" should return error rather than networking the pod", func() {
				if os.Getenv("CONTAINER_RUNTIME") == "containerd" {
					Skip("This test only applies to dockershim")
				}

				log.Infof("Creating container")
				containerID, result, contVeth, contAddresses, contRoutes, err := testutils.CreateContainer(netconf, name, testutils.K8S_TEST_NS, "", nsName)
				log.Debugf("containerID :%v , result: %v ,icontVeth : %v , contAddresses : %v ,contRoutes : %v ", containerID, result, contVeth, contAddresses, contRoutes)
				Expect(err).Should(HaveOccurred())

				endpoints, err := calicoClient.WorkloadEndpoints().List(ctx, options.ListOptions{})
				Expect(err).ShouldNot(HaveOccurred())
				Expect(endpoints.Items).Should(HaveLen(0))
			})
		})

		Context("Windows corner cases", func() {
			It("Network exists but wrong subnet, should be recreated", func() {
				log.Infof("Creating container")
				containerID, result, contVeth, contAddresses, contRoutes, err := testutils.CreateContainer(netconf, name, testutils.HnsNoneNs, "", nsName)
				Expect(err).ShouldNot(HaveOccurred())
				defer func() {
					log.Infof("Container Delete  call")
					_, err := testutils.DeleteContainerWithId(netconf, name, testutils.HnsNoneNs, containerID, nsName)
					Expect(err).ShouldNot(HaveOccurred())

					// Make sure there are no endpoints anymore
					endpoints, err := calicoClient.WorkloadEndpoints().List(ctx, options.ListOptions{})
					Expect(err).ShouldNot(HaveOccurred())
					Expect(endpoints.Items).Should(HaveLen(0))
				}()
				log.Debugf("containerID :%v , result: %v ,icontVeth : %v , contAddresses : %v ,contRoutes : %v ", containerID, result, contVeth, contAddresses, contRoutes)

				Expect(len(result.IPs)).Should(Equal(1))
				ip := result.IPs[0].Address.IP.String()
				log.Debugf("ip is %v ", ip)
				result.IPs[0].Address.IP = result.IPs[0].Address.IP.To4() // Make sure the IP is respresented as 4 bytes
				Expect(result.IPs[0].Address.Mask.String()).Should(Equal("fffff000"))

				// datastore things:
				ids := names.WorkloadEndpointIdentifiers{
					Node:         hostname,
					Orchestrator: api.OrchestratorKubernetes,
					Endpoint:     "eth0",
					Pod:          name,
					ContainerID:  containerID,
				}

				wrkload, err := ids.CalculateWorkloadEndpointName(false)
				log.Debugf("workload endpoint: %v", wrkload)
				Expect(err).NotTo(HaveOccurred())

				// The endpoint is created
				endpoints, err := calicoClient.WorkloadEndpoints().List(ctx, options.ListOptions{})
				Expect(err).ShouldNot(HaveOccurred())
				Expect(endpoints.Items).Should(HaveLen(1))
				Expect(endpoints.Items[0].Name).Should(Equal(wrkload))
				Expect(endpoints.Items[0].Namespace).Should(Equal(nsName))
				Expect(endpoints.Items[0].Labels).Should(Equal(map[string]string{
					"projectcalico.org/namespace":      nsName,
					"projectcalico.org/orchestrator":   api.OrchestratorKubernetes,
					"projectcalico.org/serviceaccount": "default",
				}))
				Expect(endpoints.Items[0].Spec.Pod).Should(Equal(name))
				Expect(endpoints.Items[0].Spec.IPNetworks[0]).Should(Equal(result.IPs[0].Address.IP.String() + "/32"))
				Expect(endpoints.Items[0].Spec.Node).Should(Equal(hostname))
				Expect(endpoints.Items[0].Spec.Endpoint).Should(Equal("eth0"))
				Expect(endpoints.Items[0].Spec.Workload).Should(Equal(""))
				Expect(endpoints.Items[0].Spec.ContainerID).Should(Equal(containerID))
				Expect(endpoints.Items[0].Spec.Orchestrator).Should(Equal(api.OrchestratorKubernetes))

				// Ensure network is created
				hnsNetwork, err := hcsshim.GetHNSNetworkByName(networkName)
				Expect(err).ShouldNot(HaveOccurred())
				Expect(hnsNetwork.Subnets[0].AddressPrefix).Should(Equal("10.254.112.0/20"))
				Expect(hnsNetwork.Subnets[0].GatewayAddress).Should(Equal("10.254.112.1"))
				Expect(hnsNetwork.Type).Should(Equal("L2Bridge"))

				// Ensure host and container endpoints are created
				hostEP, err := hcsshim.GetHNSEndpointByName("calico-fv_ep")
				Expect(err).ShouldNot(HaveOccurred())
				Expect(hostEP.GatewayAddress).Should(Equal("10.254.112.1"))
				Expect(hostEP.IPAddress.String()).Should(Equal("10.254.112.2"))
				Expect(hostEP.VirtualNetwork).Should(Equal(hnsNetwork.Id))
				Expect(hostEP.VirtualNetworkName).Should(Equal(hnsNetwork.Name))

				containerEP, err := hcsshim.GetHNSEndpointByName(containerID + "_calico-fv")
				Expect(containerEP.GatewayAddress).Should(Equal("10.254.112.2"))
				Expect(containerEP.IPAddress.String()).Should(Equal(ip))
				Expect(strings.ToUpper(containerEP.VirtualNetwork)).Should(Equal(strings.ToUpper(hnsNetwork.Id)))
				Expect(containerEP.VirtualNetworkName).Should(Equal(hnsNetwork.Name))

				// Create network with new subnet
				podIP, subnet, _ := net.ParseCIDR("20.0.0.20/8")
				result.IPs[0].Address = *subnet
				result.IPs[0].Address.IP = podIP

				netconf2 := fmt.Sprintf(`
	   				{
	   					"cniVersion": "%s",
	   					"name": "%s",
	   					"type": "calico",
	   					"etcd_endpoints": "%s",
	   					"datastore_type": "%s",
	   					"windows_use_single_network":true,
	   					"ipam": {
	   						"type": "host-local",
	   						"subnet": "20.0.0.0/8"
	   					},
	   					"kubernetes": {
	   						"k8s_api_root": "%s",
							"kubeconfig": "C:\\k\\config"
	   					},
	   					"policy": {"type": "k8s"},
	   					"nodename_file_optional": true,
	   					"log_level":"debug"
	   				}`, cniVersion, networkName, os.Getenv("ETCD_ENDPOINTS"), os.Getenv("DATASTORE_TYPE"), os.Getenv("KUBERNETES_MASTER"))

				log.Infof("Network pod again with another subnet")
				// For dockershim, use "none" for NETNS. For containerd we need
				// to use the container's namespace.
				netns := testutils.HnsNoneNs
				if os.Getenv("CONTAINER_RUNTIME") == "containerd" {
					netns, err = testutils.GetContainerNamespace(containerID)
					Expect(err).ShouldNot(HaveOccurred())
				}
				log.Infof("debug netns: %v", netns)
				err = testutils.NetworkPod(netconf2, name, ip, ctx, calicoClient, result, containerID, netns, nsName)
				Expect(err).ShouldNot(HaveOccurred())
				ip = result.IPs[0].Address.IP.String()

				hnsNetwork, err = hcsshim.GetHNSNetworkByName(networkName)
				Expect(err).ShouldNot(HaveOccurred())
				Expect(hnsNetwork.Subnets[0].AddressPrefix).Should(Equal("20.0.0.0/8"))
				Expect(hnsNetwork.Subnets[0].GatewayAddress).Should(Equal("20.0.0.1"))
				Expect(hnsNetwork.Type).Should(Equal("L2Bridge"))

				hostEP, err = hcsshim.GetHNSEndpointByName("calico-fv_ep")
				Expect(err).ShouldNot(HaveOccurred())
				Expect(hostEP.GatewayAddress).Should(Equal("20.0.0.1"))
				Expect(hostEP.IPAddress.String()).Should(Equal("20.0.0.2"))
				Expect(hostEP.VirtualNetwork).Should(Equal(hnsNetwork.Id))
				Expect(hostEP.VirtualNetworkName).Should(Equal(hnsNetwork.Name))

				containerEP, err = hcsshim.GetHNSEndpointByName(containerID + "_calico-fv")
				Expect(containerEP.GatewayAddress).Should(Equal("20.0.0.2"))
				Expect(containerEP.IPAddress.String()).Should(Equal(ip))
				Expect(strings.ToUpper(containerEP.VirtualNetwork)).Should(Equal(strings.ToUpper(hnsNetwork.Id)))
				Expect(containerEP.VirtualNetworkName).Should(Equal(hnsNetwork.Name))

				// Create network with new subnet again
				podIP, subnet, _ = net.ParseCIDR("30.0.0.30/8")
				result.IPs[0].Address = *subnet
				result.IPs[0].Address.IP = podIP

				netconf3 := fmt.Sprintf(`
	   				{
	   					"cniVersion": "%s",
	   					"name": "%s",
	   					"type": "calico",
	   					"etcd_endpoints": "%s",
	   					"datastore_type": "%s",
	   					"windows_use_single_network":true,
	   					"ipam": {
	   						"type": "host-local",
	   						"subnet": "30.0.0.0/8"
	   					},
	   					"kubernetes": {
	   						"k8s_api_root": "%s",
							"kubeconfig": "C:\\k\\config"
	   					},
	   					"policy": {"type": "k8s"},
	   					"nodename_file_optional": true,
	   					"log_level":"debug"
	   				}`, cniVersion, networkName, os.Getenv("ETCD_ENDPOINTS"), os.Getenv("DATASTORE_TYPE"), os.Getenv("KUBERNETES_MASTER"))

				testutils.DeleteRunningContainer(containerID)

				// Only applies to dockershim. With containerd, deleting the
				// container deletes the namespace too.
				if os.Getenv("CONTAINER_RUNTIME") == "docker" {
					log.Infof("Network pod again with another subnet and a stopped container")
					netns = testutils.HnsNoneNs
					err = testutils.NetworkPod(netconf3, name, ip, ctx, calicoClient, result, containerID, testutils.HnsNoneNs, nsName)
					Expect(err).Should(HaveOccurred())
				}
			})

			It("Network exists but missing management endpoint, should be added", func() {
				log.Infof("Creating container")
				containerID, result, contVeth, contAddresses, contRoutes, err := testutils.CreateContainer(netconf, name, testutils.HnsNoneNs, "", nsName)
				Expect(err).ShouldNot(HaveOccurred())
				defer func() {
					log.Infof("Container Delete  call")
					_, err := testutils.DeleteContainerWithId(netconf, name, testutils.HnsNoneNs, containerID, nsName)
					Expect(err).ShouldNot(HaveOccurred())

					// Make sure there are no endpoints anymore
					endpoints, err := calicoClient.WorkloadEndpoints().List(ctx, options.ListOptions{})
					Expect(err).ShouldNot(HaveOccurred())
					Expect(endpoints.Items).Should(HaveLen(0))
				}()
				log.Debugf("containerID :%v , result: %v ,icontVeth : %v , contAddresses : %v ,contRoutes : %v ", containerID, result, contVeth, contAddresses, contRoutes)

				Expect(len(result.IPs)).Should(Equal(1))
				ip := result.IPs[0].Address.IP.String()
				log.Debugf("ip is %v ", ip)
				result.IPs[0].Address.IP = result.IPs[0].Address.IP.To4() // Make sure the IP is respresented as 4 bytes
				Expect(result.IPs[0].Address.Mask.String()).Should(Equal("fffff000"))

				// datastore things:
				ids := names.WorkloadEndpointIdentifiers{
					Node:         hostname,
					Orchestrator: api.OrchestratorKubernetes,
					Endpoint:     "eth0",
					Pod:          name,
					ContainerID:  containerID,
				}

				wrkload, err := ids.CalculateWorkloadEndpointName(false)
				log.Debugf("workload endpoint: %v", wrkload)
				Expect(err).NotTo(HaveOccurred())

				// The endpoint is created
				endpoints, err := calicoClient.WorkloadEndpoints().List(ctx, options.ListOptions{})
				Expect(err).ShouldNot(HaveOccurred())
				Expect(endpoints.Items).Should(HaveLen(1))
				Expect(endpoints.Items[0].Name).Should(Equal(wrkload))
				Expect(endpoints.Items[0].Namespace).Should(Equal(nsName))
				Expect(endpoints.Items[0].Labels).Should(Equal(map[string]string{
					"projectcalico.org/namespace":      nsName,
					"projectcalico.org/orchestrator":   api.OrchestratorKubernetes,
					"projectcalico.org/serviceaccount": "default",
				}))
				Expect(endpoints.Items[0].Spec.Pod).Should(Equal(name))
				Expect(endpoints.Items[0].Spec.IPNetworks[0]).Should(Equal(result.IPs[0].Address.IP.String() + "/32"))
				Expect(endpoints.Items[0].Spec.Node).Should(Equal(hostname))
				Expect(endpoints.Items[0].Spec.Endpoint).Should(Equal("eth0"))
				Expect(endpoints.Items[0].Spec.Workload).Should(Equal(""))
				Expect(endpoints.Items[0].Spec.ContainerID).Should(Equal(containerID))
				Expect(endpoints.Items[0].Spec.Orchestrator).Should(Equal(api.OrchestratorKubernetes))

				// Ensure network is created
				hnsNetwork, err := hcsshim.GetHNSNetworkByName(networkName)
				Expect(err).ShouldNot(HaveOccurred())
				Expect(hnsNetwork.Subnets[0].AddressPrefix).Should(Equal("10.254.112.0/20"))
				Expect(hnsNetwork.Subnets[0].GatewayAddress).Should(Equal("10.254.112.1"))
				Expect(hnsNetwork.Type).Should(Equal("L2Bridge"))

				// Ensure host and container endpoints are created
				hostEP, err := hcsshim.GetHNSEndpointByName("calico-fv_ep")
				Expect(err).ShouldNot(HaveOccurred())
				Expect(hostEP.GatewayAddress).Should(Equal("10.254.112.1"))
				Expect(hostEP.IPAddress.String()).Should(Equal("10.254.112.2"))
				Expect(hostEP.VirtualNetwork).Should(Equal(hnsNetwork.Id))
				Expect(hostEP.VirtualNetworkName).Should(Equal(hnsNetwork.Name))

				containerEP, err := hcsshim.GetHNSEndpointByName(containerID + "_calico-fv")
				Expect(containerEP.GatewayAddress).Should(Equal("10.254.112.2"))

				Expect(containerEP.IPAddress.String()).Should(Equal(ip))
				Expect(strings.ToUpper(containerEP.VirtualNetwork)).Should(Equal(strings.ToUpper(hnsNetwork.Id)))
				Expect(containerEP.VirtualNetworkName).Should(Equal(hnsNetwork.Name))

				hnsEndpoint, err := hcsshim.GetHNSEndpointByName("calico-fv_ep")
				_, err = hnsEndpoint.Delete()
				Expect(err).ShouldNot(HaveOccurred())

				// For dockershim, use "none" for NETNS. For containerd we need
				// to use the container's namespace.
				netns := testutils.HnsNoneNs
				if os.Getenv("CONTAINER_RUNTIME") == "containerd" {
					netns, err = testutils.GetContainerNamespace(containerID)
					Expect(err).ShouldNot(HaveOccurred())
				}
				log.Infof("debug netns: %v", netns)
				err = testutils.NetworkPod(netconf, name, ip, ctx, calicoClient, result, containerID, netns, nsName)
				Expect(err).ShouldNot(HaveOccurred())

				hostEP, err = hcsshim.GetHNSEndpointByName("calico-fv_ep")
				Expect(err).ShouldNot(HaveOccurred())
				Expect(hostEP.GatewayAddress).Should(Equal("10.254.112.1"))
				Expect(hostEP.IPAddress.String()).Should(Equal("10.254.112.2"))
				Expect(hostEP.VirtualNetwork).Should(Equal(hnsNetwork.Id))
				Expect(hostEP.VirtualNetworkName).Should(Equal(hnsNetwork.Name))

				containerEP, err = hcsshim.GetHNSEndpointByName(containerID + "_calico-fv")
				Expect(containerEP.GatewayAddress).Should(Equal("10.254.112.2"))

				Expect(containerEP.IPAddress.String()).Should(Equal(ip))
				Expect(strings.ToUpper(containerEP.VirtualNetwork)).Should(Equal(strings.ToUpper(hnsNetwork.Id)))
				Expect(containerEP.VirtualNetworkName).Should(Equal(hnsNetwork.Name))

			})
		})

		hostLocalIPAMConfigs := []struct {
			description, cniVersion, config string
		}{
			{
				description: "old-style inline subnet",
				cniVersion:  cniVersion,
				config: `
	   				{
	   					"cniVersion": "%s",
	   					"name": "%s",
	   					"nodename_file_optional": true,
	   					"type": "calico",
	   					"etcd_endpoints": "%s",
	   					"windows_use_single_network":true,
	   					"datastore_type": "%s",
	   					"ipam": {
	   						"type": "host-local",
	   						"subnet": "usePodCidr"
	   					},
	   					"kubernetes": {
	   						"k8s_api_root": "%s",
							"kubeconfig": "C:\\k\\config"
	   					},
	   					"policy": {"type": "k8s"},
	   					"log_level":"debug"
	   				}`,
			},
		}

		Context("Using host-local IPAM ("+hostLocalIPAMConfigs[0].description+"): request an IP then release it, and then request it again", func() {
			It("should successfully assign IP both times and successfully release it in the middle", func() {
				netconfHostLocalIPAM := fmt.Sprintf(hostLocalIPAMConfigs[0].config, hostLocalIPAMConfigs[0].cniVersion, networkName, os.Getenv("ETCD_ENDPOINTS"), os.Getenv("DATASTORE_TYPE"), os.Getenv("KUBERNETES_MASTER"))

				requestedIP := "10.0.0.130"
				expectedIP := requestedIP

				containerID, result, _, _, _, err := testutils.CreateContainer(netconfHostLocalIPAM, name, testutils.HnsNoneNs, requestedIP, nsName)
				defer testutils.DeleteRunningContainer(containerID)
				Expect(err).NotTo(HaveOccurred())

				podIP := result.IPs[0].Address.IP.String()
				log.Debugf("container IPs: %v", podIP)
				Expect(podIP).Should(Equal(expectedIP))

				By("Deleting the pod we created earlier")
				_, err = testutils.DeleteContainerWithId(netconfHostLocalIPAM, name, testutils.HnsNoneNs, containerID, nsName)
				Expect(err).ShouldNot(HaveOccurred())

				By("Creating a second pod with the same IP address as the first pod")
				name2 := fmt.Sprintf("run2%d", rand.Uint32())
				_, err = clientset.CoreV1().Pods(nsName).Create(context.Background(), &v1.Pod{
					ObjectMeta: metav1.ObjectMeta{Name: name2},
					Spec: v1.PodSpec{
						Containers: []v1.Container{{
							Name:  fmt.Sprintf("container-%s", name2),
							Image: "ignore",
						}},
						NodeName: hostname,
					},
				}, metav1.CreateOptions{})
				Expect(err).NotTo(HaveOccurred())

				containerID, result, _, _, _, err = testutils.CreateContainer(netconfHostLocalIPAM, name2, testutils.HnsNoneNs, requestedIP, nsName)
				Expect(err).NotTo(HaveOccurred())
				defer func() {
					_, err = testutils.DeleteContainerWithId(netconfHostLocalIPAM, name2, testutils.HnsNoneNs, containerID, nsName)
					Expect(err).ShouldNot(HaveOccurred())
				}()

				pod2IP := result.IPs[0].Address.IP.String()
				log.Debugf("container IPs: %v", pod2IP)
				Expect(pod2IP).Should(Equal(expectedIP))
			})
		})
		Context("With DNS capability in CNI conf", func() {
			netconf = fmt.Sprintf(`
	   			{
	   				"cniVersion": "%s",
	   				"name": "%s",
	   				"type": "calico",
	   				"etcd_endpoints": "%s",
	   				"datastore_type": "%s",
	   				"windows_use_single_network":true,
	   				"ipam": {
	   					"type": "host-local",
	   					"subnet": "10.254.112.0/20"
	   				},
	   				"kubernetes": {
	   					"k8s_api_root": "%s",
						"kubeconfig": "C:\\k\\config"
	   				},
	   				"policy": {"type": "k8s"},
	   				"nodename_file_optional": true,
	   				"log_level":"debug",
	   				"DNS":  {
	   					"Nameservers":  [
	   					"10.96.0.10"
	   					],
	   					"Search":  [
	   					"pod.cluster.local"
	   					]
	   				}
	   			}`, cniVersion, networkName, os.Getenv("ETCD_ENDPOINTS"), os.Getenv("DATASTORE_TYPE"), os.Getenv("KUBERNETES_MASTER"))
			Context("and no runtimeConf entry", func() {
				It("should network the pod but fall back on DNS values from main CNI conf", func() {
					log.Infof("Creating container")
					containerID, result, contVeth, contAddresses, contRoutes, err := testutils.CreateContainer(netconf, name, testutils.HnsNoneNs, "", nsName)
					Expect(err).ShouldNot(HaveOccurred())
					defer func() {
						log.Infof("Container Delete  call")
						_, err := testutils.DeleteContainerWithId(netconf, name, testutils.HnsNoneNs, containerID, nsName)
						Expect(err).ShouldNot(HaveOccurred())

						// Make sure there are no endpoints anymore
						endpoints, err := calicoClient.WorkloadEndpoints().List(ctx, options.ListOptions{})
						Expect(err).ShouldNot(HaveOccurred())
						Expect(endpoints.Items).Should(HaveLen(0))
					}()
					log.Debugf("containerID :%v , result: %v ,icontVeth : %v , contAddresses : %v ,contRoutes : %v ", containerID, result, contVeth, contAddresses, contRoutes)

					Expect(len(result.IPs)).Should(Equal(1))
					ip := result.IPs[0].Address.IP.String()
					log.Debugf("ip is %v ", ip)
					result.IPs[0].Address.IP = result.IPs[0].Address.IP.To4() // Make sure the IP is respresented as 4 bytes
					Expect(result.IPs[0].Address.Mask.String()).Should(Equal("fffff000"))

					// datastore things:
					ids := names.WorkloadEndpointIdentifiers{
						Node:         hostname,
						Orchestrator: api.OrchestratorKubernetes,
						Endpoint:     "eth0",
						Pod:          name,
						ContainerID:  containerID,
					}

					wrkload, err := ids.CalculateWorkloadEndpointName(false)
					log.Debugf("workload endpoint: %v", wrkload)
					Expect(err).NotTo(HaveOccurred())

					// The endpoint is created
					endpoints, err := calicoClient.WorkloadEndpoints().List(ctx, options.ListOptions{})
					Expect(err).ShouldNot(HaveOccurred())
					Expect(endpoints.Items).Should(HaveLen(1))

					Expect(endpoints.Items[0].Name).Should(Equal(wrkload))
					Expect(endpoints.Items[0].Namespace).Should(Equal(nsName))
					Expect(endpoints.Items[0].Labels).Should(Equal(map[string]string{
						"projectcalico.org/namespace":      nsName,
						"projectcalico.org/orchestrator":   api.OrchestratorKubernetes,
						"projectcalico.org/serviceaccount": "default",
					}))
					Expect(endpoints.Items[0].Spec.Pod).Should(Equal(name))
					Expect(endpoints.Items[0].Spec.IPNetworks[0]).Should(Equal(result.IPs[0].Address.IP.String() + "/32"))
					Expect(endpoints.Items[0].Spec.Node).Should(Equal(hostname))
					Expect(endpoints.Items[0].Spec.Endpoint).Should(Equal("eth0"))
					Expect(endpoints.Items[0].Spec.Workload).Should(Equal(""))
					Expect(endpoints.Items[0].Spec.ContainerID).Should(Equal(containerID))
					Expect(endpoints.Items[0].Spec.Orchestrator).Should(Equal(api.OrchestratorKubernetes))

					// Ensure network is created
					hnsNetwork, err := hcsshim.GetHNSNetworkByName(networkName)
					Expect(err).ShouldNot(HaveOccurred())
					Expect(hnsNetwork.Subnets[0].AddressPrefix).Should(Equal("10.254.112.0/20"))
					Expect(hnsNetwork.Subnets[0].GatewayAddress).Should(Equal("10.254.112.1"))
					Expect(hnsNetwork.Type).Should(Equal("L2Bridge"))

					// Ensure host and container endpoints are created
					hostEP, err := hcsshim.GetHNSEndpointByName("calico-fv_ep")
					Expect(err).ShouldNot(HaveOccurred())
					Expect(hostEP.GatewayAddress).Should(Equal("10.254.112.1"))
					Expect(hostEP.IPAddress.String()).Should(Equal("10.254.112.2"))
					Expect(hostEP.VirtualNetwork).Should(Equal(hnsNetwork.Id))
					Expect(hostEP.VirtualNetworkName).Should(Equal(hnsNetwork.Name))

					containerEP, err := hcsshim.GetHNSEndpointByName(containerID + "_calico-fv")
					Expect(containerEP.GatewayAddress).Should(Equal("10.254.112.2"))
					Expect(containerEP.IPAddress.String()).Should(Equal(ip))
					Expect(strings.ToUpper(containerEP.VirtualNetwork)).Should(Equal(strings.ToUpper(hnsNetwork.Id)))
					Expect(containerEP.VirtualNetworkName).Should(Equal(hnsNetwork.Name))
					Expect(containerEP.DNSSuffix).Should(Equal("pod.cluster.local"))
					Expect(containerEP.DNSServerList).Should(Equal("10.96.0.10"))

				})
			})
		})
	})

	Context("l2bridge network::after a pod has already been networked once", func() {
		var nc types.NetConf
		var netconf string
		var workloadName, containerID, name string
		var endpointSpec libapi.WorkloadEndpointSpec
		var result *cniv1.Result

		checkIPAMReservation := func() {
			// IPAM reservation should still be in place.
			handleID := utils.GetHandleID(networkName, containerID, workloadName)
			ipamIPs, err := calicoClient.IPAM().IPsByHandle(context.Background(), handleID)
			ExpectWithOffset(1, err).NotTo(HaveOccurred(), "error getting IPs")
			ExpectWithOffset(1, ipamIPs).To(HaveLen(1),
				"There should be an IPAM handle for endpoint")
			ExpectWithOffset(1, ipamIPs[0].String()+"/32").To(Equal(endpointSpec.IPNetworks[0]))
		}

		var nsName string
		var clientset *kubernetes.Clientset

		BeforeEach(func() {
			// Create a network config.
			nc = types.NetConf{
				CNIVersion:              cniVersion,
				Name:                    networkName,
				Type:                    "calico",
				EtcdEndpoints:           os.Getenv("ETCD_ENDPOINTS"),
				DatastoreType:           os.Getenv("DATASTORE_TYPE"),
				Kubernetes:              types.Kubernetes{K8sAPIRoot: os.Getenv("KUBERNETES_MASTER"), Kubeconfig: "C:\\k\\config"},
				Policy:                  types.Policy{PolicyType: "k8s"},
				NodenameFileOptional:    true,
				LogLevel:                "info",
				WindowsUseSingleNetwork: true,
			}
			nc.IPAM.Type = "calico-ipam"
			ncb, err := json.Marshal(nc)
			if err != nil {
				panic(err)
			}
			netconf = string(ncb)

			testutils.WipeK8sPods(netconf)
			conf := types.NetConf{}
			if err := json.Unmarshal([]byte(netconf), &conf); err != nil {
				panic(err)
			}
			logger := log.WithFields(log.Fields{
				"Namespace": testutils.HnsNoneNs,
			})
			clientset, err = k8s.NewK8sClient(conf, logger)
			if err != nil {
				panic(err)
			}

			// Now create a K8s pod.
			// Create a new ipPool.
			testutils.MustCreateNewIPPoolBlockSize(calicoClient, "10.0.0.0/24", false, false, true, 26)

			nsName = fmt.Sprintf("ns%d", rand.Uint32())
			ensureNamespace(clientset, nsName)
			// Create a K8s Node object with PodCIDR and name equal to hostname.
			_, err = clientset.CoreV1().Nodes().Create(context.Background(), &v1.Node{
				ObjectMeta: metav1.ObjectMeta{Name: hostname},
				Spec: v1.NodeSpec{
					PodCIDR: "10.0.0.0/24",
				},
			}, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			name = fmt.Sprintf("run%d", rand.Uint32())
			pod, err := clientset.CoreV1().Pods(nsName).Create(
				context.Background(),
				&v1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name: name,
					},
					Spec: v1.PodSpec{
						Containers: []v1.Container{{
							Name:  name,
							Image: "ignore",
						}},
						NodeName: hostname,
					},
				}, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
			log.Infof("Created POD object: %v", pod)

			// Run the CNI plugin.
			containerID, result, _, _, _, err = testutils.CreateContainer(netconf, name, testutils.HnsNoneNs, "", nsName)
			Expect(err).ShouldNot(HaveOccurred(), "Failed to create initial container")
			log.Debugf("Unmarshalled result from first ADD: %v", result)

			// The endpoint is created in etcd
			endpoints, err := calicoClient.WorkloadEndpoints().List(ctx, options.ListOptions{})
			log.Debugf("workload endpoint: %v", endpoints)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(endpoints.Items).Should(HaveLen(1))
			ids := names.WorkloadEndpointIdentifiers{
				Node:         hostname,
				Orchestrator: api.OrchestratorKubernetes,
				Endpoint:     "eth0",
				Pod:          name,
				ContainerID:  containerID,
			}
			workloadName, err = ids.CalculateWorkloadEndpointName(false)
			log.Debugf("workloadName: %v", workloadName)
			Expect(err).NotTo(HaveOccurred())
			Expect(endpoints.Items[0].Name).Should(Equal(workloadName))
			Expect(endpoints.Items[0].Namespace).Should(Equal(nsName))
			Expect(endpoints.Items[0].Labels).Should(Equal(map[string]string{
				"projectcalico.org/namespace":      nsName,
				"projectcalico.org/orchestrator":   api.OrchestratorKubernetes,
				"projectcalico.org/serviceaccount": "default",
			}))
			endpointSpec = endpoints.Items[0].Spec
			log.Debugf("endpointSpec: %v", endpointSpec)
			Expect(endpointSpec.ContainerID).Should(Equal(containerID))
			checkIPAMReservation()
		})

		AfterEach(func() {
			// Cleanup hns network
			hnsNetwork, _ := hcsshim.GetHNSNetworkByName(networkName)
			if hnsNetwork != nil {
				_, err := hnsNetwork.Delete()
				Expect(err).NotTo(HaveOccurred())
			}
			// Delete node
			_ = clientset.CoreV1().Nodes().Delete(context.Background(), hostname, metav1.DeleteOptions{})
			_, err = testutils.DeleteContainerWithId(netconf, name, testutils.HnsNoneNs, containerID, nsName)
			Expect(err).ShouldNot(HaveOccurred())
			deleteNamespace(clientset, nsName)
		})

		It("a second ADD for the same container shouldn't work, returning already assigned IP", func() {
			resultSecondAdd, _, _, _, err := testutils.RunCNIPluginWithId(netconf, name, testutils.HnsNoneNs, "", "new-container-id", "eth0", nsName)
			log.Debugf("resultSecondAdd: %v", resultSecondAdd)
			Expect(err).NotTo(HaveOccurred())
			log.Debugf("Unmarshalled result from second ADD: %v", resultSecondAdd)

			// The IP addresses should be the same
			log.Debugf("resultSecondAdd.IPs: %v and result.IPs: %v ", resultSecondAdd.IPs, result.IPs)
			Expect(resultSecondAdd.IPs[0].Address.IP).Should(Equal(result.IPs[0].Address.IP))

			// results should be the same.
			resultSecondAdd.IPs = nil
			result.IPs = nil
			Expect(resultSecondAdd).Should(Equal(result))

			// IPAM reservation should still be in place.
			checkIPAMReservation()
		})
	})

	Context("l2bridge network::With a /29 IPAM blockSize", func() {
		var nsName string
		var clientset *kubernetes.Clientset
		netconf := fmt.Sprintf(`
		{
			"cniVersion": "%s",
			"name": "%s",
			"type": "calico",
			"etcd_endpoints": "%s",
			"datastore_type": "%s",
			"nodename_file_optional": true,
			"windows_use_single_network":true,
			"log_level": "debug",
			"ipam": {
				"type": "calico-ipam"
			},
			"kubernetes": {
				"k8s_api_root": "%s",
				"kubeconfig": "C:\\k\\config"
			},
			"policy": {"type": "k8s"}
		}`, cniVersion, networkName, os.Getenv("ETCD_ENDPOINTS"), os.Getenv("DATASTORE_TYPE"), os.Getenv("KUBERNETES_MASTER"))

		BeforeEach(func() {
			testutils.WipeK8sPods(netconf)
			// Create a new ipPool.
			testutils.MustCreateNewIPPoolBlockSize(calicoClient, "10.0.0.0/26", false, false, true, 29)

			conf := types.NetConf{}
			if err := json.Unmarshal([]byte(netconf), &conf); err != nil {
				panic(err)
			}
			logger := log.WithFields(log.Fields{
				"Namespace": testutils.HnsNoneNs,
			})
			clientset, err = k8s.NewK8sClient(conf, logger)
			if err != nil {
				panic(err)
			}

			// Create a K8s Node object with PodCIDR and name equal to hostname.
			_, err = clientset.CoreV1().Nodes().Create(context.Background(), &v1.Node{
				ObjectMeta: metav1.ObjectMeta{Name: hostname},
				Spec: v1.NodeSpec{
					PodCIDR: "10.0.0.0/24",
				},
			}, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
			nsName = fmt.Sprintf("ns%d", rand.Uint32())
			// Create namespace
			ensureNamespace(clientset, nsName)
		})

		AfterEach(func() {
			// Delete the IP Pools.
			testutils.MustDeleteIPPool(calicoClient, "10.0.0.0/26")
			// Delete namespace
			deleteNamespace(clientset, nsName)
			clientset.CoreV1().Nodes().Delete(context.Background(), hostname, metav1.DeleteOptions{})
			// Ensure network is created
			hnsNetwork, err := hcsshim.GetHNSNetworkByName(networkName)
			Expect(err).ShouldNot(HaveOccurred())
			_, err = hnsNetwork.Delete()
			Expect(err).ShouldNot(HaveOccurred())
		})

		It("with windows single network flag set,should successfully network 4 pods but reject networking 5th", func() {

			// Now create a K8s pod.
			name := ""
			var containerid []string
			var podName []string
			defer func() {
				var cni_err error
				for i, id := range containerid {
					log.Debugf("containerid = %v", containerid)
					_, err := testutils.DeleteContainerWithId(netconf, podName[i], testutils.HnsNoneNs, id, nsName)
					if err != nil {
						cni_err = err
					}
					clientset.CoreV1().Pods(nsName).Delete(context.Background(), podName[i], metav1.DeleteOptions{})
					Expect(err).ShouldNot(HaveOccurred())
				}
				Expect(cni_err).Should(BeNil())
			}()
			for i := 0; i < 4; i++ {
				name = fmt.Sprintf("run%d", rand.Uint32())
				pod, err := clientset.CoreV1().Pods(nsName).Create(
					context.Background(),
					&v1.Pod{
						ObjectMeta: metav1.ObjectMeta{
							Name: name,
						},
						Spec: v1.PodSpec{
							Containers: []v1.Container{{
								Name:  name,
								Image: "ignore",
							}},
							NodeName: hostname,
						},
					}, metav1.CreateOptions{})

				Expect(err).NotTo(HaveOccurred())
				podName = append(podName, name)
				log.Infof("Created POD object: %v", pod)

				// Create the container, which will call CNI and by default it will create the container with interface name 'eth0'.
				containerID, _, _, _, _, err := testutils.CreateContainer(netconf, name, testutils.HnsNoneNs, "", nsName)
				containerid = append(containerid, containerID)
				log.Debugf("containerid = %v", containerid)
				Expect(err).ShouldNot(HaveOccurred())
			}
			name = fmt.Sprintf("run%d", rand.Uint32())
			pod, err := clientset.CoreV1().Pods(nsName).Create(
				context.Background(),
				&v1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name: name,
					},
					Spec: v1.PodSpec{
						Containers: []v1.Container{{
							Name:  name,
							Image: "ignore",
						}},
						NodeName: hostname,
					},
				}, metav1.CreateOptions{})

			Expect(err).NotTo(HaveOccurred())
			log.Infof("Created POD object: %v", pod)
			podName = append(podName, name)

			// Create the container, which will call CNI and by default it will create the container with interface name 'eth0'.
			containerID, _, _, _, _, err := testutils.CreateContainer(netconf, name, testutils.HnsNoneNs, "", nsName)
			containerid = append(containerid, containerID)
			Expect(err).Should(HaveOccurred())
		})
	})
	Context("l2bridge network::With a /29 IPAM blockSize, without single network flag", func() {
		var nsName string
		var nwsName []string
		lastNWName := ""
		var nwName string
		var clientset *kubernetes.Clientset
		netconf := fmt.Sprintf(`
		{
			"cniVersion": "%s",
			"name": "%s",
			"type": "calico",
			"etcd_endpoints": "%s",
			"datastore_type": "%s",
			"nodename_file_optional": true,
			"log_level": "debug",
			"ipam": {
				"type": "calico-ipam"
			},
			"kubernetes": {
				"k8s_api_root": "%s",
				"kubeconfig": "C:\\k\\config"
			},
			"policy": {"type": "k8s"}
		}`, cniVersion, networkName, os.Getenv("ETCD_ENDPOINTS"), os.Getenv("DATASTORE_TYPE"), os.Getenv("KUBERNETES_MASTER"))

		BeforeEach(func() {
			Skip("Calico for Windows does not support multiple network. Skip test...")

			testutils.WipeK8sPods(netconf)
			// Create a new ipPool.
			testutils.MustCreateNewIPPoolBlockSize(calicoClient, "10.0.0.0/26", false, false, true, 29)

			conf := types.NetConf{}
			if err := json.Unmarshal([]byte(netconf), &conf); err != nil {
				panic(err)
			}
			logger := log.WithFields(log.Fields{
				"Namespace": testutils.HnsNoneNs,
			})
			clientset, err = k8s.NewK8sClient(conf, logger)
			if err != nil {
				panic(err)
			}

			// Create a K8s Node object with PodCIDR and name equal to hostname.
			_, err = clientset.CoreV1().Nodes().Create(context.Background(), &v1.Node{
				ObjectMeta: metav1.ObjectMeta{Name: hostname},
				Spec: v1.NodeSpec{
					PodCIDR: "10.0.0.0/24",
				},
			}, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
			nsName = fmt.Sprintf("ns%d", rand.Uint32())
			// Create namespace
			ensureNamespace(clientset, nsName)
		})

		AfterEach(func() {
			// Delete the IP Pools.
			testutils.MustDeleteIPPool(calicoClient, "10.0.0.0/26")
			// Delete namespace
			deleteNamespace(clientset, nsName)
			clientset.CoreV1().Nodes().Delete(context.Background(), hostname, metav1.DeleteOptions{})
			for i := 0; i < len(nwsName); i++ {
				// Ensure network is deleted
				log.Debugf("Deleting Network : %v", nwsName[i])
				hnsNetwork, err := hcsshim.GetHNSNetworkByName(nwsName[i])
				Expect(err).ShouldNot(HaveOccurred())
				_, err = hnsNetwork.Delete()
				Expect(err).ShouldNot(HaveOccurred())
			}
			nwsName = []string{}
			lastNWName = ""
		})
		It("with windows single network flag not set,should successfully network 4 pods and successfully create new network for 5th", func() {
			// Now create a K8s pod.
			name := ""
			var containerid []string
			var podName []string
			// Make sure the pod gets cleaned up, whether we fail or not.
			defer func() {
				log.Debugf("containerid = %v", containerid)
				var cni_err error
				for i, id := range containerid {
					_, err := testutils.DeleteContainerWithId(netconf, podName[i], testutils.HnsNoneNs, id, nsName)
					if err != nil {
						cni_err = err
					}
					clientset.CoreV1().Pods(nsName).Delete(context.Background(), podName[i], metav1.DeleteOptions{})
					Expect(err).ShouldNot(HaveOccurred())
				}
				Expect(cni_err).Should(BeNil())
			}()

			for i := 0; i < 5; i++ {
				name = fmt.Sprintf("run%d", rand.Uint32())
				_, err := clientset.CoreV1().Pods(nsName).Create(
					context.Background(),
					&v1.Pod{
						ObjectMeta: metav1.ObjectMeta{
							Name: name,
						},
						Spec: v1.PodSpec{
							Containers: []v1.Container{{
								Name:  name,
								Image: "ignore",
							}},
							NodeName: hostname,
						},
					}, metav1.CreateOptions{})

				Expect(err).NotTo(HaveOccurred())
				podName = append(podName, name)
				// Create the container, which will call CNI and by default it will create the container with interface name 'eth0'.
				containerID, result, _, _, _, err := testutils.CreateContainer(netconf, name, testutils.HnsNoneNs, "", nsName)
				containerid = append(containerid, containerID)
				log.Debugf("containerid = %v", containerid)
				Expect(err).ShouldNot(HaveOccurred())
				_, subNet, _ := net.ParseCIDR(result.IPs[0].Address.String())
				nwName := windows.CreateNetworkName(networkName, subNet)
				if nwName != lastNWName {
					lastNWName = nwName
					nwsName = append(nwsName, nwName)
				}
			}
			Expect(nwsName).To(HaveLen(2))
		})
		It("create 4 pods; delete 3 pods; create 3 pods, should still have only one network", func() {
			// Now create a K8s pod.
			podName := []string{}
			containerid := []string{}
			name := ""
			defer func() {
				log.Debugf("containerid = %v", containerid)
				var cni_err error
				for i, id := range containerid {
					_, err := testutils.DeleteContainerWithId(netconf, podName[i], testutils.HnsNoneNs, id, nsName)
					if err != nil {
						cni_err = err
					}
					clientset.CoreV1().Pods(nsName).Delete(context.Background(), podName[i], metav1.DeleteOptions{})
					Expect(err).ShouldNot(HaveOccurred())
				}
				Expect(cni_err).Should(BeNil())
			}()

			for i := 0; i < 4; i++ {
				name = fmt.Sprintf("run%d", rand.Uint32())
				_, err := clientset.CoreV1().Pods(nsName).Create(
					context.Background(),
					&v1.Pod{
						ObjectMeta: metav1.ObjectMeta{
							Name: name,
						},
						Spec: v1.PodSpec{
							Containers: []v1.Container{{
								Name:  name,
								Image: "ignore",
							}},
							NodeName: hostname,
						},
					}, metav1.CreateOptions{})

				Expect(err).NotTo(HaveOccurred())
				podName = append(podName, name)

				// Create the container, which will call CNI and by default it will create the container with interface name 'eth0'.
				containerID, result, _, _, _, err := testutils.CreateContainer(netconf, name, testutils.HnsNoneNs, "", nsName)
				containerid = append(containerid, containerID)
				log.Debugf("containerid = %v", containerid)
				Expect(err).ShouldNot(HaveOccurred())
				_, subNet, _ := net.ParseCIDR(result.IPs[0].Address.String())
				nwName = windows.CreateNetworkName(networkName, subNet)
				log.Debugf("nwName = %s lastNWName = %s nwsName = %v", nwName, lastNWName, nwsName)
				if nwName != lastNWName {
					lastNWName = nwName
					nwsName = append(nwsName, nwName)
				}
			}
			for i := 0; i < 3; i++ {
				_, err := testutils.DeleteContainerWithId(netconf, podName[i], testutils.HnsNoneNs, containerid[i], nsName)
				Expect(err).ShouldNot(HaveOccurred())
				clientset.CoreV1().Pods(nsName).Delete(context.Background(), podName[i], metav1.DeleteOptions{})
				Expect(err).ShouldNot(HaveOccurred())
			}
			log.Debugf("containerid = %v", containerid)
			for i := 0; i < 3; i++ {
				name = fmt.Sprintf("run%d", rand.Uint32())
				_, err := clientset.CoreV1().Pods(nsName).Create(
					context.Background(),
					&v1.Pod{
						ObjectMeta: metav1.ObjectMeta{
							Name: name,
						},
						Spec: v1.PodSpec{
							Containers: []v1.Container{{
								Name:  name,
								Image: "ignore",
							}},
							NodeName: hostname,
						},
					}, metav1.CreateOptions{})

				Expect(err).NotTo(HaveOccurred())
				podName[i] = name

				// Create the container, which will call CNI and by default it will create the container with interface name 'eth0'.
				containerID, result, _, _, _, err := testutils.CreateContainer(netconf, name, testutils.HnsNoneNs, "", nsName)
				containerid[i] = containerID
				log.Debugf("containerid = %v", containerid)
				Expect(err).ShouldNot(HaveOccurred())
				_, subNet, _ := net.ParseCIDR(result.IPs[0].Address.String())
				podNwName := windows.CreateNetworkName(networkName, subNet)
				log.Debugf("podNwName = %s lastNWName = %s nwsName = %v", podNwName, lastNWName, nwsName)
				if podNwName != lastNWName {
					lastNWName = podNwName
					nwsName = append(nwsName, podNwName)
				}
				//Network should  be same
				Expect(nwName).Should(Equal(podNwName))
			}
		})
	})

	Context("l2bridge network::With DNS capability in Runtime Config", func() {
		var nsName, name string
		var clientset *kubernetes.Clientset
		netconf := fmt.Sprintf(`
                        {
                                "cniVersion": "%s",
                                "name": "%s",
                                "type": "calico",
                                "etcd_endpoints": "%s",
                                "datastore_type": "%s",
                                "windows_use_single_network":true,
                                "ipam": {
                                        "type": "host-local",
                                        "subnet": "10.254.112.0/20"
                                },
                                "kubernetes": {
                                        "k8s_api_root": "%s",
                                        "kubeconfig": "C:\\k\\config"
                                },
                                "policy": {"type": "k8s"},
                                "nodename_file_optional": true,
                                "log_level":"debug",
                                "DNS":  {
                                        "Nameservers":  [
                                        "10.96.0.10"
                                        ],
                                        "Search":  [
                                        "pod.cluster.local"
                                        ]
                                },
                                "RuntimeConfig": {
                                                 "DNS": {
                                                        "servers":  [
                                                        "10.96.0.11"
                                                        ],
                                                        "searches":  [
                                                        "svc.cluster.local"
                                                        ]
                                                 }
                                }
                        }`, cniVersion, networkName, os.Getenv("ETCD_ENDPOINTS"), os.Getenv("DATASTORE_TYPE"), os.Getenv("KUBERNETES_MASTER"))
		Context("and has RuntimeConfig entry", func() {
			cleanup := func() {
				// Cleanup hns network
				hnsNetwork, _ := hcsshim.GetHNSNetworkByName(networkName)
				if hnsNetwork != nil {
					_, err := hnsNetwork.Delete()
					Expect(err).NotTo(HaveOccurred())
				}
				// Delete node
				_ = clientset.CoreV1().Nodes().Delete(context.Background(), hostname, metav1.DeleteOptions{})
			}

			BeforeEach(func() {
				testutils.WipeK8sPods(netconf)
				conf := types.NetConf{}
				if err := json.Unmarshal([]byte(netconf), &conf); err != nil {
					panic(err)
				}
				logger := log.WithFields(log.Fields{
					"Namespace": testutils.HnsNoneNs,
				})
				clientset, err = k8s.NewK8sClient(conf, logger)
				if err != nil {
					panic(err)
				}

				nsName = fmt.Sprintf("ns%d", rand.Uint32())
				name = fmt.Sprintf("run%d", rand.Uint32())
				cleanup()

				// Create namespace
				ensureNamespace(clientset, nsName)

				// Create a K8s Node object with PodCIDR and name equal to hostname.
				_, err = clientset.CoreV1().Nodes().Create(context.Background(), &v1.Node{
					ObjectMeta: metav1.ObjectMeta{Name: hostname},
					Spec: v1.NodeSpec{
						PodCIDR: "10.0.0.0/24",
					},
				}, metav1.CreateOptions{})
				Expect(err).NotTo(HaveOccurred())

				// Create a K8s pod w/o any special params
				_, err = clientset.CoreV1().Pods(nsName).Create(context.Background(), &v1.Pod{
					ObjectMeta: metav1.ObjectMeta{Name: name},
					Spec: v1.PodSpec{
						Containers: []v1.Container{{
							Name:  name,
							Image: "ignore",
						}},
						NodeName: hostname,
					},
				}, metav1.CreateOptions{})
				Expect(err).NotTo(HaveOccurred())
			})

			AfterEach(func() {
				cleanup()
				// Delete namespace
				deleteNamespace(clientset, nsName)
			})

			It("should network the pod with DNS values from Runtime Config", func() {
				log.Infof("Creating container")
				containerID, result, contVeth, contAddresses, contRoutes, err := testutils.CreateContainer(netconf, name, testutils.HnsNoneNs, "", nsName)
				Expect(err).ShouldNot(HaveOccurred())
				defer func() {
					log.Infof("Container Delete  call")
					_, err := testutils.DeleteContainerWithId(netconf, name, testutils.HnsNoneNs, containerID, nsName)
					Expect(err).ShouldNot(HaveOccurred())

					// Make sure there are no endpoints anymore
					endpoints, err := calicoClient.WorkloadEndpoints().List(ctx, options.ListOptions{})
					Expect(err).ShouldNot(HaveOccurred())
					Expect(endpoints.Items).Should(HaveLen(0))
				}()
				log.Debugf("containerID :%v , result: %v ,icontVeth : %v , contAddresses : %v ,contRoutes : %v ", containerID, result, contVeth, contAddresses, contRoutes)

				Expect(len(result.IPs)).Should(Equal(1))
				ip := result.IPs[0].Address.IP.String()
				log.Debugf("ip is %v ", ip)

				// The endpoint is created
				endpoints, err := calicoClient.WorkloadEndpoints().List(ctx, options.ListOptions{})
				Expect(err).ShouldNot(HaveOccurred())
				Expect(endpoints.Items).Should(HaveLen(1))

				// Ensure network is created.
				_, err = hcsshim.GetHNSNetworkByName(networkName)
				Expect(err).ShouldNot(HaveOccurred())

				// Ensure host endpoints are created
				_, err = hcsshim.GetHNSEndpointByName("calico-fv_ep")
				Expect(err).ShouldNot(HaveOccurred())

				// Ensure container endpoints are created and has DNS RuntimeConfig values
				containerEP, err := hcsshim.GetHNSEndpointByName(containerID + "_calico-fv")
				Expect(err).ShouldNot(HaveOccurred())
				Expect(containerEP.DNSSuffix).Should(Equal("svc.cluster.local"))
				Expect(containerEP.DNSServerList).Should(Equal("10.96.0.11"))

			})
		})
	})

	Context("overlay network::using host-local IPAM", func() {
		var nsName, name string
		var clientset *kubernetes.Clientset
		vxlanConf := fmt.Sprintf(`
		{
			"cniVersion": "%s",
			"name": "%s",
			"type": "calico",
			"mode": "vxlan",
			"vxlan_mac_prefix": "%s",
			"vxlan_vni": 4096,
			"etcd_endpoints": "%s",
			"datastore_type": "%s",
			"windows_use_single_network":true,
			"ipam": {
				"type": "host-local",
				"subnet": "10.254.112.0/20"
			},
			"kubernetes": {
				"k8s_api_root": "%s",
				"kubeconfig": "C:\\k\\config"
			},
			"policy": {"type": "k8s"},
			"nodename_file_optional": true,
			"log_level":"debug"
		}`, cniVersion, networkName, os.Getenv("MAC_PREFIX"), os.Getenv("ETCD_ENDPOINTS"), os.Getenv("DATASTORE_TYPE"), os.Getenv("KUBERNETES_MASTER"))

		cleanup := func() {
			// Cleanup hns network
			hnsNetwork, _ := hcsshim.GetHNSNetworkByName(networkName)
			if hnsNetwork != nil {
				_, err := hnsNetwork.Delete()
				Expect(err).NotTo(HaveOccurred())
			}

			// Delete node
			_ = clientset.CoreV1().Nodes().Delete(context.Background(), hostname, metav1.DeleteOptions{})
		}

		BeforeEach(func() {
			testutils.WipeK8sPods(vxlanConf)
			conf := types.NetConf{}
			if err := json.Unmarshal([]byte(vxlanConf), &conf); err != nil {
				panic(err)
			}
			logger := log.WithFields(log.Fields{
				"Namespace": testutils.HnsNoneNs,
			})
			clientset, err = k8s.NewK8sClient(conf, logger)
			if err != nil {
				panic(err)
			}

			nsName = fmt.Sprintf("ns%d", rand.Uint32())
			name = fmt.Sprintf("run%d", rand.Uint32())
			cleanup()

			// Create namespace
			ensureNamespace(clientset, nsName)

			// Create a K8s Node object with PodCIDR and name equal to hostname.
			_, err = clientset.CoreV1().Nodes().Create(context.Background(), &v1.Node{
				ObjectMeta: metav1.ObjectMeta{Name: hostname},
				Spec: v1.NodeSpec{
					PodCIDR: "10.0.0.0/24",
				},
			}, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			// Create a K8s pod w/o any special params
			_, err = clientset.CoreV1().Pods(nsName).Create(context.Background(), &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: name},
				Spec: v1.PodSpec{
					Containers: []v1.Container{{
						Name:  name,
						Image: "ignore",
					}},
					NodeName: hostname,
				},
			}, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
		})

		AfterEach(func() {
			cleanup()
			// Delete namespace
			deleteNamespace(clientset, nsName)
		})

		It("successfully creates overlay network", func() {

			log.Infof("Creating container")
			containerID, result, contVeth, contAddresses, contRoutes, err := testutils.CreateContainer(vxlanConf, name, testutils.HnsNoneNs, "", nsName)
			Expect(err).ShouldNot(HaveOccurred())
			defer func() {
				log.Infof("Container Delete  call")
				_, err = testutils.DeleteContainerWithId(vxlanConf, name, testutils.HnsNoneNs, containerID, nsName)
				Expect(err).ShouldNot(HaveOccurred())

				// Make sure there are no endpoints anymore
				endpoints, err := calicoClient.WorkloadEndpoints().List(ctx, options.ListOptions{})
				Expect(err).ShouldNot(HaveOccurred())
				Expect(endpoints.Items).Should(HaveLen(0))
			}()
			log.Debugf("containerID :%v , result: %v ,icontVeth : %v , contAddresses : %v ,contRoutes : %v ", containerID, result, contVeth, contAddresses, contRoutes)

			Expect(len(result.IPs)).Should(Equal(1))
			ip := result.IPs[0].Address.IP.String()
			log.Debugf("ip is %v ", ip)
			result.IPs[0].Address.IP = result.IPs[0].Address.IP.To4() // Make sure the IP is respresented as 4 bytes
			Expect(result.IPs[0].Address.Mask.String()).Should(Equal("fffff000"))

			// datastore things:
			ids := names.WorkloadEndpointIdentifiers{
				Node:         hostname,
				Orchestrator: api.OrchestratorKubernetes,
				Endpoint:     "eth0",
				Pod:          name,
				ContainerID:  containerID,
			}

			wrkload, err := ids.CalculateWorkloadEndpointName(false)
			log.Debugf("workload endpoint: %v", wrkload)
			Expect(err).NotTo(HaveOccurred())

			// The endpoint is created
			endpoints, err := calicoClient.WorkloadEndpoints().List(ctx, options.ListOptions{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(endpoints.Items).Should(HaveLen(1))

			Expect(endpoints.Items[0].Name).Should(Equal(wrkload))
			Expect(endpoints.Items[0].Namespace).Should(Equal(nsName))
			Expect(endpoints.Items[0].Labels).Should(Equal(map[string]string{
				"projectcalico.org/namespace":      nsName,
				"projectcalico.org/orchestrator":   api.OrchestratorKubernetes,
				"projectcalico.org/serviceaccount": "default",
			}))
			Expect(endpoints.Items[0].Spec.Pod).Should(Equal(name))
			Expect(endpoints.Items[0].Spec.IPNetworks[0]).Should(Equal(result.IPs[0].Address.IP.String() + "/32"))
			Expect(endpoints.Items[0].Spec.Node).Should(Equal(hostname))
			Expect(endpoints.Items[0].Spec.Endpoint).Should(Equal("eth0"))
			Expect(endpoints.Items[0].Spec.Workload).Should(Equal(""))
			Expect(endpoints.Items[0].Spec.ContainerID).Should(Equal(containerID))
			Expect(endpoints.Items[0].Spec.Orchestrator).Should(Equal(api.OrchestratorKubernetes))

			// Ensure tunnel mac address and ip are updated correctly
			node, err := calicoClient.Nodes().Get(ctx, hostname, options.GetOptions{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(node.Spec.IPv4VXLANTunnelAddr).Should(Equal("10.254.112.1"))
			_, subNet, _ := net.ParseCIDR(result.IPs[0].Address.String())
			mac, err := windows.GetDRMACAddr(networkName, subNet)
			Expect(mac).ShouldNot(Equal(""))
			Expect(err).ShouldNot(HaveOccurred())
			Expect(node.Spec.VXLANTunnelMACAddr).Should(Equal(mac.String()))

			// Ensure network is created
			hnsNetwork, err := hcsshim.GetHNSNetworkByName(networkName)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(hnsNetwork.Subnets[0].AddressPrefix).Should(Equal("10.254.112.0/20"))
			Expect(hnsNetwork.Subnets[0].GatewayAddress).Should(Equal("10.254.112.1"))
			Expect(hnsNetwork.Type).Should(Equal("Overlay"))

			mgmtIP := hnsNetwork.ManagementIP
			macAddr := windows.GetMacAddr(mgmtIP)

			// Ensure host and container endpoints are created
			hostEP, err := hcsshim.GetHNSEndpointByName("calico-fv_ep")
			Expect(err).ShouldNot(HaveOccurred())
			Expect(hostEP.IPAddress.String()).Should(Equal("10.254.112.2"))
			Expect(hostEP.VirtualNetwork).Should(Equal(hnsNetwork.Id))
			Expect(hostEP.VirtualNetworkName).Should(Equal(hnsNetwork.Name))
			Expect(hostEP.MacAddress).Should(Equal(macAddr))

			containerEP, err := hcsshim.GetHNSEndpointByName(containerID + "_calico-fv")
			Expect(containerEP.IPAddress.String()).Should(Equal(ip))
			Expect(containerEP.GatewayAddress).Should(Equal("10.254.112.1"))
			ipBytes := containerEP.IPAddress.To4()
			epMacAddr := fmt.Sprintf("%v-%02x-%02x-%02x-%02x", os.Getenv("MAC_PREFIX"), ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3])
			Expect(containerEP.MacAddress).Should(Equal(epMacAddr))
			Expect(strings.ToUpper(containerEP.VirtualNetwork)).Should(Equal(strings.ToUpper(hnsNetwork.Id)))
			Expect(containerEP.VirtualNetworkName).Should(Equal(hnsNetwork.Name))
		})
	})

	Context("overlay network:: Pod DEL timestamp", func() {
		var nsName, name string
		var clientset *kubernetes.Clientset

		// Set windows_pod_deletion_timestamp_timeout to 10 seconds
		vxlanConf := fmt.Sprintf(`
		{
			"cniVersion": "%s",
			"name": "%s",
			"type": "calico",
			"mode": "vxlan",
			"vxlan_mac_prefix": "%s",
			"vxlan_vni": 4096,
			"etcd_endpoints": "%s",
			"datastore_type": "%s",
			"windows_use_single_network":true,
			"windows_pod_deletion_timestamp_timeout": 12,
			"ipam": {
				"type": "host-local",
				"subnet": "10.254.112.0/20"
			},
			"kubernetes": {
				"k8s_api_root": "%s",
				"kubeconfig": "C:\\k\\config"
			},
			"policy": {"type": "k8s"},
			"nodename_file_optional": true,
			"log_level":"debug"
		}`, cniVersion, networkName, os.Getenv("MAC_PREFIX"), os.Getenv("ETCD_ENDPOINTS"), os.Getenv("DATASTORE_TYPE"), os.Getenv("KUBERNETES_MASTER"))

		conf := types.NetConf{}
		if err := json.Unmarshal([]byte(vxlanConf), &conf); err != nil {
			panic(err)
		}
		logger := log.WithFields(log.Fields{
			"Namespace": testutils.HnsNoneNs,
		})

		clientset, err = k8s.NewK8sClient(conf, logger)
		if err != nil {
			panic(err)
		}

		cleanup := func() {
			// Cleanup hns network
			hnsNetwork, _ := hcsshim.GetHNSNetworkByName(networkName)
			if hnsNetwork != nil {
				_, err := hnsNetwork.Delete()
				Expect(err).NotTo(HaveOccurred())
			}

			// Delete node
			_ = clientset.CoreV1().Nodes().Delete(context.Background(), hostname, metav1.DeleteOptions{})
		}

		setupPodResource := func(podName string) {
			// Create a K8s pod w/o any special params
			_, err = clientset.CoreV1().Pods(nsName).Create(context.Background(), &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: podName},
				Spec: v1.PodSpec{
					Containers: []v1.Container{{
						Name:  podName,
						Image: "ignore",
					}},
					NodeName: hostname,
				},
			}, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
		}

		BeforeEach(func() {
			if os.Getenv("CONTAINER_RUNTIME") == "containerd" {
				Skip("Pod deletion timestamps only apply to dockershim V1 flow")
			}

			testutils.WipeK8sPods(vxlanConf)

			nsName = fmt.Sprintf("ns%d", rand.Uint32())
			name = fmt.Sprintf("run%d", rand.Uint32())
			cleanup()

			// Create namespace
			ensureNamespace(clientset, nsName)

			// Create a K8s Node object with PodCIDR and name equal to hostname.
			_, err = clientset.CoreV1().Nodes().Create(context.Background(), &v1.Node{
				ObjectMeta: metav1.ObjectMeta{Name: hostname},
				Spec: v1.NodeSpec{
					PodCIDR: "10.0.0.0/24",
				},
			}, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			setupPodResource(name)
		})

		AfterEach(func() {
			cleanup()
			// Delete namespace
			deleteNamespace(clientset, nsName)
		})

		ensureTimestamp := func(id string) {
			log.Infof("Ensure timestamp for pod deletion")
			t, err := testutils.GetTimestampValue(utils.PodDeletedKey, id)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(t.Before(time.Now())).To(Equal(true))
		}

		It("should create pod deletion timestamp in registry", func() {
			log.Infof("Delete pod deletion subkey")
			err = testutils.DeleteSubKey(utils.CalicoRegistryKey, utils.PodDeletedKeyString)
			Expect(err).NotTo(HaveOccurred())

			log.Infof("Creating container")
			containerID, _, _, _, _, err := testutils.CreateContainer(vxlanConf, name, testutils.HnsNoneNs, "", nsName)
			Expect(err).ShouldNot(HaveOccurred())
			defer func() {
				log.Infof("Container Delete call")
				_, err = testutils.DeleteContainerWithId(vxlanConf, name, testutils.HnsNoneNs, containerID, nsName)
				Expect(err).ShouldNot(HaveOccurred())

				time.Sleep(time.Second)
				ensureTimestamp(containerID)
			}()

			keyExists, err := testutils.CheckRegistryKeyExists(utils.PodDeletedKey)
			Expect(err).NotTo(HaveOccurred())
			Expect(keyExists).To(Equal(true))
		})

		It("should checking pod deletion timestamp on ADD", func() {
			log.Infof("Creating three containers")
			// First pod has been created by BeforeEach
			containerID1, _, _, _, _, err := testutils.CreateContainer(vxlanConf, name, testutils.HnsNoneNs, "", nsName)
			Expect(err).ShouldNot(HaveOccurred())
			name2 := "secondpod"
			setupPodResource(name2)
			containerID2, _, _, _, _, err := testutils.CreateContainer(vxlanConf, name2, testutils.HnsNoneNs, "", nsName)
			Expect(err).ShouldNot(HaveOccurred())
			name3 := "thirdpod"
			setupPodResource(name3)
			containerID3, _, _, _, _, err := testutils.CreateContainer(vxlanConf, name3, testutils.HnsNoneNs, "", nsName)
			Expect(err).ShouldNot(HaveOccurred())

			log.Infof("Deleting first two containers")
			_, err = testutils.DeleteContainerWithId(vxlanConf, name, testutils.HnsNoneNs, containerID1, nsName)
			Expect(err).ShouldNot(HaveOccurred())
			ensureTimestamp(containerID1)
			_, err = testutils.DeleteContainerWithId(vxlanConf, name2, testutils.HnsNoneNs, containerID2, nsName)
			Expect(err).ShouldNot(HaveOccurred())
			ensureTimestamp(containerID2)

			log.Infof("Sleeping 7 seconds")
			time.Sleep(time.Second * 7)

			log.Infof("Checking timestamp container 1 %s", containerID1)
			justDeleted, err := utils.CheckWepJustDeleted(containerID1, 12)
			Expect(err).ShouldNot(HaveOccurred())
			//JustDeleted for container1 could vary because it depends on how long it takes to delete container2.

			log.Infof("Checking timestamp container 2 %s", containerID2)
			justDeleted, err = utils.CheckWepJustDeleted(containerID2, 12)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(justDeleted).To(Equal(true))

			log.Infof("Checking timestamp container 3 %s", containerID3)
			justDeleted, err = utils.CheckWepJustDeleted(containerID3, 12)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(justDeleted).To(Equal(false))

			log.Infof("Deleting last container")
			_, err = testutils.DeleteContainerWithId(vxlanConf, name3, testutils.HnsNoneNs, containerID3, nsName)
			Expect(err).ShouldNot(HaveOccurred())
			ensureTimestamp(containerID3)

			// Make sure timeout on pod1, pod2 deletion timestamp. 7+7 > 12
			log.Infof("Sleeping further 7 seonds")
			time.Sleep(time.Second * 7)
			justDeleted, err = utils.CheckWepJustDeleted(containerID1, 12)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(justDeleted).To(Equal(false))

			justDeleted, err = utils.CheckWepJustDeleted(containerID2, 12)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(justDeleted).To(Equal(false))

			justDeleted, err = utils.CheckWepJustDeleted(containerID3, 12)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(justDeleted).To(Equal(true))

			log.Infof("Adding last container [%s] again", containerID3)
			// Should fail adding last container
			_, _, _, _, _, err = testutils.CreateContainerWithId(vxlanConf, name3, testutils.HnsNoneNs, "", containerID3, nsName)
			Expect(err).Should(HaveOccurred())

			// first two timestamp are gone
			_, err = testutils.GetTimestampValue(utils.PodDeletedKey, containerID1)
			Expect(err).Should(HaveOccurred())

			_, err = testutils.GetTimestampValue(utils.PodDeletedKey, containerID2)
			Expect(err).Should(HaveOccurred())
		})
	})
})
