// Copyright (c) 2017,2020 Tigera, Inc. All rights reserved.

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

package clientv3_test

import (
	"net"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"context"

	"fmt"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	libapiv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/backend"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
	"github.com/projectcalico/calico/libcalico-go/lib/watch"
)

var _ = testutils.E2eDatastoreDescribe("Node tests (kdd)", testutils.DatastoreK8s, func(config apiconfig.CalicoAPIConfig) {
	ctx := context.Background()

	It("should delete labels on a node", func() {
		c, err := clientv3.New(config)
		Expect(err).NotTo(HaveOccurred())
		be, err := backend.NewClient(config)
		Expect(err).NotTo(HaveOccurred())
		be.Clean()

		// Get a node.
		By("Querying a node")
		name := "127.0.0.1"
		node, err := c.Nodes().Get(ctx, name, options.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(len(node.Labels)).To(Equal(0))

		// Without any BGP config written, the BGP spec should be nil.
		Expect(node.Spec.BGP).To(BeNil())

		// Add a label and check it gets written.
		By("Adding a label to the node")
		node.Labels = map[string]string{"test-label": "foo"}
		node.Spec.BGP = &libapiv3.NodeBGPSpec{IPv4Address: "10.0.0.1"}
		_, err = c.Nodes().Update(ctx, node, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Checking the label gets added")
		node, err = c.Nodes().Get(ctx, name, options.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(len(node.Labels)).To(Equal(1))

		// Delete the label from the node.
		By("Deleting the label from the node")
		node.Labels = map[string]string{}
		_, err = c.Nodes().Update(ctx, node, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		// Get the node, check the labels are empty.
		By("Checking the label is removed")
		n, err := c.Nodes().Get(ctx, name, options.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(len(n.Labels)).To(Equal(0))
	})

	It("should update BGP spec on a node", func() {
		c, err := clientv3.New(config)
		Expect(err).NotTo(HaveOccurred())
		be, err := backend.NewClient(config)
		Expect(err).NotTo(HaveOccurred())
		be.Clean()

		// Get a node.
		By("Querying a node with no BGP spec")
		name := "127.0.0.1"
		node, err := c.Nodes().Get(ctx, name, options.GetOptions{})
		Expect(err).NotTo(HaveOccurred())

		// Without any BGP config written, the BGP spec should be nil.
		Expect(node.Spec.BGP).To(BeNil())

		// Update the BGP spec.
		By("Updating the BGP spec")
		node.Spec.BGP = &libapiv3.NodeBGPSpec{}
		node.Spec.BGP.IPv4IPIPTunnelAddr = "192.168.1.1"
		_, err = c.Nodes().Update(ctx, node, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Querying the node again")
		node, err = c.Nodes().Get(ctx, name, options.GetOptions{})
		Expect(err).NotTo(HaveOccurred())

		// It should now not be nil.
		Expect(node.Spec.BGP).NotTo(BeNil())
	})

	It("should update VXLAN tunnel address on a node", func() {
		c, err := clientv3.New(config)
		Expect(err).NotTo(HaveOccurred())
		be, err := backend.NewClient(config)
		Expect(err).NotTo(HaveOccurred())
		be.Clean()

		// Get a node.
		By("Querying a node with no VXLAN tunnel addr")
		name := "127.0.0.1"
		node, err := c.Nodes().Get(ctx, name, options.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(node.Spec.IPv4VXLANTunnelAddr).To(Equal(""))

		// Update the address.
		By("Updating the tunnel addr")
		node.Spec.IPv4VXLANTunnelAddr = "192.168.1.1"
		_, err = c.Nodes().Update(ctx, node, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Querying the node again")
		node, err = c.Nodes().Get(ctx, name, options.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(node.Spec.IPv4VXLANTunnelAddr).To(Equal("192.168.1.1"))

		// Remove the address.
		By("Removing the tunnel addr")
		node.Spec.IPv4VXLANTunnelAddr = ""
		_, err = c.Nodes().Update(ctx, node, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Querying the node again")
		node, err = c.Nodes().Get(ctx, name, options.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(node.Spec.IPv4VXLANTunnelAddr).To(Equal(""))
	})

	It("should update Wireguard interface address on a node", func() {
		c, err := clientv3.New(config)
		Expect(err).NotTo(HaveOccurred())
		be, err := backend.NewClient(config)
		Expect(err).NotTo(HaveOccurred())
		be.Clean()

		// Get a node.
		By("Querying a node with no Wireguard spec")
		name := "127.0.0.1"
		node, err := c.Nodes().Get(ctx, name, options.GetOptions{})
		Expect(err).NotTo(HaveOccurred())

		// With no Wireguard config, wireguard spec should be nil.
		Expect(node.Spec.Wireguard).To(BeNil())

		// Update the Wireguard spec.
		By("Updating the Wireguard spec")
		node.Spec.Wireguard = &libapiv3.NodeWireguardSpec{}
		node.Spec.Wireguard.InterfaceIPv4Address = "192.168.1.1"
		_, err = c.Nodes().Update(ctx, node, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("Querying the node again")
		node, err = c.Nodes().Get(ctx, name, options.GetOptions{})
		Expect(err).NotTo(HaveOccurred())

		// It should now not be nil.
		Expect(node.Spec.Wireguard).NotTo(BeNil())
	})
})

var _ = testutils.E2eDatastoreDescribe("Node tests (etcdv3)", testutils.DatastoreEtcdV3, func(config apiconfig.CalicoAPIConfig) {

	ctx := context.Background()
	name1 := "node-1"
	name2 := "node-2"
	spec1 := libapiv3.NodeSpec{
		IPv4VXLANTunnelAddr: "192.168.50.5",
		BGP: &libapiv3.NodeBGPSpec{
			IPv4Address:        "1.2.3.4",
			IPv4IPIPTunnelAddr: "192.168.50.6",
		},
		OrchRefs: []libapiv3.OrchRef{
			{
				Orchestrator: "k8s",
				NodeName:     "node1",
			},
			{
				Orchestrator: "mesos",
				NodeName:     "node1",
			},
		},
		Wireguard: &libapiv3.NodeWireguardSpec{
			InterfaceIPv4Address: "192.168.50.7",
		},
	}
	spec2 := libapiv3.NodeSpec{
		BGP: &libapiv3.NodeBGPSpec{
			IPv4Address: "10.20.30.40",
			IPv6Address: "aa:bb:cc::ff",
		},
		OrchRefs: []libapiv3.OrchRef{
			{
				Orchestrator: "k8s",
				NodeName:     "node2",
			},
			{
				Orchestrator: "mesos",
				NodeName:     "node2",
			},
		},
	}
	status := libapiv3.NodeStatus{
		WireguardPublicKey: "jlkVyQYooZYzI2wFfNhSZez5eWh44yfq1wKVjLvSXgY=",
	}

	Describe("nodes", func() {
		It("should clean up weps, IPAM allocations, etc. when deleted", func() {
			c, err := clientv3.New(config)
			Expect(err).NotTo(HaveOccurred())

			be, err := backend.NewClient(config)
			Expect(err).NotTo(HaveOccurred())
			be.Clean()

			// Create a node.
			n, err := c.Nodes().Create(ctx, &libapiv3.Node{
				ObjectMeta: metav1.ObjectMeta{Name: name1},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())

			// Create objects associated with this node.
			pool := apiv3.IPPool{
				Spec: apiv3.IPPoolSpec{
					CIDR: "192.168.0.0/16",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "mypool",
				},
			}
			_, err = c.IPPools().Create(ctx, &pool, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())

			// Allocate IPIP and VXLAN tunnel addresses for the node based
			// on the values from the node spec.
			vxlanHandle := "vxlanTunnelAddr"
			vxlanIP := n.Spec.IPv4VXLANTunnelAddr
			err = c.IPAM().AssignIP(ctx, ipam.AssignIPArgs{
				IP:       cnet.MustParseIP(vxlanIP),
				Hostname: name1,
				HandleID: &vxlanHandle,
			})
			Expect(err).NotTo(HaveOccurred())
			ipipHandle := "ipipTunnelAddr"
			ipipIP := n.Spec.BGP.IPv4IPIPTunnelAddr
			err = c.IPAM().AssignIP(ctx, ipam.AssignIPArgs{
				IP:       cnet.MustParseIP(ipipIP),
				Hostname: name1,
				HandleID: &ipipHandle,
			})
			Expect(err).NotTo(HaveOccurred())

			// Create a wep and IP address for the wep on the node.
			swepIp := "192.168.0.1/32"
			wepIp := net.IP{192, 168, 0, 1}
			affBlock := cnet.IPNet{
				IPNet: net.IPNet{
					IP:   net.IP{192, 168, 0, 0},
					Mask: net.IPMask{255, 255, 255, 0},
				},
			}
			_, _, err = c.IPAM().ClaimAffinity(ctx, affBlock, name1)
			Expect(err).NotTo(HaveOccurred())

			handle := "myhandle"
			err = c.IPAM().AssignIP(ctx, ipam.AssignIPArgs{
				IP:       cnet.IP{wepIp},
				Hostname: name1,
				HandleID: &handle,
			})
			Expect(err).NotTo(HaveOccurred())

			wep := libapiv3.WorkloadEndpoint{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "node--1-k8s-mypod-mywep",
					Namespace: "default",
				},
				Spec: libapiv3.WorkloadEndpointSpec{
					InterfaceName: "eth0",
					Pod:           "mypod",
					Endpoint:      "mywep",
					IPNetworks: []string{
						swepIp,
					},
					Node:         name1,
					Orchestrator: "k8s",
					Workload:     "default.fakepod",
				},
			}
			_, err = c.WorkloadEndpoints().Create(ctx, &wep, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())

			bgppeer := apiv3.BGPPeer{
				Spec: apiv3.BGPPeerSpec{
					Node: name1,
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "bgppeer1",
				},
			}
			_, err = c.BGPPeers().Create(ctx, &bgppeer, options.SetOptions{})
			Expect(err).ShouldNot(HaveOccurred())

			nodeConfigName := fmt.Sprintf("node.%s", name1)
			felixConf := apiv3.FelixConfiguration{
				Spec: apiv3.FelixConfigurationSpec{},
				ObjectMeta: metav1.ObjectMeta{
					Name: nodeConfigName,
				},
			}
			_, err = c.FelixConfigurations().Create(ctx, &felixConf, options.SetOptions{})
			Expect(err).ShouldNot(HaveOccurred())

			bgpConf := apiv3.BGPConfiguration{
				Spec: apiv3.BGPConfigurationSpec{
					LogSeverityScreen: "Info",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: nodeConfigName,
				},
			}
			_, err = c.BGPConfigurations().Create(ctx, &bgpConf, options.SetOptions{})
			Expect(err).ShouldNot(HaveOccurred())

			// Create a HEP on this node and a HEP on another node.
			hep1 := apiv3.NewHostEndpoint()
			hep1.Name = "host-endpoint-1"
			hep1.Spec = apiv3.HostEndpointSpec{
				Node:          name1,
				InterfaceName: "eth0",
			}
			_, err = c.HostEndpoints().Create(ctx, hep1, options.SetOptions{})
			Expect(err).ShouldNot(HaveOccurred())
			hep2 := apiv3.NewHostEndpoint()
			hep2.Name = "host-endpoint-2"
			hep2.Spec = apiv3.HostEndpointSpec{
				Node:          "another-node",
				InterfaceName: "eth0",
			}
			_, err = c.HostEndpoints().Create(ctx, hep2, options.SetOptions{})
			Expect(err).ShouldNot(HaveOccurred())

			// Delete the node.
			_, err = c.Nodes().Delete(ctx, name1, options.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())

			// Check that the node is removed from Calico.
			node, err := c.Nodes().Get(ctx, name1, options.GetOptions{})
			Expect(node).Should(BeNil())

			// Check that all other node-specific data was also removed
			// starting with the wep.
			w, err := c.WorkloadEndpoints().Get(ctx, "default", "node--1-k8s-mypod-mywep", options.GetOptions{})
			Expect(w).To(BeNil())

			// Check that the wep's IP was released
			ips, err := c.IPAM().IPsByHandle(ctx, handle)
			Expect(ips).Should(BeNil())

			// Check that the IPIP and VXLAN tunnel addresses were released.
			ips, err = c.IPAM().IPsByHandle(ctx, vxlanHandle)
			Expect(ips).Should(BeNil())
			ips, err = c.IPAM().IPsByHandle(ctx, ipipHandle)
			Expect(ips).Should(BeNil())

			// Check that the host affinity pool was released.
			err = c.IPAM().ReleaseAffinity(ctx, affBlock, name1, false)
			Expect(err).NotTo(HaveOccurred())

			list, err := be.List(
				context.Background(),
				model.BlockAffinityListOptions{
					Host: name1,
				},
				"",
			)
			Expect(err).NotTo(HaveOccurred())
			Expect(list.KVPairs).To(HaveLen(0))

			// Check that the bgppeer was deleted
			peer, err := c.BGPPeers().Get(ctx, "bgppeer1", options.GetOptions{})
			Expect(peer).Should(BeNil())
			Expect(err).To(HaveOccurred())

			// Check that the felix config was deleted
			fconfig, err := c.FelixConfigurations().Get(ctx, nodeConfigName, options.GetOptions{})
			Expect(fconfig).Should(BeNil())
			Expect(err).To(HaveOccurred())

			// Check that the bgp config was deleted
			bconfig, err := c.BGPConfigurations().Get(ctx, nodeConfigName, options.GetOptions{})
			Expect(bconfig).Should(BeNil())
			Expect(err).To(HaveOccurred())

			// Check that the HEP was deleted.
			hep, err := c.HostEndpoints().Get(ctx, hep1.Name, options.GetOptions{})
			Expect(hep).Should(BeNil())
			Expect(err).To(HaveOccurred())

			// Check the HEP on the other node was not deleted.
			hep, err = c.HostEndpoints().Get(ctx, hep2.Name, options.GetOptions{})
			Expect(hep).ShouldNot(BeNil())
			Expect(err).NotTo(HaveOccurred())
		})

	})

	DescribeTable("Node e2e CRUD tests",
		func(name1, name2 string, spec1, spec2 libapiv3.NodeSpec, status libapiv3.NodeStatus) {
			c, err := clientv3.New(config)
			Expect(err).NotTo(HaveOccurred())

			be, err := backend.NewClient(config)
			Expect(err).NotTo(HaveOccurred())
			be.Clean()

			By("Updating the Node before it is created")
			_, outError := c.Nodes().Update(ctx, &libapiv3.Node{
				ObjectMeta: metav1.ObjectMeta{Name: name1, ResourceVersion: "1234", CreationTimestamp: metav1.Now(), UID: "test-fail-node"},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(ContainSubstring("resource does not exist: Node(" + name1 + ") with error:"))

			By("Attempting to creating a new Node with name1/spec1 and a non-empty ResourceVersion")
			_, outError = c.Nodes().Create(ctx, &libapiv3.Node{
				ObjectMeta: metav1.ObjectMeta{Name: name1, ResourceVersion: "12345"},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("error with field Metadata.ResourceVersion = '12345' (field must not be set for a Create request)"))

			By("Creating a new Node with name1/spec1")
			res1, outError := c.Nodes().Create(ctx, &libapiv3.Node{
				ObjectMeta: metav1.ObjectMeta{Name: name1},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res1).To(MatchResource(libapiv3.KindNode, testutils.ExpectNoNamespace, name1, spec1))

			// Track the version of the original data for name1.
			rv1_1 := res1.ResourceVersion

			By("Attempting to create the same Node with name1 but with spec2")
			_, outError = c.Nodes().Create(ctx, &libapiv3.Node{
				ObjectMeta: metav1.ObjectMeta{Name: name1},
				Spec:       spec2,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("resource already exists: Node(" + name1 + ")"))

			By("Getting Node (name1) and comparing the output against spec1")
			res, outError := c.Nodes().Get(ctx, name1, options.GetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res).To(MatchResource(libapiv3.KindNode, testutils.ExpectNoNamespace, name1, spec1))
			Expect(res.ResourceVersion).To(Equal(res1.ResourceVersion))

			By("Getting Node (name2) before it is created")
			_, outError = c.Nodes().Get(ctx, name2, options.GetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(ContainSubstring("resource does not exist: Node(" + name2 + ") with error:"))

			By("Listing all the Nodes, expecting a single result with name1/spec1")
			outList, outError := c.Nodes().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(ConsistOf(
				testutils.Resource(libapiv3.KindNode, testutils.ExpectNoNamespace, name1, spec1),
			))

			By("Creating a new Node with name2/spec2")
			res2, outError := c.Nodes().Create(ctx, &libapiv3.Node{
				ObjectMeta: metav1.ObjectMeta{Name: name2},
				Spec:       spec2,
			}, options.SetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res2).To(MatchResource(libapiv3.KindNode, testutils.ExpectNoNamespace, name2, spec2))

			By("Getting Node (name2) and comparing the output against spec2")
			res, outError = c.Nodes().Get(ctx, name2, options.GetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res2).To(MatchResource(libapiv3.KindNode, testutils.ExpectNoNamespace, name2, spec2))
			Expect(res.ResourceVersion).To(Equal(res2.ResourceVersion))

			By("Listing all the Nodes, expecting a two results with name1/spec1 and name2/spec2")
			outList, outError = c.Nodes().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(ConsistOf(
				testutils.Resource(libapiv3.KindNode, testutils.ExpectNoNamespace, name1, spec1),
				testutils.Resource(libapiv3.KindNode, testutils.ExpectNoNamespace, name2, spec2),
			))

			By("Updating Node name1 with spec2")
			res1.Spec = spec2
			res1, outError = c.Nodes().Update(ctx, res1, options.SetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res1).To(MatchResource(libapiv3.KindNode, testutils.ExpectNoNamespace, name1, spec2))

			By("Attempting to update the Node without a Creation Timestamp")
			res, outError = c.Nodes().Update(ctx, &libapiv3.Node{
				ObjectMeta: metav1.ObjectMeta{Name: name1, ResourceVersion: "1234", UID: "test-fail-workload-endpoint"},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(res).To(BeNil())
			Expect(outError.Error()).To(Equal("error with field Metadata.CreationTimestamp = '0001-01-01 00:00:00 +0000 UTC' (field must be set for an Update request)"))

			By("Attempting to update the Node without a UID")
			res, outError = c.Nodes().Update(ctx, &libapiv3.Node{
				ObjectMeta: metav1.ObjectMeta{Name: name1, ResourceVersion: "1234", CreationTimestamp: metav1.Now()},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(res).To(BeNil())
			Expect(outError.Error()).To(Equal("error with field Metadata.UID = '' (field must be set for an Update request)"))

			// Track the version of the updated name1 data.
			rv1_2 := res1.ResourceVersion

			By("Updating Node name1 without specifying a resource version")
			res1.Spec = spec1
			res1.ObjectMeta.ResourceVersion = ""
			_, outError = c.Nodes().Update(ctx, res1, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("error with field Metadata.ResourceVersion = '' (field must be set for an Update request)"))

			By("Updating Node name1 using the previous resource version")
			res1.Spec = spec1
			res1.ResourceVersion = rv1_1
			_, outError = c.Nodes().Update(ctx, res1, options.SetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("update conflict: Node(" + name1 + ")"))

			By("Getting Node (name1) with the original resource version and comparing the output against spec1")
			res, outError = c.Nodes().Get(ctx, name1, options.GetOptions{ResourceVersion: rv1_1})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res).To(MatchResource(libapiv3.KindNode, testutils.ExpectNoNamespace, name1, spec1))
			Expect(res.ResourceVersion).To(Equal(rv1_1))

			By("Getting Node (name1) with the updated resource version and comparing the output against spec2")
			res, outError = c.Nodes().Get(ctx, name1, options.GetOptions{ResourceVersion: rv1_2})
			Expect(outError).NotTo(HaveOccurred())
			Expect(res).To(MatchResource(libapiv3.KindNode, testutils.ExpectNoNamespace, name1, spec2))
			Expect(res.ResourceVersion).To(Equal(rv1_2))

			By("Listing Nodes with the original resource version and checking for a single result with name1/spec1")
			outList, outError = c.Nodes().List(ctx, options.ListOptions{ResourceVersion: rv1_1})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(ConsistOf(
				testutils.Resource(libapiv3.KindNode, testutils.ExpectNoNamespace, name1, spec1),
			))

			By("Listing Nodes with the latest resource version and checking for two results with name1/spec2 and name2/spec2")
			outList, outError = c.Nodes().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(ConsistOf(
				testutils.Resource(libapiv3.KindNode, testutils.ExpectNoNamespace, name1, spec2),
				testutils.Resource(libapiv3.KindNode, testutils.ExpectNoNamespace, name2, spec2),
			))

			By("Deleting Node (name1) with the old resource version")
			_, outError = c.Nodes().Delete(ctx, name1, options.DeleteOptions{ResourceVersion: rv1_1})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(Equal("update conflict: Node(" + name1 + ")"))

			By("Deleting Node (name1) with the new resource version")
			dres, outError := c.Nodes().Delete(ctx, name1, options.DeleteOptions{ResourceVersion: rv1_2})
			Expect(outError).NotTo(HaveOccurred())
			Expect(dres).To(MatchResource(libapiv3.KindNode, testutils.ExpectNoNamespace, name1, spec2))

			By("Updating Node name2 with a 2s TTL and waiting for the entry to be deleted")
			_, outError = c.Nodes().Update(ctx, res2, options.SetOptions{TTL: 2 * time.Second})
			Expect(outError).NotTo(HaveOccurred())
			time.Sleep(1 * time.Second)
			_, outError = c.Nodes().Get(ctx, name2, options.GetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			time.Sleep(2 * time.Second)
			_, outError = c.Nodes().Get(ctx, name2, options.GetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(ContainSubstring("resource does not exist: Node(" + name2 + ") with error:"))

			By("Creating Node name2 with a 2s TTL and waiting for the entry to be deleted")
			_, outError = c.Nodes().Create(ctx, &libapiv3.Node{
				ObjectMeta: metav1.ObjectMeta{Name: name2},
				Spec:       spec2,
			}, options.SetOptions{TTL: 2 * time.Second})
			Expect(outError).NotTo(HaveOccurred())
			time.Sleep(1 * time.Second)
			_, outError = c.Nodes().Get(ctx, name2, options.GetOptions{})
			Expect(outError).NotTo(HaveOccurred())
			time.Sleep(2 * time.Second)
			_, outError = c.Nodes().Get(ctx, name2, options.GetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(ContainSubstring("resource does not exist: Node(" + name2 + ") with error:"))

			By("Attempting to deleting Node (name2) again")
			_, outError = c.Nodes().Delete(ctx, name2, options.DeleteOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(ContainSubstring("resource does not exist: Node(" + name2 + ") with error:"))

			By("Listing all Nodes and expecting no items")
			outList, outError = c.Nodes().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(HaveLen(0))

			By("Getting Node (name2) and expecting an error")
			_, outError = c.Nodes().Get(ctx, name2, options.GetOptions{})
			Expect(outError).To(HaveOccurred())
			Expect(outError.Error()).To(ContainSubstring("resource does not exist: Node(" + name2 + ") with error:"))

			By("Setting status no node resource")
			res1, outError = c.Nodes().Create(ctx, &libapiv3.Node{
				ObjectMeta: metav1.ObjectMeta{Name: name1},
				Spec:       spec1,
			}, options.SetOptions{})
			Expect(outError).ToNot(HaveOccurred())
			res1.Status = status
			res, outError = c.Nodes().Update(ctx, res1, options.SetOptions{})
			Expect(outError).ToNot(HaveOccurred())
			Expect(res).To(MatchResourceWithStatus(libapiv3.KindNode, testutils.ExpectNoNamespace, name1, spec1, status))

			By("Getting resource and verifying status is present")
			res, outError = c.Nodes().Get(ctx, name1, options.GetOptions{})
			Expect(outError).ToNot(HaveOccurred())
			Expect(res).To(MatchResourceWithStatus(libapiv3.KindNode, testutils.ExpectNoNamespace, name1, spec1, status))

		},

		// Test 1: Pass two fully populated NodeSpecs and expect the series of operations to succeed.
		Entry("Two fully populated NodeSpecs", name1, name2, spec1, spec2, status),
	)

	Describe("Node watch functionality", func() {
		It("should handle watch events for different resource versions and event types", func() {
			c, err := clientv3.New(config)
			Expect(err).NotTo(HaveOccurred())

			be, err := backend.NewClient(config)
			Expect(err).NotTo(HaveOccurred())
			be.Clean()

			By("Listing Nodes with the latest resource version and checking for two results with name1/spec2 and name2/spec2")
			outList, outError := c.Nodes().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(HaveLen(0))
			rev0 := outList.ResourceVersion

			By("Configuring a Node name1/spec1 and storing the response")
			outRes1, err := c.Nodes().Create(
				ctx,
				&libapiv3.Node{
					ObjectMeta: metav1.ObjectMeta{Name: name1},
					Spec:       spec1,
				},
				options.SetOptions{},
			)
			rev1 := outRes1.ResourceVersion

			By("Configuring a Node name2/spec2 and storing the response")
			outRes2, err := c.Nodes().Create(
				ctx,
				&libapiv3.Node{
					ObjectMeta: metav1.ObjectMeta{Name: name2},
					Spec:       spec2,
				},
				options.SetOptions{},
			)

			By("Starting a watcher from revision rev1 - this should skip the first creation")
			w, err := c.Nodes().Watch(ctx, options.ListOptions{ResourceVersion: rev1})
			Expect(err).NotTo(HaveOccurred())
			testWatcher1 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
			defer testWatcher1.Stop()

			By("Deleting res1")
			_, err = c.Nodes().Delete(ctx, name1, options.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())

			By("Checking for two events, create res2 and delete re1")
			testWatcher1.ExpectEvents(libapiv3.KindNode, []watch.Event{
				{
					Type:   watch.Added,
					Object: outRes2,
				},
				{
					Type:     watch.Deleted,
					Previous: outRes1,
				},
			})
			testWatcher1.Stop()

			By("Starting a watcher from rev0 - this should get all events")
			w, err = c.Nodes().Watch(ctx, options.ListOptions{ResourceVersion: rev0})
			Expect(err).NotTo(HaveOccurred())
			testWatcher2 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
			defer testWatcher2.Stop()

			By("Modifying res2")
			outRes3, err := c.Nodes().Update(
				ctx,
				&libapiv3.Node{
					ObjectMeta: outRes2.ObjectMeta,
					Spec:       spec1,
				},
				options.SetOptions{},
			)
			Expect(err).NotTo(HaveOccurred())
			testWatcher2.ExpectEvents(libapiv3.KindNode, []watch.Event{
				{
					Type:   watch.Added,
					Object: outRes1,
				},
				{
					Type:   watch.Added,
					Object: outRes2,
				},
				{
					Type:     watch.Deleted,
					Previous: outRes1,
				},
				{
					Type:     watch.Modified,
					Previous: outRes2,
					Object:   outRes3,
				},
			})
			testWatcher2.Stop()

			// Only etcdv3 supports watching a specific instance of a resource.
			if config.Spec.DatastoreType == apiconfig.EtcdV3 {
				By("Starting a watcher from rev0 watching name1 - this should get all events for name1")
				w, err = c.Nodes().Watch(ctx, options.ListOptions{Name: name1, ResourceVersion: rev0})
				Expect(err).NotTo(HaveOccurred())
				testWatcher2_1 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
				defer testWatcher2_1.Stop()
				testWatcher2_1.ExpectEvents(libapiv3.KindNode, []watch.Event{
					{
						Type:   watch.Added,
						Object: outRes1,
					},
					{
						Type:     watch.Deleted,
						Previous: outRes1,
					},
				})
				testWatcher2_1.Stop()
			}

			By("Starting a watcher not specifying a rev - expect the current snapshot")
			w, err = c.Nodes().Watch(ctx, options.ListOptions{})
			Expect(err).NotTo(HaveOccurred())
			testWatcher3 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
			defer testWatcher3.Stop()
			testWatcher3.ExpectEvents(libapiv3.KindNode, []watch.Event{
				{
					Type:   watch.Added,
					Object: outRes3,
				},
			})
			testWatcher3.Stop()

			By("Configuring Node name1/spec1 again and storing the response")
			outRes1, err = c.Nodes().Create(
				ctx,
				&libapiv3.Node{
					ObjectMeta: metav1.ObjectMeta{Name: name1},
					Spec:       spec1,
				},
				options.SetOptions{},
			)

			By("Starting a watcher not specifying a rev - expect the current snapshot")
			w, err = c.Nodes().Watch(ctx, options.ListOptions{})
			Expect(err).NotTo(HaveOccurred())
			testWatcher4 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
			defer testWatcher4.Stop()
			testWatcher4.ExpectEventsAnyOrder(libapiv3.KindNode, []watch.Event{
				{
					Type:   watch.Added,
					Object: outRes1,
				},
				{
					Type:   watch.Added,
					Object: outRes3,
				},
			})

			By("Cleaning the datastore and expecting deletion events for each configured resource (tests prefix deletes results in individual events for each key)")
			be.Clean()
			testWatcher4.ExpectEvents(libapiv3.KindNode, []watch.Event{
				{
					Type:     watch.Deleted,
					Previous: outRes1,
				},
				{
					Type:     watch.Deleted,
					Previous: outRes3,
				},
			})
			testWatcher4.Stop()
		})
	})
})
