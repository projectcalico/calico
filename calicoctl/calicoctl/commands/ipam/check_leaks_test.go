// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

package ipam

import (
	"bytes"
	"context"
	"io"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	kubevirtv1 "kubevirt.io/api/core/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/projectcalico/calico/libcalico-go/lib/apis/internalapi"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam/accounting"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam/vmipam"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
)

// checkFixture is the cluster state one CheckIPAM run sees.
type checkFixture struct {
	pools  []string
	blocks []*model.AllocationBlock
	nodes  []internalapi.Node
	weps   []internalapi.WorkloadEndpoint

	// handles is the IPAM handles that exist, and services the Kubernetes Services.
	handles  []string
	services []ctrlclient.Object

	// kubevirt is the VMs and VMIs, and nil when KubeVirt is not installed.
	kubevirt []ctrlclient.Object
}

// checkBlock builds a valid /29 block, whose Unallocated list is the complement of its allocations.
func checkBlock(cidr, affinity string, attrs map[int]model.AllocationAttribute) *model.AllocationBlock {
	b := &model.AllocationBlock{
		CIDR:        net.MustParseCIDR(cidr),
		Allocations: make([]*int, 8),
	}
	if affinity != "" {
		b.Affinity = ptr.To(affinity)
	}
	for ord := range 8 {
		attr, ok := attrs[ord]
		if !ok {
			b.Unallocated = append(b.Unallocated, ord)
			continue
		}
		b.Attributes = append(b.Attributes, attr)
		b.Allocations[ord] = ptr.To(len(b.Attributes) - 1)
	}
	return b
}

func podAttr(handle, node string) model.AllocationAttribute {
	return model.AllocationAttribute{
		HandleID: ptr.To(handle),
		ActiveOwnerAttrs: map[string]string{
			model.IPAMBlockAttributeNamespace: "default",
			model.IPAMBlockAttributePod:       handle,
			model.IPAMBlockAttributeNode:      node,
		},
	}
}

func typedAttr(handle, node, attrType string) model.AllocationAttribute {
	return model.AllocationAttribute{
		HandleID: ptr.To(handle),
		ActiveOwnerAttrs: map[string]string{
			model.IPAMBlockAttributeNode: node,
			model.IPAMBlockAttributeType: attrType,
		},
	}
}

func checkNode(name, vxlanAddr string) internalapi.Node {
	n := internalapi.Node{ObjectMeta: v1.ObjectMeta{Name: name}}
	n.Spec.IPv4VXLANTunnelAddr = vxlanAddr
	return n
}

func checkWEP(name, ip string) internalapi.WorkloadEndpoint {
	w := internalapi.WorkloadEndpoint{ObjectMeta: v1.ObjectMeta{Name: name, Namespace: "default"}}
	w.Spec.IPNetworks = []string{ip + "/32"}
	return w
}

var leakedLine = regexp.MustCompile(`(?m)^  (\S+) leaked; `)

// runCheck runs CheckIPAM over the fixture and returns the checker and the IPs it reported leaked.
func runCheck(f checkFixture) (*IPAMChecker, []string) {
	var pools []apiv3.IPPool
	for _, cidr := range f.pools {
		pools = append(pools, apiv3.IPPool{
			ObjectMeta: v1.ObjectMeta{Name: cidr},
			Spec:       apiv3.IPPoolSpec{CIDR: cidr, BlockSize: 29},
		})
	}
	v3Client := &mockV3Client{
		clusterInfo:       &mockClusterInformation{clusterInfo: &apiv3.ClusterInformation{Spec: apiv3.ClusterInformationSpec{DatastoreReady: ptr.To(true)}}},
		ipPools:           &mockIPPools{ipPools: &apiv3.IPPoolList{Items: pools}},
		nodes:             &mockNodes{nodes: &internalapi.NodeList{Items: f.nodes}},
		workloadEndpoints: &mockWorkloadEndpoints{weps: &internalapi.WorkloadEndpointList{Items: f.weps}},
		kubeControllers:   &mockKubeControllersConfiguration{config: &apiv3.KubeControllersConfiguration{}},
	}
	backendClient := &mockBackendClient{}
	for _, b := range f.blocks {
		backendClient.blocks.KVPairs = append(backendClient.blocks.KVPairs, &model.KVPair{
			Key:   model.BlockKey{CIDR: netip.MustParsePrefix(b.CIDR.String())},
			Value: b,
		})
	}
	scheme := runtime.NewScheme()
	Expect(corev1.AddToScheme(scheme)).To(Succeed())
	if f.kubevirt != nil {
		Expect(kubevirtv1.AddToScheme(scheme)).To(Succeed())
	}
	for _, h := range f.handles {
		backendClient.handles.KVPairs = append(backendClient.handles.KVPairs, &model.KVPair{
			Key:   model.IPAMHandleKey{HandleID: h},
			Value: &model.IPAMHandle{HandleID: h},
		})
	}
	objects := append(slices.Clone(f.services), f.kubevirt...)
	k8sClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
	checker := NewIPAMChecker(k8sClient, v3Client, backendClient, false, true, "", "test")

	old := os.Stdout
	r, w, err := os.Pipe()
	Expect(err).NotTo(HaveOccurred())
	os.Stdout = w
	checkErr := checker.CheckIPAM(context.Background())
	Expect(w.Close()).To(Succeed())
	os.Stdout = old
	var buf bytes.Buffer
	_, err = io.Copy(&buf, r)
	Expect(err).NotTo(HaveOccurred())
	Expect(checkErr).NotTo(HaveOccurred())

	var leaked []string
	for _, m := range leakedLine.FindAllStringSubmatch(buf.String(), -1) {
		if !slices.Contains(leaked, m[1]) {
			leaked = append(leaked, m[1])
		}
	}
	return checker, leaked
}

var _ = Describe("CheckIPAM leak and borrow classification", func() {
	It("reports a pod address only when no workload endpoint holds it", func() {
		_, leaked := runCheck(checkFixture{
			pools: []string{"192.168.0.0/24"},
			blocks: []*model.AllocationBlock{
				checkBlock("192.168.0.0/29", "host:node-a", map[int]model.AllocationAttribute{
					1: podAttr("held", "node-a"),
					2: podAttr("gone", "node-a"),
				}),
			},
			nodes: []internalapi.Node{checkNode("node-a", "")},
			weps:  []internalapi.WorkloadEndpoint{checkWEP("held", "192.168.0.1")},
		})
		Expect(leaked).To(ConsistOf("192.168.0.2"))
	})

	It("reports an address assigned by hand that nothing holds", func() {
		_, leaked := runCheck(checkFixture{
			pools: []string{"192.168.0.0/24"},
			blocks: []*model.AllocationBlock{
				checkBlock("192.168.0.0/29", "host:node-a", map[int]model.AllocationAttribute{
					1: {HandleID: ptr.To("manual"), ActiveOwnerAttrs: map[string]string{"note": "assigned by hand"}},
				}),
			},
			nodes: []internalapi.Node{checkNode("node-a", "")},
		})
		Expect(leaked).To(ConsistOf("192.168.0.1"))
	})

	It("holds a tunnel address only when its node's spec names it", func() {
		_, leaked := runCheck(checkFixture{
			pools: []string{"192.168.0.0/24"},
			blocks: []*model.AllocationBlock{
				checkBlock("192.168.0.0/29", "host:node-a", map[int]model.AllocationAttribute{
					1: typedAttr("vxlan-a", "node-a", model.IPAMBlockAttributeTypeVXLAN),
					2: typedAttr("vxlan-stale", "node-a", model.IPAMBlockAttributeTypeVXLAN),
				}),
			},
			nodes: []internalapi.Node{checkNode("node-a", "192.168.0.1")},
		})
		Expect(leaked).To(ConsistOf("192.168.0.2"))
	})

	It("never reports unknown types, Windows-reserved or cooling addresses", func() {
		checker, leaked := runCheck(checkFixture{
			pools: []string{"192.168.0.0/24"},
			blocks: []*model.AllocationBlock{
				checkBlock("192.168.0.0/29", "host:node-a", map[int]model.AllocationAttribute{
					0: {HandleID: ptr.To(accounting.WindowsReservedHandle), ActiveOwnerAttrs: map[string]string{"note": "windows host rsvd"}},
					1: typedAttr("new", "node-a", "somethingNew"),
					2: {ReleasedAt: ptr.To(v1.NewTime(time.Now().Add(-time.Minute)))},
				}),
			},
			nodes: []internalapi.Node{checkNode("node-a", "")},
		})
		Expect(leaked).To(BeEmpty())
		Expect(checker.allocations["192.168.0.1"][0].InUse).To(BeTrue())
		Expect(checker.allocations["192.168.0.2"][0].CoolingDown).To(BeTrue())
	})

	It("reports a pod address in a block no pool claims", func() {
		_, leaked := runCheck(checkFixture{
			pools: []string{"192.168.0.0/24"},
			blocks: []*model.AllocationBlock{
				checkBlock("10.9.0.0/29", "host:node-a", map[int]model.AllocationAttribute{
					1: podAttr("orphan", "node-a"),
				}),
			},
			nodes: []internalapi.Node{checkNode("node-a", "")},
		})
		Expect(leaked).To(ConsistOf("10.9.0.1"))
	})

	It("marks addresses held by another node as borrowed, including in unaffined blocks", func() {
		checker, _ := runCheck(checkFixture{
			pools: []string{"192.168.0.0/24"},
			blocks: []*model.AllocationBlock{
				checkBlock("192.168.0.0/29", "host:node-a", map[int]model.AllocationAttribute{
					1: podAttr("own", "node-a"),
					2: podAttr("borrowed", "node-b"),
				}),
				checkBlock("192.168.0.8/29", "", map[int]model.AllocationAttribute{
					1: podAttr("unaffined", "node-c"),
					2: {HandleID: ptr.To("no-node")},
				}),
			},
			nodes: []internalapi.Node{checkNode("node-a", ""), checkNode("node-b", ""), checkNode("node-c", "")},
		})
		borrowed := map[string]bool{}
		for ip, allocs := range checker.allocations {
			borrowed[ip] = allocs[0].Borrowed
		}
		Expect(borrowed).To(Equal(map[string]bool{
			"192.168.0.1":  false,
			"192.168.0.2":  true,
			"192.168.0.9":  true,
			"192.168.0.10": false,
		}))
		Expect(checker.allocations["192.168.0.2"][0].Node).To(Equal("node-b"))
		Expect(checker.allocations["192.168.0.1"][0].Node).To(Equal("node-a"))
	})

	It("names what holds each address in use", func() {
		checker, _ := runCheck(checkFixture{
			pools: []string{"192.168.0.0/24"},
			blocks: []*model.AllocationBlock{
				checkBlock("192.168.0.0/29", "host:node-a", map[int]model.AllocationAttribute{
					0: {HandleID: ptr.To(accounting.WindowsReservedHandle), ActiveOwnerAttrs: map[string]string{"note": "windows host rsvd"}},
					1: podAttr("held", "node-a"),
					2: typedAttr("vxlan-a", "node-a", model.IPAMBlockAttributeTypeVXLAN),
					4: typedAttr("new", "node-a", "somethingNew"),
					5: podAttr("gone", "node-a"),
				}),
			},
			nodes: []internalapi.Node{checkNode("node-a", "192.168.0.2")},
			weps:  []internalapi.WorkloadEndpoint{checkWEP("held", "192.168.0.1")},
		})
		owners := map[string][]string{}
		for ip, allocs := range checker.allocations {
			owners[ip] = allocs[0].Owners
		}
		Expect(owners).To(Equal(map[string][]string{
			"192.168.0.0": {"Reserved for Windows"},
			"192.168.0.1": {"Workload(default/held)"},
			"192.168.0.2": {"Node(node-a)"},
			"192.168.0.4": {"UnknownType(somethingNew)"},
			"192.168.0.5": nil,
		}))
	})
})

// These are where check's answer differs from before it moved onto the accounting package.
var _ = Describe("CheckIPAM on the accounting package", func() {
	It("keeps a stopped VM's persisted address only while the VM or its VMI exists", func() {
		// CNI DEL of a VM whose address persists clears the owners, leaving only the handle.
		checker, leaked := runCheck(checkFixture{
			pools: []string{"192.168.0.0/24"},
			blocks: []*model.AllocationBlock{
				checkBlock("192.168.0.0/29", "host:node-a", map[int]model.AllocationAttribute{
					1: {HandleID: ptr.To(vmipam.CreateVMHandleID("", "default", "vm1"))},
					2: {HandleID: ptr.To(vmipam.CreateVMHandleID("", "default", "vm-gone"))},
					3: {HandleID: ptr.To(vmipam.CreateVMHandleID("", "default", "standalone"))},
					4: {HandleID: ptr.To(vmipam.CreateVMHandleID("multus-net", "default", "vm-multus"))},
				}),
			},
			nodes: []internalapi.Node{checkNode("node-a", "")},
			kubevirt: []ctrlclient.Object{
				&kubevirtv1.VirtualMachine{ObjectMeta: v1.ObjectMeta{Namespace: "default", Name: "vm1"}},
				&kubevirtv1.VirtualMachine{ObjectMeta: v1.ObjectMeta{Namespace: "default", Name: "vm-multus"}},
				&kubevirtv1.VirtualMachineInstance{ObjectMeta: v1.ObjectMeta{Namespace: "default", Name: "standalone"}},
			},
		})
		Expect(leaked).To(ConsistOf("192.168.0.2"))
		Expect(checker.allocations["192.168.0.1"][0].InUse).To(BeTrue())
		Expect(checker.allocations["192.168.0.1"][0].Owners).To(Equal([]string{"VirtualMachine(default/vm1)"}))
	})

	It("matches a VM whose network name contains .vmi.", func() {
		_, leaked := runCheck(checkFixture{
			pools: []string{"192.168.0.0/24"},
			blocks: []*model.AllocationBlock{
				checkBlock("192.168.0.0/29", "host:node-a", map[int]model.AllocationAttribute{
					1: {HandleID: ptr.To(vmipam.CreateVMHandleID("foo.vmi.bar", "default", "vm1"))},
				}),
			},
			nodes: []internalapi.Node{checkNode("node-a", "")},
			kubevirt: []ctrlclient.Object{
				&kubevirtv1.VirtualMachine{ObjectMeta: v1.ObjectMeta{Namespace: "default", Name: "vm1"}},
			},
		})
		Expect(leaked).To(BeEmpty())
	})

	It("marks an address in a deleted block in use only while something references it", func() {
		deleted := checkBlock("192.168.0.0/29", "host:node-a", map[int]model.AllocationAttribute{
			1: podAttr("held", "node-a"),
			2: podAttr("gone", "node-a"),
		})
		deleted.Deleted = true
		checker, leaked := runCheck(checkFixture{
			pools:   []string{"192.168.0.0/24"},
			blocks:  []*model.AllocationBlock{deleted},
			nodes:   []internalapi.Node{checkNode("node-a", "")},
			weps:    []internalapi.WorkloadEndpoint{checkWEP("held", "192.168.0.1")},
			handles: []string{"held", "gone"},
		})
		Expect(leaked).To(ConsistOf("192.168.0.2"))
		Expect(checker.allocations["192.168.0.1"][0].InUse).To(BeTrue())
		Expect(checker.allocations["192.168.0.2"][0].InUse).To(BeFalse())

		// Both handles still name an allocation, so neither is leaked.
		Expect(checker.leakedHandles).To(BeEmpty())
	})

	It("holds a LoadBalancer address while a service names it, with the LoadBalancer controller unconfigured", func() {
		svc := &corev1.Service{
			ObjectMeta: v1.ObjectMeta{Namespace: "default", Name: "lb"},
			Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer},
			Status: corev1.ServiceStatus{LoadBalancer: corev1.LoadBalancerStatus{Ingress: []corev1.LoadBalancerIngress{
				{IP: "192.168.0.1"},
			}}},
		}
		_, leaked := runCheck(checkFixture{
			pools: []string{"192.168.0.0/24"},
			blocks: []*model.AllocationBlock{
				checkBlock("192.168.0.0/29", model.IPAMAffinityLoadBalancer, map[int]model.AllocationAttribute{
					1: typedAttr("lb-held", "", string(corev1.ServiceTypeLoadBalancer)),
					2: typedAttr("lb-gone", "", string(corev1.ServiceTypeLoadBalancer)),
				}),
			},
			services: []ctrlclient.Object{svc},
		})
		Expect(leaked).To(ConsistOf("192.168.0.2"))
	})

	It("holds a tunnel address from before attributes while its node names it", func() {
		_, leaked := runCheck(checkFixture{
			pools: []string{"192.168.0.0/24"},
			blocks: []*model.AllocationBlock{
				checkBlock("192.168.0.0/29", "host:node-a", map[int]model.AllocationAttribute{
					1: {},
					2: {},
				}),
			},
			nodes: []internalapi.Node{checkNode("node-a", "192.168.0.1")},
		})
		Expect(leaked).To(ConsistOf("192.168.0.2"))
	})

	It("reports an address with no owner when KubeVirt is not installed", func() {
		_, leaked := runCheck(checkFixture{
			pools: []string{"192.168.0.0/24"},
			blocks: []*model.AllocationBlock{
				checkBlock("192.168.0.0/29", "host:node-a", map[int]model.AllocationAttribute{
					1: {HandleID: ptr.To(vmipam.CreateVMHandleID("", "default", "vm1"))},
				}),
			},
			nodes: []internalapi.Node{checkNode("node-a", "")},
		})
		Expect(leaked).To(ConsistOf("192.168.0.1"))
	})

	It("marks Windows-reserved addresses in use", func() {
		checker, _ := runCheck(checkFixture{
			pools: []string{"192.168.0.0/24"},
			blocks: []*model.AllocationBlock{
				checkBlock("192.168.0.0/29", "host:node-a", map[int]model.AllocationAttribute{
					0: {HandleID: ptr.To(accounting.WindowsReservedHandle), ActiveOwnerAttrs: map[string]string{"note": "windows host rsvd"}},
				}),
			},
			nodes: []internalapi.Node{checkNode("node-a", "")},
		})
		Expect(checker.allocations["192.168.0.0"][0].InUse).To(BeTrue())
	})

	It("only lets a reference of the allocation's own kind account for it", func() {
		_, leaked := runCheck(checkFixture{
			pools: []string{"192.168.0.0/24"},
			blocks: []*model.AllocationBlock{
				checkBlock("192.168.0.0/29", "host:node-a", map[int]model.AllocationAttribute{
					1: podAttr("pod-on-tunnel-ip", "node-a"),
				}),
			},
			nodes: []internalapi.Node{checkNode("node-a", "192.168.0.1")},
		})
		Expect(leaked).To(ConsistOf("192.168.0.1"))
	})

	It("still reports an allocation the tracker cannot read", func() {
		b := checkBlock("192.168.0.0/29", "host:node-a", map[int]model.AllocationAttribute{
			1: podAttr("gone", "node-a"),
		})
		b.Allocations[1] = ptr.To(9)
		_, leaked := runCheck(checkFixture{
			pools:  []string{"192.168.0.0/24"},
			blocks: []*model.AllocationBlock{b},
			nodes:  []internalapi.Node{checkNode("node-a", "")},
		})
		Expect(leaked).To(ConsistOf("192.168.0.1"))
	})

	It("holds IPv6 tunnel addresses named in the node spec", func() {
		n := checkNode("node-a", "")
		n.Spec.IPv6VXLANTunnelAddr = "fd00::1"
		n.Spec.Wireguard = &internalapi.NodeWireguardSpec{InterfaceIPv6Address: "fd00::2"}
		_, leaked := runCheck(checkFixture{
			pools: []string{"fd00::/120"},
			blocks: []*model.AllocationBlock{
				checkBlock("fd00::/125", "host:node-a", map[int]model.AllocationAttribute{
					1: typedAttr("vxlan-v6-a", "node-a", model.IPAMBlockAttributeTypeVXLANV6),
					2: typedAttr("wg-v6-a", "node-a", model.IPAMBlockAttributeTypeWireguardV6),
					3: typedAttr("vxlan-v6-stale", "node-a", model.IPAMBlockAttributeTypeVXLANV6),
				}),
			},
			nodes: []internalapi.Node{n},
		})
		Expect(leaked).To(ConsistOf("fd00::3"))
	})
})
