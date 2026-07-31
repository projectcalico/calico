// Copyright (c) 2019-2026 Tigera, Inc. All rights reserved.

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
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	fakek8s "k8s.io/client-go/kubernetes/fake"

	"github.com/projectcalico/calico/libcalico-go/lib/apis/internalapi"
	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

var _ = Describe("validateBlock", func() {
	cidr := net.MustParseCIDR("10.0.0.0/30")

	It("returns no error for an empty block", func() {
		b := &model.AllocationBlock{
			CIDR:        cidr,
			Allocations: []*int{nil, nil, nil, nil},
			Unallocated: []int{0, 1, 2, 3},
			Attributes:  []model.AllocationAttribute{},
		}
		Expect(validateBlock(b)).To(Succeed())
	})

	It("returns an error when an allocation references an invalid attr index", func() {
		b := &model.AllocationBlock{
			CIDR:        cidr,
			Allocations: []*int{new(99), nil, nil, nil},
			Unallocated: []int{1, 2, 3},
			Attributes:  []model.AllocationAttribute{},
		}
		Expect(validateBlock(b)).
			To(MatchError("allocation 0 indexes a nonexistent attribute 99"))
	})

	It("returns an error when an allocation references a negative attr index", func() {
		b := &model.AllocationBlock{
			CIDR:        cidr,
			Allocations: []*int{new(-1), nil, nil, nil},
			Unallocated: []int{1, 2, 3},
			Attributes:  []model.AllocationAttribute{},
		}
		Expect(validateBlock(b)).
			To(MatchError("allocation 0 indexes a nonexistent attribute -1"))
	})

	It("returns an error when an attribute is not pointed to by an allocation", func() {
		b := &model.AllocationBlock{
			CIDR:        cidr,
			Allocations: []*int{nil, nil, nil, nil},
			Unallocated: []int{0, 1, 2, 3},
			Attributes: []model.AllocationAttribute{
				{HandleID: new("uhoh")},
			},
		}
		Expect(validateBlock(b)).
			To(MatchError("attribute index 0 exists but is not indexed by an allocation"))
	})

	It("returns an error when an an attribute has ReleasedAt in the future", func() {
		b := &model.AllocationBlock{
			CIDR:        cidr,
			Allocations: []*int{new(0), nil, nil, nil},
			Unallocated: []int{1, 2, 3},
			Attributes: []model.AllocationAttribute{
				{ReleasedAt: new(v1.NewTime(time.Now().Add(time.Minute)))},
			},
		}
		Expect(validateBlock(b)).
			To(MatchError("attribute index 0 has releasedAt in the future, suggesting clock skew"))
	})

	It("returns an error when an ordinal appears twice in Unallocated", func() {
		b := &model.AllocationBlock{
			CIDR:        cidr,
			Allocations: []*int{nil, nil, nil, nil},
			Unallocated: []int{0, 1, 1, 2, 3},
			Attributes:  []model.AllocationAttribute{},
		}
		Expect(validateBlock(b)).
			To(MatchError("ordinal 1 appears more than once in Unallocated array"))
	})

	It("returns an error when an allocated ordinal appears in Unallocated", func() {
		b := &model.AllocationBlock{
			CIDR:        cidr,
			Allocations: []*int{nil, new(0), nil, nil},
			Unallocated: []int{0, 1, 2, 3},
			Attributes: []model.AllocationAttribute{
				{HandleID: new("allocated")},
			},
		}
		Expect(validateBlock(b)).
			To(MatchError("ordinal 1 is allocated but appears in Unallocated"))
	})

	It("returns an error when an unallocated ordinal is too large", func() {
		b := &model.AllocationBlock{
			CIDR:        cidr,
			Allocations: []*int{nil, nil, nil, nil},
			Unallocated: []int{0, 2, 3, 99},
			Attributes:  []model.AllocationAttribute{},
		}
		Expect(validateBlock(b)).
			To(MatchError("ordinal 99 appears in the Unallocated array but is out of the block"))
	})

	It("returns an error if size of allocated an unallocated does not sum to NumAddresses", func() {
		b := &model.AllocationBlock{
			CIDR:        cidr,
			Allocations: []*int{nil, new(0), new(0), nil},
			Unallocated: []int{0},
			Attributes: []model.AllocationAttribute{
				{HandleID: new("hello")},
			},
		}
		Expect(validateBlock(b)).
			To(MatchError("expected 4 addresses in this block, but Unallocated (1) + Allocated (2) = 3"))
	})
})

type mockClusterInformation struct {
	clientv3.ClusterInformationInterface
	clusterInfo *apiv3.ClusterInformation
}

func (m *mockClusterInformation) Get(ctx context.Context, name string, opts options.GetOptions) (*apiv3.ClusterInformation, error) {
	return m.clusterInfo, nil
}

type mockIPPools struct {
	clientv3.IPPoolInterface
	ipPools *apiv3.IPPoolList
}

func (m *mockIPPools) List(ctx context.Context, opts options.ListOptions) (*apiv3.IPPoolList, error) {
	return m.ipPools, nil
}

type mockNodes struct {
	clientv3.NodeInterface
	nodes *internalapi.NodeList
}

func (m *mockNodes) List(ctx context.Context, opts options.ListOptions) (*internalapi.NodeList, error) {
	return m.nodes, nil
}

type mockKubeControllersConfiguration struct {
	clientv3.KubeControllersConfigurationInterface
	config *apiv3.KubeControllersConfiguration
}

func (m *mockKubeControllersConfiguration) Get(ctx context.Context, name string, opts options.GetOptions) (*apiv3.KubeControllersConfiguration, error) {
	return m.config, nil
}

type mockWorkloadEndpoints struct {
	clientv3.WorkloadEndpointInterface
	weps *internalapi.WorkloadEndpointList
}

func (m *mockWorkloadEndpoints) List(ctx context.Context, opts options.ListOptions) (*internalapi.WorkloadEndpointList, error) {
	return m.weps, nil
}

type mockV3Client struct {
	clientv3.Interface
	clusterInfo       *mockClusterInformation
	ipPools           *mockIPPools
	nodes             *mockNodes
	kubeControllers   *mockKubeControllersConfiguration
	workloadEndpoints *mockWorkloadEndpoints
}

func (m *mockV3Client) ClusterInformation() clientv3.ClusterInformationInterface {
	return m.clusterInfo
}

func (m *mockV3Client) IPPools() clientv3.IPPoolInterface {
	return m.ipPools
}

func (m *mockV3Client) Nodes() clientv3.NodeInterface {
	return m.nodes
}

func (m *mockV3Client) KubeControllersConfiguration() clientv3.KubeControllersConfigurationInterface {
	return m.kubeControllers
}

func (m *mockV3Client) WorkloadEndpoints() clientv3.WorkloadEndpointInterface {
	return m.workloadEndpoints
}

type mockBackendClient struct {
	bapi.Client
	blocks  model.KVPairList
	handles model.KVPairList
}

func (m *mockBackendClient) List(ctx context.Context, list model.ListInterface, revision string) (*model.KVPairList, error) {
	switch list.(type) {
	case model.BlockListOptions:
		return &m.blocks, nil
	case model.IPAMHandleListOptions:
		return &m.handles, nil
	}
	return nil, nil
}

var _ = Describe("CheckIPAM with Cooldown IPs", func() {
	var (
		k8sClient     *fakek8s.Clientset
		v3Client      *mockV3Client
		backendClient *mockBackendClient
		checker       *IPAMChecker
		ctx           context.Context
	)

	BeforeEach(func() {
		ctx = context.Background()
		k8sClient = fakek8s.NewSimpleClientset()

		// Prepare mock cluster info
		trueVal := true
		clusterInfo := &apiv3.ClusterInformation{
			ObjectMeta: v1.ObjectMeta{
				ResourceVersion: "1234",
			},
			Spec: apiv3.ClusterInformationSpec{
				ClusterGUID:    "test-guid",
				ClusterType:    "k8s",
				DatastoreReady: &trueVal,
			},
		}
		mockClusterInfo := &mockClusterInformation{clusterInfo: clusterInfo}

		// Prepare active IP pool
		ipPools := &apiv3.IPPoolList{
			Items: []apiv3.IPPool{
				{
					Spec: apiv3.IPPoolSpec{
						CIDR: "192.168.0.0/24",
					},
				},
			},
		}
		mockIPPoolsObj := &mockIPPools{ipPools: ipPools}

		// Prepare empty nodes list
		nodes := &internalapi.NodeList{
			Items: []internalapi.Node{},
		}
		mockNodesObj := &mockNodes{nodes: nodes}

		// Prepare empty workload endpoints
		weps := &internalapi.WorkloadEndpointList{
			Items: []internalapi.WorkloadEndpoint{},
		}
		mockWepsObj := &mockWorkloadEndpoints{weps: weps}

		// Prepare mock kube controllers config
		kubeControllersConfig := &apiv3.KubeControllersConfiguration{
			Spec: apiv3.KubeControllersConfigurationSpec{
				Controllers: apiv3.ControllersConfig{
					LoadBalancer: nil,
				},
			},
		}
		mockKubeControllersObj := &mockKubeControllersConfiguration{config: kubeControllersConfig}

		v3Client = &mockV3Client{
			clusterInfo:       mockClusterInfo,
			ipPools:           mockIPPoolsObj,
			nodes:             mockNodesObj,
			workloadEndpoints: mockWepsObj,
			kubeControllers:   mockKubeControllersObj,
		}
	})

	It("should report 0 problems when there are IPs in Cooldown state", func() {
		// Define a block with one allocation that is in Cooldown (ReleasedAt is set)
		blockCIDR := net.MustParseCIDR("192.168.0.0/30")
		releasedAt := v1.NewTime(time.Now().Add(-1 * time.Minute))

		block := &model.AllocationBlock{
			CIDR:        blockCIDR,
			Allocations: []*int{new(0), nil, nil, nil},
			Unallocated: []int{1, 2, 3},
			Attributes: []model.AllocationAttribute{
				{
					ReleasedAt: &releasedAt,
				},
			},
		}

		backendClient = &mockBackendClient{
			blocks: model.KVPairList{
				KVPairs: []*model.KVPair{
					{
						Key:   model.BlockKey{CIDR: netip.MustParsePrefix("192.168.0.0/30")},
						Value: block,
					},
				},
			},
		}

		checker = NewIPAMChecker(k8sClient, v3Client, backendClient, false, false, "", "v3.0.0")

		// Capture stdout to verify printed output
		old := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		err := checker.CheckIPAM(ctx)

		_ = w.Close()
		os.Stdout = old
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		output := buf.String()

		Expect(err).NotTo(HaveOccurred())
		Expect(output).To(ContainSubstring("Check complete; found 0 problems."))

		// Double check that the IP allocation in the block is identified as CoolingDown
		Expect(checker.allocations["192.168.0.0"]).To(HaveLen(1))
		Expect(checker.allocations["192.168.0.0"][0].CoolingDown).To(BeTrue())
	})
})
