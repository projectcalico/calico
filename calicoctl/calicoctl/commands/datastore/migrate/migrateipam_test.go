// Copyright (c) 2020-2025 Tigera, Inc. All rights reserved.

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

package migrate

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
)

var (
	nodeName           = "etcdNodeName"
	newNodeName        = "k8sNodeName"
	blockAffinityField = fmt.Sprintf("host:%s", nodeName)
	ipipTunnelHandle   = "ipip-tunnel-addr-etcdNodeName"
)

var _ = Describe("IPAM migration handling", func() {
	var block1 *model.KVPair
	var affinity1 *model.KVPair
	var handle1 *model.KVPair

	// Reset the IPAM information before each test
	BeforeEach(func() {
		block1 = &model.KVPair{
			Key: model.BlockKey{
				CIDR: net.MustParseCIDR("192.168.201.0/26"),
			},
			Value: &model.AllocationBlock{
				CIDR:     net.MustParseCIDR("192.168.201.0/26"),
				Affinity: &blockAffinityField,
				Attributes: []model.AllocationAttribute{
					{
						HandleID: &ipipTunnelHandle,
						ActiveOwnerAttrs: map[string]string{
							"node": nodeName,
							"type": "ipipTunnelAddress",
						},
					},
				},
			},
		}

		affinity1 = &model.KVPair{
			Key: model.BlockAffinityKey{
				CIDR:         net.MustParseCIDR("192.168.201.0/26"),
				Host:         nodeName,
				AffinityType: string(ipam.AffinityTypeHost),
			},
			Value: &model.BlockAffinity{
				State:   model.StateConfirmed,
				Deleted: false,
			},
		}

		handle1 = &model.KVPair{
			Key: model.IPAMHandleKey{
				HandleID: ipipTunnelHandle,
			},
			Value: &model.IPAMHandle{
				Block: map[string]int{
					"192.168.201.0/26": 1,
				},
				Deleted: false,
			},
		}
	})

	It("Should replace the node names in the IPAM block, block affinity, and handle", func() {
		blocks := model.KVPairList{
			KVPairs: []*model.KVPair{block1},
		}
		affinities := model.KVPairList{
			KVPairs: []*model.KVPair{affinity1},
		}
		handles := model.KVPairList{
			KVPairs: []*model.KVPair{handle1},
		}

		bc := NewMockIPAMBackendClient(blocks, affinities, handles)
		client := NewMockIPAMClient(bc)
		migrateIPAM := NewMigrateIPAM(client)
		migrateIPAM.SetNodeMap(map[string]string{nodeName: newNodeName})
		err := migrateIPAM.PullFromDatastore()
		Expect(err).NotTo(HaveOccurred())

		// Check that the block attributes were changed correctly
		Expect(migrateIPAM.IPAMBlocks).To(HaveLen(1))
		Expect(*migrateIPAM.IPAMBlocks[0].Value.Affinity).To(Equal(fmt.Sprintf("host:%s", newNodeName)))
		Expect(migrateIPAM.IPAMBlocks[0].Value.Attributes).To(HaveLen(1))
		Expect(*migrateIPAM.IPAMBlocks[0].Value.Attributes[0].HandleID).To(Equal(fmt.Sprintf("ipip-tunnel-addr-%s", newNodeName)))
		Expect(migrateIPAM.IPAMBlocks[0].Value.Attributes[0].ActiveOwnerAttrs["node"]).To(Equal(newNodeName))

		// Check that the block affinity attributes were changed correctly
		newAffinityKey := model.BlockAffinityKey{
			CIDR:         net.MustParseCIDR("192.168.201.0/26"),
			Host:         newNodeName,
			AffinityType: string(ipam.AffinityTypeHost),
		}
		newAffinityKeyPath, err := model.KeyToDefaultPath(newAffinityKey)
		Expect(err).NotTo(HaveOccurred())
		Expect(migrateIPAM.BlockAffinities).To(HaveLen(1))
		Expect(migrateIPAM.BlockAffinities[0].Key).To(Equal(newAffinityKeyPath))

		// Check that the IPAM handle attributes were changed correctly
		newHandleKey := model.IPAMHandleKey{
			HandleID: fmt.Sprintf("ipip-tunnel-addr-%s", newNodeName),
		}
		newHandleKeyPath, err := model.KeyToDefaultPath(newHandleKey)
		Expect(err).NotTo(HaveOccurred())
		Expect(migrateIPAM.IPAMHandles).To(HaveLen(1))
		Expect(migrateIPAM.IPAMHandles[0].Key).To(Equal(newHandleKeyPath))
	})

	It("Should not replace the node names in the IPAM block, block affinity, and handle if the node names are the same", func() {
		blocks := model.KVPairList{
			KVPairs: []*model.KVPair{block1},
		}
		affinities := model.KVPairList{
			KVPairs: []*model.KVPair{affinity1},
		}
		handles := model.KVPairList{
			KVPairs: []*model.KVPair{handle1},
		}

		bc := NewMockIPAMBackendClient(blocks, affinities, handles)
		client := NewMockIPAMClient(bc)
		migrateIPAM := NewMigrateIPAM(client)
		migrateIPAM.SetNodeMap(map[string]string{nodeName: nodeName})
		err := migrateIPAM.PullFromDatastore()
		Expect(err).NotTo(HaveOccurred())

		// Check that the block attributes were not changed
		Expect(migrateIPAM.IPAMBlocks).To(HaveLen(1))
		Expect(*migrateIPAM.IPAMBlocks[0].Value.Affinity).To(Equal(fmt.Sprintf("host:%s", nodeName)))
		Expect(migrateIPAM.IPAMBlocks[0].Value.Attributes).To(HaveLen(1))
		Expect(*migrateIPAM.IPAMBlocks[0].Value.Attributes[0].HandleID).To(Equal(fmt.Sprintf("ipip-tunnel-addr-%s", nodeName)))
		Expect(migrateIPAM.IPAMBlocks[0].Value.Attributes[0].ActiveOwnerAttrs["node"]).To(Equal(nodeName))

		// Check that the block affinity attributes were not changed
		newAffinityKeyPath, err := model.KeyToDefaultPath(affinity1.Key)
		Expect(err).NotTo(HaveOccurred())
		Expect(migrateIPAM.BlockAffinities).To(HaveLen(1))
		Expect(migrateIPAM.BlockAffinities[0].Key).To(Equal(newAffinityKeyPath))

		// Check that the IPAM handle attributes were not changed
		newHandleKeyPath, err := model.KeyToDefaultPath(handle1.Key)
		Expect(err).NotTo(HaveOccurred())
		Expect(migrateIPAM.IPAMHandles).To(HaveLen(1))
		Expect(migrateIPAM.IPAMHandles[0].Key).To(Equal(newHandleKeyPath))
	})
})

// MockIPAMClient subs out the clientv3.Interface but only in a way where'
// the bapi.Client is available for IPAM migration tests.
type MockIPAMClient struct {
	backend bapi.Client
}

func NewMockIPAMClient(bc bapi.Client) client.Interface {
	return &MockIPAMClient{
		backend: bc,
	}
}

func (c *MockIPAMClient) StagedGlobalNetworkPolicies() client.StagedGlobalNetworkPolicyInterface {
	return nil
}

func (c *MockIPAMClient) StagedNetworkPolicies() client.StagedNetworkPolicyInterface {
	return nil
}

func (c *MockIPAMClient) StagedKubernetesNetworkPolicies() client.StagedKubernetesNetworkPolicyInterface {
	return nil
}

func (c *MockIPAMClient) Tiers() client.TierInterface {
	return nil
}

func (c *MockIPAMClient) Backend() bapi.Client {
	return c.backend
}

func (c *MockIPAMClient) Nodes() client.NodeInterface {
	// DO NOTHING
	return nil
}

func (c *MockIPAMClient) GlobalNetworkPolicies() client.GlobalNetworkPolicyInterface {
	// DO NOTHING
	return nil
}

func (c *MockIPAMClient) NetworkPolicies() client.NetworkPolicyInterface {
	// DO NOTHING
	return nil
}

func (c *MockIPAMClient) IPPools() client.IPPoolInterface {
	// DO NOTHING
	return nil
}

func (c *MockIPAMClient) IPReservations() client.IPReservationInterface {
	// DO NOTHING
	return nil
}

func (c *MockIPAMClient) Profiles() client.ProfileInterface {
	// DO NOTHING
	return nil
}

func (c *MockIPAMClient) GlobalNetworkSets() client.GlobalNetworkSetInterface {
	// DO NOTHING
	return nil
}

func (c *MockIPAMClient) NetworkSets() client.NetworkSetInterface {
	// DO NOTHING
	return nil
}

func (c *MockIPAMClient) HostEndpoints() client.HostEndpointInterface {
	// DO NOTHING
	return nil
}

func (c *MockIPAMClient) LiveMigrations() client.LiveMigrationInterface {
	// DO NOTHING
	return nil
}

func (c *MockIPAMClient) WorkloadEndpoints() client.WorkloadEndpointInterface {
	// DO NOTHING
	return nil
}

func (c *MockIPAMClient) BGPPeers() client.BGPPeerInterface {
	// DO NOTHING
	return nil
}

func (c *MockIPAMClient) BGPFilter() client.BGPFilterInterface {
	// DO NOTHING
	return nil
}

func (c *MockIPAMClient) IPAM() ipam.Interface {
	// DO NOTHING
	return nil
}

func (c *MockIPAMClient) BGPConfigurations() client.BGPConfigurationInterface {
	// DO NOTHING
	return nil
}

func (c *MockIPAMClient) FelixConfigurations() client.FelixConfigurationInterface {
	// DO NOTHING
	return nil
}

func (c *MockIPAMClient) ClusterInformation() client.ClusterInformationInterface {
	// DO NOTHING
	return nil
}

func (c *MockIPAMClient) KubeControllersConfiguration() client.KubeControllersConfigurationInterface {
	// DO NOTHING
	return nil
}

func (c *MockIPAMClient) CalicoNodeStatus() client.CalicoNodeStatusInterface {
	// DO NOTHING
	return nil
}

func (c *MockIPAMClient) IPAMConfiguration() client.IPAMConfigurationInterface {
	// DO NOTHING
	return nil
}

func (c *MockIPAMClient) BlockAffinities() client.BlockAffinityInterface {
	// DO NOTHING
	return nil
}

func (c *MockIPAMClient) EnsureInitialized(ctx context.Context, calicoVersion, clusterType string) error {
	// DO NOTHING
	return nil
}

func (c *MockIPAMClient) Close() error {
	return nil
}

// MockIPAMBackendClient stubs out bapi.Client but only implements List
// for the IPAM objects in order to test IPAM migration logic.
type MockIPAMBackendClient struct {
	blocks     model.KVPairList
	affinities model.KVPairList
	handles    model.KVPairList
}

func NewMockIPAMBackendClient(blocks model.KVPairList, affinities model.KVPairList, handles model.KVPairList) bapi.Client {
	return &MockIPAMBackendClient{
		blocks:     blocks,
		affinities: affinities,
		handles:    handles,
	}
}

func (bc *MockIPAMBackendClient) Create(ctx context.Context, object *model.KVPair) (*model.KVPair, error) {
	// DO NOTHING
	return object, nil
}

func (bc *MockIPAMBackendClient) Update(ctx context.Context, object *model.KVPair) (*model.KVPair, error) {
	// DO NOTHING
	return object, nil
}

func (bc *MockIPAMBackendClient) Apply(ctx context.Context, object *model.KVPair) (*model.KVPair, error) {
	// DO NOTHING
	return object, nil
}

func (bc *MockIPAMBackendClient) Delete(ctx context.Context, key model.Key, revision string) (*model.KVPair, error) {
	// DO NOTHING
	return nil, nil
}

func (bc *MockIPAMBackendClient) DeleteKVP(ctx context.Context, object *model.KVPair) (*model.KVPair, error) {
	// DO NOTHING
	return object, nil
}

func (bc *MockIPAMBackendClient) Get(ctx context.Context, key model.Key, revision string) (*model.KVPair, error) {
	// DO NOTHING
	return nil, nil
}

func (bc *MockIPAMBackendClient) List(ctx context.Context, list model.ListInterface, revision string) (*model.KVPairList, error) {
	// Since this is a mock client, we only return the values based on the type of the ListInterface
	switch list.(type) {
	case model.BlockListOptions:
		return &bc.blocks, nil
	case model.BlockAffinityListOptions:
		return &bc.affinities, nil
	case model.IPAMHandleListOptions:
		return &bc.handles, nil
	}
	return nil, nil
}

func (bc *MockIPAMBackendClient) Watch(ctx context.Context, list model.ListInterface, options bapi.WatchOptions) (bapi.WatchInterface, error) {
	// DO NOTHING
	return bapi.NewFake(), nil
}

func (bc *MockIPAMBackendClient) EnsureInitialized() error {
	// DO NOTHING
	return nil
}

func (bc *MockIPAMBackendClient) Close() error {
	return nil
}

func (bc *MockIPAMBackendClient) Clean() error {
	// DO NOTHING
	return nil
}
