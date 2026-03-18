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

package migration

import (
	"fmt"
	"strings"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/migration/migrators"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/names"
)

// Kind constants for IPAM types that don't have exported Kind constants in the v3 API package.
const (
	KindIPAMBlock  = "IPAMBlock"
	KindIPAMHandle = "IPAMHandle"
)

// Migration ordering constants.
const (
	OrderTiers              = 10
	OrderConfigSingletons   = 20
	OrderClusterInformation = 30
	OrderNetworkInfra       = 40
	OrderPolicy             = 50
	OrderEndpointsAndSets   = 60
	OrderIPAM               = 100
	OrderCalicoNodeStatus   = 110
)

// NewMigrators returns migrators for all OSS Calico resource types.
func NewMigrators(bc api.Client, rt client.Client) []migrators.ResourceMigrator {
	return []migrators.ResourceMigrator{
		migrators.New[apiv3.Tier, apiv3.TierList](apiv3.KindTier, OrderTiers, bc, rt),
		migrators.New[apiv3.FelixConfiguration, apiv3.FelixConfigurationList](apiv3.KindFelixConfiguration, OrderConfigSingletons, bc, rt),
		migrators.New[apiv3.BGPConfiguration, apiv3.BGPConfigurationList](apiv3.KindBGPConfiguration, OrderConfigSingletons, bc, rt),
		migrators.New[apiv3.KubeControllersConfiguration, apiv3.KubeControllersConfigurationList](apiv3.KindKubeControllersConfiguration, OrderConfigSingletons, bc, rt),
		migrators.New[apiv3.ClusterInformation, apiv3.ClusterInformationList](apiv3.KindClusterInformation, OrderClusterInformation, bc, rt),
		migrators.New[apiv3.IPPool, apiv3.IPPoolList](apiv3.KindIPPool, OrderNetworkInfra, bc, rt),
		migrators.New[apiv3.IPReservation, apiv3.IPReservationList](apiv3.KindIPReservation, OrderNetworkInfra, bc, rt),
		migrators.New[apiv3.BGPPeer, apiv3.BGPPeerList](apiv3.KindBGPPeer, OrderNetworkInfra, bc, rt),
		migrators.New[apiv3.BGPFilter, apiv3.BGPFilterList](apiv3.KindBGPFilter, OrderNetworkInfra, bc, rt),
		migrators.New[apiv3.GlobalNetworkPolicy, apiv3.GlobalNetworkPolicyList](
			apiv3.KindGlobalNetworkPolicy, OrderPolicy, bc, rt,
			migrators.WithConvert(convertGlobalNetworkPolicy),
		),
		migrators.New[apiv3.NetworkPolicy, apiv3.NetworkPolicyList](
			apiv3.KindNetworkPolicy, OrderPolicy, bc, rt,
			migrators.WithConvert(convertNetworkPolicy),
		),
		migrators.New[apiv3.StagedGlobalNetworkPolicy, apiv3.StagedGlobalNetworkPolicyList](
			apiv3.KindStagedGlobalNetworkPolicy, OrderPolicy, bc, rt,
			migrators.WithConvert(convertStagedGlobalNetworkPolicy),
		),
		migrators.New[apiv3.StagedNetworkPolicy, apiv3.StagedNetworkPolicyList](
			apiv3.KindStagedNetworkPolicy, OrderPolicy, bc, rt,
			migrators.WithConvert(convertStagedNetworkPolicy),
		),
		migrators.New[apiv3.StagedKubernetesNetworkPolicy, apiv3.StagedKubernetesNetworkPolicyList](apiv3.KindStagedKubernetesNetworkPolicy, OrderPolicy, bc, rt),
		migrators.New[apiv3.HostEndpoint, apiv3.HostEndpointList](apiv3.KindHostEndpoint, OrderEndpointsAndSets, bc, rt),
		migrators.New[apiv3.GlobalNetworkSet, apiv3.GlobalNetworkSetList](apiv3.KindGlobalNetworkSet, OrderEndpointsAndSets, bc, rt),
		migrators.New[apiv3.NetworkSet, apiv3.NetworkSetList](apiv3.KindNetworkSet, OrderEndpointsAndSets, bc, rt),
		migrators.New[apiv3.IPAMConfiguration, apiv3.IPAMConfigurationList](apiv3.KindIPAMConfiguration, OrderIPAM, bc, rt),
		migrators.New[apiv3.BlockAffinity, apiv3.BlockAffinityList](apiv3.KindBlockAffinity, OrderIPAM, bc, rt),
		migrators.New[apiv3.IPAMBlock, apiv3.IPAMBlockList](
			KindIPAMBlock, OrderIPAM, bc, rt,
			migrators.WithConvert(convertIPAMBlock),
			migrators.WithListOptions(model.BlockListOptions{}),
		),
		migrators.New[apiv3.IPAMHandle, apiv3.IPAMHandleList](
			KindIPAMHandle, OrderIPAM, bc, rt,
			migrators.WithConvert(convertIPAMHandle),
			migrators.WithListOptions(model.IPAMHandleListOptions{}),
		),
		migrators.New[apiv3.CalicoNodeStatus, apiv3.CalicoNodeStatusList](apiv3.KindCalicoNodeStatus, OrderCalicoNodeStatus, bc, rt),
	}
}

// migratedPolicyName handles the default. prefix removal for default-tier policies.
func migratedPolicyName(name, tier string) string {
	if (tier == "default" || tier == "") && strings.HasPrefix(name, "default.") {
		return strings.TrimPrefix(name, "default.")
	}
	return name
}

func convertGlobalNetworkPolicy(kvp *model.KVPair) (*apiv3.GlobalNetworkPolicy, error) {
	v1, ok := kvp.Value.(*apiv3.GlobalNetworkPolicy)
	if !ok {
		return nil, fmt.Errorf("unexpected type for GlobalNetworkPolicy: %T", kvp.Value)
	}
	name := migratedPolicyName(v1.Name, v1.Spec.Tier)
	v3 := v1.DeepCopy()
	v3.Name = name
	v3.ResourceVersion = ""
	v3.CreationTimestamp = metav1.Time{}
	v3.ManagedFields = nil
	v3.Generation = 0
	filterInternalAnnotations(v3)
	return v3, nil
}

func convertNetworkPolicy(kvp *model.KVPair) (*apiv3.NetworkPolicy, error) {
	v1, ok := kvp.Value.(*apiv3.NetworkPolicy)
	if !ok {
		return nil, fmt.Errorf("unexpected type for NetworkPolicy: %T", kvp.Value)
	}
	name := migratedPolicyName(v1.Name, v1.Spec.Tier)
	v3 := v1.DeepCopy()
	v3.Name = name
	v3.ResourceVersion = ""
	v3.CreationTimestamp = metav1.Time{}
	v3.ManagedFields = nil
	v3.Generation = 0
	filterInternalAnnotations(v3)
	return v3, nil
}

func convertStagedGlobalNetworkPolicy(kvp *model.KVPair) (*apiv3.StagedGlobalNetworkPolicy, error) {
	v1, ok := kvp.Value.(*apiv3.StagedGlobalNetworkPolicy)
	if !ok {
		return nil, fmt.Errorf("unexpected type for StagedGlobalNetworkPolicy: %T", kvp.Value)
	}
	name := migratedPolicyName(v1.Name, v1.Spec.Tier)
	v3 := v1.DeepCopy()
	v3.Name = name
	v3.ResourceVersion = ""
	v3.CreationTimestamp = metav1.Time{}
	v3.ManagedFields = nil
	v3.Generation = 0
	filterInternalAnnotations(v3)
	return v3, nil
}

func convertStagedNetworkPolicy(kvp *model.KVPair) (*apiv3.StagedNetworkPolicy, error) {
	v1, ok := kvp.Value.(*apiv3.StagedNetworkPolicy)
	if !ok {
		return nil, fmt.Errorf("unexpected type for StagedNetworkPolicy: %T", kvp.Value)
	}
	name := migratedPolicyName(v1.Name, v1.Spec.Tier)
	v3 := v1.DeepCopy()
	v3.Name = name
	v3.ResourceVersion = ""
	v3.CreationTimestamp = metav1.Time{}
	v3.ManagedFields = nil
	v3.Generation = 0
	filterInternalAnnotations(v3)
	return v3, nil
}

// filterInternalAnnotations removes the projectcalico.org/metadata annotation
// used by the v1 backend.
func filterInternalAnnotations(obj metav1.Object) {
	annotations := obj.GetAnnotations()
	if len(annotations) == 0 {
		return
	}
	if _, ok := annotations["projectcalico.org/metadata"]; !ok {
		return
	}
	cleaned := make(map[string]string, len(annotations)-1)
	for k, v := range annotations {
		if k == "projectcalico.org/metadata" {
			continue
		}
		cleaned[k] = v
	}
	if len(cleaned) > 0 {
		obj.SetAnnotations(cleaned)
	} else {
		obj.SetAnnotations(nil)
	}
}

// convertIPAMBlock converts a model.AllocationBlock KVPair to a v3 IPAMBlock.
func convertIPAMBlock(kvp *model.KVPair) (*apiv3.IPAMBlock, error) {
	block, ok := kvp.Value.(*model.AllocationBlock)
	if !ok {
		return nil, fmt.Errorf("unexpected type for AllocationBlock: %T", kvp.Value)
	}
	name := names.CIDRToName(block.CIDR)

	attrs := make([]apiv3.AllocationAttribute, len(block.Attributes))
	for i, a := range block.Attributes {
		attrs[i] = apiv3.AllocationAttribute{
			HandleID:            a.HandleID,
			ActiveOwnerAttrs:    a.ActiveOwnerAttrs,
			AlternateOwnerAttrs: a.AlternateOwnerAttrs,
		}
	}

	v3Block := &apiv3.IPAMBlock{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: apiv3.IPAMBlockSpec{
			CIDR:                        block.CIDR.String(),
			Affinity:                    block.Affinity,
			AffinityClaimTime:           block.AffinityClaimTime,
			Allocations:                 block.Allocations,
			Unallocated:                 block.Unallocated,
			Attributes:                  attrs,
			SequenceNumber:              block.SequenceNumber,
			SequenceNumberForAllocation: block.SequenceNumberForAllocation,
			Deleted:                     block.Deleted,
		},
	}
	if kvp.UID != nil {
		v3Block.UID = *kvp.UID
	}
	return v3Block, nil
}

// convertIPAMHandle converts a model.IPAMHandle KVPair to a v3 IPAMHandle.
func convertIPAMHandle(kvp *model.KVPair) (*apiv3.IPAMHandle, error) {
	handle, ok := kvp.Value.(*model.IPAMHandle)
	if !ok {
		return nil, fmt.Errorf("unexpected type for IPAMHandle: %T", kvp.Value)
	}
	handleKey, ok := kvp.Key.(model.IPAMHandleKey)
	if !ok {
		return nil, fmt.Errorf("unexpected key type for IPAMHandle: %T", kvp.Key)
	}
	name := handleKey.HandleID

	v3Handle := &apiv3.IPAMHandle{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: apiv3.IPAMHandleSpec{
			HandleID: handle.HandleID,
			Block:    handle.Block,
			Deleted:  handle.Deleted,
		},
	}
	if kvp.UID != nil {
		v3Handle.UID = *kvp.UID
	}
	return v3Handle, nil
}
