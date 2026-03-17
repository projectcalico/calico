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
	"context"
	"fmt"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

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

// RegisterOSSResources registers all OSS resource migrators.
func RegisterOSSResources() {
	// 1. Tiers
	Register(ResourceMigrator{
		Kind:         apiv3.KindTier,
		Order:        OrderTiers,
		V3Object:     func() client.Object { return &apiv3.Tier{} },
		V3ObjectList: func() client.ObjectList { return &apiv3.TierList{} },
		GetSpec:      func(obj client.Object) any { return obj.(*apiv3.Tier).Spec },
		ListV1: func(ctx context.Context, bc api.Client) (*model.KVPairList, error) {
			return listV1Resources(ctx, bc, apiv3.KindTier)
		},
		Convert: func(kvp *model.KVPair) (client.Object, error) {
			v1, ok := kvp.Value.(*apiv3.Tier)
			if !ok {
				return nil, fmt.Errorf("unexpected type for Tier: %T", kvp.Value)
			}
			v3 := &apiv3.Tier{
				TypeMeta:   newV3TypeMeta(apiv3.KindTier),
				ObjectMeta: metav1.ObjectMeta{Name: v1.Name},
				Spec:       *v1.Spec.DeepCopy(),
			}
			copyLabelsAndAnnotations(v1, v3)
			return v3, nil
		},
	})

	// 2. FelixConfiguration
	Register(ResourceMigrator{
		Kind:         apiv3.KindFelixConfiguration,
		Order:        OrderConfigSingletons,
		V3Object:     func() client.Object { return &apiv3.FelixConfiguration{} },
		V3ObjectList: func() client.ObjectList { return &apiv3.FelixConfigurationList{} },
		GetSpec:      func(obj client.Object) any { return obj.(*apiv3.FelixConfiguration).Spec },
		ListV1: func(ctx context.Context, bc api.Client) (*model.KVPairList, error) {
			return listV1Resources(ctx, bc, apiv3.KindFelixConfiguration)
		},
		Convert: func(kvp *model.KVPair) (client.Object, error) {
			v1, ok := kvp.Value.(*apiv3.FelixConfiguration)
			if !ok {
				return nil, fmt.Errorf("unexpected type for FelixConfiguration: %T", kvp.Value)
			}
			v3 := &apiv3.FelixConfiguration{
				TypeMeta:   newV3TypeMeta(apiv3.KindFelixConfiguration),
				ObjectMeta: metav1.ObjectMeta{Name: v1.Name},
				Spec:       *v1.Spec.DeepCopy(),
			}
			copyLabelsAndAnnotations(v1, v3)
			return v3, nil
		},
	})

	// 3. BGPConfiguration
	Register(ResourceMigrator{
		Kind:         apiv3.KindBGPConfiguration,
		Order:        OrderConfigSingletons,
		V3Object:     func() client.Object { return &apiv3.BGPConfiguration{} },
		V3ObjectList: func() client.ObjectList { return &apiv3.BGPConfigurationList{} },
		GetSpec:      func(obj client.Object) any { return obj.(*apiv3.BGPConfiguration).Spec },
		ListV1: func(ctx context.Context, bc api.Client) (*model.KVPairList, error) {
			return listV1Resources(ctx, bc, apiv3.KindBGPConfiguration)
		},
		Convert: func(kvp *model.KVPair) (client.Object, error) {
			v1, ok := kvp.Value.(*apiv3.BGPConfiguration)
			if !ok {
				return nil, fmt.Errorf("unexpected type for BGPConfiguration: %T", kvp.Value)
			}
			v3 := &apiv3.BGPConfiguration{
				TypeMeta:   newV3TypeMeta(apiv3.KindBGPConfiguration),
				ObjectMeta: metav1.ObjectMeta{Name: v1.Name},
				Spec:       *v1.Spec.DeepCopy(),
			}
			copyLabelsAndAnnotations(v1, v3)
			return v3, nil
		},
	})

	// 4. KubeControllersConfiguration
	Register(ResourceMigrator{
		Kind:         apiv3.KindKubeControllersConfiguration,
		Order:        OrderConfigSingletons,
		V3Object:     func() client.Object { return &apiv3.KubeControllersConfiguration{} },
		V3ObjectList: func() client.ObjectList { return &apiv3.KubeControllersConfigurationList{} },
		GetSpec:      func(obj client.Object) any { return obj.(*apiv3.KubeControllersConfiguration).Spec },
		ListV1: func(ctx context.Context, bc api.Client) (*model.KVPairList, error) {
			return listV1Resources(ctx, bc, apiv3.KindKubeControllersConfiguration)
		},
		Convert: func(kvp *model.KVPair) (client.Object, error) {
			v1, ok := kvp.Value.(*apiv3.KubeControllersConfiguration)
			if !ok {
				return nil, fmt.Errorf("unexpected type for KubeControllersConfiguration: %T", kvp.Value)
			}
			v3 := &apiv3.KubeControllersConfiguration{
				TypeMeta:   newV3TypeMeta(apiv3.KindKubeControllersConfiguration),
				ObjectMeta: metav1.ObjectMeta{Name: v1.Name},
				Spec:       *v1.Spec.DeepCopy(),
			}
			copyLabelsAndAnnotations(v1, v3)
			return v3, nil
		},
	})

	// 5. ClusterInformation
	Register(ResourceMigrator{
		Kind:         apiv3.KindClusterInformation,
		Order:        OrderClusterInformation,
		V3Object:     func() client.Object { return &apiv3.ClusterInformation{} },
		V3ObjectList: func() client.ObjectList { return &apiv3.ClusterInformationList{} },
		GetSpec:      func(obj client.Object) any { return obj.(*apiv3.ClusterInformation).Spec },
		ListV1: func(ctx context.Context, bc api.Client) (*model.KVPairList, error) {
			return listV1Resources(ctx, bc, apiv3.KindClusterInformation)
		},
		Convert: func(kvp *model.KVPair) (client.Object, error) {
			v1, ok := kvp.Value.(*apiv3.ClusterInformation)
			if !ok {
				return nil, fmt.Errorf("unexpected type for ClusterInformation: %T", kvp.Value)
			}
			v3 := &apiv3.ClusterInformation{
				TypeMeta:   newV3TypeMeta(apiv3.KindClusterInformation),
				ObjectMeta: metav1.ObjectMeta{Name: v1.Name},
				Spec:       *v1.Spec.DeepCopy(),
			}
			copyLabelsAndAnnotations(v1, v3)
			return v3, nil
		},
	})

	// 6. IPPool
	Register(ResourceMigrator{
		Kind:         apiv3.KindIPPool,
		Order:        OrderNetworkInfra,
		V3Object:     func() client.Object { return &apiv3.IPPool{} },
		V3ObjectList: func() client.ObjectList { return &apiv3.IPPoolList{} },
		GetSpec:      func(obj client.Object) any { return obj.(*apiv3.IPPool).Spec },
		ListV1: func(ctx context.Context, bc api.Client) (*model.KVPairList, error) {
			return listV1Resources(ctx, bc, apiv3.KindIPPool)
		},
		Convert: func(kvp *model.KVPair) (client.Object, error) {
			v1, ok := kvp.Value.(*apiv3.IPPool)
			if !ok {
				return nil, fmt.Errorf("unexpected type for IPPool: %T", kvp.Value)
			}
			v3 := &apiv3.IPPool{
				TypeMeta:   newV3TypeMeta(apiv3.KindIPPool),
				ObjectMeta: metav1.ObjectMeta{Name: v1.Name},
				Spec:       *v1.Spec.DeepCopy(),
			}
			copyLabelsAndAnnotations(v1, v3)
			return v3, nil
		},
	})

	// 6b. IPReservation
	Register(ResourceMigrator{
		Kind:         apiv3.KindIPReservation,
		Order:        OrderNetworkInfra,
		V3Object:     func() client.Object { return &apiv3.IPReservation{} },
		V3ObjectList: func() client.ObjectList { return &apiv3.IPReservationList{} },
		GetSpec:      func(obj client.Object) any { return obj.(*apiv3.IPReservation).Spec },
		ListV1: func(ctx context.Context, bc api.Client) (*model.KVPairList, error) {
			return listV1Resources(ctx, bc, apiv3.KindIPReservation)
		},
		Convert: func(kvp *model.KVPair) (client.Object, error) {
			v1, ok := kvp.Value.(*apiv3.IPReservation)
			if !ok {
				return nil, fmt.Errorf("unexpected type for IPReservation: %T", kvp.Value)
			}
			v3 := &apiv3.IPReservation{
				TypeMeta:   newV3TypeMeta(apiv3.KindIPReservation),
				ObjectMeta: metav1.ObjectMeta{Name: v1.Name},
				Spec:       *v1.Spec.DeepCopy(),
			}
			copyLabelsAndAnnotations(v1, v3)
			return v3, nil
		},
	})

	// 7. BGPPeer
	Register(ResourceMigrator{
		Kind:         apiv3.KindBGPPeer,
		Order:        OrderNetworkInfra,
		V3Object:     func() client.Object { return &apiv3.BGPPeer{} },
		V3ObjectList: func() client.ObjectList { return &apiv3.BGPPeerList{} },
		GetSpec:      func(obj client.Object) any { return obj.(*apiv3.BGPPeer).Spec },
		ListV1: func(ctx context.Context, bc api.Client) (*model.KVPairList, error) {
			return listV1Resources(ctx, bc, apiv3.KindBGPPeer)
		},
		Convert: func(kvp *model.KVPair) (client.Object, error) {
			v1, ok := kvp.Value.(*apiv3.BGPPeer)
			if !ok {
				return nil, fmt.Errorf("unexpected type for BGPPeer: %T", kvp.Value)
			}
			v3 := &apiv3.BGPPeer{
				TypeMeta:   newV3TypeMeta(apiv3.KindBGPPeer),
				ObjectMeta: metav1.ObjectMeta{Name: v1.Name},
				Spec:       *v1.Spec.DeepCopy(),
			}
			copyLabelsAndAnnotations(v1, v3)
			return v3, nil
		},
	})

	// 8. BGPFilter
	Register(ResourceMigrator{
		Kind:         apiv3.KindBGPFilter,
		Order:        OrderNetworkInfra,
		V3Object:     func() client.Object { return &apiv3.BGPFilter{} },
		V3ObjectList: func() client.ObjectList { return &apiv3.BGPFilterList{} },
		GetSpec:      func(obj client.Object) any { return obj.(*apiv3.BGPFilter).Spec },
		ListV1: func(ctx context.Context, bc api.Client) (*model.KVPairList, error) {
			return listV1Resources(ctx, bc, apiv3.KindBGPFilter)
		},
		Convert: func(kvp *model.KVPair) (client.Object, error) {
			v1, ok := kvp.Value.(*apiv3.BGPFilter)
			if !ok {
				return nil, fmt.Errorf("unexpected type for BGPFilter: %T", kvp.Value)
			}
			v3 := &apiv3.BGPFilter{
				TypeMeta:   newV3TypeMeta(apiv3.KindBGPFilter),
				ObjectMeta: metav1.ObjectMeta{Name: v1.Name},
				Spec:       *v1.Spec.DeepCopy(),
			}
			copyLabelsAndAnnotations(v1, v3)
			return v3, nil
		},
	})

	// 9. GlobalNetworkPolicy (with policy name migration)
	Register(ResourceMigrator{
		Kind:         apiv3.KindGlobalNetworkPolicy,
		Order:        OrderPolicy,
		V3Object:     func() client.Object { return &apiv3.GlobalNetworkPolicy{} },
		V3ObjectList: func() client.ObjectList { return &apiv3.GlobalNetworkPolicyList{} },
		GetSpec:      func(obj client.Object) any { return obj.(*apiv3.GlobalNetworkPolicy).Spec },
		ListV1: func(ctx context.Context, bc api.Client) (*model.KVPairList, error) {
			return listV1Resources(ctx, bc, apiv3.KindGlobalNetworkPolicy)
		},
		Convert: func(kvp *model.KVPair) (client.Object, error) {
			v1, ok := kvp.Value.(*apiv3.GlobalNetworkPolicy)
			if !ok {
				return nil, fmt.Errorf("unexpected type for GlobalNetworkPolicy: %T", kvp.Value)
			}
			name := migratedPolicyName(v1.Name, v1.Spec.Tier)
			v3 := &apiv3.GlobalNetworkPolicy{
				TypeMeta:   newV3TypeMeta(apiv3.KindGlobalNetworkPolicy),
				ObjectMeta: metav1.ObjectMeta{Name: name},
				Spec:       *v1.Spec.DeepCopy(),
			}
			copyLabelsAndAnnotations(v1, v3)
			return v3, nil
		},
	})

	// 10. NetworkPolicy (namespaced, with policy name migration)
	Register(ResourceMigrator{
		Kind:         apiv3.KindNetworkPolicy,
		Namespaced:   true,
		Order:        OrderPolicy,
		V3Object:     func() client.Object { return &apiv3.NetworkPolicy{} },
		V3ObjectList: func() client.ObjectList { return &apiv3.NetworkPolicyList{} },
		GetSpec:      func(obj client.Object) any { return obj.(*apiv3.NetworkPolicy).Spec },
		ListV1: func(ctx context.Context, bc api.Client) (*model.KVPairList, error) {
			return listV1NamespacedResources(ctx, bc, apiv3.KindNetworkPolicy)
		},
		Convert: func(kvp *model.KVPair) (client.Object, error) {
			v1, ok := kvp.Value.(*apiv3.NetworkPolicy)
			if !ok {
				return nil, fmt.Errorf("unexpected type for NetworkPolicy: %T", kvp.Value)
			}
			name := migratedPolicyName(v1.Name, v1.Spec.Tier)
			v3 := &apiv3.NetworkPolicy{
				TypeMeta: newV3TypeMeta(apiv3.KindNetworkPolicy),
				ObjectMeta: metav1.ObjectMeta{
					Name:      name,
					Namespace: v1.Namespace,
				},
				Spec: *v1.Spec.DeepCopy(),
			}
			copyLabelsAndAnnotations(v1, v3)
			return v3, nil
		},
	})

	// 11. StagedGlobalNetworkPolicy (with policy name migration)
	Register(ResourceMigrator{
		Kind:         apiv3.KindStagedGlobalNetworkPolicy,
		Order:        OrderPolicy,
		V3Object:     func() client.Object { return &apiv3.StagedGlobalNetworkPolicy{} },
		V3ObjectList: func() client.ObjectList { return &apiv3.StagedGlobalNetworkPolicyList{} },
		GetSpec:      func(obj client.Object) any { return obj.(*apiv3.StagedGlobalNetworkPolicy).Spec },
		ListV1: func(ctx context.Context, bc api.Client) (*model.KVPairList, error) {
			return listV1Resources(ctx, bc, apiv3.KindStagedGlobalNetworkPolicy)
		},
		Convert: func(kvp *model.KVPair) (client.Object, error) {
			v1, ok := kvp.Value.(*apiv3.StagedGlobalNetworkPolicy)
			if !ok {
				return nil, fmt.Errorf("unexpected type for StagedGlobalNetworkPolicy: %T", kvp.Value)
			}
			name := migratedPolicyName(v1.Name, v1.Spec.Tier)
			v3 := &apiv3.StagedGlobalNetworkPolicy{
				TypeMeta:   newV3TypeMeta(apiv3.KindStagedGlobalNetworkPolicy),
				ObjectMeta: metav1.ObjectMeta{Name: name},
				Spec:       *v1.Spec.DeepCopy(),
			}
			copyLabelsAndAnnotations(v1, v3)
			return v3, nil
		},
	})

	// 12. StagedNetworkPolicy (namespaced, with policy name migration)
	Register(ResourceMigrator{
		Kind:         apiv3.KindStagedNetworkPolicy,
		Namespaced:   true,
		Order:        OrderPolicy,
		V3Object:     func() client.Object { return &apiv3.StagedNetworkPolicy{} },
		V3ObjectList: func() client.ObjectList { return &apiv3.StagedNetworkPolicyList{} },
		GetSpec:      func(obj client.Object) any { return obj.(*apiv3.StagedNetworkPolicy).Spec },
		ListV1: func(ctx context.Context, bc api.Client) (*model.KVPairList, error) {
			return listV1NamespacedResources(ctx, bc, apiv3.KindStagedNetworkPolicy)
		},
		Convert: func(kvp *model.KVPair) (client.Object, error) {
			v1, ok := kvp.Value.(*apiv3.StagedNetworkPolicy)
			if !ok {
				return nil, fmt.Errorf("unexpected type for StagedNetworkPolicy: %T", kvp.Value)
			}
			name := migratedPolicyName(v1.Name, v1.Spec.Tier)
			v3 := &apiv3.StagedNetworkPolicy{
				TypeMeta: newV3TypeMeta(apiv3.KindStagedNetworkPolicy),
				ObjectMeta: metav1.ObjectMeta{
					Name:      name,
					Namespace: v1.Namespace,
				},
				Spec: *v1.Spec.DeepCopy(),
			}
			copyLabelsAndAnnotations(v1, v3)
			return v3, nil
		},
	})

	// 13. StagedKubernetesNetworkPolicy (namespaced)
	Register(ResourceMigrator{
		Kind:         apiv3.KindStagedKubernetesNetworkPolicy,
		Namespaced:   true,
		Order:        OrderPolicy,
		V3Object:     func() client.Object { return &apiv3.StagedKubernetesNetworkPolicy{} },
		V3ObjectList: func() client.ObjectList { return &apiv3.StagedKubernetesNetworkPolicyList{} },
		GetSpec:      func(obj client.Object) any { return obj.(*apiv3.StagedKubernetesNetworkPolicy).Spec },
		ListV1: func(ctx context.Context, bc api.Client) (*model.KVPairList, error) {
			return listV1NamespacedResources(ctx, bc, apiv3.KindStagedKubernetesNetworkPolicy)
		},
		Convert: func(kvp *model.KVPair) (client.Object, error) {
			v1, ok := kvp.Value.(*apiv3.StagedKubernetesNetworkPolicy)
			if !ok {
				return nil, fmt.Errorf("unexpected type for StagedKubernetesNetworkPolicy: %T", kvp.Value)
			}
			v3 := &apiv3.StagedKubernetesNetworkPolicy{
				TypeMeta: newV3TypeMeta(apiv3.KindStagedKubernetesNetworkPolicy),
				ObjectMeta: metav1.ObjectMeta{
					Name:      v1.Name,
					Namespace: v1.Namespace,
				},
				Spec: *v1.Spec.DeepCopy(),
			}
			copyLabelsAndAnnotations(v1, v3)
			return v3, nil
		},
	})

	// 14. HostEndpoint
	Register(ResourceMigrator{
		Kind:         apiv3.KindHostEndpoint,
		Order:        OrderEndpointsAndSets,
		V3Object:     func() client.Object { return &apiv3.HostEndpoint{} },
		V3ObjectList: func() client.ObjectList { return &apiv3.HostEndpointList{} },
		GetSpec:      func(obj client.Object) any { return obj.(*apiv3.HostEndpoint).Spec },
		ListV1: func(ctx context.Context, bc api.Client) (*model.KVPairList, error) {
			return listV1Resources(ctx, bc, apiv3.KindHostEndpoint)
		},
		Convert: func(kvp *model.KVPair) (client.Object, error) {
			v1, ok := kvp.Value.(*apiv3.HostEndpoint)
			if !ok {
				return nil, fmt.Errorf("unexpected type for HostEndpoint: %T", kvp.Value)
			}
			v3 := &apiv3.HostEndpoint{
				TypeMeta:   newV3TypeMeta(apiv3.KindHostEndpoint),
				ObjectMeta: metav1.ObjectMeta{Name: v1.Name},
				Spec:       *v1.Spec.DeepCopy(),
			}
			copyLabelsAndAnnotations(v1, v3)
			return v3, nil
		},
	})

	// 15. GlobalNetworkSet
	Register(ResourceMigrator{
		Kind:         apiv3.KindGlobalNetworkSet,
		Order:        OrderEndpointsAndSets,
		V3Object:     func() client.Object { return &apiv3.GlobalNetworkSet{} },
		V3ObjectList: func() client.ObjectList { return &apiv3.GlobalNetworkSetList{} },
		GetSpec:      func(obj client.Object) any { return obj.(*apiv3.GlobalNetworkSet).Spec },
		ListV1: func(ctx context.Context, bc api.Client) (*model.KVPairList, error) {
			return listV1Resources(ctx, bc, apiv3.KindGlobalNetworkSet)
		},
		Convert: func(kvp *model.KVPair) (client.Object, error) {
			v1, ok := kvp.Value.(*apiv3.GlobalNetworkSet)
			if !ok {
				return nil, fmt.Errorf("unexpected type for GlobalNetworkSet: %T", kvp.Value)
			}
			v3 := &apiv3.GlobalNetworkSet{
				TypeMeta:   newV3TypeMeta(apiv3.KindGlobalNetworkSet),
				ObjectMeta: metav1.ObjectMeta{Name: v1.Name},
				Spec:       *v1.Spec.DeepCopy(),
			}
			copyLabelsAndAnnotations(v1, v3)
			return v3, nil
		},
	})

	// 16. NetworkSet (namespaced)
	Register(ResourceMigrator{
		Kind:         apiv3.KindNetworkSet,
		Namespaced:   true,
		Order:        OrderEndpointsAndSets,
		V3Object:     func() client.Object { return &apiv3.NetworkSet{} },
		V3ObjectList: func() client.ObjectList { return &apiv3.NetworkSetList{} },
		GetSpec:      func(obj client.Object) any { return obj.(*apiv3.NetworkSet).Spec },
		ListV1: func(ctx context.Context, bc api.Client) (*model.KVPairList, error) {
			return listV1NamespacedResources(ctx, bc, apiv3.KindNetworkSet)
		},
		Convert: func(kvp *model.KVPair) (client.Object, error) {
			v1, ok := kvp.Value.(*apiv3.NetworkSet)
			if !ok {
				return nil, fmt.Errorf("unexpected type for NetworkSet: %T", kvp.Value)
			}
			v3 := &apiv3.NetworkSet{
				TypeMeta: newV3TypeMeta(apiv3.KindNetworkSet),
				ObjectMeta: metav1.ObjectMeta{
					Name:      v1.Name,
					Namespace: v1.Namespace,
				},
				Spec: *v1.Spec.DeepCopy(),
			}
			copyLabelsAndAnnotations(v1, v3)
			return v3, nil
		},
	})

	// 17. IPAMConfiguration (v1 is "IPAMConfig", v3 is "IPAMConfiguration")
	Register(ResourceMigrator{
		Kind:         apiv3.KindIPAMConfiguration,
		Order:        OrderIPAM,
		V3Object:     func() client.Object { return &apiv3.IPAMConfiguration{} },
		V3ObjectList: func() client.ObjectList { return &apiv3.IPAMConfigurationList{} },
		GetSpec:      func(obj client.Object) any { return obj.(*apiv3.IPAMConfiguration).Spec },
		ListV1: func(ctx context.Context, bc api.Client) (*model.KVPairList, error) {
			return listV1Resources(ctx, bc, apiv3.KindIPAMConfiguration)
		},
		Convert: func(kvp *model.KVPair) (client.Object, error) {
			v1, ok := kvp.Value.(*apiv3.IPAMConfiguration)
			if !ok {
				return nil, fmt.Errorf("unexpected type for IPAMConfiguration: %T", kvp.Value)
			}
			v3 := &apiv3.IPAMConfiguration{
				TypeMeta:   newV3TypeMeta(apiv3.KindIPAMConfiguration),
				ObjectMeta: metav1.ObjectMeta{Name: v1.Name},
				Spec:       *v1.Spec.DeepCopy(),
			}
			copyLabelsAndAnnotations(v1, v3)
			return v3, nil
		},
	})

	// 18. BlockAffinity (IPAM)
	Register(ResourceMigrator{
		Kind:         apiv3.KindBlockAffinity,
		Order:        OrderIPAM,
		V3Object:     func() client.Object { return &apiv3.BlockAffinity{} },
		V3ObjectList: func() client.ObjectList { return &apiv3.BlockAffinityList{} },
		GetSpec:      func(obj client.Object) any { return obj.(*apiv3.BlockAffinity).Spec },
		ListV1: func(ctx context.Context, bc api.Client) (*model.KVPairList, error) {
			return listV1Resources(ctx, bc, apiv3.KindBlockAffinity)
		},
		Convert: func(kvp *model.KVPair) (client.Object, error) {
			v1, ok := kvp.Value.(*apiv3.BlockAffinity)
			if !ok {
				return nil, fmt.Errorf("unexpected type for BlockAffinity: %T", kvp.Value)
			}
			v3 := &apiv3.BlockAffinity{
				TypeMeta:   newV3TypeMeta(apiv3.KindBlockAffinity),
				ObjectMeta: metav1.ObjectMeta{Name: v1.Name},
				Spec:       *v1.Spec.DeepCopy(),
			}
			copyLabelsAndAnnotations(v1, v3)
			return v3, nil
		},
	})

	// 19. IPAMBlock — uses BlockListOptions instead of ResourceListOptions, so ListV1
	// converts the model.AllocationBlock values back to v3 IPAMBlock objects.
	Register(ResourceMigrator{
		Kind:         KindIPAMBlock,
		Order:        OrderIPAM,
		V3Object:     func() client.Object { return &apiv3.IPAMBlock{} },
		V3ObjectList: func() client.ObjectList { return &apiv3.IPAMBlockList{} },
		GetSpec:      func(obj client.Object) any { return obj.(*apiv3.IPAMBlock).Spec },
		ListV1: func(ctx context.Context, bc api.Client) (*model.KVPairList, error) {
			return listV1IPAMBlocks(ctx, bc)
		},
		Convert: func(kvp *model.KVPair) (client.Object, error) {
			v1, ok := kvp.Value.(*apiv3.IPAMBlock)
			if !ok {
				return nil, fmt.Errorf("unexpected type for IPAMBlock: %T", kvp.Value)
			}
			v3 := &apiv3.IPAMBlock{
				TypeMeta:   newV3TypeMeta(KindIPAMBlock),
				ObjectMeta: metav1.ObjectMeta{Name: v1.Name},
				Spec:       *v1.Spec.DeepCopy(),
			}
			copyLabelsAndAnnotations(v1, v3)
			return v3, nil
		},
	})

	// 20. IPAMHandle — uses IPAMHandleListOptions instead of ResourceListOptions, so
	// ListV1 converts the model.IPAMHandle values back to v3 IPAMHandle objects.
	Register(ResourceMigrator{
		Kind:         KindIPAMHandle,
		Order:        OrderIPAM,
		V3Object:     func() client.Object { return &apiv3.IPAMHandle{} },
		V3ObjectList: func() client.ObjectList { return &apiv3.IPAMHandleList{} },
		GetSpec:      func(obj client.Object) any { return obj.(*apiv3.IPAMHandle).Spec },
		ListV1: func(ctx context.Context, bc api.Client) (*model.KVPairList, error) {
			return listV1IPAMHandles(ctx, bc)
		},
		Convert: func(kvp *model.KVPair) (client.Object, error) {
			v1, ok := kvp.Value.(*apiv3.IPAMHandle)
			if !ok {
				return nil, fmt.Errorf("unexpected type for IPAMHandle: %T", kvp.Value)
			}
			v3 := &apiv3.IPAMHandle{
				TypeMeta:   newV3TypeMeta(KindIPAMHandle),
				ObjectMeta: metav1.ObjectMeta{Name: v1.Name},
				Spec:       *v1.Spec.DeepCopy(),
			}
			copyLabelsAndAnnotations(v1, v3)
			return v3, nil
		},
	})

	// 21. CalicoNodeStatus
	Register(ResourceMigrator{
		Kind:         apiv3.KindCalicoNodeStatus,
		Order:        OrderCalicoNodeStatus,
		V3Object:     func() client.Object { return &apiv3.CalicoNodeStatus{} },
		V3ObjectList: func() client.ObjectList { return &apiv3.CalicoNodeStatusList{} },
		GetSpec:      func(obj client.Object) any { return obj.(*apiv3.CalicoNodeStatus).Spec },
		ListV1: func(ctx context.Context, bc api.Client) (*model.KVPairList, error) {
			return listV1Resources(ctx, bc, apiv3.KindCalicoNodeStatus)
		},
		Convert: func(kvp *model.KVPair) (client.Object, error) {
			v1, ok := kvp.Value.(*apiv3.CalicoNodeStatus)
			if !ok {
				return nil, fmt.Errorf("unexpected type for CalicoNodeStatus: %T", kvp.Value)
			}
			v3 := &apiv3.CalicoNodeStatus{
				TypeMeta:   newV3TypeMeta(apiv3.KindCalicoNodeStatus),
				ObjectMeta: metav1.ObjectMeta{Name: v1.Name},
				Spec:       *v1.Spec.DeepCopy(),
			}
			copyLabelsAndAnnotations(v1, v3)
			return v3, nil
		},
	})
}

// listV1IPAMBlocks lists v1 IPAMBlocks using BlockListOptions (since IPAMBlock
// can't be listed via ResourceListOptions), then converts the returned
// model.AllocationBlock values back to v3 IPAMBlock objects so they work with
// the generic MigrateResourceType function.
func listV1IPAMBlocks(ctx context.Context, bc api.Client) (*model.KVPairList, error) {
	v1List, err := bc.List(ctx, model.BlockListOptions{}, "")
	if err != nil {
		return nil, err
	}
	result := &model.KVPairList{
		KVPairs:  make([]*model.KVPair, 0, len(v1List.KVPairs)),
		Revision: v1List.Revision,
	}
	for _, kvp := range v1List.KVPairs {
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
			TypeMeta:   newV3TypeMeta(KindIPAMBlock),
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
		result.KVPairs = append(result.KVPairs, &model.KVPair{
			Key:      model.ResourceKey{Kind: KindIPAMBlock, Name: name},
			Value:    v3Block,
			Revision: kvp.Revision,
		})
	}
	return result, nil
}

// listV1IPAMHandles lists v1 IPAMHandles using IPAMHandleListOptions (since
// IPAMHandle can't be listed via ResourceListOptions), then converts the
// returned model.IPAMHandle values back to v3 IPAMHandle objects.
func listV1IPAMHandles(ctx context.Context, bc api.Client) (*model.KVPairList, error) {
	v1List, err := bc.List(ctx, model.IPAMHandleListOptions{}, "")
	if err != nil {
		return nil, err
	}
	result := &model.KVPairList{
		KVPairs:  make([]*model.KVPair, 0, len(v1List.KVPairs)),
		Revision: v1List.Revision,
	}
	for _, kvp := range v1List.KVPairs {
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
			TypeMeta:   newV3TypeMeta(KindIPAMHandle),
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
		result.KVPairs = append(result.KVPairs, &model.KVPair{
			Key:      model.ResourceKey{Kind: KindIPAMHandle, Name: name},
			Value:    v3Handle,
			Revision: kvp.Revision,
		})
	}
	return result, nil
}
