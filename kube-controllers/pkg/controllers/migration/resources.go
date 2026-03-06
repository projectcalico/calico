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
	"reflect"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/client/clientset_generated/clientset"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
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

// RegisterOSSResources registers all OSS resource migrators with the given v3 clientset.
func RegisterOSSResources(v3Client clientset.Interface) {
	pc := v3Client.ProjectcalicoV3()

	// 1. Tiers
	Register(ResourceMigrator{
		Kind:  apiv3.KindTier,
		Order: OrderTiers,
		ListV1: func(ctx context.Context, bc api.Client) (*model.KVPairList, error) {
			return listV1Resources(ctx, bc, apiv3.KindTier)
		},
		Convert: func(kvp *model.KVPair) (metav1.Object, error) {
			v1 := kvp.Value.(*apiv3.Tier)
			v3 := &apiv3.Tier{
				TypeMeta:   newV3TypeMeta(apiv3.KindTier),
				ObjectMeta: metav1.ObjectMeta{Name: v1.Name},
				Spec:       *v1.Spec.DeepCopy(),
			}
			copyLabelsAndAnnotations(v1, v3)
			return v3, nil
		},
		CreateV3: func(ctx context.Context, obj metav1.Object) error {
			_, err := pc.Tiers().Create(ctx, obj.(*apiv3.Tier), metav1.CreateOptions{})
			return err
		},
		GetV3: func(ctx context.Context, name, namespace string) (metav1.Object, error) {
			obj, err := pc.Tiers().Get(ctx, name, metav1.GetOptions{})
			if kerrors.IsNotFound(err) {
				return nil, nil
			}
			return obj, err
		},
		SpecsEqual: func(a, b metav1.Object) bool {
			return reflect.DeepEqual(a.(*apiv3.Tier).Spec, b.(*apiv3.Tier).Spec)
		},
	})

	// 2. FelixConfiguration
	Register(ResourceMigrator{
		Kind:  apiv3.KindFelixConfiguration,
		Order: OrderConfigSingletons,
		ListV1: func(ctx context.Context, bc api.Client) (*model.KVPairList, error) {
			return listV1Resources(ctx, bc, apiv3.KindFelixConfiguration)
		},
		Convert: func(kvp *model.KVPair) (metav1.Object, error) {
			v1 := kvp.Value.(*apiv3.FelixConfiguration)
			v3 := &apiv3.FelixConfiguration{
				TypeMeta:   newV3TypeMeta(apiv3.KindFelixConfiguration),
				ObjectMeta: metav1.ObjectMeta{Name: v1.Name},
				Spec:       *v1.Spec.DeepCopy(),
			}
			copyLabelsAndAnnotations(v1, v3)
			return v3, nil
		},
		CreateV3: func(ctx context.Context, obj metav1.Object) error {
			_, err := pc.FelixConfigurations().Create(ctx, obj.(*apiv3.FelixConfiguration), metav1.CreateOptions{})
			return err
		},
		GetV3: func(ctx context.Context, name, namespace string) (metav1.Object, error) {
			obj, err := pc.FelixConfigurations().Get(ctx, name, metav1.GetOptions{})
			if kerrors.IsNotFound(err) {
				return nil, nil
			}
			return obj, err
		},
		SpecsEqual: func(a, b metav1.Object) bool {
			return reflect.DeepEqual(a.(*apiv3.FelixConfiguration).Spec, b.(*apiv3.FelixConfiguration).Spec)
		},
	})

	// 3. BGPConfiguration
	Register(ResourceMigrator{
		Kind:  apiv3.KindBGPConfiguration,
		Order: OrderConfigSingletons,
		ListV1: func(ctx context.Context, bc api.Client) (*model.KVPairList, error) {
			return listV1Resources(ctx, bc, apiv3.KindBGPConfiguration)
		},
		Convert: func(kvp *model.KVPair) (metav1.Object, error) {
			v1 := kvp.Value.(*apiv3.BGPConfiguration)
			v3 := &apiv3.BGPConfiguration{
				TypeMeta:   newV3TypeMeta(apiv3.KindBGPConfiguration),
				ObjectMeta: metav1.ObjectMeta{Name: v1.Name},
				Spec:       *v1.Spec.DeepCopy(),
			}
			copyLabelsAndAnnotations(v1, v3)
			return v3, nil
		},
		CreateV3: func(ctx context.Context, obj metav1.Object) error {
			_, err := pc.BGPConfigurations().Create(ctx, obj.(*apiv3.BGPConfiguration), metav1.CreateOptions{})
			return err
		},
		GetV3: func(ctx context.Context, name, namespace string) (metav1.Object, error) {
			obj, err := pc.BGPConfigurations().Get(ctx, name, metav1.GetOptions{})
			if kerrors.IsNotFound(err) {
				return nil, nil
			}
			return obj, err
		},
		SpecsEqual: func(a, b metav1.Object) bool {
			return reflect.DeepEqual(a.(*apiv3.BGPConfiguration).Spec, b.(*apiv3.BGPConfiguration).Spec)
		},
	})

	// 4. KubeControllersConfiguration
	Register(ResourceMigrator{
		Kind:  apiv3.KindKubeControllersConfiguration,
		Order: OrderConfigSingletons,
		ListV1: func(ctx context.Context, bc api.Client) (*model.KVPairList, error) {
			return listV1Resources(ctx, bc, apiv3.KindKubeControllersConfiguration)
		},
		Convert: func(kvp *model.KVPair) (metav1.Object, error) {
			v1 := kvp.Value.(*apiv3.KubeControllersConfiguration)
			v3 := &apiv3.KubeControllersConfiguration{
				TypeMeta:   newV3TypeMeta(apiv3.KindKubeControllersConfiguration),
				ObjectMeta: metav1.ObjectMeta{Name: v1.Name},
				Spec:       *v1.Spec.DeepCopy(),
			}
			copyLabelsAndAnnotations(v1, v3)
			return v3, nil
		},
		CreateV3: func(ctx context.Context, obj metav1.Object) error {
			_, err := pc.KubeControllersConfigurations().Create(ctx, obj.(*apiv3.KubeControllersConfiguration), metav1.CreateOptions{})
			return err
		},
		GetV3: func(ctx context.Context, name, namespace string) (metav1.Object, error) {
			obj, err := pc.KubeControllersConfigurations().Get(ctx, name, metav1.GetOptions{})
			if kerrors.IsNotFound(err) {
				return nil, nil
			}
			return obj, err
		},
		SpecsEqual: func(a, b metav1.Object) bool {
			return reflect.DeepEqual(a.(*apiv3.KubeControllersConfiguration).Spec, b.(*apiv3.KubeControllersConfiguration).Spec)
		},
	})

	// 5. IPPool
	Register(ResourceMigrator{
		Kind:  apiv3.KindIPPool,
		Order: OrderNetworkInfra,
		ListV1: func(ctx context.Context, bc api.Client) (*model.KVPairList, error) {
			return listV1Resources(ctx, bc, apiv3.KindIPPool)
		},
		Convert: func(kvp *model.KVPair) (metav1.Object, error) {
			v1 := kvp.Value.(*apiv3.IPPool)
			v3 := &apiv3.IPPool{
				TypeMeta:   newV3TypeMeta(apiv3.KindIPPool),
				ObjectMeta: metav1.ObjectMeta{Name: v1.Name},
				Spec:       *v1.Spec.DeepCopy(),
			}
			copyLabelsAndAnnotations(v1, v3)
			return v3, nil
		},
		CreateV3: func(ctx context.Context, obj metav1.Object) error {
			_, err := pc.IPPools().Create(ctx, obj.(*apiv3.IPPool), metav1.CreateOptions{})
			return err
		},
		GetV3: func(ctx context.Context, name, namespace string) (metav1.Object, error) {
			obj, err := pc.IPPools().Get(ctx, name, metav1.GetOptions{})
			if kerrors.IsNotFound(err) {
				return nil, nil
			}
			return obj, err
		},
		SpecsEqual: func(a, b metav1.Object) bool {
			return reflect.DeepEqual(a.(*apiv3.IPPool).Spec, b.(*apiv3.IPPool).Spec)
		},
	})

	// 6. IPReservation
	Register(ResourceMigrator{
		Kind:  apiv3.KindIPReservation,
		Order: OrderNetworkInfra,
		ListV1: func(ctx context.Context, bc api.Client) (*model.KVPairList, error) {
			return listV1Resources(ctx, bc, apiv3.KindIPReservation)
		},
		Convert: func(kvp *model.KVPair) (metav1.Object, error) {
			v1 := kvp.Value.(*apiv3.IPReservation)
			v3 := &apiv3.IPReservation{
				TypeMeta:   newV3TypeMeta(apiv3.KindIPReservation),
				ObjectMeta: metav1.ObjectMeta{Name: v1.Name},
				Spec:       *v1.Spec.DeepCopy(),
			}
			copyLabelsAndAnnotations(v1, v3)
			return v3, nil
		},
		CreateV3: func(ctx context.Context, obj metav1.Object) error {
			_, err := pc.IPReservations().Create(ctx, obj.(*apiv3.IPReservation), metav1.CreateOptions{})
			return err
		},
		GetV3: func(ctx context.Context, name, namespace string) (metav1.Object, error) {
			obj, err := pc.IPReservations().Get(ctx, name, metav1.GetOptions{})
			if kerrors.IsNotFound(err) {
				return nil, nil
			}
			return obj, err
		},
		SpecsEqual: func(a, b metav1.Object) bool {
			return reflect.DeepEqual(a.(*apiv3.IPReservation).Spec, b.(*apiv3.IPReservation).Spec)
		},
	})

	// 7. BGPPeer
	Register(ResourceMigrator{
		Kind:  apiv3.KindBGPPeer,
		Order: OrderNetworkInfra,
		ListV1: func(ctx context.Context, bc api.Client) (*model.KVPairList, error) {
			return listV1Resources(ctx, bc, apiv3.KindBGPPeer)
		},
		Convert: func(kvp *model.KVPair) (metav1.Object, error) {
			v1 := kvp.Value.(*apiv3.BGPPeer)
			v3 := &apiv3.BGPPeer{
				TypeMeta:   newV3TypeMeta(apiv3.KindBGPPeer),
				ObjectMeta: metav1.ObjectMeta{Name: v1.Name},
				Spec:       *v1.Spec.DeepCopy(),
			}
			copyLabelsAndAnnotations(v1, v3)
			return v3, nil
		},
		CreateV3: func(ctx context.Context, obj metav1.Object) error {
			_, err := pc.BGPPeers().Create(ctx, obj.(*apiv3.BGPPeer), metav1.CreateOptions{})
			return err
		},
		GetV3: func(ctx context.Context, name, namespace string) (metav1.Object, error) {
			obj, err := pc.BGPPeers().Get(ctx, name, metav1.GetOptions{})
			if kerrors.IsNotFound(err) {
				return nil, nil
			}
			return obj, err
		},
		SpecsEqual: func(a, b metav1.Object) bool {
			return reflect.DeepEqual(a.(*apiv3.BGPPeer).Spec, b.(*apiv3.BGPPeer).Spec)
		},
	})

	// 8. BGPFilter
	Register(ResourceMigrator{
		Kind:  apiv3.KindBGPFilter,
		Order: OrderNetworkInfra,
		ListV1: func(ctx context.Context, bc api.Client) (*model.KVPairList, error) {
			return listV1Resources(ctx, bc, apiv3.KindBGPFilter)
		},
		Convert: func(kvp *model.KVPair) (metav1.Object, error) {
			v1 := kvp.Value.(*apiv3.BGPFilter)
			v3 := &apiv3.BGPFilter{
				TypeMeta:   newV3TypeMeta(apiv3.KindBGPFilter),
				ObjectMeta: metav1.ObjectMeta{Name: v1.Name},
				Spec:       *v1.Spec.DeepCopy(),
			}
			copyLabelsAndAnnotations(v1, v3)
			return v3, nil
		},
		CreateV3: func(ctx context.Context, obj metav1.Object) error {
			_, err := pc.BGPFilters().Create(ctx, obj.(*apiv3.BGPFilter), metav1.CreateOptions{})
			return err
		},
		GetV3: func(ctx context.Context, name, namespace string) (metav1.Object, error) {
			obj, err := pc.BGPFilters().Get(ctx, name, metav1.GetOptions{})
			if kerrors.IsNotFound(err) {
				return nil, nil
			}
			return obj, err
		},
		SpecsEqual: func(a, b metav1.Object) bool {
			return reflect.DeepEqual(a.(*apiv3.BGPFilter).Spec, b.(*apiv3.BGPFilter).Spec)
		},
	})

	// 9. GlobalNetworkPolicy (with policy name migration)
	Register(ResourceMigrator{
		Kind:  apiv3.KindGlobalNetworkPolicy,
		Order: OrderPolicy,
		ListV1: func(ctx context.Context, bc api.Client) (*model.KVPairList, error) {
			return listV1Resources(ctx, bc, apiv3.KindGlobalNetworkPolicy)
		},
		Convert: func(kvp *model.KVPair) (metav1.Object, error) {
			v1 := kvp.Value.(*apiv3.GlobalNetworkPolicy)
			name := migratedPolicyName(v1.Name, v1.Spec.Tier)
			v3 := &apiv3.GlobalNetworkPolicy{
				TypeMeta:   newV3TypeMeta(apiv3.KindGlobalNetworkPolicy),
				ObjectMeta: metav1.ObjectMeta{Name: name},
				Spec:       *v1.Spec.DeepCopy(),
			}
			copyLabelsAndAnnotations(v1, v3)
			return v3, nil
		},
		CreateV3: func(ctx context.Context, obj metav1.Object) error {
			_, err := pc.GlobalNetworkPolicies().Create(ctx, obj.(*apiv3.GlobalNetworkPolicy), metav1.CreateOptions{})
			return err
		},
		GetV3: func(ctx context.Context, name, namespace string) (metav1.Object, error) {
			obj, err := pc.GlobalNetworkPolicies().Get(ctx, name, metav1.GetOptions{})
			if kerrors.IsNotFound(err) {
				return nil, nil
			}
			return obj, err
		},
		SpecsEqual: func(a, b metav1.Object) bool {
			return reflect.DeepEqual(a.(*apiv3.GlobalNetworkPolicy).Spec, b.(*apiv3.GlobalNetworkPolicy).Spec)
		},
	})

	// 10. NetworkPolicy (namespaced, with policy name migration)
	Register(ResourceMigrator{
		Kind:       apiv3.KindNetworkPolicy,
		Namespaced: true,
		Order:      OrderPolicy,
		ListV1: func(ctx context.Context, bc api.Client) (*model.KVPairList, error) {
			return listV1NamespacedResources(ctx, bc, apiv3.KindNetworkPolicy)
		},
		Convert: func(kvp *model.KVPair) (metav1.Object, error) {
			v1 := kvp.Value.(*apiv3.NetworkPolicy)
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
		CreateV3: func(ctx context.Context, obj metav1.Object) error {
			np := obj.(*apiv3.NetworkPolicy)
			_, err := pc.NetworkPolicies(np.Namespace).Create(ctx, np, metav1.CreateOptions{})
			return err
		},
		GetV3: func(ctx context.Context, name, namespace string) (metav1.Object, error) {
			obj, err := pc.NetworkPolicies(namespace).Get(ctx, name, metav1.GetOptions{})
			if kerrors.IsNotFound(err) {
				return nil, nil
			}
			return obj, err
		},
		SpecsEqual: func(a, b metav1.Object) bool {
			return reflect.DeepEqual(a.(*apiv3.NetworkPolicy).Spec, b.(*apiv3.NetworkPolicy).Spec)
		},
	})

	// 11. StagedGlobalNetworkPolicy (with policy name migration)
	Register(ResourceMigrator{
		Kind:  apiv3.KindStagedGlobalNetworkPolicy,
		Order: OrderPolicy,
		ListV1: func(ctx context.Context, bc api.Client) (*model.KVPairList, error) {
			return listV1Resources(ctx, bc, apiv3.KindStagedGlobalNetworkPolicy)
		},
		Convert: func(kvp *model.KVPair) (metav1.Object, error) {
			v1 := kvp.Value.(*apiv3.StagedGlobalNetworkPolicy)
			name := migratedPolicyName(v1.Name, v1.Spec.Tier)
			v3 := &apiv3.StagedGlobalNetworkPolicy{
				TypeMeta:   newV3TypeMeta(apiv3.KindStagedGlobalNetworkPolicy),
				ObjectMeta: metav1.ObjectMeta{Name: name},
				Spec:       *v1.Spec.DeepCopy(),
			}
			copyLabelsAndAnnotations(v1, v3)
			return v3, nil
		},
		CreateV3: func(ctx context.Context, obj metav1.Object) error {
			_, err := pc.StagedGlobalNetworkPolicies().Create(ctx, obj.(*apiv3.StagedGlobalNetworkPolicy), metav1.CreateOptions{})
			return err
		},
		GetV3: func(ctx context.Context, name, namespace string) (metav1.Object, error) {
			obj, err := pc.StagedGlobalNetworkPolicies().Get(ctx, name, metav1.GetOptions{})
			if kerrors.IsNotFound(err) {
				return nil, nil
			}
			return obj, err
		},
		SpecsEqual: func(a, b metav1.Object) bool {
			return reflect.DeepEqual(a.(*apiv3.StagedGlobalNetworkPolicy).Spec, b.(*apiv3.StagedGlobalNetworkPolicy).Spec)
		},
	})

	// 12. StagedNetworkPolicy (namespaced, with policy name migration)
	Register(ResourceMigrator{
		Kind:       apiv3.KindStagedNetworkPolicy,
		Namespaced: true,
		Order:      OrderPolicy,
		ListV1: func(ctx context.Context, bc api.Client) (*model.KVPairList, error) {
			return listV1NamespacedResources(ctx, bc, apiv3.KindStagedNetworkPolicy)
		},
		Convert: func(kvp *model.KVPair) (metav1.Object, error) {
			v1 := kvp.Value.(*apiv3.StagedNetworkPolicy)
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
		CreateV3: func(ctx context.Context, obj metav1.Object) error {
			snp := obj.(*apiv3.StagedNetworkPolicy)
			_, err := pc.StagedNetworkPolicies(snp.Namespace).Create(ctx, snp, metav1.CreateOptions{})
			return err
		},
		GetV3: func(ctx context.Context, name, namespace string) (metav1.Object, error) {
			obj, err := pc.StagedNetworkPolicies(namespace).Get(ctx, name, metav1.GetOptions{})
			if kerrors.IsNotFound(err) {
				return nil, nil
			}
			return obj, err
		},
		SpecsEqual: func(a, b metav1.Object) bool {
			return reflect.DeepEqual(a.(*apiv3.StagedNetworkPolicy).Spec, b.(*apiv3.StagedNetworkPolicy).Spec)
		},
	})

	// 13. StagedKubernetesNetworkPolicy (namespaced)
	Register(ResourceMigrator{
		Kind:       apiv3.KindStagedKubernetesNetworkPolicy,
		Namespaced: true,
		Order:      OrderPolicy,
		ListV1: func(ctx context.Context, bc api.Client) (*model.KVPairList, error) {
			return listV1NamespacedResources(ctx, bc, apiv3.KindStagedKubernetesNetworkPolicy)
		},
		Convert: func(kvp *model.KVPair) (metav1.Object, error) {
			v1 := kvp.Value.(*apiv3.StagedKubernetesNetworkPolicy)
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
		CreateV3: func(ctx context.Context, obj metav1.Object) error {
			sknp := obj.(*apiv3.StagedKubernetesNetworkPolicy)
			_, err := pc.StagedKubernetesNetworkPolicies(sknp.Namespace).Create(ctx, sknp, metav1.CreateOptions{})
			return err
		},
		GetV3: func(ctx context.Context, name, namespace string) (metav1.Object, error) {
			obj, err := pc.StagedKubernetesNetworkPolicies(namespace).Get(ctx, name, metav1.GetOptions{})
			if kerrors.IsNotFound(err) {
				return nil, nil
			}
			return obj, err
		},
		SpecsEqual: func(a, b metav1.Object) bool {
			return reflect.DeepEqual(a.(*apiv3.StagedKubernetesNetworkPolicy).Spec, b.(*apiv3.StagedKubernetesNetworkPolicy).Spec)
		},
	})

	// 14. HostEndpoint
	Register(ResourceMigrator{
		Kind:  apiv3.KindHostEndpoint,
		Order: OrderEndpointsAndSets,
		ListV1: func(ctx context.Context, bc api.Client) (*model.KVPairList, error) {
			return listV1Resources(ctx, bc, apiv3.KindHostEndpoint)
		},
		Convert: func(kvp *model.KVPair) (metav1.Object, error) {
			v1 := kvp.Value.(*apiv3.HostEndpoint)
			v3 := &apiv3.HostEndpoint{
				TypeMeta:   newV3TypeMeta(apiv3.KindHostEndpoint),
				ObjectMeta: metav1.ObjectMeta{Name: v1.Name},
				Spec:       *v1.Spec.DeepCopy(),
			}
			copyLabelsAndAnnotations(v1, v3)
			return v3, nil
		},
		CreateV3: func(ctx context.Context, obj metav1.Object) error {
			_, err := pc.HostEndpoints().Create(ctx, obj.(*apiv3.HostEndpoint), metav1.CreateOptions{})
			return err
		},
		GetV3: func(ctx context.Context, name, namespace string) (metav1.Object, error) {
			obj, err := pc.HostEndpoints().Get(ctx, name, metav1.GetOptions{})
			if kerrors.IsNotFound(err) {
				return nil, nil
			}
			return obj, err
		},
		SpecsEqual: func(a, b metav1.Object) bool {
			return reflect.DeepEqual(a.(*apiv3.HostEndpoint).Spec, b.(*apiv3.HostEndpoint).Spec)
		},
	})

	// 15. GlobalNetworkSet
	Register(ResourceMigrator{
		Kind:  apiv3.KindGlobalNetworkSet,
		Order: OrderEndpointsAndSets,
		ListV1: func(ctx context.Context, bc api.Client) (*model.KVPairList, error) {
			return listV1Resources(ctx, bc, apiv3.KindGlobalNetworkSet)
		},
		Convert: func(kvp *model.KVPair) (metav1.Object, error) {
			v1 := kvp.Value.(*apiv3.GlobalNetworkSet)
			v3 := &apiv3.GlobalNetworkSet{
				TypeMeta:   newV3TypeMeta(apiv3.KindGlobalNetworkSet),
				ObjectMeta: metav1.ObjectMeta{Name: v1.Name},
				Spec:       *v1.Spec.DeepCopy(),
			}
			copyLabelsAndAnnotations(v1, v3)
			return v3, nil
		},
		CreateV3: func(ctx context.Context, obj metav1.Object) error {
			_, err := pc.GlobalNetworkSets().Create(ctx, obj.(*apiv3.GlobalNetworkSet), metav1.CreateOptions{})
			return err
		},
		GetV3: func(ctx context.Context, name, namespace string) (metav1.Object, error) {
			obj, err := pc.GlobalNetworkSets().Get(ctx, name, metav1.GetOptions{})
			if kerrors.IsNotFound(err) {
				return nil, nil
			}
			return obj, err
		},
		SpecsEqual: func(a, b metav1.Object) bool {
			return reflect.DeepEqual(a.(*apiv3.GlobalNetworkSet).Spec, b.(*apiv3.GlobalNetworkSet).Spec)
		},
	})

	// 16. NetworkSet (namespaced)
	Register(ResourceMigrator{
		Kind:       apiv3.KindNetworkSet,
		Namespaced: true,
		Order:      OrderEndpointsAndSets,
		ListV1: func(ctx context.Context, bc api.Client) (*model.KVPairList, error) {
			return listV1NamespacedResources(ctx, bc, apiv3.KindNetworkSet)
		},
		Convert: func(kvp *model.KVPair) (metav1.Object, error) {
			v1 := kvp.Value.(*apiv3.NetworkSet)
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
		CreateV3: func(ctx context.Context, obj metav1.Object) error {
			ns := obj.(*apiv3.NetworkSet)
			_, err := pc.NetworkSets(ns.Namespace).Create(ctx, ns, metav1.CreateOptions{})
			return err
		},
		GetV3: func(ctx context.Context, name, namespace string) (metav1.Object, error) {
			obj, err := pc.NetworkSets(namespace).Get(ctx, name, metav1.GetOptions{})
			if kerrors.IsNotFound(err) {
				return nil, nil
			}
			return obj, err
		},
		SpecsEqual: func(a, b metav1.Object) bool {
			return reflect.DeepEqual(a.(*apiv3.NetworkSet).Spec, b.(*apiv3.NetworkSet).Spec)
		},
	})

	// 17. IPAMConfiguration (v1 is "IPAMConfig", v3 is "IPAMConfiguration")
	Register(ResourceMigrator{
		Kind:  apiv3.KindIPAMConfiguration,
		Order: OrderIPAM,
		ListV1: func(ctx context.Context, bc api.Client) (*model.KVPairList, error) {
			return listV1Resources(ctx, bc, apiv3.KindIPAMConfiguration)
		},
		Convert: func(kvp *model.KVPair) (metav1.Object, error) {
			v1 := kvp.Value.(*apiv3.IPAMConfiguration)
			v3 := &apiv3.IPAMConfiguration{
				TypeMeta:   newV3TypeMeta(apiv3.KindIPAMConfiguration),
				ObjectMeta: metav1.ObjectMeta{Name: v1.Name},
				Spec:       *v1.Spec.DeepCopy(),
			}
			copyLabelsAndAnnotations(v1, v3)
			return v3, nil
		},
		CreateV3: func(ctx context.Context, obj metav1.Object) error {
			_, err := pc.IPAMConfigurations().Create(ctx, obj.(*apiv3.IPAMConfiguration), metav1.CreateOptions{})
			return err
		},
		GetV3: func(ctx context.Context, name, namespace string) (metav1.Object, error) {
			obj, err := pc.IPAMConfigurations().Get(ctx, name, metav1.GetOptions{})
			if kerrors.IsNotFound(err) {
				return nil, nil
			}
			return obj, err
		},
		SpecsEqual: func(a, b metav1.Object) bool {
			return reflect.DeepEqual(a.(*apiv3.IPAMConfiguration).Spec, b.(*apiv3.IPAMConfiguration).Spec)
		},
	})

	// 18. BlockAffinity (IPAM)
	Register(ResourceMigrator{
		Kind:  apiv3.KindBlockAffinity,
		Order: OrderIPAM,
		ListV1: func(ctx context.Context, bc api.Client) (*model.KVPairList, error) {
			return listV1Resources(ctx, bc, apiv3.KindBlockAffinity)
		},
		Convert: func(kvp *model.KVPair) (metav1.Object, error) {
			v1 := kvp.Value.(*apiv3.BlockAffinity)
			v3 := &apiv3.BlockAffinity{
				TypeMeta:   newV3TypeMeta(apiv3.KindBlockAffinity),
				ObjectMeta: metav1.ObjectMeta{Name: v1.Name},
				Spec:       *v1.Spec.DeepCopy(),
			}
			copyLabelsAndAnnotations(v1, v3)
			return v3, nil
		},
		CreateV3: func(ctx context.Context, obj metav1.Object) error {
			_, err := pc.BlockAffinities().Create(ctx, obj.(*apiv3.BlockAffinity), metav1.CreateOptions{})
			return err
		},
		GetV3: func(ctx context.Context, name, namespace string) (metav1.Object, error) {
			obj, err := pc.BlockAffinities().Get(ctx, name, metav1.GetOptions{})
			if kerrors.IsNotFound(err) {
				return nil, nil
			}
			return obj, err
		},
		SpecsEqual: func(a, b metav1.Object) bool {
			return reflect.DeepEqual(a.(*apiv3.BlockAffinity).Spec, b.(*apiv3.BlockAffinity).Spec)
		},
	})

	// 19. IPAMBlock (IPAM)
	Register(ResourceMigrator{
		Kind:  KindIPAMBlock,
		Order: OrderIPAM,
		ListV1: func(ctx context.Context, bc api.Client) (*model.KVPairList, error) {
			return listV1Resources(ctx, bc, KindIPAMBlock)
		},
		Convert: func(kvp *model.KVPair) (metav1.Object, error) {
			v1 := kvp.Value.(*apiv3.IPAMBlock)
			v3 := &apiv3.IPAMBlock{
				TypeMeta:   newV3TypeMeta(KindIPAMBlock),
				ObjectMeta: metav1.ObjectMeta{Name: v1.Name},
				Spec:       *v1.Spec.DeepCopy(),
			}
			copyLabelsAndAnnotations(v1, v3)
			return v3, nil
		},
		CreateV3: func(ctx context.Context, obj metav1.Object) error {
			_, err := pc.IPAMBlocks().Create(ctx, obj.(*apiv3.IPAMBlock), metav1.CreateOptions{})
			return err
		},
		GetV3: func(ctx context.Context, name, namespace string) (metav1.Object, error) {
			obj, err := pc.IPAMBlocks().Get(ctx, name, metav1.GetOptions{})
			if kerrors.IsNotFound(err) {
				return nil, nil
			}
			return obj, err
		},
		SpecsEqual: func(a, b metav1.Object) bool {
			return reflect.DeepEqual(a.(*apiv3.IPAMBlock).Spec, b.(*apiv3.IPAMBlock).Spec)
		},
	})

	// 20. IPAMHandle (IPAM)
	Register(ResourceMigrator{
		Kind:  KindIPAMHandle,
		Order: OrderIPAM,
		ListV1: func(ctx context.Context, bc api.Client) (*model.KVPairList, error) {
			return listV1Resources(ctx, bc, KindIPAMHandle)
		},
		Convert: func(kvp *model.KVPair) (metav1.Object, error) {
			v1 := kvp.Value.(*apiv3.IPAMHandle)
			v3 := &apiv3.IPAMHandle{
				TypeMeta:   newV3TypeMeta(KindIPAMHandle),
				ObjectMeta: metav1.ObjectMeta{Name: v1.Name},
				Spec:       *v1.Spec.DeepCopy(),
			}
			copyLabelsAndAnnotations(v1, v3)
			return v3, nil
		},
		CreateV3: func(ctx context.Context, obj metav1.Object) error {
			_, err := pc.IPAMHandles(obj.GetNamespace()).Create(ctx, obj.(*apiv3.IPAMHandle), metav1.CreateOptions{})
			return err
		},
		GetV3: func(ctx context.Context, name, namespace string) (metav1.Object, error) {
			obj, err := pc.IPAMHandles(namespace).Get(ctx, name, metav1.GetOptions{})
			if kerrors.IsNotFound(err) {
				return nil, nil
			}
			return obj, err
		},
		SpecsEqual: func(a, b metav1.Object) bool {
			return reflect.DeepEqual(a.(*apiv3.IPAMHandle).Spec, b.(*apiv3.IPAMHandle).Spec)
		},
	})

	// 21. CalicoNodeStatus
	Register(ResourceMigrator{
		Kind:  apiv3.KindCalicoNodeStatus,
		Order: OrderCalicoNodeStatus,
		ListV1: func(ctx context.Context, bc api.Client) (*model.KVPairList, error) {
			return listV1Resources(ctx, bc, apiv3.KindCalicoNodeStatus)
		},
		Convert: func(kvp *model.KVPair) (metav1.Object, error) {
			v1 := kvp.Value.(*apiv3.CalicoNodeStatus)
			v3 := &apiv3.CalicoNodeStatus{
				TypeMeta:   newV3TypeMeta(apiv3.KindCalicoNodeStatus),
				ObjectMeta: metav1.ObjectMeta{Name: v1.Name},
				Spec:       *v1.Spec.DeepCopy(),
			}
			copyLabelsAndAnnotations(v1, v3)
			return v3, nil
		},
		CreateV3: func(ctx context.Context, obj metav1.Object) error {
			_, err := pc.CalicoNodeStatuses().Create(ctx, obj.(*apiv3.CalicoNodeStatus), metav1.CreateOptions{})
			return err
		},
		GetV3: func(ctx context.Context, name, namespace string) (metav1.Object, error) {
			obj, err := pc.CalicoNodeStatuses().Get(ctx, name, metav1.GetOptions{})
			if kerrors.IsNotFound(err) {
				return nil, nil
			}
			return obj, err
		},
		SpecsEqual: func(a, b metav1.Object) bool {
			return reflect.DeepEqual(a.(*apiv3.CalicoNodeStatus).Spec, b.(*apiv3.CalicoNodeStatus).Spec)
		},
	})
}

// convertClusterInformation converts a v1 ClusterInformation to a v3 object,
// but does NOT set DatastoreReady — that is handled specially by the controller.
func convertClusterInformation(kvp *model.KVPair) (*apiv3.ClusterInformation, error) {
	v1, ok := kvp.Value.(*apiv3.ClusterInformation)
	if !ok {
		return nil, fmt.Errorf("expected *apiv3.ClusterInformation, got %T", kvp.Value)
	}
	v3 := &apiv3.ClusterInformation{
		TypeMeta:   newV3TypeMeta(apiv3.KindClusterInformation),
		ObjectMeta: metav1.ObjectMeta{Name: v1.Name},
		Spec:       *v1.Spec.DeepCopy(),
	}
	copyLabelsAndAnnotations(v1, v3)
	return v3, nil
}
