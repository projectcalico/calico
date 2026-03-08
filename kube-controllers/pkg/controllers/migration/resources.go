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
		ListV3: func(ctx context.Context) ([]metav1.Object, error) {
			list, err := pc.Tiers().List(ctx, metav1.ListOptions{})
			if err != nil {
				return nil, err
			}
			result := make([]metav1.Object, len(list.Items))
			for i := range list.Items {
				result[i] = &list.Items[i]
			}
			return result, nil
		},
		UpdateV3: func(ctx context.Context, obj metav1.Object) error {
			_, err := pc.Tiers().Update(ctx, obj.(*apiv3.Tier), metav1.UpdateOptions{})
			return err
		},
		DeleteV3: func(ctx context.Context, name, namespace string) error {
			return pc.Tiers().Delete(ctx, name, metav1.DeleteOptions{})
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
		ListV3: func(ctx context.Context) ([]metav1.Object, error) {
			list, err := pc.FelixConfigurations().List(ctx, metav1.ListOptions{})
			if err != nil {
				return nil, err
			}
			result := make([]metav1.Object, len(list.Items))
			for i := range list.Items {
				result[i] = &list.Items[i]
			}
			return result, nil
		},
		UpdateV3: func(ctx context.Context, obj metav1.Object) error {
			_, err := pc.FelixConfigurations().Update(ctx, obj.(*apiv3.FelixConfiguration), metav1.UpdateOptions{})
			return err
		},
		DeleteV3: func(ctx context.Context, name, namespace string) error {
			return pc.FelixConfigurations().Delete(ctx, name, metav1.DeleteOptions{})
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
		ListV3: func(ctx context.Context) ([]metav1.Object, error) {
			list, err := pc.BGPConfigurations().List(ctx, metav1.ListOptions{})
			if err != nil {
				return nil, err
			}
			result := make([]metav1.Object, len(list.Items))
			for i := range list.Items {
				result[i] = &list.Items[i]
			}
			return result, nil
		},
		UpdateV3: func(ctx context.Context, obj metav1.Object) error {
			_, err := pc.BGPConfigurations().Update(ctx, obj.(*apiv3.BGPConfiguration), metav1.UpdateOptions{})
			return err
		},
		DeleteV3: func(ctx context.Context, name, namespace string) error {
			return pc.BGPConfigurations().Delete(ctx, name, metav1.DeleteOptions{})
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
		ListV3: func(ctx context.Context) ([]metav1.Object, error) {
			list, err := pc.KubeControllersConfigurations().List(ctx, metav1.ListOptions{})
			if err != nil {
				return nil, err
			}
			result := make([]metav1.Object, len(list.Items))
			for i := range list.Items {
				result[i] = &list.Items[i]
			}
			return result, nil
		},
		UpdateV3: func(ctx context.Context, obj metav1.Object) error {
			_, err := pc.KubeControllersConfigurations().Update(ctx, obj.(*apiv3.KubeControllersConfiguration), metav1.UpdateOptions{})
			return err
		},
		DeleteV3: func(ctx context.Context, name, namespace string) error {
			return pc.KubeControllersConfigurations().Delete(ctx, name, metav1.DeleteOptions{})
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
		ListV3: func(ctx context.Context) ([]metav1.Object, error) {
			list, err := pc.IPPools().List(ctx, metav1.ListOptions{})
			if err != nil {
				return nil, err
			}
			result := make([]metav1.Object, len(list.Items))
			for i := range list.Items {
				result[i] = &list.Items[i]
			}
			return result, nil
		},
		UpdateV3: func(ctx context.Context, obj metav1.Object) error {
			_, err := pc.IPPools().Update(ctx, obj.(*apiv3.IPPool), metav1.UpdateOptions{})
			return err
		},
		DeleteV3: func(ctx context.Context, name, namespace string) error {
			return pc.IPPools().Delete(ctx, name, metav1.DeleteOptions{})
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
		ListV3: func(ctx context.Context) ([]metav1.Object, error) {
			list, err := pc.IPReservations().List(ctx, metav1.ListOptions{})
			if err != nil {
				return nil, err
			}
			result := make([]metav1.Object, len(list.Items))
			for i := range list.Items {
				result[i] = &list.Items[i]
			}
			return result, nil
		},
		UpdateV3: func(ctx context.Context, obj metav1.Object) error {
			_, err := pc.IPReservations().Update(ctx, obj.(*apiv3.IPReservation), metav1.UpdateOptions{})
			return err
		},
		DeleteV3: func(ctx context.Context, name, namespace string) error {
			return pc.IPReservations().Delete(ctx, name, metav1.DeleteOptions{})
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
		ListV3: func(ctx context.Context) ([]metav1.Object, error) {
			list, err := pc.BGPPeers().List(ctx, metav1.ListOptions{})
			if err != nil {
				return nil, err
			}
			result := make([]metav1.Object, len(list.Items))
			for i := range list.Items {
				result[i] = &list.Items[i]
			}
			return result, nil
		},
		UpdateV3: func(ctx context.Context, obj metav1.Object) error {
			_, err := pc.BGPPeers().Update(ctx, obj.(*apiv3.BGPPeer), metav1.UpdateOptions{})
			return err
		},
		DeleteV3: func(ctx context.Context, name, namespace string) error {
			return pc.BGPPeers().Delete(ctx, name, metav1.DeleteOptions{})
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
		ListV3: func(ctx context.Context) ([]metav1.Object, error) {
			list, err := pc.BGPFilters().List(ctx, metav1.ListOptions{})
			if err != nil {
				return nil, err
			}
			result := make([]metav1.Object, len(list.Items))
			for i := range list.Items {
				result[i] = &list.Items[i]
			}
			return result, nil
		},
		UpdateV3: func(ctx context.Context, obj metav1.Object) error {
			_, err := pc.BGPFilters().Update(ctx, obj.(*apiv3.BGPFilter), metav1.UpdateOptions{})
			return err
		},
		DeleteV3: func(ctx context.Context, name, namespace string) error {
			return pc.BGPFilters().Delete(ctx, name, metav1.DeleteOptions{})
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
		ListV3: func(ctx context.Context) ([]metav1.Object, error) {
			list, err := pc.GlobalNetworkPolicies().List(ctx, metav1.ListOptions{})
			if err != nil {
				return nil, err
			}
			result := make([]metav1.Object, len(list.Items))
			for i := range list.Items {
				result[i] = &list.Items[i]
			}
			return result, nil
		},
		UpdateV3: func(ctx context.Context, obj metav1.Object) error {
			_, err := pc.GlobalNetworkPolicies().Update(ctx, obj.(*apiv3.GlobalNetworkPolicy), metav1.UpdateOptions{})
			return err
		},
		DeleteV3: func(ctx context.Context, name, namespace string) error {
			return pc.GlobalNetworkPolicies().Delete(ctx, name, metav1.DeleteOptions{})
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
		ListV3: func(ctx context.Context) ([]metav1.Object, error) {
			list, err := pc.NetworkPolicies("").List(ctx, metav1.ListOptions{})
			if err != nil {
				return nil, err
			}
			result := make([]metav1.Object, len(list.Items))
			for i := range list.Items {
				result[i] = &list.Items[i]
			}
			return result, nil
		},
		UpdateV3: func(ctx context.Context, obj metav1.Object) error {
			t := obj.(*apiv3.NetworkPolicy)
			_, err := pc.NetworkPolicies(t.Namespace).Update(ctx, t, metav1.UpdateOptions{})
			return err
		},
		DeleteV3: func(ctx context.Context, name, namespace string) error {
			return pc.NetworkPolicies(namespace).Delete(ctx, name, metav1.DeleteOptions{})
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
		ListV3: func(ctx context.Context) ([]metav1.Object, error) {
			list, err := pc.StagedGlobalNetworkPolicies().List(ctx, metav1.ListOptions{})
			if err != nil {
				return nil, err
			}
			result := make([]metav1.Object, len(list.Items))
			for i := range list.Items {
				result[i] = &list.Items[i]
			}
			return result, nil
		},
		UpdateV3: func(ctx context.Context, obj metav1.Object) error {
			_, err := pc.StagedGlobalNetworkPolicies().Update(ctx, obj.(*apiv3.StagedGlobalNetworkPolicy), metav1.UpdateOptions{})
			return err
		},
		DeleteV3: func(ctx context.Context, name, namespace string) error {
			return pc.StagedGlobalNetworkPolicies().Delete(ctx, name, metav1.DeleteOptions{})
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
		ListV3: func(ctx context.Context) ([]metav1.Object, error) {
			list, err := pc.StagedNetworkPolicies("").List(ctx, metav1.ListOptions{})
			if err != nil {
				return nil, err
			}
			result := make([]metav1.Object, len(list.Items))
			for i := range list.Items {
				result[i] = &list.Items[i]
			}
			return result, nil
		},
		UpdateV3: func(ctx context.Context, obj metav1.Object) error {
			t := obj.(*apiv3.StagedNetworkPolicy)
			_, err := pc.StagedNetworkPolicies(t.Namespace).Update(ctx, t, metav1.UpdateOptions{})
			return err
		},
		DeleteV3: func(ctx context.Context, name, namespace string) error {
			return pc.StagedNetworkPolicies(namespace).Delete(ctx, name, metav1.DeleteOptions{})
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
		ListV3: func(ctx context.Context) ([]metav1.Object, error) {
			list, err := pc.StagedKubernetesNetworkPolicies("").List(ctx, metav1.ListOptions{})
			if err != nil {
				return nil, err
			}
			result := make([]metav1.Object, len(list.Items))
			for i := range list.Items {
				result[i] = &list.Items[i]
			}
			return result, nil
		},
		UpdateV3: func(ctx context.Context, obj metav1.Object) error {
			t := obj.(*apiv3.StagedKubernetesNetworkPolicy)
			_, err := pc.StagedKubernetesNetworkPolicies(t.Namespace).Update(ctx, t, metav1.UpdateOptions{})
			return err
		},
		DeleteV3: func(ctx context.Context, name, namespace string) error {
			return pc.StagedKubernetesNetworkPolicies(namespace).Delete(ctx, name, metav1.DeleteOptions{})
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
		ListV3: func(ctx context.Context) ([]metav1.Object, error) {
			list, err := pc.HostEndpoints().List(ctx, metav1.ListOptions{})
			if err != nil {
				return nil, err
			}
			result := make([]metav1.Object, len(list.Items))
			for i := range list.Items {
				result[i] = &list.Items[i]
			}
			return result, nil
		},
		UpdateV3: func(ctx context.Context, obj metav1.Object) error {
			_, err := pc.HostEndpoints().Update(ctx, obj.(*apiv3.HostEndpoint), metav1.UpdateOptions{})
			return err
		},
		DeleteV3: func(ctx context.Context, name, namespace string) error {
			return pc.HostEndpoints().Delete(ctx, name, metav1.DeleteOptions{})
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
		ListV3: func(ctx context.Context) ([]metav1.Object, error) {
			list, err := pc.GlobalNetworkSets().List(ctx, metav1.ListOptions{})
			if err != nil {
				return nil, err
			}
			result := make([]metav1.Object, len(list.Items))
			for i := range list.Items {
				result[i] = &list.Items[i]
			}
			return result, nil
		},
		UpdateV3: func(ctx context.Context, obj metav1.Object) error {
			_, err := pc.GlobalNetworkSets().Update(ctx, obj.(*apiv3.GlobalNetworkSet), metav1.UpdateOptions{})
			return err
		},
		DeleteV3: func(ctx context.Context, name, namespace string) error {
			return pc.GlobalNetworkSets().Delete(ctx, name, metav1.DeleteOptions{})
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
		ListV3: func(ctx context.Context) ([]metav1.Object, error) {
			list, err := pc.NetworkSets("").List(ctx, metav1.ListOptions{})
			if err != nil {
				return nil, err
			}
			result := make([]metav1.Object, len(list.Items))
			for i := range list.Items {
				result[i] = &list.Items[i]
			}
			return result, nil
		},
		UpdateV3: func(ctx context.Context, obj metav1.Object) error {
			t := obj.(*apiv3.NetworkSet)
			_, err := pc.NetworkSets(t.Namespace).Update(ctx, t, metav1.UpdateOptions{})
			return err
		},
		DeleteV3: func(ctx context.Context, name, namespace string) error {
			return pc.NetworkSets(namespace).Delete(ctx, name, metav1.DeleteOptions{})
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
		ListV3: func(ctx context.Context) ([]metav1.Object, error) {
			list, err := pc.IPAMConfigurations().List(ctx, metav1.ListOptions{})
			if err != nil {
				return nil, err
			}
			result := make([]metav1.Object, len(list.Items))
			for i := range list.Items {
				result[i] = &list.Items[i]
			}
			return result, nil
		},
		UpdateV3: func(ctx context.Context, obj metav1.Object) error {
			_, err := pc.IPAMConfigurations().Update(ctx, obj.(*apiv3.IPAMConfiguration), metav1.UpdateOptions{})
			return err
		},
		DeleteV3: func(ctx context.Context, name, namespace string) error {
			return pc.IPAMConfigurations().Delete(ctx, name, metav1.DeleteOptions{})
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
		ListV3: func(ctx context.Context) ([]metav1.Object, error) {
			list, err := pc.BlockAffinities().List(ctx, metav1.ListOptions{})
			if err != nil {
				return nil, err
			}
			result := make([]metav1.Object, len(list.Items))
			for i := range list.Items {
				result[i] = &list.Items[i]
			}
			return result, nil
		},
		UpdateV3: func(ctx context.Context, obj metav1.Object) error {
			_, err := pc.BlockAffinities().Update(ctx, obj.(*apiv3.BlockAffinity), metav1.UpdateOptions{})
			return err
		},
		DeleteV3: func(ctx context.Context, name, namespace string) error {
			return pc.BlockAffinities().Delete(ctx, name, metav1.DeleteOptions{})
		},
	})

	// 19. IPAMBlock — uses BlockListOptions instead of ResourceListOptions, so ListV1
	// converts the model.AllocationBlock values back to v3 IPAMBlock objects.
	Register(ResourceMigrator{
		Kind:  KindIPAMBlock,
		Order: OrderIPAM,
		ListV1: func(ctx context.Context, bc api.Client) (*model.KVPairList, error) {
			return listV1IPAMBlocks(ctx, bc)
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
		ListV3: func(ctx context.Context) ([]metav1.Object, error) {
			list, err := pc.IPAMBlocks().List(ctx, metav1.ListOptions{})
			if err != nil {
				return nil, err
			}
			result := make([]metav1.Object, len(list.Items))
			for i := range list.Items {
				result[i] = &list.Items[i]
			}
			return result, nil
		},
		UpdateV3: func(ctx context.Context, obj metav1.Object) error {
			_, err := pc.IPAMBlocks().Update(ctx, obj.(*apiv3.IPAMBlock), metav1.UpdateOptions{})
			return err
		},
		DeleteV3: func(ctx context.Context, name, namespace string) error {
			return pc.IPAMBlocks().Delete(ctx, name, metav1.DeleteOptions{})
		},
	})

	// 20. IPAMHandle — uses IPAMHandleListOptions instead of ResourceListOptions, so
	// ListV1 converts the model.IPAMHandle values back to v3 IPAMHandle objects.
	Register(ResourceMigrator{
		Kind:  KindIPAMHandle,
		Order: OrderIPAM,
		ListV1: func(ctx context.Context, bc api.Client) (*model.KVPairList, error) {
			return listV1IPAMHandles(ctx, bc)
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
			_, err := pc.IPAMHandles("").Create(ctx, obj.(*apiv3.IPAMHandle), metav1.CreateOptions{})
			return err
		},
		GetV3: func(ctx context.Context, name, namespace string) (metav1.Object, error) {
			obj, err := pc.IPAMHandles("").Get(ctx, name, metav1.GetOptions{})
			if kerrors.IsNotFound(err) {
				return nil, nil
			}
			return obj, err
		},
		SpecsEqual: func(a, b metav1.Object) bool {
			return reflect.DeepEqual(a.(*apiv3.IPAMHandle).Spec, b.(*apiv3.IPAMHandle).Spec)
		},
		ListV3: func(ctx context.Context) ([]metav1.Object, error) {
			list, err := pc.IPAMHandles("").List(ctx, metav1.ListOptions{})
			if err != nil {
				return nil, err
			}
			result := make([]metav1.Object, len(list.Items))
			for i := range list.Items {
				result[i] = &list.Items[i]
			}
			return result, nil
		},
		UpdateV3: func(ctx context.Context, obj metav1.Object) error {
			_, err := pc.IPAMHandles("").Update(ctx, obj.(*apiv3.IPAMHandle), metav1.UpdateOptions{})
			return err
		},
		DeleteV3: func(ctx context.Context, name, namespace string) error {
			return pc.IPAMHandles("").Delete(ctx, name, metav1.DeleteOptions{})
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
		ListV3: func(ctx context.Context) ([]metav1.Object, error) {
			list, err := pc.CalicoNodeStatuses().List(ctx, metav1.ListOptions{})
			if err != nil {
				return nil, err
			}
			result := make([]metav1.Object, len(list.Items))
			for i := range list.Items {
				result[i] = &list.Items[i]
			}
			return result, nil
		},
		UpdateV3: func(ctx context.Context, obj metav1.Object) error {
			_, err := pc.CalicoNodeStatuses().Update(ctx, obj.(*apiv3.CalicoNodeStatus), metav1.UpdateOptions{})
			return err
		},
		DeleteV3: func(ctx context.Context, name, namespace string) error {
			return pc.CalicoNodeStatuses().Delete(ctx, name, metav1.DeleteOptions{})
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
		block := kvp.Value.(*model.AllocationBlock)
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
		handle := kvp.Value.(*model.IPAMHandle)
		name := kvp.Key.(model.IPAMHandleKey).HandleID

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
