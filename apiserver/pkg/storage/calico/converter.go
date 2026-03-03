// Copyright (c) 2019-2025 Tigera, Inc. All rights reserved.

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

package calico

import (
	"reflect"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/storage"

	"github.com/projectcalico/calico/libcalico-go/lib/errors"
)

func aapiError(err error, key string) error {
	switch err.(type) {
	case errors.ErrorResourceAlreadyExists:
		return storage.NewKeyExistsError(key, 0)
	case errors.ErrorResourceDoesNotExist:
		return storage.NewKeyNotFoundError(key, 0)
	case errors.ErrorResourceUpdateConflict:
		return storage.NewResourceVersionConflictsError(key, 0)
	default:
		return err
	}
}

// TODO: convertToAAPI should be same as the ones specific to resources.
// This is common code. Refactor this workflow.
func convertToAAPI(libcalicoObject runtime.Object) (res runtime.Object) {
	switch obj := libcalicoObject.(type) {
	case *v3.Tier:
		aapiTier := &v3.Tier{}
		TierConverter{}.convertToAAPI(obj, aapiTier)
		return aapiTier
	case *v3.NetworkPolicy:
		aapiPolicy := &v3.NetworkPolicy{}
		NetworkPolicyConverter{}.convertToAAPI(obj, aapiPolicy)
		return aapiPolicy
	case *v3.StagedKubernetesNetworkPolicy:
		aapiPolicy := &v3.StagedKubernetesNetworkPolicy{}
		StagedKubernetesNetworkPolicyConverter{}.convertToAAPI(obj, aapiPolicy)
		return aapiPolicy
	case *v3.StagedNetworkPolicy:
		aapiPolicy := &v3.StagedNetworkPolicy{}
		StagedNetworkPolicyConverter{}.convertToAAPI(obj, aapiPolicy)
		return aapiPolicy
	case *v3.GlobalNetworkPolicy:
		aapiPolicy := &v3.GlobalNetworkPolicy{}
		GlobalNetworkPolicyConverter{}.convertToAAPI(obj, aapiPolicy)
		return aapiPolicy
	case *v3.StagedGlobalNetworkPolicy:
		aapiPolicy := &v3.StagedGlobalNetworkPolicy{}
		StagedGlobalNetworkPolicyConverter{}.convertToAAPI(obj, aapiPolicy)
		return aapiPolicy
	case *v3.GlobalNetworkSet:
		aapiNetworkSet := &v3.GlobalNetworkSet{}
		GlobalNetworkSetConverter{}.convertToAAPI(obj, aapiNetworkSet)
		return aapiNetworkSet
	case *v3.NetworkSet:
		aapiNetworkSet := &v3.NetworkSet{}
		NetworkSetConverter{}.convertToAAPI(obj, aapiNetworkSet)
		return aapiNetworkSet
	case *v3.HostEndpoint:
		aapi := &v3.HostEndpoint{}
		HostEndpointConverter{}.convertToAAPI(obj, aapi)
		return aapi
	case *v3.IPPool:
		aapi := &v3.IPPool{}
		IPPoolConverter{}.convertToAAPI(obj, aapi)
		return aapi
	case *v3.IPReservation:
		aapi := &v3.IPReservation{}
		IPReservationConverter{}.convertToAAPI(obj, aapi)
		return aapi
	case *v3.BGPConfiguration:
		aapi := &v3.BGPConfiguration{}
		BGPConfigurationConverter{}.convertToAAPI(obj, aapi)
		return aapi
	case *v3.BGPPeer:
		aapi := &v3.BGPPeer{}
		BGPPeerConverter{}.convertToAAPI(obj, aapi)
		return aapi
	case *v3.BGPFilter:
		aapi := &v3.BGPFilter{}
		BGPFilterConverter{}.convertToAAPI(obj, aapi)
		return aapi
	case *v3.Profile:
		aapi := &v3.Profile{}
		ProfileConverter{}.convertToAAPI(obj, aapi)
		return aapi
	case *v3.FelixConfiguration:
		aapi := &v3.FelixConfiguration{}
		FelixConfigurationConverter{}.convertToAAPI(obj, aapi)
		return aapi
	case *v3.KubeControllersConfiguration:
		aapi := &v3.KubeControllersConfiguration{}
		KubeControllersConfigurationConverter{}.convertToAAPI(obj, aapi)
		return aapi
	case *v3.ClusterInformation:
		aapi := &v3.ClusterInformation{}
		ClusterInformationConverter{}.convertToAAPI(obj, aapi)
		return aapi
	case *v3.CalicoNodeStatus:
		aapi := &v3.CalicoNodeStatus{}
		CalicoNodeStatusConverter{}.convertToAAPI(obj, aapi)
		return aapi
	case *v3.IPAMConfiguration:
		aapi := &v3.IPAMConfiguration{}
		IPAMConfigConverter{}.convertToAAPI(obj, aapi)
		return aapi
	case *v3.BlockAffinity:
		aapi := &v3.BlockAffinity{}
		BlockAffinityConverter{}.convertToAAPI(obj, aapi)
		return aapi
	default:
		logrus.Tracef("Unrecognized libcalico object (type %v)", reflect.TypeOf(libcalicoObject))
		return nil
	}
}
