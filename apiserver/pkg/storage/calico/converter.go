// Copyright (c) 2019-2020 Tigera, Inc. All rights reserved.

package calico

import (
	"reflect"

	"k8s.io/klog/v2"

	libapi "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"

	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/errors"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/storage"

	aapi "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
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
	switch libcalicoObject.(type) {
	case *api.NetworkPolicy:
		lcgPolicy := libcalicoObject.(*api.NetworkPolicy)
		aapiPolicy := &aapi.NetworkPolicy{}
		NetworkPolicyConverter{}.convertToAAPI(lcgPolicy, aapiPolicy)
		return aapiPolicy
	case *api.GlobalNetworkPolicy:
		lcgPolicy := libcalicoObject.(*api.GlobalNetworkPolicy)
		aapiPolicy := &aapi.GlobalNetworkPolicy{}
		GlobalNetworkPolicyConverter{}.convertToAAPI(lcgPolicy, aapiPolicy)
		return aapiPolicy
	case *api.GlobalNetworkSet:
		lcgNetworkSet := libcalicoObject.(*api.GlobalNetworkSet)
		aapiNetworkSet := &aapi.GlobalNetworkSet{}
		GlobalNetworkSetConverter{}.convertToAAPI(lcgNetworkSet, aapiNetworkSet)
		return aapiNetworkSet
	case *api.NetworkSet:
		lcgNetworkSet := libcalicoObject.(*api.NetworkSet)
		aapiNetworkSet := &aapi.NetworkSet{}
		NetworkSetConverter{}.convertToAAPI(lcgNetworkSet, aapiNetworkSet)
		return aapiNetworkSet
	case *api.HostEndpoint:
		lcg := libcalicoObject.(*api.HostEndpoint)
		aapi := &aapi.HostEndpoint{}
		HostEndpointConverter{}.convertToAAPI(lcg, aapi)
		return aapi
	case *api.IPPool:
		lcg := libcalicoObject.(*api.IPPool)
		aapi := &aapi.IPPool{}
		IPPoolConverter{}.convertToAAPI(lcg, aapi)
		return aapi
	case *api.IPReservation:
		lcg := libcalicoObject.(*api.IPReservation)
		aapi := &aapi.IPReservation{}
		IPReservationConverter{}.convertToAAPI(lcg, aapi)
		return aapi
	case *api.BGPConfiguration:
		lcg := libcalicoObject.(*api.BGPConfiguration)
		aapi := &aapi.BGPConfiguration{}
		BGPConfigurationConverter{}.convertToAAPI(lcg, aapi)
		return aapi
	case *api.BGPPeer:
		lcg := libcalicoObject.(*api.BGPPeer)
		aapi := &aapi.BGPPeer{}
		BGPPeerConverter{}.convertToAAPI(lcg, aapi)
		return aapi
	case *api.Profile:
		lcg := libcalicoObject.(*api.Profile)
		aapi := &aapi.Profile{}
		ProfileConverter{}.convertToAAPI(lcg, aapi)
		return aapi
	case *api.FelixConfiguration:
		lcg := libcalicoObject.(*api.FelixConfiguration)
		aapi := &aapi.FelixConfiguration{}
		FelixConfigurationConverter{}.convertToAAPI(lcg, aapi)
		return aapi
	case *api.KubeControllersConfiguration:
		lcg := libcalicoObject.(*api.KubeControllersConfiguration)
		aapi := &aapi.KubeControllersConfiguration{}
		KubeControllersConfigurationConverter{}.convertToAAPI(lcg, aapi)
		return aapi
	case *api.ClusterInformation:
		lcg := libcalicoObject.(*api.ClusterInformation)
		aapi := &aapi.ClusterInformation{}
		ClusterInformationConverter{}.convertToAAPI(lcg, aapi)
		return aapi
	case *api.CalicoNodeStatus:
		lcg := libcalicoObject.(*api.CalicoNodeStatus)
		aapi := &aapi.CalicoNodeStatus{}
		CalicoNodeStatusConverter{}.convertToAAPI(lcg, aapi)
		return aapi
	case *api.IPAMConfig:
		lcg := libcalicoObject.(*libapi.BlockAffinity)
		aapi := &aapi.BlockAffinity{}
		BlockAffinityConverter{}.convertToAAPI(lcg, aapi)
		return aapi
	default:
		klog.Infof("Unrecognized libcalico object (type %v)", reflect.TypeOf(libcalicoObject))
		return nil
	}
}
