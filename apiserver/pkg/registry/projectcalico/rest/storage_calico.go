// Copyright (c) 2021 Tigera, Inc. All rights reserved.
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

package rest

import (
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/registry/generic"
	"k8s.io/apiserver/pkg/registry/rest"

	calico "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	calicobgpconfiguration "github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/bgpconfiguration"
	calicobgppeer "github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/bgppeer"
	"github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/caliconodestatus"
	calicoclusterinformation "github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/clusterinformation"
	calicofelixconfig "github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/felixconfig"
	calicognetworkset "github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/globalnetworkset"
	calicogpolicy "github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/globalpolicy"
	calicohostendpoint "github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/hostendpoint"
	calicoipamconfig "github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/ipamconfig"
	calicoippool "github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/ippool"
	calicoipreservation "github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/ipreservation"
	calicokubecontrollersconfig "github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/kubecontrollersconfig"
	calicopolicy "github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/networkpolicy"
	caliconetworkset "github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/networkset"
	calicoprofile "github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/profile"
	"github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/server"
	calicostorage "github.com/projectcalico/calico/apiserver/pkg/storage/calico"
	"github.com/projectcalico/calico/apiserver/pkg/storage/etcd"
)

// RESTStorageProvider provides a factory method to create a new APIGroupInfo for
// the calico API group. It implements (./pkg/apiserver).RESTStorageProvider
type RESTStorageProvider struct {
	StorageType server.StorageType
}

// NewV3Storage constructs v3 api storage.
func (p RESTStorageProvider) NewV3Storage(
	scheme *runtime.Scheme,
	restOptionsGetter generic.RESTOptionsGetter,
	authorizer authorizer.Authorizer,
) (map[string]rest.Storage, error) {
	policyRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("networkpolicies"))
	if err != nil {
		return nil, err
	}
	policyOpts := server.NewOptions(
		etcd.Options{
			RESTOptions:   policyRESTOptions,
			Capacity:      1000,
			ObjectType:    calicopolicy.EmptyObject(),
			ScopeStrategy: calicopolicy.NewStrategy(scheme),
			NewListFunc:   calicopolicy.NewList,
			GetAttrsFunc:  calicopolicy.GetAttrs,
			Trigger:       nil,
		},
		calicostorage.Options{
			RESTOptions: policyRESTOptions,
		},
		p.StorageType,
		authorizer,
		[]string{"cnp", "caliconetworkpolicy", "caliconetworkpolicies"},
	)

	networksetRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("networksets"))
	if err != nil {
		return nil, err
	}
	networksetOpts := server.NewOptions(
		etcd.Options{
			RESTOptions:   networksetRESTOptions,
			Capacity:      1000,
			ObjectType:    caliconetworkset.EmptyObject(),
			ScopeStrategy: caliconetworkset.NewStrategy(scheme),
			NewListFunc:   caliconetworkset.NewList,
			GetAttrsFunc:  caliconetworkset.GetAttrs,
			Trigger:       nil,
		},
		calicostorage.Options{
			RESTOptions: networksetRESTOptions,
		},
		p.StorageType,
		authorizer,
		[]string{"netsets"},
	)

	gpolicyRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("globalnetworkpolicies"))
	if err != nil {
		return nil, err
	}
	gpolicyOpts := server.NewOptions(
		etcd.Options{
			RESTOptions:   gpolicyRESTOptions,
			Capacity:      1000,
			ObjectType:    calicogpolicy.EmptyObject(),
			ScopeStrategy: calicogpolicy.NewStrategy(scheme),
			NewListFunc:   calicogpolicy.NewList,
			GetAttrsFunc:  calicogpolicy.GetAttrs,
			Trigger:       nil,
		},
		calicostorage.Options{
			RESTOptions: gpolicyRESTOptions,
		},
		p.StorageType,
		authorizer,
		[]string{"gnp", "cgnp", "calicoglobalnetworkpolicies"},
	)

	gNetworkSetRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("globalnetworksets"))
	if err != nil {
		return nil, err
	}
	gNetworkSetOpts := server.NewOptions(
		etcd.Options{
			RESTOptions:   gNetworkSetRESTOptions,
			Capacity:      1000,
			ObjectType:    calicognetworkset.EmptyObject(),
			ScopeStrategy: calicognetworkset.NewStrategy(scheme),
			NewListFunc:   calicognetworkset.NewList,
			GetAttrsFunc:  calicognetworkset.GetAttrs,
			Trigger:       nil,
		},
		calicostorage.Options{
			RESTOptions: gNetworkSetRESTOptions,
		},
		p.StorageType,
		authorizer,
		[]string{},
	)

	hostEndpointRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("hostendpoints"))
	if err != nil {
		return nil, err
	}
	hostEndpointOpts := server.NewOptions(
		etcd.Options{
			RESTOptions:   hostEndpointRESTOptions,
			Capacity:      1000,
			ObjectType:    calicohostendpoint.EmptyObject(),
			ScopeStrategy: calicohostendpoint.NewStrategy(scheme),
			NewListFunc:   calicohostendpoint.NewList,
			GetAttrsFunc:  calicohostendpoint.GetAttrs,
			Trigger:       nil,
		},
		calicostorage.Options{
			RESTOptions: hostEndpointRESTOptions,
		},
		p.StorageType,
		authorizer,
		[]string{"hep", "heps"},
	)

	ipPoolRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("ippools"))
	if err != nil {
		return nil, err
	}
	ipPoolSetOpts := server.NewOptions(
		etcd.Options{
			RESTOptions:   ipPoolRESTOptions,
			Capacity:      10,
			ObjectType:    calicoippool.EmptyObject(),
			ScopeStrategy: calicoippool.NewStrategy(scheme),
			NewListFunc:   calicoippool.NewList,
			GetAttrsFunc:  calicoippool.GetAttrs,
			Trigger:       nil,
		},
		calicostorage.Options{
			RESTOptions: ipPoolRESTOptions,
		},
		p.StorageType,
		authorizer,
		[]string{},
	)

	ipReservationRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("ipreservations"))
	if err != nil {
		return nil, err
	}
	ipReservationSetOpts := server.NewOptions(
		etcd.Options{
			RESTOptions:   ipReservationRESTOptions,
			Capacity:      10,
			ObjectType:    calicoipreservation.EmptyObject(),
			ScopeStrategy: calicoipreservation.NewStrategy(scheme),
			NewListFunc:   calicoipreservation.NewList,
			GetAttrsFunc:  calicoipreservation.GetAttrs,
			Trigger:       nil,
		},
		calicostorage.Options{
			RESTOptions: ipReservationRESTOptions,
		},
		p.StorageType,
		authorizer,
		[]string{},
	)

	bgpConfigurationRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("bgpconfigurations"))
	if err != nil {
		return nil, err
	}
	bgpConfigurationOpts := server.NewOptions(
		etcd.Options{
			RESTOptions:   bgpConfigurationRESTOptions,
			Capacity:      1000,
			ObjectType:    calicobgpconfiguration.EmptyObject(),
			ScopeStrategy: calicobgpconfiguration.NewStrategy(scheme),
			NewListFunc:   calicobgpconfiguration.NewList,
			GetAttrsFunc:  calicobgpconfiguration.GetAttrs,
			Trigger:       nil,
		},
		calicostorage.Options{
			RESTOptions: bgpConfigurationRESTOptions,
		},
		p.StorageType,
		authorizer,
		[]string{"bgpconfig", "bgpconfigs"},
	)

	bgpPeerRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("bgppeers"))
	if err != nil {
		return nil, err
	}
	bgpPeerOpts := server.NewOptions(
		etcd.Options{
			RESTOptions:   bgpPeerRESTOptions,
			Capacity:      1000,
			ObjectType:    calicobgppeer.EmptyObject(),
			ScopeStrategy: calicobgppeer.NewStrategy(scheme),
			NewListFunc:   calicobgppeer.NewList,
			GetAttrsFunc:  calicobgppeer.GetAttrs,
			Trigger:       nil,
		},
		calicostorage.Options{
			RESTOptions: bgpPeerRESTOptions,
		},
		p.StorageType,
		authorizer,
		[]string{},
	)

	profileRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("profiles"))
	if err != nil {
		return nil, err
	}
	profileOpts := server.NewOptions(
		etcd.Options{
			RESTOptions:   profileRESTOptions,
			Capacity:      1000,
			ObjectType:    calicoprofile.EmptyObject(),
			ScopeStrategy: calicoprofile.NewStrategy(scheme),
			NewListFunc:   calicoprofile.NewList,
			GetAttrsFunc:  calicoprofile.GetAttrs,
			Trigger:       nil,
		},
		calicostorage.Options{
			RESTOptions: profileRESTOptions,
		},
		p.StorageType,
		authorizer,
		[]string{},
	)

	felixConfigRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("felixconfigurations"))
	if err != nil {
		return nil, err
	}
	felixConfigOpts := server.NewOptions(
		etcd.Options{
			RESTOptions:   felixConfigRESTOptions,
			Capacity:      1000,
			ObjectType:    calicofelixconfig.EmptyObject(),
			ScopeStrategy: calicofelixconfig.NewStrategy(scheme),
			NewListFunc:   calicofelixconfig.NewList,
			GetAttrsFunc:  calicofelixconfig.GetAttrs,
			Trigger:       nil,
		},
		calicostorage.Options{
			RESTOptions: felixConfigRESTOptions,
		},
		p.StorageType,
		authorizer,
		[]string{"felixconfig", "felixconfigs"},
	)

	kubeControllersConfigsRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("kubecontrollersconfigurations"))
	if err != nil {
		return nil, err
	}
	kubeControllersConfigsOpts := server.NewOptions(
		etcd.Options{
			RESTOptions:   kubeControllersConfigsRESTOptions,
			Capacity:      1000,
			ObjectType:    calicokubecontrollersconfig.EmptyObject(),
			ScopeStrategy: calicokubecontrollersconfig.NewStrategy(scheme),
			NewListFunc:   calicokubecontrollersconfig.NewList,
			GetAttrsFunc:  calicokubecontrollersconfig.GetAttrs,
			Trigger:       nil,
		},
		calicostorage.Options{
			RESTOptions: kubeControllersConfigsRESTOptions,
		},
		p.StorageType,
		authorizer,
		[]string{"kcconfig"},
	)

	clusterInformationRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("clusterinformations"))
	if err != nil {
		return nil, err
	}
	clusterInformationOpts := server.NewOptions(
		etcd.Options{
			RESTOptions:   clusterInformationRESTOptions,
			Capacity:      1000,
			ObjectType:    calicoclusterinformation.EmptyObject(),
			ScopeStrategy: calicoclusterinformation.NewStrategy(scheme),
			NewListFunc:   calicoclusterinformation.NewList,
			GetAttrsFunc:  calicoclusterinformation.GetAttrs,
			Trigger:       nil,
		},
		calicostorage.Options{
			RESTOptions: clusterInformationRESTOptions,
		},
		p.StorageType,
		authorizer,
		[]string{"clusterinfo"},
	)

	caliconodestatusRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("caliconodestatuses"))
	if err != nil {
		return nil, err
	}
	caliconodestatusOpts := server.NewOptions(
		etcd.Options{
			RESTOptions:   caliconodestatusRESTOptions,
			Capacity:      1000,
			ObjectType:    caliconodestatus.EmptyObject(),
			ScopeStrategy: caliconodestatus.NewStrategy(scheme),
			NewListFunc:   caliconodestatus.NewList,
			GetAttrsFunc:  caliconodestatus.GetAttrs,
			Trigger:       nil,
		},
		calicostorage.Options{
			RESTOptions: caliconodestatusRESTOptions,
		},
		p.StorageType,
		authorizer,
		[]string{"caliconodestatus"},
	)

	ipamconfigRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("ipamconfigs"))
	if err != nil {
		return nil, err
	}
	ipamconfigOpts := server.NewOptions(
		etcd.Options{
			RESTOptions:   ipamconfigRESTOptions,
			Capacity:      1000,
			ObjectType:    calicoipamconfig.EmptyObject(),
			ScopeStrategy: calicoipamconfig.NewStrategy(scheme),
			NewListFunc:   calicoipamconfig.NewList,
			GetAttrsFunc:  calicoipamconfig.GetAttrs,
			Trigger:       nil,
		},
		calicostorage.Options{
			RESTOptions: caliconodestatusRESTOptions,
		},
		p.StorageType,
		authorizer,
		[]string{"caliconodestatus"},
	)

	storage := map[string]rest.Storage{}
	storage["networkpolicies"] = rESTInPeace(calicopolicy.NewREST(scheme, *policyOpts))
	storage["globalnetworkpolicies"] = rESTInPeace(calicogpolicy.NewREST(scheme, *gpolicyOpts))
	storage["globalnetworksets"] = rESTInPeace(calicognetworkset.NewREST(scheme, *gNetworkSetOpts))
	storage["networksets"] = rESTInPeace(caliconetworkset.NewREST(scheme, *networksetOpts))
	storage["hostendpoints"] = rESTInPeace(calicohostendpoint.NewREST(scheme, *hostEndpointOpts))
	storage["ippools"] = rESTInPeace(calicoippool.NewREST(scheme, *ipPoolSetOpts))
	storage["ipreservations"] = rESTInPeace(calicoipreservation.NewREST(scheme, *ipReservationSetOpts))
	storage["bgpconfigurations"] = rESTInPeace(calicobgpconfiguration.NewREST(scheme, *bgpConfigurationOpts))
	storage["bgppeers"] = rESTInPeace(calicobgppeer.NewREST(scheme, *bgpPeerOpts))
	storage["profiles"] = rESTInPeace(calicoprofile.NewREST(scheme, *profileOpts))
	storage["felixconfigurations"] = rESTInPeace(calicofelixconfig.NewREST(scheme, *felixConfigOpts))
	storage["clusterinformations"] = rESTInPeace(calicoclusterinformation.NewREST(scheme, *clusterInformationOpts))
	storage["caliconodestatuses"] = rESTInPeace(caliconodestatus.NewREST(scheme, *caliconodestatusOpts))
	storage["ipamconfigs"] = rESTInPeace(calicoipamconfig.NewREST(scheme, *ipamconfigOpts))

	kubeControllersConfigsStorage, kubeControllersConfigsStatusStorage, err := calicokubecontrollersconfig.NewREST(scheme, *kubeControllersConfigsOpts)
	if err != nil {
		err = fmt.Errorf("unable to create REST storage for a resource due to %v, will die", err)
		panic(err)
	}
	storage["kubecontrollersconfigurations"] = kubeControllersConfigsStorage
	storage["kubecontrollersconfigurations/status"] = kubeControllersConfigsStatusStorage
	return storage, nil
}

// GroupName returns the API group name.
func (p RESTStorageProvider) GroupName() string {
	return calico.GroupName
}

// rESTInPeace is just a simple function that panics on error.
// Otherwise returns the given storage object. It is meant to be
// a wrapper for projectcalico registries.
func rESTInPeace(storage rest.Storage, err error) rest.Storage {
	if err != nil {
		err = fmt.Errorf("unable to create REST storage for a resource due to %v, will die", err)
		panic(err)
	}
	return storage
}
