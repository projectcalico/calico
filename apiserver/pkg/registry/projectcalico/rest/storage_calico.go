// Copyright (c) 2021-2025 Tigera, Inc. All rights reserved.
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

	calico "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/registry/generic"
	"k8s.io/apiserver/pkg/registry/rest"

	"github.com/projectcalico/calico/apiserver/pkg/rbac"
	calicobgpconfiguration "github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/bgpconfiguration"
	calicobgpfilter "github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/bgpfilter"
	calicobgppeer "github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/bgppeer"
	calicoblockaffinity "github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/blockaffinity"
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
	calicostagedgpolicy "github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/stagedglobalnetworkpolicy"
	calicostagedk8spolicy "github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/stagedkubernetesnetworkpolicy"
	calicostagedpolicy "github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/stagednetworkpolicy"
	calicotier "github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/tier"
	"github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/util"
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
	calicoLister rbac.CalicoResourceLister,
	watchManager *util.WatchManager,
) (map[string]rest.Storage, error) {
	policyRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("networkpolicies"), nil)
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

	stagedk8spolicyRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("stagedkubernetesnetworkpolicies"), nil)
	if err != nil {
		return nil, err
	}
	stagedk8spolicyOpts := server.NewOptions(
		etcd.Options{
			RESTOptions:   stagedk8spolicyRESTOptions,
			Capacity:      1000,
			ObjectType:    calicostagedk8spolicy.EmptyObject(),
			ScopeStrategy: calicostagedk8spolicy.NewStrategy(scheme),
			NewListFunc:   calicostagedk8spolicy.NewList,
			GetAttrsFunc:  calicostagedk8spolicy.GetAttrs,
			Trigger:       nil,
		},
		calicostorage.Options{
			RESTOptions: stagedk8spolicyRESTOptions,
		},
		p.StorageType,
		authorizer,
		[]string{"sknp"},
	)

	stagedpolicyRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("stagednetworkpolicies"), nil)
	if err != nil {
		return nil, err
	}
	stagedpolicyOpts := server.NewOptions(
		etcd.Options{
			RESTOptions:   stagedpolicyRESTOptions,
			Capacity:      1000,
			ObjectType:    calicostagedpolicy.EmptyObject(),
			ScopeStrategy: calicostagedpolicy.NewStrategy(scheme),
			NewListFunc:   calicostagedpolicy.NewList,
			GetAttrsFunc:  calicostagedpolicy.GetAttrs,
			Trigger:       nil,
		},
		calicostorage.Options{
			RESTOptions: stagedpolicyRESTOptions,
		},
		p.StorageType,
		authorizer,
		[]string{"snp"},
	)

	networksetRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("networksets"), nil)
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

	tierRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("tiers"), nil)
	if err != nil {
		return nil, err
	}
	tierOpts := server.NewOptions(
		etcd.Options{
			RESTOptions:   tierRESTOptions,
			Capacity:      1000,
			ObjectType:    calicotier.EmptyObject(),
			ScopeStrategy: calicotier.NewStrategy(scheme),
			NewListFunc:   calicotier.NewList,
			GetAttrsFunc:  calicotier.GetAttrs,
			Trigger:       nil,
		},
		calicostorage.Options{
			RESTOptions: tierRESTOptions,
		},
		p.StorageType,
		authorizer,
		[]string{},
	)

	gpolicyRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("globalnetworkpolicies"), nil)
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

	stagedgpolicyRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("stagedglobalnetworkpolicies"), nil)
	if err != nil {
		return nil, err
	}
	stagedgpolicyOpts := server.NewOptions(
		etcd.Options{
			RESTOptions:   stagedgpolicyRESTOptions,
			Capacity:      1000,
			ObjectType:    calicostagedgpolicy.EmptyObject(),
			ScopeStrategy: calicostagedgpolicy.NewStrategy(scheme),
			NewListFunc:   calicostagedgpolicy.NewList,
			GetAttrsFunc:  calicostagedgpolicy.GetAttrs,
			Trigger:       nil,
		},
		calicostorage.Options{
			RESTOptions: stagedgpolicyRESTOptions,
		},
		p.StorageType,
		authorizer,
		[]string{"sgnp"},
	)

	gNetworkSetRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("globalnetworksets"), nil)
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

	hostEndpointRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("hostendpoints"), nil)
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

	ipPoolRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("ippools"), nil)
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

	ipReservationRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("ipreservations"), nil)
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

	bgpConfigurationRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("bgpconfigurations"), nil)
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

	bgpPeerRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("bgppeers"), nil)
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

	bgpFilterRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("bgpfilters"), nil)
	if err != nil {
		return nil, err
	}
	bgpFilterOpts := server.NewOptions(
		etcd.Options{
			RESTOptions:   bgpFilterRESTOptions,
			Capacity:      1000,
			ObjectType:    calicobgpfilter.EmptyObject(),
			ScopeStrategy: calicobgpfilter.NewStrategy(scheme),
			NewListFunc:   calicobgpfilter.NewList,
			GetAttrsFunc:  calicobgpfilter.GetAttrs,
			Trigger:       nil,
		},
		calicostorage.Options{
			RESTOptions: bgpFilterRESTOptions,
		},
		p.StorageType,
		authorizer,
		[]string{},
	)

	profileRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("profiles"), nil)
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

	felixConfigRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("felixconfigurations"), nil)
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

	kubeControllersConfigsRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("kubecontrollersconfigurations"), nil)
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

	kubeControllersConfigsStatusRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("kubecontrollersconfigurations/status"), nil)
	if err != nil {
		return nil, err
	}
	kubeControllersConfigsStatusOpts := server.NewOptions(
		etcd.Options{
			RESTOptions:   kubeControllersConfigsStatusRESTOptions,
			Capacity:      1000,
			ObjectType:    calicokubecontrollersconfig.EmptyObject(),
			ScopeStrategy: calicokubecontrollersconfig.NewStrategy(scheme),
			NewListFunc:   calicokubecontrollersconfig.NewList,
			GetAttrsFunc:  calicokubecontrollersconfig.GetAttrs,
			Trigger:       nil,
		},
		calicostorage.Options{
			RESTOptions: kubeControllersConfigsStatusRESTOptions,
		},
		p.StorageType,
		authorizer,
		[]string{"kcconfig"},
	)

	clusterInformationRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("clusterinformations"), nil)
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

	caliconodestatusRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("caliconodestatuses"), nil)
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

	ipamconfigRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("ipamconfigurations"), nil)
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
			RESTOptions: ipamconfigRESTOptions,
		},
		p.StorageType,
		authorizer,
		[]string{"ipamconfig"},
	)

	blockAffinityRESTOptions, err := restOptionsGetter.GetRESTOptions(calico.Resource("blockaffinities"), nil)
	if err != nil {
		return nil, err
	}
	blockAffinityOpts := server.NewOptions(
		etcd.Options{
			RESTOptions:   blockAffinityRESTOptions,
			Capacity:      1000,
			ObjectType:    calicoblockaffinity.EmptyObject(),
			ScopeStrategy: calicoblockaffinity.NewStrategy(scheme),
			NewListFunc:   calicoblockaffinity.NewList,
			GetAttrsFunc:  calicoblockaffinity.GetAttrs,
			Trigger:       nil,
		},
		calicostorage.Options{
			RESTOptions: blockAffinityRESTOptions,
		},
		p.StorageType,
		authorizer,
		[]string{"blockaffinity", "affinity", "affinities"},
	)

	storage := map[string]rest.Storage{}
	storage["tiers"] = rESTInPeace(calicotier.NewREST(scheme, *tierOpts))
	storage["networkpolicies"] = rESTInPeace(calicopolicy.NewREST(scheme, *policyOpts, calicoLister, watchManager))
	storage["stagednetworkpolicies"] = rESTInPeace(calicostagedpolicy.NewREST(scheme, *stagedpolicyOpts, calicoLister, watchManager))
	storage["stagedkubernetesnetworkpolicies"] = rESTInPeace(calicostagedk8spolicy.NewREST(scheme, *stagedk8spolicyOpts))
	storage["globalnetworkpolicies"] = rESTInPeace(calicogpolicy.NewREST(scheme, *gpolicyOpts, calicoLister, watchManager))
	storage["stagedglobalnetworkpolicies"] = rESTInPeace(calicostagedgpolicy.NewREST(scheme, *stagedgpolicyOpts, calicoLister, watchManager))
	storage["globalnetworksets"] = rESTInPeace(calicognetworkset.NewREST(scheme, *gNetworkSetOpts))
	storage["networksets"] = rESTInPeace(caliconetworkset.NewREST(scheme, *networksetOpts))
	storage["hostendpoints"] = rESTInPeace(calicohostendpoint.NewREST(scheme, *hostEndpointOpts))
	storage["ippools"] = rESTInPeace(calicoippool.NewREST(scheme, *ipPoolSetOpts))
	storage["ipreservations"] = rESTInPeace(calicoipreservation.NewREST(scheme, *ipReservationSetOpts))
	storage["bgpconfigurations"] = rESTInPeace(calicobgpconfiguration.NewREST(scheme, *bgpConfigurationOpts))
	storage["bgppeers"] = rESTInPeace(calicobgppeer.NewREST(scheme, *bgpPeerOpts))
	storage["bgpfilters"] = rESTInPeace(calicobgpfilter.NewREST(scheme, *bgpFilterOpts))
	storage["profiles"] = rESTInPeace(calicoprofile.NewREST(scheme, *profileOpts))
	storage["felixconfigurations"] = rESTInPeace(calicofelixconfig.NewREST(scheme, *felixConfigOpts))
	storage["clusterinformations"] = rESTInPeace(calicoclusterinformation.NewREST(scheme, *clusterInformationOpts))
	storage["caliconodestatuses"] = rESTInPeace(caliconodestatus.NewREST(scheme, *caliconodestatusOpts))
	storage["ipamconfigurations"] = rESTInPeace(calicoipamconfig.NewREST(scheme, *ipamconfigOpts))
	storage["blockaffinities"] = rESTInPeace(calicoblockaffinity.NewREST(scheme, *blockAffinityOpts))

	kubeControllersConfigsStorage, kubeControllersConfigsStatusStorage, err := calicokubecontrollersconfig.NewREST(scheme, *kubeControllersConfigsOpts, *kubeControllersConfigsStatusOpts)
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
