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

package v3

import (
	"sync"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/scheme"
)

// GroupName is the group name use in this package
const (
	GroupName = "projectcalico.org"
)

// SchemeGroupVersion is group version used to register these objects
var (
	SchemeGroupVersion         = schema.GroupVersion{Group: GroupName, Version: "v3"}
	SchemeGroupVersionInternal = schema.GroupVersion{Group: GroupName, Version: runtime.APIVersionInternal}
)

var (
	once               sync.Once
	SchemeBuilder      runtime.SchemeBuilder
	localSchemeBuilder = &SchemeBuilder
	AllKnownTypes      = []runtime.Object{
		&NetworkPolicy{},
		&NetworkPolicyList{},
		&GlobalNetworkPolicy{},
		&GlobalNetworkPolicyList{},
		&GlobalNetworkSet{},
		&GlobalNetworkSetList{},
		&HostEndpoint{},
		&HostEndpointList{},
		&IPPool{},
		&IPPoolList{},
		&IPReservation{},
		&IPReservationList{},
		&BGPConfiguration{},
		&BGPConfigurationList{},
		&BGPFilter{},
		&BGPFilterList{},
		&BGPPeer{},
		&BGPPeerList{},
		&Profile{},
		&ProfileList{},
		&FelixConfiguration{},
		&FelixConfigurationList{},
		&KubeControllersConfiguration{},
		&KubeControllersConfigurationList{},
		&ClusterInformation{},
		&ClusterInformationList{},
		&NetworkSet{},
		&NetworkSetList{},
		&CalicoNodeStatus{},
		&CalicoNodeStatusList{},
		&IPAMConfiguration{},
		&IPAMConfigurationList{},
		&IPAMHandle{},
		&IPAMHandleList{},
		&IPAMBlock{},
		&IPAMBlockList{},
		&BlockAffinity{},
		&BlockAffinityList{},
		&BGPFilter{},
		&BGPFilterList{},
		&Tier{},
		&TierList{},
		&StagedGlobalNetworkPolicy{},
		&StagedGlobalNetworkPolicyList{},
		&StagedKubernetesNetworkPolicy{},
		&StagedKubernetesNetworkPolicyList{},
		&StagedNetworkPolicy{},
		&StagedNetworkPolicyList{},
	}
)

func init() {
	// We only register manually written functions here. The registration of the
	// generated functions takes place in the generated files. The separation
	// makes the code compile even when the generated files are missing.
	localSchemeBuilder.Register(addKnownTypes, addConversionFuncs)
}

func AddToGlobalScheme() error {
	var err error
	once.Do(func() {
		err = AddToScheme(scheme.Scheme)
	})
	return err
}

func AddToScheme(scheme *runtime.Scheme) error {
	return localSchemeBuilder.AddToScheme(scheme)
}

// Adds the list of known types to api.Scheme.
func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(SchemeGroupVersion, AllKnownTypes...)
	metav1.AddToGroupVersion(scheme, SchemeGroupVersion)
	return nil
}

// Resource takes an unqualified resource and returns a Group qualified GroupResource
func Resource(resource string) schema.GroupResource {
	return SchemeGroupVersion.WithResource(resource).GroupResource()
}
