// Copyright (c) 2019-2020 Tigera, Inc. All rights reserved.

package projectcalico

import (
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// GroupName is the group name use in this package
const GroupName = "projectcalico.org"

// SchemeGroupVersion is group version used to register these objects
var SchemeGroupVersion = schema.GroupVersion{Group: GroupName, Version: runtime.APIVersionInternal}

// Kind takes an unqualified kind and returns back a Group qualified GroupKind
func Kind(kind string) schema.GroupKind {
	return SchemeGroupVersion.WithKind(kind).GroupKind()
}

// Resource takes an unqualified resource and returns back a Group qualified GroupResource
func Resource(resource string) schema.GroupResource {
	return SchemeGroupVersion.WithResource(resource).GroupResource()
}

var (
	// SchemeBuilder needs to be exported as `SchemeBuilder` so
	// the code-generation can find it.
	SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)
	// AddToScheme is exposed for API installation
	AddToScheme = SchemeBuilder.AddToScheme
)

// Adds the list of known types to api.Scheme.
func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(SchemeGroupVersion,
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
		&BGPConfiguration{},
		&BGPConfigurationList{},
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
	)
	return nil
}
