// Copyright (c) 2019-2020 Tigera, Inc. All rights reserved.

package projectcalico

import (
	calico "github.com/projectcalico/libcalico-go/lib/apis/v3"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// NetworkPolicyList is a list of Policy objects.
type NetworkPolicyList struct {
	metav1.TypeMeta
	metav1.ListMeta

	Items []NetworkPolicy
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type NetworkPolicy struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	Spec calico.NetworkPolicySpec
}

// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// GlobalNetworkPolicyList is a list of Policy objects.
type GlobalNetworkPolicyList struct {
	metav1.TypeMeta
	metav1.ListMeta

	Items []GlobalNetworkPolicy
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type GlobalNetworkPolicy struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	Spec calico.GlobalNetworkPolicySpec
}

// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// GlobalNetworkPolicyList is a list of Policy objects.
type GlobalNetworkSetList struct {
	metav1.TypeMeta
	metav1.ListMeta

	Items []GlobalNetworkSet
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type GlobalNetworkSet struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	Spec calico.GlobalNetworkSetSpec
}

// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// NetworkPolicyList is a list of Policy objects.
type NetworkSetList struct {
	metav1.TypeMeta
	metav1.ListMeta

	Items []NetworkSet
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type NetworkSet struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	Spec calico.NetworkSetSpec
}

// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// HostEndpointList is a list of Policy objects.
type HostEndpointList struct {
	metav1.TypeMeta
	metav1.ListMeta

	Items []HostEndpoint
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type HostEndpoint struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	Spec calico.HostEndpointSpec
}

// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// IPPoolList contains a list of IPPool resources.
type IPPoolList struct {
	metav1.TypeMeta
	metav1.ListMeta

	Items []IPPool
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type IPPool struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	Spec calico.IPPoolSpec
}

// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// BGPConfigurationList is a list of BGPConfiguration objects.
type BGPConfigurationList struct {
	metav1.TypeMeta
	metav1.ListMeta

	Items []BGPConfiguration
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type BGPConfiguration struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	Spec calico.BGPConfigurationSpec
}

// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// BGPPeerList is a list of BGPPeer objects.
type BGPPeerList struct {
	metav1.TypeMeta
	metav1.ListMeta

	Items []BGPPeer
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type BGPPeer struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	Spec calico.BGPPeerSpec
}

// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ProfileList is a list of Profile objects.
type ProfileList struct {
	metav1.TypeMeta
	metav1.ListMeta

	Items []Profile
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type Profile struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	Spec calico.ProfileSpec
}

// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// FelixConfigurationList is a list of FelixConfiguration objects.
type FelixConfigurationList struct {
	metav1.TypeMeta
	metav1.ListMeta

	Items []FelixConfiguration
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type FelixConfiguration struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	Spec calico.FelixConfigurationSpec
}

// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// KubeControllersConfigurationList is a list of KubeControllersConfiguration objects.
type KubeControllersConfigurationList struct {
	metav1.TypeMeta
	metav1.ListMeta

	Items []KubeControllersConfiguration
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type KubeControllersConfiguration struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	Spec   calico.KubeControllersConfigurationSpec
	Status calico.KubeControllersConfigurationStatus
}

// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ClusterInformationList is a list of ClusterInformation objects.
type ClusterInformationList struct {
	metav1.TypeMeta
	metav1.ListMeta

	Items []ClusterInformation
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type ClusterInformation struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	Spec calico.ClusterInformationSpec
}
