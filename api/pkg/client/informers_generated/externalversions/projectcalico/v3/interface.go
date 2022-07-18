// Copyright (c) 2022 Tigera, Inc. All rights reserved.

// Code generated by informer-gen. DO NOT EDIT.

package v3

import (
	internalinterfaces "github.com/projectcalico/api/pkg/client/informers_generated/externalversions/internalinterfaces"
)

// Interface provides access to all the informers in this group version.
type Interface interface {
	// BGPConfigurations returns a BGPConfigurationInformer.
	BGPConfigurations() BGPConfigurationInformer
	// BGPPeers returns a BGPPeerInformer.
	BGPPeers() BGPPeerInformer
	// CalicoNodeStatuses returns a CalicoNodeStatusInformer.
	CalicoNodeStatuses() CalicoNodeStatusInformer
	// ClusterInformations returns a ClusterInformationInformer.
	ClusterInformations() ClusterInformationInformer
	// FelixConfigurations returns a FelixConfigurationInformer.
	FelixConfigurations() FelixConfigurationInformer
	// GlobalNetworkPolicies returns a GlobalNetworkPolicyInformer.
	GlobalNetworkPolicies() GlobalNetworkPolicyInformer
	// GlobalNetworkSets returns a GlobalNetworkSetInformer.
	GlobalNetworkSets() GlobalNetworkSetInformer
	// HostEndpoints returns a HostEndpointInformer.
	HostEndpoints() HostEndpointInformer
	// IPAMConfigs returns a IPAMConfigInformer.
	IPAMConfigs() IPAMConfigInformer
	// IPPools returns a IPPoolInformer.
	IPPools() IPPoolInformer
	// IPReservations returns a IPReservationInformer.
	IPReservations() IPReservationInformer
	// KubeControllersConfigurations returns a KubeControllersConfigurationInformer.
	KubeControllersConfigurations() KubeControllersConfigurationInformer
	// NetworkPolicies returns a NetworkPolicyInformer.
	NetworkPolicies() NetworkPolicyInformer
	// NetworkSets returns a NetworkSetInformer.
	NetworkSets() NetworkSetInformer
	// Profiles returns a ProfileInformer.
	Profiles() ProfileInformer
}

type version struct {
	factory          internalinterfaces.SharedInformerFactory
	namespace        string
	tweakListOptions internalinterfaces.TweakListOptionsFunc
}

// New returns a new Interface.
func New(f internalinterfaces.SharedInformerFactory, namespace string, tweakListOptions internalinterfaces.TweakListOptionsFunc) Interface {
	return &version{factory: f, namespace: namespace, tweakListOptions: tweakListOptions}
}

// BGPConfigurations returns a BGPConfigurationInformer.
func (v *version) BGPConfigurations() BGPConfigurationInformer {
	return &bGPConfigurationInformer{factory: v.factory, tweakListOptions: v.tweakListOptions}
}

// BGPPeers returns a BGPPeerInformer.
func (v *version) BGPPeers() BGPPeerInformer {
	return &bGPPeerInformer{factory: v.factory, tweakListOptions: v.tweakListOptions}
}

// CalicoNodeStatuses returns a CalicoNodeStatusInformer.
func (v *version) CalicoNodeStatuses() CalicoNodeStatusInformer {
	return &calicoNodeStatusInformer{factory: v.factory, tweakListOptions: v.tweakListOptions}
}

// ClusterInformations returns a ClusterInformationInformer.
func (v *version) ClusterInformations() ClusterInformationInformer {
	return &clusterInformationInformer{factory: v.factory, tweakListOptions: v.tweakListOptions}
}

// FelixConfigurations returns a FelixConfigurationInformer.
func (v *version) FelixConfigurations() FelixConfigurationInformer {
	return &felixConfigurationInformer{factory: v.factory, tweakListOptions: v.tweakListOptions}
}

// GlobalNetworkPolicies returns a GlobalNetworkPolicyInformer.
func (v *version) GlobalNetworkPolicies() GlobalNetworkPolicyInformer {
	return &globalNetworkPolicyInformer{factory: v.factory, tweakListOptions: v.tweakListOptions}
}

// GlobalNetworkSets returns a GlobalNetworkSetInformer.
func (v *version) GlobalNetworkSets() GlobalNetworkSetInformer {
	return &globalNetworkSetInformer{factory: v.factory, tweakListOptions: v.tweakListOptions}
}

// HostEndpoints returns a HostEndpointInformer.
func (v *version) HostEndpoints() HostEndpointInformer {
	return &hostEndpointInformer{factory: v.factory, tweakListOptions: v.tweakListOptions}
}

// IPAMConfigs returns a IPAMConfigInformer.
func (v *version) IPAMConfigs() IPAMConfigInformer {
	return &iPAMConfigInformer{factory: v.factory, tweakListOptions: v.tweakListOptions}
}

// IPPools returns a IPPoolInformer.
func (v *version) IPPools() IPPoolInformer {
	return &iPPoolInformer{factory: v.factory, tweakListOptions: v.tweakListOptions}
}

// IPReservations returns a IPReservationInformer.
func (v *version) IPReservations() IPReservationInformer {
	return &iPReservationInformer{factory: v.factory, tweakListOptions: v.tweakListOptions}
}

// KubeControllersConfigurations returns a KubeControllersConfigurationInformer.
func (v *version) KubeControllersConfigurations() KubeControllersConfigurationInformer {
	return &kubeControllersConfigurationInformer{factory: v.factory, tweakListOptions: v.tweakListOptions}
}

// NetworkPolicies returns a NetworkPolicyInformer.
func (v *version) NetworkPolicies() NetworkPolicyInformer {
	return &networkPolicyInformer{factory: v.factory, namespace: v.namespace, tweakListOptions: v.tweakListOptions}
}

// NetworkSets returns a NetworkSetInformer.
func (v *version) NetworkSets() NetworkSetInformer {
	return &networkSetInformer{factory: v.factory, namespace: v.namespace, tweakListOptions: v.tweakListOptions}
}

// Profiles returns a ProfileInformer.
func (v *version) Profiles() ProfileInformer {
	return &profileInformer{factory: v.factory, tweakListOptions: v.tweakListOptions}
}
