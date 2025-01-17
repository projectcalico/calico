// Copyright (c) 2019-2024 Tigera, Inc. All rights reserved.

package calico

import (
	"github.com/sirupsen/logrus"
	"k8s.io/apiserver/pkg/registry/generic/registry"
	"k8s.io/apiserver/pkg/storage/storagebackend/factory"
)

// NewStorage creates a new libcalico-based storage.Interface implementation
func NewStorage(opts Options) (registry.DryRunnableStorage, factory.DestroyFunc) {
	logrus.Debug("Constructing Calico Storage")

	switch opts.RESTOptions.ResourcePrefix {
	case "projectcalico.org/networkpolicies":
		return NewNetworkPolicyStorage(opts)
	case "projectcalico.org/globalnetworkpolicies":
		return NewGlobalNetworkPolicyStorage(opts)
	case "projectcalico.org/tiers":
		return NewTierStorage(opts)
	case "projectcalico.org/globalnetworksets":
		return NewGlobalNetworkSetStorage(opts)
	case "projectcalico.org/networksets":
		return NewNetworkSetStorage(opts)
	case "projectcalico.org/hostendpoints":
		return NewHostEndpointStorage(opts)
	case "projectcalico.org/ippools":
		return NewIPPoolStorage(opts)
	case "projectcalico.org/ipreservations":
		return NewIPReservationStorage(opts)
	case "projectcalico.org/bgpconfigurations":
		return NewBGPConfigurationStorage(opts)
	case "projectcalico.org/bgppeers":
		return NewBGPPeerStorage(opts)
	case "projectcalico.org/bgpfilters":
		return NewBGPFilterStorage(opts)
	case "projectcalico.org/profiles":
		return NewProfileStorage(opts)
	case "projectcalico.org/felixconfigurations":
		return NewFelixConfigurationStorage(opts)
	case "projectcalico.org/kubecontrollersconfigurations":
		return NewKubeControllersConfigurationStorage(opts)
	case "projectcalico.org/clusterinformations":
		return NewClusterInformationStorage(opts)
	case "projectcalico.org/caliconodestatuses":
		return NewCalicoNodeStatusStorage(opts)
	case "projectcalico.org/ipamconfigurations":
		return NewIPAMConfigurationStorage(opts)
	case "projectcalico.org/blockaffinities":
		return NewBlockAffinityStorage(opts)
	default:
		logrus.Fatalf("Unable to create storage for resource %v", opts.RESTOptions.ResourcePrefix)
		return registry.DryRunnableStorage{}, nil
	}
}
