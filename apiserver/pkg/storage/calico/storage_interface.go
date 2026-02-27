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
	case "projectcalico.org/stagedkubernetesnetworkpolicies":
		return NewStagedKubernetesNetworkPolicyStorage(opts)
	case "projectcalico.org/stagednetworkpolicies":
		return NewStagedNetworkPolicyStorage(opts)
	case "projectcalico.org/globalnetworkpolicies":
		return NewGlobalNetworkPolicyStorage(opts)
	case "projectcalico.org/stagedglobalnetworkpolicies":
		return NewStagedGlobalNetworkPolicyStorage(opts)
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
	case "projectcalico.org/kubecontrollersconfigurations/status":
		return NewKubeControllersConfigurationStatusStorage(opts)
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
