// Copyright (c) 2017-2021 Tigera, Inc. All rights reserved.

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

package felixsyncer

import (
	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	libapiv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/syncersv1/updateprocessors"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/watchersyncer"
)

// New creates a new Felix v1 Syncer.
func New(client api.Client, cfg apiconfig.CalicoAPIConfigSpec, callbacks api.SyncerCallbacks, isLeader bool) api.Syncer {
	// Felix always needs ClusterInformation and FelixConfiguration resources.
	resourceTypes := []watchersyncer.ResourceType{
		{
			ListInterface:   model.ResourceListOptions{Kind: apiv3.KindClusterInformation},
			UpdateProcessor: updateprocessors.NewClusterInfoUpdateProcessor(),
		},
		{
			ListInterface:   model.ResourceListOptions{Kind: apiv3.KindFelixConfiguration},
			UpdateProcessor: updateprocessors.NewFelixConfigUpdateProcessor(),
		},
	}

	if isLeader {
		// These resources are only required if this is the active Felix instance on the node.
		additionalTypes := []watchersyncer.ResourceType{
			{
				ListInterface:   model.ResourceListOptions{Kind: apiv3.KindGlobalNetworkPolicy},
				UpdateProcessor: updateprocessors.NewGlobalNetworkPolicyUpdateProcessor(),
			},
			{
				ListInterface:   model.ResourceListOptions{Kind: apiv3.KindGlobalNetworkSet},
				UpdateProcessor: updateprocessors.NewGlobalNetworkSetUpdateProcessor(),
			},
			{
				ListInterface:   model.ResourceListOptions{Kind: apiv3.KindIPPool},
				UpdateProcessor: updateprocessors.NewIPPoolUpdateProcessor(),
			},
			{
				ListInterface:   model.ResourceListOptions{Kind: libapiv3.KindNode},
				UpdateProcessor: updateprocessors.NewFelixNodeUpdateProcessor(cfg.K8sUsePodCIDR),
			},
			{
				ListInterface:   model.ResourceListOptions{Kind: apiv3.KindProfile},
				UpdateProcessor: updateprocessors.NewProfileUpdateProcessor(),
			},
			{
				ListInterface:   model.ResourceListOptions{Kind: libapiv3.KindWorkloadEndpoint},
				UpdateProcessor: updateprocessors.NewWorkloadEndpointUpdateProcessor(),
			},
			{
				ListInterface:   model.ResourceListOptions{Kind: apiv3.KindNetworkPolicy},
				UpdateProcessor: updateprocessors.NewNetworkPolicyUpdateProcessor(),
			},
			{
				ListInterface:   model.ResourceListOptions{Kind: apiv3.KindNetworkSet},
				UpdateProcessor: updateprocessors.NewNetworkSetUpdateProcessor(),
			},
			{
				ListInterface:   model.ResourceListOptions{Kind: apiv3.KindHostEndpoint},
				UpdateProcessor: updateprocessors.NewHostEndpointUpdateProcessor(),
			},
			{
				ListInterface: model.ResourceListOptions{Kind: apiv3.KindBGPConfiguration},
			},
		}

		// If running in kdd mode, also watch Kubernetes network policies directly.
		// We don't need this in etcd mode, since kube-controllers copies k8s policies into etcd.
		if cfg.DatastoreType == apiconfig.Kubernetes {
			additionalTypes = append(additionalTypes, watchersyncer.ResourceType{
				ListInterface:   model.ResourceListOptions{Kind: model.KindKubernetesNetworkPolicy},
				UpdateProcessor: updateprocessors.NewNetworkPolicyUpdateProcessor(),
			})
			additionalTypes = append(additionalTypes, watchersyncer.ResourceType{
				ListInterface: model.ResourceListOptions{Kind: model.KindKubernetesEndpointSlice},
			})
			additionalTypes = append(additionalTypes, watchersyncer.ResourceType{
				ListInterface: model.ResourceListOptions{Kind: model.KindK8sService},
			})
		}

		// If using Calico IPAM, include IPAM resources that felix cares about.
		if !cfg.K8sUsePodCIDR {
			additionalTypes = append(additionalTypes, watchersyncer.ResourceType{ListInterface: model.BlockListOptions{}})
		}

		resourceTypes = append(resourceTypes, additionalTypes...)
	}

	return watchersyncer.New(
		client,
		resourceTypes,
		callbacks,
	)
}
