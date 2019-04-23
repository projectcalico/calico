// Copyright (c) 2017-2019 Tigera, Inc. All rights reserved.

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
	"github.com/projectcalico/libcalico-go/lib/apiconfig"
	apiv3 "github.com/projectcalico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/backend/syncersv1/updateprocessors"
	"github.com/projectcalico/libcalico-go/lib/backend/watchersyncer"
)

// New creates a new Felix v1 Syncer.
func New(client api.Client, cfg apiconfig.CalicoAPIConfigSpec, callbacks api.SyncerCallbacks) api.Syncer {
	// Create the set of ResourceTypes required for Felix.  Since the update processors
	// also cache state, we need to create individual ones per syncer rather than create
	// a common global set.
	resourceTypes := []watchersyncer.ResourceType{
		{
			ListInterface:   model.ResourceListOptions{Kind: apiv3.KindClusterInformation},
			UpdateProcessor: updateprocessors.NewClusterInfoUpdateProcessor(),
		},
		{
			ListInterface:   model.ResourceListOptions{Kind: apiv3.KindFelixConfiguration},
			UpdateProcessor: updateprocessors.NewFelixConfigUpdateProcessor(),
		},
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
			ListInterface:   model.ResourceListOptions{Kind: apiv3.KindNode},
			UpdateProcessor: updateprocessors.NewFelixNodeUpdateProcessor(),
		},
		{
			ListInterface:   model.ResourceListOptions{Kind: apiv3.KindProfile},
			UpdateProcessor: updateprocessors.NewProfileUpdateProcessor(),
		},
		{
			ListInterface:   model.ResourceListOptions{Kind: apiv3.KindWorkloadEndpoint},
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
	}

	// If using Calico IPAM, include IPAM resources the felix cares about.
	if !cfg.K8sUsePodCIDR {
		resourceTypes = append(resourceTypes, watchersyncer.ResourceType{ListInterface: model.BlockListOptions{}})
	}

	return watchersyncer.New(
		client,
		resourceTypes,
		callbacks,
	)
}
