// Copyright (c) 2017 Tigera, Inc. All rights reserved.

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

package bgpsyncer

import (
	apiv3 "github.com/projectcalico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/backend/syncersv1/updateprocessors"
	"github.com/projectcalico/libcalico-go/lib/backend/watchersyncer"
)

// New creates a new BGP v1 Syncer.  Since only etcdv3 supports Watchers for all of
// the required resource types, the WatcherSyncer will go into a polling loop for
// KDD.  An optional node name may be supplied.  If set, the syncer only watches
// the specified node rather than all nodes.
func New(client api.Client, callbacks api.SyncerCallbacks, node string, watchAllNodes bool) api.Syncer {
	// Create the set of ResourceTypes required for Felix.  Since the update processors
	// also cache state, we need to create individual ones per syncer rather than create
	// a common global set.
	// For BGP we always only care about affinity blocks assigned to our own particuar node.
	// However, depending on whether we are in full-mesh mode or not changes whether we want
	// to watch all Node resources or just our own.
	nodeToWatch := node
	if watchAllNodes {
		nodeToWatch = ""
	}
	resourceTypes := []watchersyncer.ResourceType{
		{
			ListInterface:   model.ResourceListOptions{Kind: apiv3.KindIPPool},
			UpdateProcessor: updateprocessors.NewIPPoolUpdateProcessor(),
		},
		{
			ListInterface:   model.ResourceListOptions{Kind: apiv3.KindBGPConfiguration},
			UpdateProcessor: updateprocessors.NewBGPConfigUpdateProcessor(),
		},
		{
			ListInterface: model.ResourceListOptions{
				Kind: apiv3.KindNode,
				Name: nodeToWatch,
			},
			UpdateProcessor: updateprocessors.NewBGPNodeUpdateProcessor(),
		},
		{
			ListInterface:   model.ResourceListOptions{Kind: apiv3.KindBGPPeer},
			UpdateProcessor: updateprocessors.NewBGPPeerUpdateProcessor(),
		},
		{
			ListInterface: model.BlockAffinityListOptions{Host: node},
		},
	}

	return watchersyncer.New(
		client,
		resourceTypes,
		callbacks,
	)
}
