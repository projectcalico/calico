// Copyright (c) 2017-2020 Tigera, Inc. All rights reserved.
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

package node

import (
	api "github.com/projectcalico/libcalico-go/lib/apis/v3"
	apiv3 "github.com/projectcalico/libcalico-go/lib/apis/v3"
	bapi "github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/backend/watchersyncer"
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
)

func (c *NodeController) initSyncer() {
	resourceTypes := []watchersyncer.ResourceType{
		{
			ListInterface: model.ResourceListOptions{Kind: apiv3.KindNode},
		},
		{
			ListInterface: model.BlockListOptions{},
		},
	}
	type accessor interface {
		Backend() bapi.Client
	}
	c.syncer = watchersyncer.New(c.calicoClient.(accessor).Backend(), resourceTypes, c)
}

// listBlocks returns the full set of IPAM blocks from the controller's cache, as populated by the syncer.
func (c *NodeController) listBlocks() (map[string]model.KVPair, error) {
	c.Lock()
	defer c.Unlock()

	// Make a copy of the blocks map to return.
	blocks := make(map[string]model.KVPair, len(c.allBlocks))
	for k, v := range c.allBlocks {
		blocks[k] = v
	}
	return blocks, nil
}

// getCalicoNode returns the Calico node name for the given Kubernetes node name, as it exists in the syncer's cache,
// and a boolean indicating cache hit or miss.
func (c *NodeController) getCalicoNode(kn string) (string, bool) {
	c.Lock()
	defer c.Unlock()
	cn, ok := c.nodemapper[kn]
	return cn, ok
}

func (c *NodeController) OnStatusUpdated(status bapi.SyncStatus) {
	logrus.Infof("Node controller syncer status updated: %s", status)
	c.syncStatus = status

	switch status {
	case bapi.ResyncInProgress:
		// Starting the resync so clear our node cache.
		c.nodeCache = make(map[string]*api.Node)

	case bapi.InSync:
		err := c.syncAllAutoHostendpoints()
		if err != nil {
			logrus.WithError(err).Fatal("failed to sync all auto hostendpoints")
		}
	}
}

func (c *NodeController) OnUpdates(updates []bapi.Update) {
	logrus.Debugf("Node controller syncer received updates: %#v", updates)
	for _, upd := range updates {
		switch upd.UpdateType {
		case bapi.UpdateTypeKVNew:
			fallthrough

		case bapi.UpdateTypeKVUpdated:
			switch upd.KVPair.Value.(type) {
			case *model.AllocationBlock:
				c.Lock()
				c.allBlocks[upd.Key.(model.BlockKey).CIDR.String()] = upd.KVPair
				c.Unlock()
				kick(c.blockUpdate)
			case *apiv3.Node:
				n := upd.KVPair.Value.(*apiv3.Node)

				if kn := getK8sNodeName(*n); kn != "" {
					// Create a mapping from Kubernetes node -> Calico node.
					logrus.Debugf("Mapping k8s node -> calico node. %s -> %s", kn, n.Name)
					c.Lock()
					c.nodemapper[kn] = n.Name
					c.Unlock()

					if c.config.SyncLabels {
						// It has a node reference - get that Kubernetes node, and if
						// it exists perform a sync.
						obj, ok, err := c.indexer.GetByKey(kn)

						// Sync labels if there is a corresponding kubernetes node.
						// If we can't get a kubernetes node, just log.
						// We want execution for this event to continue onto the
						// auto host endpoints processing logic.
						if !ok {
							logrus.Debugf("No corresponding kubernetes node")
						} else if err != nil {
							logrus.WithError(err).Warnf("Couldn't get node from indexer")
						} else {
							c.syncNodeLabels(obj.(*v1.Node))
						}
					}
				}

				if c.config.AutoHostEndpoints {
					// Cache all updated nodes.
					c.nodeCache[n.Name] = n

					// If we're already in-sync, sync the node's auto hostendpoint.
					if c.syncStatus == bapi.InSync {
						err := c.syncAutoHostendpointWithRetries(n)
						if err != nil {
							logrus.WithError(err).Fatal()
						}
					}
				}
			}

		case bapi.UpdateTypeKVDeleted:
			if upd.KVPair.Value != nil {
				logrus.Warnf("KVPair value should be nil for Deleted UpdataType")
			}

			switch upd.KVPair.Key.(type) {
			case model.BlockKey:
				c.Lock()
				delete(c.allBlocks, upd.Key.(model.BlockKey).CIDR.String())
				c.Unlock()
				kick(c.blockUpdate)
			case model.ResourceKey:
				switch upd.KVPair.Key.(model.ResourceKey).Kind {
				case apiv3.KindNode:
					// Try to perform unmapping based on resource name (calico node name).
					nodeName := upd.KVPair.Key.(model.ResourceKey).Name
					for kn, cn := range c.nodemapper {
						if cn == nodeName {
							// Remove it from node map.
							logrus.Debugf("Unmapping k8s node -> calico node. %s -> %s", kn, cn)
							c.Lock()
							delete(c.nodemapper, kn)
							c.Unlock()
							break
						}
					}

					if c.config.AutoHostEndpoints && c.syncStatus == bapi.InSync {
						hepName := c.generateAutoHostendpointName(nodeName)
						err := c.deleteHostendpointWithRetries(hepName)
						if err != nil {
							logrus.WithError(err).Fatal()
						}
					}
				default:
					// Shouldn't have any other kinds show up here.
					logrus.Warnf("Unexpected kind received over syncer: %s", upd.KVPair.Key.(model.ResourceKey).Kind)
				}
			}

		default:
			logrus.Errorf("Unhandled update type")
		}
	}
}
