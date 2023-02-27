// Copyright (c) 2017-2020 Tigera, Ic. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package node

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"

	apiv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

func NewNodeLabelController(c client.Interface) *nodeLabelController {
	return &nodeLabelController{
		nodemapper: map[string]string{},
		client:     c,
	}
}

// nodeLabelController is responsible for syncing Node labels in etcd mode.
type nodeLabelController struct {
	// The node label controller receives a async event streams
	// from both the Kubernetes API informer as well as the Calico Syncer.
	// We use a Mutex to lock data as we work on it.
	sync.Mutex

	// nodemapper maps a Kubernetes node name to the corresponding Calico node name.
	nodemapper map[string]string

	// For interacting with the Calico API to update nodes.
	client client.Interface
}

func (c *nodeLabelController) RegisterWith(f *DataFeed) {
	// We want nodes, which are sent with key model.ResourceKey
	f.RegisterForNotification(model.ResourceKey{}, c.onUpdate)
	f.RegisterForSyncStatus(c.onStatusUpdate)
}

func (c *nodeLabelController) onStatusUpdate(s bapi.SyncStatus) {
	// No-op.
}

// onUpdate receives node objects and maintains the mapping of Kubernetes nodes to Calico nodes.
func (c *nodeLabelController) onUpdate(update bapi.Update) {
	// Use the presence / absence of the update Value to determine if this is a delete or not.
	// The value can be nil even if the UpdateType is New or Updated if it is the result of a
	// failed validation in the syncer, and we want to treat those as deletes.
	if update.Value != nil {
		switch update.KVPair.Value.(type) {
		case *apiv3.Node:
			n := update.KVPair.Value.(*apiv3.Node)
			kn, err := getK8sNodeName(*n)
			if err != nil {
				log.WithError(err).Info("Unable to get corresponding k8s node name, skipping")
			} else if kn != "" {
				// Create a mapping from Kubernetes node -> Calico node.
				logrus.Debugf("Mapping k8s node -> calico node. %s -> %s", kn, n.Name)
				c.Lock()
				c.nodemapper[kn] = n.Name
				c.Unlock()
			}
		default:
			// Shouldn't have any other kinds show up here.
			logrus.Warnf("Unexpected kind received over syncer: %s", update.KVPair.Key)
		}
	} else {
		switch update.KVPair.Key.(type) {
		case model.ResourceKey:
			switch update.KVPair.Key.(model.ResourceKey).Kind {
			case apiv3.KindNode:
				// Try to perform unmapping based on resource name (calico node name).
				nodeName := update.KVPair.Key.(model.ResourceKey).Name
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
			default:
				// Shouldn't have any other kinds show up here.
				logrus.Warnf("Unexpected kind received over syncer: %s", update.KVPair.Key)
			}
		}

	}
}

// OnKubernetesNodeUpdate is called by the Kubernetes informer callback when a node is added or updated.
// This may not be called from the same goroutine as onUpdate, and so care should be taken in sharing data.
func (c *nodeLabelController) OnKubernetesNodeUpdate(obj interface{}) {
	if n, ok := obj.(*v1.Node); ok {
		c.syncNodeLabels(n)
	} else {
		log.Warnf("Received update that is not a v1.Node: %+v", obj)
	}
}

// getCalicoNode returns the Calico node name for the given Kubernetes node name, as it exists in the syncer's cache,
// and a boolean indicating cache hit or miss.
func (c *nodeLabelController) getCalicoNode(kn string) (string, bool) {
	c.Lock()
	defer c.Unlock()
	cn, ok := c.nodemapper[kn]
	return cn, ok
}

// syncNodeLabels syncs the labels found in v1.Node to the Calico node object.
// It uses an annotation on the Calico node object to keep track of which labels have
// been synced from Kubernetes, so that it doesn't overwrite user provided labels (e.g.,
// via calicoctl or another Calico controller).
func (c *nodeLabelController) syncNodeLabels(node *v1.Node) {
	// On failure, we retry a certain number of times.
	for n := 1; n < 5; n++ {
		// Get the Calico node representation.
		name, ok := c.getCalicoNode(node.Name)
		if !ok {
			// We haven't learned this Calico node yet.
			log.Debugf("Skipping update for node with no Calico equivalent")
			return
		}
		calNode, err := c.client.Nodes().Get(context.Background(), name, options.GetOptions{})
		if err != nil {
			log.WithError(err).Warnf("Failed to get node, retrying")
			time.Sleep(retrySleepTime)
			continue
		}
		if calNode.Labels == nil {
			calNode.Labels = map[string]string{}
		}
		if calNode.Annotations == nil {
			calNode.Annotations = map[string]string{}
		}

		// Track if we need to perform an update.
		needsUpdate := false

		// Check if it has the annotation for k8s labels.

		// If there are labels present, then parse them. Otherwise this is
		// a first-time sync, in which case there are no old labels.
		oldLabels := map[string]string{}
		if a, ok := calNode.Annotations[nodeLabelAnnotation]; ok {
			if err = json.Unmarshal([]byte(a), &oldLabels); err != nil {
				log.WithError(err).Error("Failed to unmarshal node labels")
				return
			}
		}
		log.Debugf("Determined previously synced labels: %s", oldLabels)

		// We've synced labels before. Determine diffs to apply.
		// For each k/v in node.Labels, if it isn't present or the value
		// differs, add it to the node.
		for k, v := range node.Labels {
			if v2, ok := calNode.Labels[k]; !ok || v != v2 {
				log.Debugf("Adding node label %s=%s", k, v)
				calNode.Labels[k] = v
				needsUpdate = true
			}
		}

		// For each k/v that used to be in the k8s node labels, but is no longer,
		// remove it from the Calico node.
		for k, v := range oldLabels {
			if _, ok := node.Labels[k]; !ok {
				// The old label is no longer present. Remove it.
				log.Debugf("Deleting node label %s=%s", k, v)
				delete(calNode.Labels, k)
				needsUpdate = true
			}
		}

		// Set the annotation to the correct values.
		bytes, err := json.Marshal(node.Labels)
		if err != nil {
			log.WithError(err).Errorf("Error marshalling node labels")
			return
		}
		calNode.Annotations[nodeLabelAnnotation] = string(bytes)

		// Update the node in the datastore.
		if needsUpdate {
			if _, err := c.client.Nodes().Update(context.Background(), calNode, options.SetOptions{}); err != nil {
				log.WithError(err).Warnf("Failed to update node, retrying")
				time.Sleep(retrySleepTime)
				continue
			}
			log.WithField("node", node.ObjectMeta.Name).Info("Successfully synced node labels")
		}
		return
	}
	log.Errorf("Too many retries when updating node")
}
