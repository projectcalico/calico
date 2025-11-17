// Copyright (c) 2017-2025 Tigera, Ic. All rights reserved.
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
	"time"

	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	v1lister "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/utils"
	apiv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

// nodeLabelController is responsible for syncing Node labels in etcd mode.
type nodeLabelController struct {
	// k8sNodeMapper maps a Kubernetes node name to the corresponding Calico node name.
	k8sNodeMapper map[string]string

	// calicoNodeCache stores calicoNodes received via the syncer in local map
	calicoNodeCache map[string]*apiv3.Node

	// For interacting with the Calico API to update nodes.
	client client.Interface

	nodeInformer  cache.SharedIndexInformer
	nodeLister    v1lister.NodeLister
	syncStatus    bapi.SyncStatus
	syncerUpdates chan interface{}
	k8sNodeUpdate chan *v1.Node
	syncChan      chan interface{}
}

func NewNodeLabelController(client client.Interface, nodeInformer cache.SharedIndexInformer) *nodeLabelController {
	c := &nodeLabelController{
		k8sNodeMapper:   map[string]string{},
		calicoNodeCache: map[string]*apiv3.Node{},
		client:          client,
		nodeInformer:    nodeInformer,
		nodeLister:      v1lister.NewNodeLister(nodeInformer.GetIndexer()),
		syncerUpdates:   make(chan interface{}, utils.BatchUpdateSize),
		k8sNodeUpdate:   make(chan *v1.Node, utils.BatchUpdateSize),
		syncChan:        make(chan interface{}, 1),
	}

	_, err := c.nodeInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.OnKubernetesNodeAdd,
		UpdateFunc: c.OnKubernetesNodeUpdate,
		DeleteFunc: c.OnKubernetesNodeDelete,
	})
	if err != nil {
		logrus.WithError(err).Fatal("Failed to add event handler for Node")
	}

	return c
}

func (c *nodeLabelController) OnKubernetesNodeAdd(obj interface{}) {
	if n, ok := obj.(*v1.Node); ok {
		c.k8sNodeUpdate <- n
	}
}

func (c *nodeLabelController) OnKubernetesNodeUpdate(objOld interface{}, objNew interface{}) {
	if n, ok := objNew.(*v1.Node); ok {
		c.k8sNodeUpdate <- n
	}
}

func (c *nodeLabelController) OnKubernetesNodeDelete(obj interface{}) {
	if n, ok := obj.(*v1.Node); ok {
		c.k8sNodeUpdate <- n
	}
}

func (c *nodeLabelController) Start(stopCh chan struct{}) {
	go c.acceptScheduledRequests(stopCh)
}

func (c *nodeLabelController) RegisterWith(f *utils.DataFeed) {
	// We want nodes, which are sent with key model.ResourceKey
	f.RegisterForNotification(model.ResourceKey{}, c.onUpdate)
	f.RegisterForSyncStatus(c.onStatusUpdate)
}

func (c *nodeLabelController) onStatusUpdate(s bapi.SyncStatus) {
	c.syncerUpdates <- s
}

func (c *nodeLabelController) onUpdate(update bapi.Update) {
	switch update.Key.(type) {
	case model.ResourceKey:
		switch update.KVPair.Key.(model.ResourceKey).Kind {
		case apiv3.KindNode:
			c.syncerUpdates <- update.KVPair
		}
	}
}

func (c *nodeLabelController) handleUpdate(update interface{}) {
	switch update := update.(type) {
	case bapi.SyncStatus:
		c.syncStatus = update
		switch update {
		case bapi.InSync:
			logrus.WithField("status", update).Info("Syncer in sync, kicking sync channel")
			kick(c.syncChan)
		}
	case model.KVPair:
		switch update.Key.(type) {
		case model.ResourceKey:
			switch update.Key.(model.ResourceKey).Kind {
			case apiv3.KindNode:
				c.handleNodeUpdate(update)
			}
		}
	}
}

// onUpdate receives node objects and maintains the mapping of Kubernetes nodes to Calico nodes.
func (c *nodeLabelController) handleNodeUpdate(update model.KVPair) {
	// Use the presence / absence of the update Value to determine if this is a delete or not.
	// The value can be nil even if the UpdateType is New or Updated if it is the result of a
	// failed validation in the syncer, and we want to treat those as deletes.
	if update.Value == nil {
		nodeName := update.Key.(model.ResourceKey).Name
		// Try to perform unmapping based on resource name (calico node name).
		for kn, cn := range c.k8sNodeMapper {
			if cn == nodeName {
				// Remove it from node map.
				logrus.Debugf("Unmapping k8s node -> calico node. %s -> %s", kn, cn)
				delete(c.k8sNodeMapper, kn)
				delete(c.calicoNodeCache, cn)
				break
			}
		}
		return
	}

	n := update.Value.(*apiv3.Node)

	kn, err := getK8sNodeName(*n)
	if err != nil {
		logrus.WithError(err).Info("Unable to get corresponding k8s node name, skipping")
		return
	}

	if kn == "" {
		logrus.WithError(err).Info("Corresponding k8s node name is empty, skipping")
		return
	}

	// Create a mapping from Kubernetes node -> Calico node.
	logrus.Debugf("Mapping k8s node -> calico node. %s -> %s", kn, n.Name)

	c.k8sNodeMapper[kn] = n.Name

	node, err := c.nodeLister.Get(kn)
	if err != nil {
		logrus.WithError(err).WithField("node", kn).Error("Unable to get node")
	}

	_, existsCalicoNode := c.calicoNodeCache[n.Name]
	c.calicoNodeCache[n.Name] = n
	if !existsCalicoNode &&
		node != nil &&
		c.syncStatus == bapi.InSync {
		// If this is new calicoNode trigger sync for corresponding k8s node, if the k8s node exists.
		// As we only sync labels k8s -> calico node, no need to sync when calico node already exists in our cache
		c.k8sNodeUpdate <- node
	}
}

func (c *nodeLabelController) acceptScheduledRequests(stopCh <-chan struct{}) {
	logrus.Infof("Will run periodic Node labels sync every %s", timer)
	t := time.NewTicker(timer)
	for {
		select {
		case update := <-c.syncerUpdates:
			c.handleUpdate(update)
		case <-t.C:
			c.syncAllNodesLabels()
		case <-c.syncChan:
			c.syncAllNodesLabels()
		case node := <-c.k8sNodeUpdate:
			log := logrus.WithFields(logrus.Fields{"controller": "Labels", "type": "nodeUpdate"})
			utils.ProcessBatch(c.k8sNodeUpdate, node, c.syncNodeLabels, log)
		case <-stopCh:
			return
		}
	}
}

func (c *nodeLabelController) syncAllNodesLabels() {
	if c.syncStatus != bapi.InSync {
		logrus.WithField("status", c.syncStatus).Debug("Not in sync, skipping node sync")
		return
	}
	nodes, err := c.nodeLister.List(labels.Everything())
	if err != nil {
		logrus.WithError(err).Error("failed to list nodes")
		return
	}
	for _, node := range nodes {
		c.syncNodeLabels(node)
	}
}

// syncNodeLabels syncs the labels found in v1.Node to the Calico node object.
// It uses an annotation on the Calico node object to keep track of which labels have
// been synced from Kubernetes, so that it doesn't overwrite user provided labels (e.g.,
// via calicoctl or another Calico controller).
func (c *nodeLabelController) syncNodeLabels(node *v1.Node) {
	logrus.WithField("node", node.Name).Debug("Syncing node labels")
	// Get the Calico node representation.
	name, ok := c.k8sNodeMapper[node.Name]
	if !ok {
		// We haven't learned this Calico node yet.
		logrus.Debugf("Update for node with no Calico equivalent")
		return
	}
	calNode, ok := c.calicoNodeCache[name]
	if !ok {
		logrus.Warnf("Calico Node does not exists")
		return
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
		if err := json.Unmarshal([]byte(a), &oldLabels); err != nil {
			logrus.WithError(err).Error("Failed to unmarshal node labels")
			return
		}
	}
	logrus.Debugf("Determined previously synced labels: %s", oldLabels)

	// We've synced labels before. Determine diffs to apply.
	// For each k/v in node.Labels, if it isn't present or the value
	// differs, add it to the node.
	for k, v := range node.Labels {
		if v2, ok := calNode.Labels[k]; !ok || v != v2 {
			logrus.Debugf("Adding node label %s=%s", k, v)
			calNode.Labels[k] = v
			needsUpdate = true
		}
	}

	// For each k/v that used to be in the k8s node labels, but is no longer,
	// remove it from the Calico node.
	for k, v := range oldLabels {
		if _, ok := node.Labels[k]; !ok {
			// The old label is no longer present. Remove it.
			logrus.Debugf("Deleting node label %s=%s", k, v)
			delete(calNode.Labels, k)
			needsUpdate = true
		}
	}

	// Set the annotation to the correct values.
	bytes, err := json.Marshal(node.Labels)
	if err != nil {
		logrus.WithError(err).Errorf("Error marshalling node labels")
		return
	}
	calNode.Annotations[nodeLabelAnnotation] = string(bytes)

	// Update the node in the datastore.
	if needsUpdate {
		if _, err := c.client.Nodes().Update(context.Background(), calNode, options.SetOptions{}); err != nil {
			logrus.WithError(err).Warnf("Failed to update node, retrying")
			return
		}
		c.calicoNodeCache[calNode.Name] = calNode
		logrus.WithField("node", node.ObjectMeta.Name).Info("Successfully synced node labels")
	}
}
