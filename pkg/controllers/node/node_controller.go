// Copyright (c) 2017 Tigera, Inc. All rights reserved.
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
	"context"
	"encoding/json"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"k8s.io/api/core/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	uruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"github.com/projectcalico/kube-controllers/pkg/config"
	"github.com/projectcalico/kube-controllers/pkg/controllers/controller"
	api "github.com/projectcalico/libcalico-go/lib/apis/v3"
	bapi "github.com/projectcalico/libcalico-go/lib/backend/api"
	client "github.com/projectcalico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/libcalico-go/lib/errors"
	"github.com/projectcalico/libcalico-go/lib/options"
)

const (
	RateLimitCalicoList   = "calico-list"
	RateLimitK8s          = "k8s"
	RateLimitCalicoDelete = "calico-delete"
	nodeLabelAnnotation   = "projectcalico.org/kube-labels"
)

var (
	maxAttempts    = 5
	retrySleepTime = 100 * time.Millisecond
)

// NodeController implements the Controller interface.  It is responsible for monitoring
// kubernetes nodes and responding to delete events by removing them from the Calico datastore.
type NodeController struct {
	ctx          context.Context
	informer     cache.Controller
	indexer      cache.Indexer
	calicoClient client.Interface
	k8sClientset *kubernetes.Clientset
	rl           workqueue.RateLimiter
	schedule     chan interface{}
	nodemapper   map[string]string
	nodemapLock  sync.Mutex
	syncer       bapi.Syncer
}

// NewNodeController Constructor for NodeController
func NewNodeController(ctx context.Context, k8sClientset *kubernetes.Clientset, calicoClient client.Interface, cfg *config.Config) controller.Controller {
	nc := &NodeController{
		ctx:          ctx,
		calicoClient: calicoClient,
		k8sClientset: k8sClientset,
		rl:           workqueue.DefaultControllerRateLimiter(),
		nodemapper:   map[string]string{},
	}
	// channel used to kick the controller into scheduling a sync. It has length
	// 1 so that we coalesce multiple kicks while a sync is happening down to
	// just one additional sync.
	nc.schedule = make(chan interface{}, 1)

	// Create a Node watcher.
	listWatcher := cache.NewListWatchFromClient(k8sClientset.CoreV1().RESTClient(), "nodes", "", fields.Everything())

	// Setup event handlers
	handlers := cache.ResourceEventHandlerFuncs{
		DeleteFunc: func(obj interface{}) {
			// Just kick controller to wake up and perform a sync. No need to bother what node it was
			// as we sync everything.
			kick(nc.schedule)
		}}

	if cfg.SyncNodeLabels {
		// Start the syncer.
		nc.initSyncer()
		nc.syncer.Start()

		// Add handlers for node add/update events from k8s.
		handlers.AddFunc = func(obj interface{}) {
			nc.syncNodeLabels(obj.(*v1.Node))
		}
		handlers.UpdateFunc = func(_, obj interface{}) {
			nc.syncNodeLabels(obj.(*v1.Node))
		}
	}

	// Informer handles managing the watch and signals us when nodes are deleted.
	// also syncs up labels between k8s/calico node objects
	nc.indexer, nc.informer = cache.NewIndexerInformer(listWatcher, &v1.Node{}, 0, handlers, cache.Indexers{})

	return nc
}

// syncNodeLabels syncs the labels found in v1.Node to the Calico node object.
// It uses an annotation on the Calico node object to keep track of which labels have
// beend synced from Kubernetes, so that it doesn't overwrite user provided labels (e.g.,
// via calicoctl or another Calico controller).
func (nc *NodeController) syncNodeLabels(node *v1.Node) {
	// On failure, we retry a certain number of times.
	for n := 1; n < maxAttempts; n++ {
		// Get the Calico node representation.
		nc.nodemapLock.Lock()
		name, ok := nc.nodemapper[node.Name]
		nc.nodemapLock.Unlock()
		if !ok {
			// We havent learned this Calico node yet.
			log.Debugf("Skipping update for node with no Calico equivalent")
			return
		}
		calNode, err := nc.calicoClient.Nodes().Get(context.Background(), name, options.GetOptions{})
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
		a, ok := calNode.Annotations[nodeLabelAnnotation]

		// If there are labels present, then parse them. Otherwise this is
		// a first-time sync, in which case there are no old labels.
		var oldLabels map[string]string = map[string]string{}
		if ok {
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
			if _, err := nc.calicoClient.Nodes().Update(context.Background(), calNode, options.SetOptions{}); err != nil {
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

// getK8sNodeName is a helper method that searches a calicoNode for its kubernetes nodeRef.
func getK8sNodeName(calicoNode api.Node) string {
	for _, orchRef := range calicoNode.Spec.OrchRefs {
		if orchRef.Orchestrator == "k8s" {
			return orchRef.NodeName
		}
	}
	return ""
}

// Run starts the node controller. It does start-of-day preparation
// and then launches worker threads. We ignore reconcilerPeriod and threadiness
// as this controller does not use a cache and runs only one worker thread.
func (c *NodeController) Run(threadiness int, reconcilerPeriod string, stopCh chan struct{}) {
	defer uruntime.HandleCrash()

	log.Info("Starting Node controller")

	// Wait till k8s cache is synced
	go c.informer.Run(stopCh)
	log.Debug("Waiting to sync with Kubernetes API (Nodes)")
	for !c.informer.HasSynced() {
		time.Sleep(100 * time.Millisecond)
	}
	log.Debug("Finished syncing with Kubernetes API (Nodes)")

	// Start Calico cache.
	go c.acceptScheduleRequests(stopCh)

	log.Info("Node controller is now running")

	// Kick off a start of day sync. Write non-blocking so that if a sync is
	// already scheduled, we don't schedule another.
	kick(c.schedule)

	<-stopCh
	log.Info("Stopping Node controller")
}

// acceptScheduleRequests monitors the schedule channel for kicks to wake up
// and schedule syncs.
func (c *NodeController) acceptScheduleRequests(stopCh <-chan struct{}) {
	for {
		// Wait until something wakes us up, or we are stopped
		select {
		case <-c.schedule:
			err := c.syncDelete()
			if err != nil {
				// Reschedule the sync since we hit an error. Note that
				// syncDelete() does its own rate limiting, so it's fine to
				// reschedule immediately.
				kick(c.schedule)
			}
		case <-stopCh:
			return
		}
	}
}

// syncDelete is the main work routine of the controller. It queries Calico and
// K8s, and deletes any Calico nodes which do not exist in K8s.
func (c *NodeController) syncDelete() error {
	// Possibly rate limit calls to Calico
	time.Sleep(c.rl.When(RateLimitCalicoList))
	cNodes, err := c.calicoClient.Nodes().List(c.ctx, options.ListOptions{})
	if err != nil {
		log.WithError(err).Error("Error listing Calico nodes")
		return err
	}
	c.rl.Forget(RateLimitCalicoList)

	time.Sleep(c.rl.When(RateLimitK8s))
	kNodes, err := c.k8sClientset.CoreV1().Nodes().List(meta_v1.ListOptions{})
	if err != nil {
		log.WithError(err).Error("Error listing K8s nodes")
		return err
	}
	c.rl.Forget(RateLimitK8s)
	kNodeIdx := make(map[string]bool)
	for _, node := range kNodes.Items {
		kNodeIdx[node.Name] = true
	}

	for _, node := range cNodes.Items {
		k8sNodeName := getK8sNodeName(node)
		if k8sNodeName != "" && !kNodeIdx[k8sNodeName] {
			// No matching Kubernetes node with that name
			time.Sleep(c.rl.When(RateLimitCalicoDelete))
			_, err := c.calicoClient.Nodes().Delete(c.ctx, node.Name, options.DeleteOptions{})
			if _, doesNotExist := err.(errors.ErrorResourceDoesNotExist); err != nil && !doesNotExist {
				// We hit an error other than "does not exist".
				log.WithError(err).Errorf("Error deleting Calico node: %v", node.Name)
				return err
			}
			c.rl.Forget(RateLimitCalicoDelete)
		}
	}
	return nil
}

// kick puts an item on the channel in non-blocking write. This means if there
// is already something pending, it has no effect. This allows us to coalesce
// multiple requests into a single pending request.
func kick(c chan<- interface{}) {
	select {
	case c <- nil:
		// pass
	default:
		// pass
	}

}
