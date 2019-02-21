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
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"k8s.io/api/core/v1"
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
)

const (
	RateLimitCalicoList   = "calico-list"
	RateLimitK8s          = "k8s"
	RateLimitCalicoDelete = "calico-delete"
	nodeLabelAnnotation   = "projectcalico.org/kube-labels"
)

var (
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
	config       *config.Config
}

// NewNodeController Constructor for NodeController
func NewNodeController(ctx context.Context, k8sClientset *kubernetes.Clientset, calicoClient client.Interface, cfg *config.Config) controller.Controller {
	nc := &NodeController{
		ctx:          ctx,
		calicoClient: calicoClient,
		k8sClientset: k8sClientset,
		rl:           workqueue.DefaultControllerRateLimiter(),
		nodemapper:   map[string]string{},
		config:       cfg,
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

	// Determine if we should sync node labels.
	syncLabels := cfg.SyncNodeLabels && cfg.DatastoreType != "kubernetes"

	if syncLabels {
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

	if syncLabels {
		// Start the syncer.
		nc.initSyncer()
		nc.syncer.Start()
	}

	return nc
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

func (c *NodeController) syncDelete() error {
	// Call the appropriate cleanup logic based on whether we're using
	// Kubernetes datastore or etecdv3.
	if c.config.DatastoreType == "kubernetes" {
		return c.syncDeleteKDD()
	}
	return c.syncDeleteEtcd()
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
