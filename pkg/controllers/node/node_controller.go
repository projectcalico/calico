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
	"context"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	uruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"github.com/projectcalico/kube-controllers/pkg/config"
	"github.com/projectcalico/kube-controllers/pkg/controllers/controller"
	api "github.com/projectcalico/libcalico-go/lib/apis/v3"
	bapi "github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	client "github.com/projectcalico/libcalico-go/lib/clientv3"
)

const (
	RateLimitK8s          = "k8s"
	RateLimitCalicoCreate = "calico-create"
	RateLimitCalicoList   = "calico-list"
	RateLimitCalicoUpdate = "calico-update"
	RateLimitCalicoDelete = "calico-delete"
	nodeLabelAnnotation   = "projectcalico.org/kube-labels"
	hepCreatedLabelKey    = "projectcalico.org/created-by"
	hepCreatedLabelValue  = "calico-kube-controllers"
)

var (
	retrySleepTime = 100 * time.Millisecond
)

// NodeController implements the Controller interface.  It is responsible for monitoring
// kubernetes nodes and responding to delete events by removing them from the Calico datastore.
type NodeController struct {
	sync.Mutex
	ctx          context.Context
	informer     cache.Controller
	indexer      cache.Indexer
	calicoClient client.Interface
	k8sClientset *kubernetes.Clientset
	rl           workqueue.RateLimiter
	schedule     chan interface{}
	blockUpdate  chan interface{}
	nodemapper   map[string]string
	allBlocks    map[string]model.KVPair
	syncer       bapi.Syncer
	config       config.NodeControllerConfig
	nodeCache    map[string]*api.Node
	syncStatus   bapi.SyncStatus
}

// NewNodeController Constructor for NodeController
func NewNodeController(ctx context.Context, k8sClientset *kubernetes.Clientset, calicoClient client.Interface, cfg config.NodeControllerConfig) controller.Controller {
	nc := &NodeController{
		ctx:          ctx,
		calicoClient: calicoClient,
		k8sClientset: k8sClientset,
		rl:           workqueue.DefaultControllerRateLimiter(),
		nodemapper:   map[string]string{},
		allBlocks:    map[string]model.KVPair{},
		config:       cfg,
		nodeCache:    make(map[string]*api.Node),
	}

	// channel used to kick the controller into scheduling a sync. It has length
	// 1 so that we coalesce multiple kicks while a sync is happening down to
	// just one additional sync.
	nc.schedule = make(chan interface{}, 1)
	nc.blockUpdate = make(chan interface{}, 1)

	// Create a Node watcher.
	listWatcher := cache.NewListWatchFromClient(k8sClientset.CoreV1().RESTClient(), "nodes", "", fields.Everything())

	// Setup event handlers
	handlers := cache.ResourceEventHandlerFuncs{
		DeleteFunc: func(obj interface{}) {
			// Just kick controller to wake up and perform a sync. No need to bother what node it was
			// as we sync everything.
			kick(nc.schedule)
		}}

	// Note that the configuration code has already handled disabling this if
	// we are in KDD mode.
	if cfg.SyncLabels {
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

	// Start the syncer. We always need to run this to manage auto
	// hostendpoints: if autoHostEndpoints was enabled then disabled later on
	// then we need to remove the leftover auto heps.
	nc.initSyncer()
	nc.syncer.Start()

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
// and then launches worker threads.
func (c *NodeController) Run(stopCh chan struct{}) {
	defer uruntime.HandleCrash()

	log.Info("Starting Node controller")

	// Register metrics.
	registerPrometheusMetrics()

	// Wait till k8s cache is synced
	go c.informer.Run(stopCh)
	log.Debug("Waiting to sync with Kubernetes API (Nodes)")
	for !c.informer.HasSynced() {
		time.Sleep(100 * time.Millisecond)
	}
	log.Debug("Finished syncing with Kubernetes API (Nodes)")

	// Start worker thread.
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
		case <-c.blockUpdate:
			// Gather IPAM data for metrics.
			_, err := c.gatherIPAMData()
			if err != nil {
				log.WithError(err).Warn("error gathering IPAM data")
			}
		case <-stopCh:
			return
		}
	}
}

func (c *NodeController) syncDelete() error {
	// First, try doing an IPAM sync. This will check IPAM state and clean up any blocks
	// which don't belong based on nodes/pods in the k8s API. Don't return the error right away, since
	// even if this IPAM sync fails we shouldn't block cleaning up the node object. If we do encounter an error,
	// we'll return it after we're done.
	err := c.syncIPAMCleanup()
	if c.config.DeleteNodes {
		// If we're running in etcd mode, then we also need to delete the node resource.
		// We don't need this for KDD mode, since the Calico Node resource is backed
		// directly by the Kubernetes Node resource, so their lifecycle is identical.
		errEtcd := c.syncDeleteEtcd()
		if errEtcd != nil {
			return errEtcd
		}
	}
	return err
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
