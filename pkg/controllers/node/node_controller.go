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
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	uruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"github.com/projectcalico/kube-controllers/pkg/controllers/controller"
	api "github.com/projectcalico/libcalico-go/lib/apis/v3"
	client "github.com/projectcalico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/libcalico-go/lib/errors"
	"github.com/projectcalico/libcalico-go/lib/options"
)

// NodeController implements the Controller interface.  It is responsible for monitoring
// kubernetes nodes and responding to delete events by removing them from the Calico datastore.
type NodeController struct {
	ctx          context.Context
	informer     cache.Controller
	calicoClient client.Interface
	k8sClientset *kubernetes.Clientset
	rl           workqueue.RateLimiter
	schedule     chan interface{}

	// the two bools are protected by the Mutex.
	m              sync.Mutex
	syncInProgress bool
	syncScheduled  bool
}

// NewNodeController Constructor for NodeController
func NewNodeController(ctx context.Context, k8sClientset *kubernetes.Clientset, calicoClient client.Interface) controller.Controller {
	// channel used to kick the controller into scheduling a sync
	schedule := make(chan interface{})

	// Create a Node watcher.
	listWatcher := cache.NewListWatchFromClient(k8sClientset.CoreV1().RESTClient(), "nodes", "", fields.Everything())

	// Informer handles managing the watch and signals us when nodes are deleted.
	_, informer := cache.NewIndexerInformer(listWatcher, &v1.Node{}, 0, cache.ResourceEventHandlerFuncs{
		DeleteFunc: func(obj interface{}) {
			// Just kick controller to wake up and perform a sync. No need to bother what node it was
			// as we sync everything.
			schedule <- nil
		},
	}, cache.Indexers{})

	return &NodeController{
		ctx:          ctx,
		informer:     informer,
		calicoClient: calicoClient,
		k8sClientset: k8sClientset,
		rl:           workqueue.DefaultControllerRateLimiter(),
		schedule:     schedule,
	}
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
	}
	log.Debug("Finished syncing with Kubernetes API (Nodes)")

	// Start Calico cache.
	go c.acceptScheduleRequests(stopCh)

	log.Info("Node controller is now running")

	// Kick off a start of day sync.
	c.schedule <- nil

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
			c.doSchedule(stopCh)
		case <-stopCh:
			return
		}
	}
}

// doSchedule actually performs the scheduling of syncs. It is a separate method
// so that we don't introduce locking into the acceptScheduleRequests method.
func (c *NodeController) doSchedule(stopCh <-chan struct{}) {
	c.m.Lock()
	defer c.m.Unlock()
	c.syncScheduled = true
	if c.syncInProgress {
		return
	}
	c.syncInProgress = true
	go c.syncUntilDone(stopCh)
}

// syncUntilDone kicks off the sync and handles re-synching if something schedules
// a sync while one is in progress. This method assumes the syncInProgress
// and syncScheduled flags are set when it is called.
func (c *NodeController) syncUntilDone(stopCh <-chan struct{}) {
	for {
		// Maybe stop?
		select {
		case <-stopCh:
			return
		default:
			c.m.Lock()
			if c.syncScheduled {
				c.syncScheduled = false
				c.m.Unlock()
				err := c.syncDelete()
				if err != nil {
					// If we hit an error, reschedule another sync.  SyncDelete
					// handles its own rate limiting.
					c.m.Lock()
					c.syncScheduled = true
					c.m.Unlock()
				}
			} else {
				c.syncInProgress = false
				c.m.Unlock()
				return
			}
		}
	}
}

// syncDelete is the main work routine of the controller. It queries Calico and
// K8s, and deletes any Calico nodes which do not exist in K8s.
func (c *NodeController) syncDelete() error {
	// Possibly rate limit calls to Calico
	time.Sleep(c.rl.When("calico-list"))
	cNodes, err := c.calicoClient.Nodes().List(c.ctx, options.ListOptions{})
	if err != nil {
		log.WithError(err).Errorf("Error listing Calico nodes", err)
		return err
	}
	c.rl.Forget("calico")

	time.Sleep(c.rl.When("k8s"))
	kNodes, err := c.k8sClientset.CoreV1().Nodes().List(meta_v1.ListOptions{})
	if err != nil {
		log.WithError(err).Errorf("Error listing K8s nodes", err)
		return err
	}
	c.rl.Forget("k8s")
	kNodeIdx := make(map[string]bool)
	for _, node := range kNodes.Items {
		kNodeIdx[node.Name] = true
	}

	for _, node := range cNodes.Items {
		k8sNodeName := getK8sNodeName(node)
		if k8sNodeName != "" && !kNodeIdx[k8sNodeName] {
			// No matching Kubernetes node with that name
			time.Sleep(c.rl.When("calico-delete"))
			_, err := c.calicoClient.Nodes().Delete(c.ctx, node.Name, options.DeleteOptions{})
			if _, doesNotExist := err.(errors.ErrorResourceDoesNotExist); err != nil && !doesNotExist {
				// We hit an error other than "does not exist".
				log.WithError(err).Errorf("Error deleting Calico node: %v", node.Name, err)
				return err
			}
			c.rl.Forget("calico-delete")
		}
	}
	return nil
}
