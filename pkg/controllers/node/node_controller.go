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

const (
	RateLimitCalicoList   = "calico-list"
	RateLimitK8s          = "k8s"
	RateLimitCalicoDelete = "calico-delete"
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
}

// NewNodeController Constructor for NodeController
func NewNodeController(ctx context.Context, k8sClientset *kubernetes.Clientset, calicoClient client.Interface) controller.Controller {
	// channel used to kick the controller into scheduling a sync. It has length
	// 1 so that we coalesce multiple kicks while a sync is happening down to
	// just one additional sync.
	schedule := make(chan interface{}, 1)

	// Create a Node watcher.
	listWatcher := cache.NewListWatchFromClient(k8sClientset.CoreV1().RESTClient(), "nodes", "", fields.Everything())

	// Informer handles managing the watch and signals us when nodes are deleted.
	_, informer := cache.NewIndexerInformer(listWatcher, &v1.Node{}, 0, cache.ResourceEventHandlerFuncs{
		DeleteFunc: func(obj interface{}) {
			// Just kick controller to wake up and perform a sync. No need to bother what node it was
			// as we sync everything.
			kick(schedule)
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
		log.WithError(err).Errorf("Error listing Calico nodes", err)
		return err
	}
	c.rl.Forget(RateLimitCalicoList)

	time.Sleep(c.rl.When(RateLimitK8s))
	kNodes, err := c.k8sClientset.CoreV1().Nodes().List(meta_v1.ListOptions{})
	if err != nil {
		log.WithError(err).Errorf("Error listing K8s nodes", err)
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
				log.WithError(err).Errorf("Error deleting Calico node: %v", node.Name, err)
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
