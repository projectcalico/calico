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
	"time"

	log "github.com/sirupsen/logrus"
	uruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"github.com/projectcalico/calico/kube-controllers/pkg/config"
	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/controller"
	"github.com/projectcalico/calico/kube-controllers/pkg/converter"
	api "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
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
	ctx context.Context

	// For syncing node objects from the k8s API.
	nodeInformer cache.SharedIndexInformer
	podInformer  cache.SharedIndexInformer
	k8sClientset *kubernetes.Clientset

	// For accessing Calico datastore.
	calicoClient client.Interface
	dataFeed     *DataFeed

	// Sub-controllers
	ipamCtrl *ipamController
}

// NewNodeController Constructor for NodeController
func NewNodeController(ctx context.Context,
	k8sClientset *kubernetes.Clientset,
	calicoClient client.Interface,
	cfg config.NodeControllerConfig,
	nodeInformer, podInformer cache.SharedIndexInformer) controller.Controller {
	nc := &NodeController{
		ctx:          ctx,
		calicoClient: calicoClient,
		k8sClientset: k8sClientset,
		dataFeed:     NewDataFeed(calicoClient),
		nodeInformer: nodeInformer,
		podInformer:  podInformer,
	}

	// Store functions to call on node deletion.
	nodeDeletionFuncs := []func(){}

	// Create the IPAM controller.
	nc.ipamCtrl = NewIPAMController(cfg, calicoClient, k8sClientset, nodeInformer.GetIndexer())
	nc.ipamCtrl.RegisterWith(nc.dataFeed)
	nodeDeletionFuncs = append(nodeDeletionFuncs, nc.ipamCtrl.OnKubernetesNodeDeleted)

	if cfg.DeleteNodes {
		// If we're running in etcd mode, then we also need to delete the node resource.
		// We don't need this for KDD mode, since the Calico Node resource is backed
		// directly by the Kubernetes Node resource, so their lifecycle is identical.
		nodeDeletionController := NewNodeDeletionController(calicoClient, k8sClientset)
		nodeDeletionController.RegisterWith(nc.dataFeed)
		nodeDeletionFuncs = append(nodeDeletionFuncs, nodeDeletionController.OnKubernetesNodeDeleted)
	}

	// Setup event handlers for nodes and pods learned through the
	// respective informers.
	nodeHandlers := cache.ResourceEventHandlerFuncs{
		DeleteFunc: func(obj interface{}) {
			// Call all of the registered node deletion funcs.
			for _, f := range nodeDeletionFuncs {
				f()
			}
		}}

	podHandlers := cache.ResourceEventHandlerFuncs{}
	podHandlers.AddFunc = func(obj interface{}) {
		key, err := cache.MetaNamespaceKeyFunc(obj)
		if err != nil {
			log.WithError(err).Error("Failed to generate key")
			return
		}
		pod, err := converter.ExtractPodFromUpdate(obj)
		if err != nil {
			log.WithError(err).Error("Failed to extract pod")
			return
		}
		nc.ipamCtrl.OnKubernetesPodUpdated(key, pod)
	}
	podHandlers.UpdateFunc = func(_, obj interface{}) {
		key, err := cache.MetaNamespaceKeyFunc(obj)
		if err != nil {
			log.WithError(err).Error("Failed to generate key")
			return
		}
		pod, err := converter.ExtractPodFromUpdate(obj)
		if err != nil {
			log.WithError(err).Error("Failed to extract pod")
			return
		}
		nc.ipamCtrl.OnKubernetesPodUpdated(key, pod)
	}
	podHandlers.DeleteFunc = func(obj interface{}) {
		key, err := cache.MetaNamespaceKeyFunc(obj)
		if err != nil {
			log.WithError(err).Error("Failed to generate key")
			return
		}
		nc.ipamCtrl.OnKubernetesPodDeleted(key)
	}

	// Create the Auto HostEndpoint sub-controller and register it to receive data.
	// We always launch this controller, even if auto-HEPs are disabled, since the controller
	// is responsible for cleaning up after itself in case it was previously enabled.
	autoHEPController := NewAutoHEPController(cfg, calicoClient)
	autoHEPController.RegisterWith(nc.dataFeed)

	if cfg.SyncLabels {
		// Note that the configuration code has already handled disabling this if
		// we are in KDD mode.

		// Create Label-sync controller and register it to receive data.
		nodeLabelCtrl := NewNodeLabelController(calicoClient)
		nodeLabelCtrl.RegisterWith(nc.dataFeed)

		// Hook the node label controller into the node informer so we are notified
		// when Kubernetes node labels change.
		nodeHandlers.AddFunc = func(obj interface{}) { nodeLabelCtrl.OnKubernetesNodeUpdate(obj) }
		nodeHandlers.UpdateFunc = func(_, obj interface{}) { nodeLabelCtrl.OnKubernetesNodeUpdate(obj) }
	}

	// Set the handlers on the informers.
	nc.nodeInformer.AddEventHandler(nodeHandlers)
	nc.podInformer.AddEventHandler(podHandlers)

	// Start the Calico data feed.
	nc.dataFeed.Start()

	return nc
}

// getK8sNodeName is a helper method that searches a calicoNode for its kubernetes nodeRef.
func getK8sNodeName(calicoNode api.Node) (string, error) {
	for _, orchRef := range calicoNode.Spec.OrchRefs {
		if orchRef.Orchestrator == "k8s" {
			if orchRef.NodeName == "" {
				return "", &ErrorNotKubernetes{calicoNode.Name}
			} else {
				return orchRef.NodeName, nil
			}
		}
	}
	return "", &ErrorNotKubernetes{calicoNode.Name}
}

// Run starts the node controller. It does start-of-day preparation
// and then launches worker threads.
func (c *NodeController) Run(stopCh chan struct{}) {
	defer uruntime.HandleCrash()

	log.Info("Starting Node controller")

	// Wait till k8s cache is synced
	log.Debug("Waiting to sync with Kubernetes API (Nodes and Pods)")
	for !c.nodeInformer.HasSynced() || !c.podInformer.HasSynced() {
		f := log.Fields{"node": c.nodeInformer.HasSynced(), "pod": c.podInformer.HasSynced()}
		log.WithFields(f).Debug("Waiting for sync")
		time.Sleep(100 * time.Millisecond)
	}
	log.Debug("Finished syncing with Kubernetes API (Nodes and Pods)")

	// We're in-sync. Start the sub-controllers.
	c.ipamCtrl.Start(stopCh)

	<-stopCh
	log.Info("Stopping Node controller")
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
