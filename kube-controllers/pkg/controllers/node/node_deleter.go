// Copyright (c) 2017-2020 Tigera, Inc. All rights reserved.
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
	"time"

	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/workqueue"

	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

// NewNodeDeletionController creates a new controller responsible for garbage collection Calico node objects
// in etcd mode when their corresponding Kubernetes node is deleted.
func NewNodeDeletionController(client client.Interface, cs *kubernetes.Clientset) *nodeDeleter {
	return &nodeDeleter{
		clientset: cs,
		client:    client,
		rl:        workqueue.DefaultControllerRateLimiter(),
	}
}

type nodeDeleter struct {
	rl        workqueue.RateLimiter
	clientset *kubernetes.Clientset
	client    client.Interface
}

func (c *nodeDeleter) RegisterWith(f *DataFeed) {
	// No-op - we only care about Kubernetes node deletion events.
}

func (c *nodeDeleter) OnKubernetesNodeDeleted() {
	// When a Kubernetes node is deleted, trigger a sync.
	log.Debug("Kubernetes node deletion event")
	err := c.deleteStaleNodes()
	if err != nil {
		log.WithError(err).Warn("Error deleting any stale nodes")
	}
}

// deleteStaleNodes compares the set of Calico and Kubernetes nodes and deletes and nodes
// which are present in the Calico datastore, but whose corresponding Kubernetes node has
// been deleted. Non-Kubernetes nodes will be ignored.
func (c *nodeDeleter) deleteStaleNodes() error {
	// Possibly rate limit calls to Calico
	time.Sleep(c.rl.When(RateLimitCalicoList))
	cNodes, err := c.client.Nodes().List(context.TODO(), options.ListOptions{})
	if err != nil {
		log.WithError(err).Error("Error listing Calico nodes")
		return err
	}
	c.rl.Forget(RateLimitCalicoList)

	time.Sleep(c.rl.When(RateLimitK8s))
	kNodes, err := c.clientset.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
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
		k8sNodeName, err := getK8sNodeName(node)
		if err != nil {
			if _, ok := err.(*ErrorNotKubernetes); ok {
				log.WithError(err).Info("Skipping non-kubernetes node")
				continue
			}
			log.WithError(err).Error("Error getting k8s node name")
			continue
		}
		if k8sNodeName != "" && !kNodeIdx[k8sNodeName] {
			// No matching Kubernetes node with that name.
			time.Sleep(c.rl.When(RateLimitCalicoDelete))

			// Re-confirm that the node is actually missing. This minimizes the potential that the node was
			// deleted and then re-created between the initial List() call above, and the decision to delete the
			// node here.
			_, err := c.clientset.CoreV1().Nodes().Get(context.TODO(), k8sNodeName, metav1.GetOptions{})
			if errors.IsNotFound(err) {
				_, err = c.client.Nodes().Delete(context.TODO(), node.Name, options.DeleteOptions{})
				if _, doesNotExist := err.(cerrors.ErrorResourceDoesNotExist); err != nil && !doesNotExist {
					// We hit an error other than "does not exist".
					log.WithError(err).Errorf("Error deleting Calico node: %v", node.Name)
					return err
				}
			}
			c.rl.Forget(RateLimitCalicoDelete)
		}
	}
	return nil
}
