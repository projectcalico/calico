// Copyright (c) 2019 Tigera, Inc. All rights reserved.
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
	"time"

	"github.com/projectcalico/libcalico-go/lib/errors"
	"github.com/projectcalico/libcalico-go/lib/options"
	log "github.com/sirupsen/logrus"
	"k8s.io/api/core/v1"

	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// syncDelete is the main work routine of the controller. It queries Calico and
// K8s, and deletes any Calico nodes which do not exist in K8s.
func (c *NodeController) syncDeleteEtcd() error {
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

// syncNodeLabels syncs the labels found in v1.Node to the Calico node object.
// It uses an annotation on the Calico node object to keep track of which labels have
// been synced from Kubernetes, so that it doesn't overwrite user provided labels (e.g.,
// via calicoctl or another Calico controller).
func (nc *NodeController) syncNodeLabels(node *v1.Node) {
	// On failure, we retry a certain number of times.
	for n := 1; n < 5; n++ {
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
