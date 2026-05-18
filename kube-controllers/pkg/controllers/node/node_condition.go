// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	v1lister "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
)

const (
	calicoNodeLabel               = "k8s-app"
	calicoNodeLabelValue          = "calico-node"
	defaultConditionGracePeriod   = 30 * time.Second
	defaultConditionCheckInterval = 10 * time.Second
)

// nodeConditionController watches calico-node pods and sets the NetworkUnavailable
// condition on Kubernetes nodes when calico-node pods are not Ready. This handles the
// case where calico-node crashes or is OOMKilled, which the in-pod health monitoring
// cannot detect. It only sets NetworkUnavailable=True; recovery (setting False) is left
// to calico-node's own startup logic to avoid races.
type nodeConditionController struct {
	k8sClientset *kubernetes.Clientset
	nodeLister   v1lister.NodeLister
	podLister    v1lister.PodLister

	// notReadySince tracks when we first detected that a node has no Ready calico-node pod.
	notReadySince map[string]time.Time

	// markedUnavailable tracks nodes we've already patched to avoid duplicate patches.
	markedUnavailable map[string]bool

	gracePeriod   time.Duration
	checkInterval time.Duration

	// For testing: allow injecting a custom time function and patch function.
	nowFn   func() time.Time
	patchFn func(nodeName string) error
}

func newNodeConditionController(
	k8sClientset *kubernetes.Clientset,
	nodeInformer cache.SharedIndexInformer,
	podInformer cache.SharedIndexInformer,
) *nodeConditionController {
	c := &nodeConditionController{
		k8sClientset:      k8sClientset,
		nodeLister:        v1lister.NewNodeLister(nodeInformer.GetIndexer()),
		podLister:         v1lister.NewPodLister(podInformer.GetIndexer()),
		notReadySince:     make(map[string]time.Time),
		markedUnavailable: make(map[string]bool),
		gracePeriod:       defaultConditionGracePeriod,
		checkInterval:     defaultConditionCheckInterval,
		nowFn:             time.Now,
	}
	c.patchFn = c.patchNodeUnavailable
	return c
}

func (c *nodeConditionController) Start(stopCh chan struct{}) {
	go c.run(stopCh)
}

func (c *nodeConditionController) run(stopCh chan struct{}) {
	log.Info("Starting node condition controller")
	ticker := time.NewTicker(c.checkInterval)
	defer ticker.Stop()
	for {
		select {
		case <-stopCh:
			log.Info("Stopping node condition controller")
			return
		case <-ticker.C:
			c.checkNodes()
		}
	}
}

// checkNodes iterates over all Kubernetes nodes and checks whether each has a Ready
// calico-node pod. If a node has no Ready calico-node pod for longer than the grace
// period, it sets NetworkUnavailable=True.
func (c *nodeConditionController) checkNodes() {
	nodes, err := c.nodeLister.List(labels.Everything())
	if err != nil {
		log.WithError(err).Warn("Failed to list nodes for condition check")
		return
	}

	now := c.nowFn()
	activeNodes := make(map[string]bool)

	for _, node := range nodes {
		nodeName := node.Name
		activeNodes[nodeName] = true

		if c.hasReadyCalicoNodePod(nodeName) {
			// Node has a Ready calico-node pod. Clear any not-ready tracking and
			// allow calico-node to handle setting the condition back to False.
			delete(c.notReadySince, nodeName)
			c.markedUnavailable[nodeName] = false
			continue
		}

		// No Ready calico-node pod found for this node.
		if _, tracked := c.notReadySince[nodeName]; !tracked {
			c.notReadySince[nodeName] = now
			log.WithField("node", nodeName).Info("No Ready calico-node pod detected, starting grace period")
			continue
		}

		// Check if we've exceeded the grace period.
		if now.Sub(c.notReadySince[nodeName]) < c.gracePeriod {
			continue
		}

		// Grace period exceeded. Patch the node if we haven't already.
		if c.markedUnavailable[nodeName] {
			continue
		}

		log.WithField("node", nodeName).Warn("Calico-node pod not Ready, setting NetworkUnavailable=True")
		if err := c.patchFn(nodeName); err != nil {
			log.WithError(err).WithField("node", nodeName).Error("Failed to set NetworkUnavailable condition")
			continue
		}
		c.markedUnavailable[nodeName] = true
	}

	// Clean up tracking for nodes that no longer exist.
	for nodeName := range c.notReadySince {
		if !activeNodes[nodeName] {
			delete(c.notReadySince, nodeName)
			delete(c.markedUnavailable, nodeName)
		}
	}
}

// hasReadyCalicoNodePod checks if there's at least one Ready calico-node pod on the given node.
func (c *nodeConditionController) hasReadyCalicoNodePod(nodeName string) bool {
	pods, err := c.podLister.List(labels.Everything())
	if err != nil {
		log.WithError(err).Warn("Failed to list pods for condition check")
		return true // err on the side of caution
	}

	for _, pod := range pods {
		if pod.Spec.NodeName != nodeName {
			continue
		}
		if pod.Labels[calicoNodeLabel] != calicoNodeLabelValue {
			continue
		}
		if isPodReady(pod) {
			return true
		}
	}
	return false
}

// isPodReady returns true if the pod has a Ready condition set to True.
func isPodReady(pod *v1.Pod) bool {
	for _, cond := range pod.Status.Conditions {
		if cond.Type == v1.PodReady {
			return cond.Status == v1.ConditionTrue
		}
	}
	return false
}

// patchNodeUnavailable patches the node's NetworkUnavailable condition to True.
func (c *nodeConditionController) patchNodeUnavailable(nodeName string) error {
	condition := v1.NodeCondition{
		Type:               v1.NodeNetworkUnavailable,
		Status:             v1.ConditionTrue,
		Reason:             "CalicoIsDown",
		Message:            "Calico node pod is not Ready",
		LastTransitionTime: metav1.Now(),
		LastHeartbeatTime:  metav1.Now(),
	}
	raw, err := json.Marshal(&[]v1.NodeCondition{condition})
	if err != nil {
		return fmt.Errorf("failed to marshal condition: %w", err)
	}
	patch := fmt.Appendf(nil, `{"status":{"conditions":%s}}`, raw)
	_, err = c.k8sClientset.CoreV1().Nodes().PatchStatus(context.Background(), nodeName, patch)
	return err
}
