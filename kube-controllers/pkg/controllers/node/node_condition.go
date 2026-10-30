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
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	uruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	v1lister "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"github.com/projectcalico/calico/kube-controllers/pkg/converter"
	"github.com/projectcalico/calico/libcalico-go/lib/nodestatus"
)

const (
	// notReadyGracePeriod is how long a node goes without a Ready calico-node pod before we
	// call its network unavailable. Long enough to ride out a calico-node restart.
	notReadyGracePeriod = 30 * time.Second

	// maxRetries is how many times a node is retried before it is dropped from the queue.
	// A later pod or node event brings it back.
	nodeConditionMaxRetries = 5

	// calicoNodePodsByNodeIndex indexes calico-node pods by node name.
	calicoNodePodsByNodeIndex = "calicoNodePodsByNode"

	// networkingBackendEnvVar tells us whether Calico or another CNI provides pod networking.
	networkingBackendEnvVar = "CALICO_NETWORKING_BACKEND"

	// unmanagedGracePeriod is how long a node goes with no calico-node pod at all before we
	// treat Calico as gone from it. Long enough to outlast a new node waiting for its first pod.
	unmanagedGracePeriod = 5 * time.Minute
)

// nodeConditionController keeps the NetworkUnavailable condition, and optionally the
// network-ready taint, in step with calico-node pod readiness. See node/DESIGN.md for why this
// lives here rather than in calico-node.
type nodeConditionController struct {
	k8sClientset kubernetes.Interface
	nodeLister   v1lister.NodeLister
	podIndexer   cache.Indexer
	workqueue    workqueue.TypedRateLimitingInterface[string]

	gracePeriod          time.Duration
	unmanagedGracePeriod time.Duration

	// manageTaint controls whether we add the network-ready taint alongside the condition.
	// Removal is unconditional, so turning the feature off drains the taint.
	manageTaint bool

	nowFn func() time.Time
}

func newNodeConditionController(
	k8sClientset kubernetes.Interface,
	nodeInformer cache.SharedIndexInformer,
	podInformer cache.SharedIndexInformer,
) *nodeConditionController {
	c := &nodeConditionController{
		k8sClientset: k8sClientset,
		nodeLister:   v1lister.NewNodeLister(nodeInformer.GetIndexer()),
		podIndexer:   podInformer.GetIndexer(),
		workqueue: workqueue.NewTypedRateLimitingQueue(
			workqueue.DefaultTypedControllerRateLimiter[string](),
		),
		gracePeriod:          notReadyGracePeriod,
		unmanagedGracePeriod: unmanagedGracePeriod,
		manageTaint:          nodestatus.AddNetworkReadyTaintEnabled(),
		nowFn:                time.Now,
	}
	indexers := cache.Indexers{calicoNodePodsByNodeIndex: calicoNodePodsByNode}
	if err := podInformer.AddIndexers(indexers); err != nil {
		log.WithError(err).Fatal("Failed to index calico-node pods by node")
	}
	c.registerHandlers(nodeInformer, podInformer)
	return c
}

func (c *nodeConditionController) registerHandlers(nodeInformer, podInformer cache.SharedIndexInformer) {
	podHandlers := cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj any) { c.enqueuePod(obj) },
		UpdateFunc: func(_, obj any) { c.enqueuePod(obj) },
		DeleteFunc: func(obj any) { c.enqueuePod(obj) },
	}
	if _, err := podInformer.AddEventHandler(podHandlers); err != nil {
		log.WithError(err).Fatal("Failed to watch pods for the node condition controller")
	}

	nodeHandlers := cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj any) { c.enqueueNode(obj) },
		DeleteFunc: func(obj any) { c.enqueueNode(obj) },
	}
	if _, err := nodeInformer.AddEventHandler(nodeHandlers); err != nil {
		log.WithError(err).Fatal("Failed to watch nodes for the node condition controller")
	}
}

func (c *nodeConditionController) enqueuePod(obj any) {
	pod, ok := obj.(*v1.Pod)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			return
		}
		if pod, ok = tombstone.Obj.(*v1.Pod); !ok {
			return
		}
	}
	if pod.Spec.NodeName == "" || !converter.IsCalicoNodePod(pod) {
		return
	}
	c.workqueue.Add(pod.Spec.NodeName)
}

func (c *nodeConditionController) enqueueNode(obj any) {
	node, ok := obj.(*v1.Node)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			return
		}
		if node, ok = tombstone.Obj.(*v1.Node); !ok {
			return
		}
	}
	c.workqueue.Add(node.Name)
}

func (c *nodeConditionController) Start(stopCh chan struct{}) {
	go c.Run(stopCh)
}

func (c *nodeConditionController) Run(stopCh chan struct{}) {
	defer uruntime.HandleCrash()
	defer c.workqueue.ShutDown()

	log.Info("Starting node condition controller")

	// The informer caches are already synced by the parent node controller, but the initial
	// List events fired before our handlers were registered on a restart, so sweep once.
	nodes, err := c.nodeLister.List(labels.Everything())
	if err != nil {
		log.WithError(err).Error("Failed to list nodes; the first sweep will be skipped")
	}
	for _, node := range nodes {
		c.workqueue.Add(node.Name)
	}

	go wait.Until(c.runWorker, time.Second, stopCh)

	<-stopCh
	log.Info("Stopping node condition controller")
}

func (c *nodeConditionController) runWorker() {
	for c.processNextItem() {
	}
}

func (c *nodeConditionController) processNextItem() bool {
	nodeName, quit := c.workqueue.Get()
	if quit {
		return false
	}
	defer c.workqueue.Done(nodeName)

	c.handleErr(c.syncNode(context.Background(), nodeName), nodeName)
	return true
}

func (c *nodeConditionController) handleErr(err error, nodeName string) {
	if err == nil {
		c.workqueue.Forget(nodeName)
		return
	}
	if c.workqueue.NumRequeues(nodeName) < nodeConditionMaxRetries {
		log.WithError(err).WithField("node", nodeName).Error("Failed to sync node network status")
		c.workqueue.AddRateLimited(nodeName)
		return
	}
	c.workqueue.Forget(nodeName)
	uruntime.HandleError(err)
	log.WithError(err).WithField("node", nodeName).Error("Dropping node out of the queue")
}

// syncNode reconciles one node's condition and taint against its calico-node pod readiness. It
// reads the node's current state rather than tracking what it wrote, so a restart of this
// process doesn't re-mark or strand anything.
func (c *nodeConditionController) syncNode(ctx context.Context, nodeName string) error {
	node, err := c.nodeLister.Get(nodeName)
	if err != nil {
		if kerrors.IsNotFound(err) {
			return nil
		}
		return err
	}

	pods, err := c.calicoNodePodsOn(nodeName)
	if err != nil {
		return err
	}
	if len(pods) == 0 {
		return c.syncNodeWithoutPod(ctx, node)
	}

	if !calicoOwnsNetworking(pods) {
		// Another CNI provides pod networking here, so NetworkUnavailable is not ours to set.
		// The taint is still ours to clear.
		return c.releaseNode(ctx, node)
	}

	if anyPodReady(pods) {
		return c.markAvailable(ctx, node)
	}

	if remaining := c.gracePeriod - c.nowFn().Sub(notReadySince(pods)); remaining > 0 {
		log.WithField("node", nodeName).WithField("remaining", remaining).Info("No Ready calico-node pod")
		c.workqueue.AddAfter(nodeName, remaining)
		return nil
	}

	return c.markUnavailable(ctx, node)
}

// syncNodeWithoutPod handles a node with no calico-node pod, where there is nothing to observe.
// Waiting out unmanagedGracePeriod separates a node still waiting for its first pod from one
// Calico has stopped managing.
func (c *nodeConditionController) syncNodeWithoutPod(ctx context.Context, node *v1.Node) error {
	if age := c.nowFn().Sub(node.CreationTimestamp.Time); age < c.unmanagedGracePeriod {
		// New node. Its pod is on the way, and the admission-time taint has to survive until
		// calico-node arrives to clear it.
		c.workqueue.AddAfter(node.Name, c.unmanagedGracePeriod-age)
		return nil
	}

	// The DaemonSet controller replaces a deleted pod within seconds, so a sustained absence
	// means Calico is gone from this node - uninstalled, or the node is on its way out.
	return c.releaseNode(ctx, node)
}

// releaseNode gives up whatever Calico wrote on a node it can no longer speak for. Without it an
// uninstall would leave every node it had marked permanently unschedulable.
func (c *nodeConditionController) releaseNode(ctx context.Context, node *v1.Node) error {
	// Same writes as the healthy path: clear our condition, clear our taint, touch nothing else.
	return c.markAvailable(ctx, node)
}

// markAvailable clears the taint and the condition, but only touches a condition Calico set.
func (c *nodeConditionController) markAvailable(ctx context.Context, node *v1.Node) error {
	if nodestatus.HasNetworkReadyTaint(node) {
		updated := node.DeepCopy()
		updated.Spec.Taints = nodestatus.WithoutNetworkReadyTaint(updated.Spec.Taints)
		if err := c.updateTaints(ctx, updated); err != nil {
			return err
		}
	}
	if nodestatus.NetworkUnavailable(node) != v1.ConditionTrue || !nodestatus.OwnsNetworkUnavailable(node) {
		return nil
	}

	log.WithField("node", node.Name).Info("Calico-node pod is Ready, setting NetworkUnavailable=False")
	return c.patchCondition(ctx, node.Name, false)
}

func (c *nodeConditionController) markUnavailable(ctx context.Context, node *v1.Node) error {
	if c.manageTaint && !nodestatus.HasNetworkReadyTaint(node) {
		updated := node.DeepCopy()
		updated.Spec.Taints = append(updated.Spec.Taints, v1.Taint{
			Key:    nodestatus.NetworkReadyTaintKey,
			Effect: v1.TaintEffectNoSchedule,
		})
		if err := c.updateTaints(ctx, updated); err != nil {
			return err
		}
	}
	if nodestatus.NetworkUnavailable(node) == v1.ConditionTrue {
		return nil
	}

	log.WithField("node", node.Name).Warn("No Ready calico-node pod, setting NetworkUnavailable=True")
	return c.patchCondition(ctx, node.Name, true)
}

func (c *nodeConditionController) patchCondition(ctx context.Context, nodeName string, unavailable bool) error {
	condition := v1.NodeCondition{
		Type:               v1.NodeNetworkUnavailable,
		Status:             v1.ConditionFalse,
		Reason:             nodestatus.NetworkReadyReason,
		Message:            nodestatus.NetworkReadyMessage,
		LastTransitionTime: metav1.Now(),
		LastHeartbeatTime:  metav1.Now(),
	}
	if unavailable {
		condition.Status = v1.ConditionTrue
		condition.Reason = nodestatus.NetworkDownReason
		condition.Message = nodestatus.NetworkDownUnhealthy
	}

	raw, err := json.Marshal(&[]v1.NodeCondition{condition})
	if err != nil {
		return fmt.Errorf("marshal node condition: %w", err)
	}
	patch := fmt.Appendf(nil, `{"status":{"conditions":%s}}`, raw)
	_, err = c.k8sClientset.CoreV1().Nodes().PatchStatus(ctx, nodeName, patch)
	return err
}

func (c *nodeConditionController) updateTaints(ctx context.Context, node *v1.Node) error {
	log.WithField("node", node.Name).Info("Updating the network-ready taint")
	_, err := c.k8sClientset.CoreV1().Nodes().Update(ctx, node, metav1.UpdateOptions{})
	return err
}

// calicoNodePodsOn returns the calico-node pods scheduled to a node.
func (c *nodeConditionController) calicoNodePodsOn(nodeName string) ([]*v1.Pod, error) {
	objs, err := c.podIndexer.ByIndex(calicoNodePodsByNodeIndex, nodeName)
	if err != nil {
		return nil, err
	}

	pods := make([]*v1.Pod, 0, len(objs))
	for _, obj := range objs {
		pod, ok := obj.(*v1.Pod)
		if !ok {
			return nil, fmt.Errorf("expected *v1.Pod in the pod index, got %T", obj)
		}
		pods = append(pods, pod)
	}
	return pods, nil
}

// calicoNodePodsByNode indexes calico-node pods by the node they run on. Pods are matched on the
// container name rather than a label, because Canal labels the same DaemonSet "canal".
func calicoNodePodsByNode(obj any) ([]string, error) {
	pod, ok := obj.(*v1.Pod)
	if !ok || pod.Spec.NodeName == "" || !converter.IsCalicoNodePod(pod) {
		return nil, nil
	}
	return []string{pod.Spec.NodeName}, nil
}

// calicoOwnsNetworking reports whether Calico provides pod networking on the node these pods run
// on, read off calico-node's own environment. Under CALICO_NETWORKING_BACKEND=none another CNI
// owns it, and NetworkUnavailable describes that CNI rather than Calico.
func calicoOwnsNetworking(pods []*v1.Pod) bool {
	for _, pod := range pods {
		if converter.CalicoNodeEnv(pod, networkingBackendEnvVar) == "none" {
			return false
		}
	}
	return true
}

func anyPodReady(pods []*v1.Pod) bool {
	for _, pod := range pods {
		for _, cond := range pod.Status.Conditions {
			if cond.Type == v1.PodReady && cond.Status == v1.ConditionTrue {
				return true
			}
		}
	}
	return false
}

// notReadySince returns the most recent moment one of these pods could still have been Ready.
// Reading the clock off the pods keeps the grace period honest across a restart of this
// controller.
func notReadySince(pods []*v1.Pod) time.Time {
	var latest time.Time
	for _, pod := range pods {
		since := pod.CreationTimestamp.Time
		for _, cond := range pod.Status.Conditions {
			if cond.Type == v1.PodReady && !cond.LastTransitionTime.IsZero() {
				since = cond.LastTransitionTime.Time
				break
			}
		}
		if since.After(latest) {
			latest = since
		}
	}
	return latest
}
