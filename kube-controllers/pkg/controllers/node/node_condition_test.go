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
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	v1lister "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"github.com/projectcalico/calico/libcalico-go/lib/nodestatus"
)

// The node under test, plus two pod ages either side of the 30s grace period.
const (
	testNodeName = "node-a"
	withinGrace  = 5 * time.Second
	pastGrace    = 45 * time.Second
)

var _ = Describe("nodeConditionController", func() {
	var (
		ctrl       *nodeConditionController
		fakeClient *fake.Clientset
		podIndexer cache.Indexer
		nodeStore  cache.Store
	)

	// syncNode reconciles one node and returns it as the API server now holds it.
	syncNode := func(name string) *v1.Node {
		GinkgoHelper()
		Expect(ctrl.syncNode(context.Background(), name)).To(Succeed())
		node, err := fakeClient.CoreV1().Nodes().Get(context.Background(), name, metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		return node
	}

	sync := func() *v1.Node {
		GinkgoHelper()
		return syncNode(testNodeName)
	}

	// addNode puts a node in both the informer store and the fake API server.
	addNode := func(node *v1.Node) {
		GinkgoHelper()
		Expect(nodeStore.Add(node)).To(Succeed())
		_, err := fakeClient.CoreV1().Nodes().Create(context.Background(), node, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
	}

	addPod := func(pod *v1.Pod) {
		GinkgoHelper()
		Expect(podIndexer.Add(pod)).To(Succeed())
	}

	BeforeEach(func() {
		fakeClient = fake.NewSimpleClientset()
		factory := informers.NewSharedInformerFactory(fakeClient, 0)
		nodeInformer := factory.Core().V1().Nodes().Informer()
		podInformer := factory.Core().V1().Pods().Informer()
		Expect(podInformer.AddIndexers(cache.Indexers{calicoNodePodsByNodeIndex: calicoNodePodsByNode})).To(Succeed())

		nodeStore = nodeInformer.GetIndexer()
		podIndexer = podInformer.GetIndexer()

		ctrl = &nodeConditionController{
			k8sClientset: fakeClient,
			nodeLister:   v1lister.NewNodeLister(nodeInformer.GetIndexer()),
			podIndexer:   podIndexer,
			workqueue: workqueue.NewTypedRateLimitingQueue(
				workqueue.DefaultTypedControllerRateLimiter[string](),
			),
			gracePeriod: notReadyGracePeriod,
			nowFn:       time.Now,
		}
	})

	AfterEach(func() {
		ctrl.workqueue.ShutDown()
	})

	Describe("deciding which nodes it speaks for", func() {
		It("marks a node whose calico-node pod has been not Ready past the grace period", func() {
			addNode(node(testNodeName))
			addPod(calicoNodePod("calico-node-xyz", testNodeName, notReady, pastGrace))

			Expect(networkUnavailable(sync())).To(Equal(v1.ConditionTrue))
		})

		It("holds off while the pod is still inside the grace period", func() {
			addNode(node(testNodeName))
			addPod(calicoNodePod("calico-node-xyz", testNodeName, notReady, withinGrace))

			Expect(sync().Status.Conditions).To(BeEmpty())
		})

		It("leaves a node with no calico-node pod alone", func() {
			// Windows, virtual-kubelet and Fargate nodes are skipped by the DaemonSet's node
			// selector, so Calico has nothing to say about their networking.
			addNode(node("windows-node"))

			Expect(syncNode("windows-node").Status.Conditions).To(BeEmpty())
		})

		It("recognises a Canal pod, which carries a different k8s-app label", func() {
			addNode(node(testNodeName))
			pod := calicoNodePod("canal-xyz", testNodeName, notReady, pastGrace)
			pod.Labels = map[string]string{"k8s-app": "canal"}
			addPod(pod)

			Expect(networkUnavailable(sync())).To(Equal(v1.ConditionTrue))
		})

		It("ignores a pod that is not owned by a DaemonSet", func() {
			addNode(node(testNodeName))
			pod := calicoNodePod("impostor", testNodeName, notReady, pastGrace)
			pod.OwnerReferences = nil
			addPod(pod)

			Expect(sync().Status.Conditions).To(BeEmpty())
		})

		It("treats a node as healthy while any of its calico-node pods is Ready", func() {
			// A rolling update leaves the old and new pods side by side for a few seconds.
			addNode(nodeWithCondition(testNodeName, v1.ConditionTrue, nodestatus.NetworkDownReason))
			addPod(calicoNodePod("calico-node-old", testNodeName, ready, pastGrace))
			addPod(calicoNodePod("calico-node-new", testNodeName, notReady, pastGrace))

			Expect(networkUnavailable(sync())).To(Equal(v1.ConditionFalse))
		})

		It("gives a replacement pod its own grace period", func() {
			// The old pod has been gone a while, but the new one only just started, so the node
			// is not yet unavailable.
			addNode(node(testNodeName))
			addPod(calicoNodePod("calico-node-old", testNodeName, notReady, pastGrace))
			addPod(calicoNodePod("calico-node-new", testNodeName, notReady, withinGrace))

			Expect(sync().Status.Conditions).To(BeEmpty())
		})
	})

	Describe("recovering", func() {
		It("clears a condition it set once the pod goes Ready again", func() {
			addNode(nodeWithCondition(testNodeName, v1.ConditionTrue, nodestatus.NetworkDownReason))
			addPod(calicoNodePod("calico-node-xyz", testNodeName, ready, withinGrace))

			Expect(networkUnavailable(sync())).To(Equal(v1.ConditionFalse))
		})

		It("leaves a condition set by a cloud route controller alone", func() {
			// Calico is up here, but the cloud routes are not, so clearing the condition would
			// tell the scheduler the node is routable when it isn't.
			addNode(nodeWithCondition(testNodeName, v1.ConditionTrue, "NoRouteCreated"))
			addPod(calicoNodePod("calico-node-xyz", testNodeName, ready, withinGrace))

			Expect(networkUnavailable(sync())).To(Equal(v1.ConditionTrue))
		})
	})

	Describe("managing the taint", func() {
		It("adds the taint alongside the condition when the feature is on", func() {
			ctrl.manageTaint = true
			addNode(node(testNodeName))
			addPod(calicoNodePod("calico-node-xyz", testNodeName, notReady, pastGrace))

			Expect(nodestatus.HasNetworkReadyTaint(sync())).To(BeTrue())
		})

		It("does not add the taint when the feature is off", func() {
			ctrl.manageTaint = false
			addNode(node(testNodeName))
			addPod(calicoNodePod("calico-node-xyz", testNodeName, notReady, pastGrace))

			marked := sync()
			Expect(networkUnavailable(marked)).To(Equal(v1.ConditionTrue))
			Expect(nodestatus.HasNetworkReadyTaint(marked)).To(BeFalse())
		})

		It("removes an existing taint even when the feature is off, so disabling it drains", func() {
			ctrl.manageTaint = false
			tainted := node(testNodeName)
			tainted.Spec.Taints = []v1.Taint{
				{Key: "other-taint", Effect: v1.TaintEffectNoSchedule},
				{Key: nodestatus.NetworkReadyTaintKey, Effect: v1.TaintEffectNoSchedule},
			}
			addNode(tainted)
			addPod(calicoNodePod("calico-node-xyz", testNodeName, ready, withinGrace))

			cleared := sync()
			Expect(nodestatus.HasNetworkReadyTaint(cleared)).To(BeFalse())
			Expect(cleared.Spec.Taints).To(HaveLen(1), "unrelated taints should be left in place")
		})
	})
})

func node(name string) *v1.Node {
	return &v1.Node{ObjectMeta: metav1.ObjectMeta{Name: name}}
}

func nodeWithCondition(name string, status v1.ConditionStatus, reason string) *v1.Node {
	n := node(name)
	n.Status.Conditions = []v1.NodeCondition{
		{
			Type:   v1.NodeNetworkUnavailable,
			Status: status,
			Reason: reason,
		},
	}
	return n
}

const (
	ready    = true
	notReady = false
)

// calicoNodePod builds a calico-node pod whose PodReady condition last changed `since` ago.
func calicoNodePod(name, nodeName string, isReady bool, since time.Duration) *v1.Pod {
	status := v1.ConditionFalse
	if isReady {
		status = v1.ConditionTrue
	}
	changed := metav1.NewTime(time.Now().Add(-since))
	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:              name,
			Namespace:         "kube-system",
			CreationTimestamp: changed,
			OwnerReferences:   []metav1.OwnerReference{{Kind: "DaemonSet", Name: "calico-node"}},
		},
		Spec: v1.PodSpec{
			NodeName:   nodeName,
			Containers: []v1.Container{{Name: "calico-node"}},
		},
		Status: v1.PodStatus{
			Conditions: []v1.PodCondition{
				{
					Type:               v1.PodReady,
					Status:             status,
					LastTransitionTime: changed,
				},
			},
		},
	}
}

func networkUnavailable(node *v1.Node) v1.ConditionStatus {
	for _, cond := range node.Status.Conditions {
		if cond.Type == v1.NodeNetworkUnavailable {
			return cond.Status
		}
	}
	return ""
}
