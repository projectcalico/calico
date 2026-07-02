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
)

var _ = Describe("nodeConditionController", func() {
	var (
		ctrl       *nodeConditionController
		fakeClient *fake.Clientset
		factory    informers.SharedInformerFactory
		stopCh     chan struct{}
		now        time.Time
		patched    map[string]int // tracks patch calls per node
	)

	BeforeEach(func() {
		fakeClient = fake.NewSimpleClientset()
		factory = informers.NewSharedInformerFactory(fakeClient, 0)
		nodeInformer := factory.Core().V1().Nodes().Informer()
		podInformer := factory.Core().V1().Pods().Informer()

		// Build the controller manually since newNodeConditionController
		// requires *kubernetes.Clientset but the fake is a different type.
		// The k8sClientset is only used in the default patchFn, which we override.
		ctrl = &nodeConditionController{
			nodeLister:        v1lister.NewNodeLister(nodeInformer.GetIndexer()),
			podLister:         v1lister.NewPodLister(podInformer.GetIndexer()),
			notReadySince:     make(map[string]time.Time),
			markedUnavailable: make(map[string]bool),
			gracePeriod:       5 * time.Second,
			checkInterval:     defaultConditionCheckInterval,
		}

		now = time.Now()
		ctrl.nowFn = func() time.Time { return now }

		patched = make(map[string]int)
		ctrl.patchFn = func(nodeName string) error {
			patched[nodeName]++
			return nil
		}

		stopCh = make(chan struct{})
		factory.Start(stopCh)
		factory.WaitForCacheSync(stopCh)
	})

	AfterEach(func() {
		close(stopCh)
	})

	createNode := func(name string) {
		_, err := fakeClient.CoreV1().Nodes().Create(context.Background(), &v1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: name},
		}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
	}

	createCalicoNodePod := func(nodeName string, ready bool) {
		status := v1.ConditionFalse
		if ready {
			status = v1.ConditionTrue
		}
		_, err := fakeClient.CoreV1().Pods("kube-system").Create(context.Background(), &v1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "calico-node-" + nodeName,
				Namespace: "kube-system",
				Labels:    map[string]string{calicoNodeLabel: calicoNodeLabelValue},
			},
			Spec: v1.PodSpec{
				NodeName: nodeName,
			},
			Status: v1.PodStatus{
				Phase: v1.PodRunning,
				Conditions: []v1.PodCondition{{
					Type:   v1.PodReady,
					Status: status,
				}},
			},
		}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
	}

	waitForSync := func() {
		factory.WaitForCacheSync(stopCh)
		time.Sleep(100 * time.Millisecond)
	}

	Context("with a node that has a Ready calico-node pod", func() {
		It("should not patch the node", func() {
			createNode("node1")
			createCalicoNodePod("node1", true)
			waitForSync()

			ctrl.checkNodes()
			Expect(patched).To(BeEmpty())
		})
	})

	Context("with a node whose calico-node pod is not Ready", func() {
		It("should not patch before grace period", func() {
			createNode("node1")
			createCalicoNodePod("node1", false)
			waitForSync()

			// First check starts the grace period.
			ctrl.checkNodes()
			Expect(patched).To(BeEmpty())

			// Advance time less than grace period.
			now = now.Add(3 * time.Second)
			ctrl.checkNodes()
			Expect(patched).To(BeEmpty())
		})

		It("should patch after grace period expires", func() {
			createNode("node1")
			createCalicoNodePod("node1", false)
			waitForSync()

			ctrl.checkNodes()
			Expect(patched).To(BeEmpty())

			// Advance past grace period.
			now = now.Add(6 * time.Second)
			ctrl.checkNodes()
			Expect(patched).To(HaveKeyWithValue("node1", 1))
		})
	})

	Context("when pod recovers before grace period", func() {
		It("should not patch the node", func() {
			createNode("node1")
			createCalicoNodePod("node1", false)
			waitForSync()

			// Start tracking.
			ctrl.checkNodes()
			Expect(patched).To(BeEmpty())

			// Pod becomes Ready before grace period.
			_, err := fakeClient.CoreV1().Pods("kube-system").UpdateStatus(context.Background(), &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "calico-node-node1",
					Namespace: "kube-system",
					Labels:    map[string]string{calicoNodeLabel: calicoNodeLabelValue},
				},
				Spec: v1.PodSpec{NodeName: "node1"},
				Status: v1.PodStatus{
					Phase: v1.PodRunning,
					Conditions: []v1.PodCondition{{
						Type:   v1.PodReady,
						Status: v1.ConditionTrue,
					}},
				},
			}, metav1.UpdateOptions{})
			Expect(err).NotTo(HaveOccurred())
			waitForSync()

			now = now.Add(6 * time.Second)
			ctrl.checkNodes()
			Expect(patched).To(BeEmpty())
		})
	})

	Context("with no calico-node pod on the node", func() {
		It("should patch after grace period", func() {
			createNode("node1")
			waitForSync()

			ctrl.checkNodes()
			Expect(patched).To(BeEmpty())

			now = now.Add(6 * time.Second)
			ctrl.checkNodes()
			Expect(patched).To(HaveKeyWithValue("node1", 1))
		})
	})

	Context("with multiple pods on a node, one Ready", func() {
		It("should not patch if any calico-node pod is Ready", func() {
			createNode("node1")
			createCalicoNodePod("node1", false)
			_, err := fakeClient.CoreV1().Pods("kube-system").Create(context.Background(), &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "calico-node-node1-new",
					Namespace: "kube-system",
					Labels:    map[string]string{calicoNodeLabel: calicoNodeLabelValue},
				},
				Spec: v1.PodSpec{NodeName: "node1"},
				Status: v1.PodStatus{
					Phase: v1.PodRunning,
					Conditions: []v1.PodCondition{{
						Type:   v1.PodReady,
						Status: v1.ConditionTrue,
					}},
				},
			}, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
			waitForSync()

			now = now.Add(60 * time.Second)
			ctrl.checkNodes()
			Expect(patched).To(BeEmpty())
		})
	})

	Context("when node was already patched", func() {
		It("should not patch again", func() {
			createNode("node1")
			createCalicoNodePod("node1", false)
			waitForSync()

			ctrl.checkNodes()
			now = now.Add(6 * time.Second)
			ctrl.checkNodes()
			Expect(patched).To(HaveKeyWithValue("node1", 1))

			// Another check should not patch again.
			ctrl.checkNodes()
			Expect(patched).To(HaveKeyWithValue("node1", 1))
		})
	})

	Context("when a previously unavailable node recovers then fails again", func() {
		It("should patch again after new grace period", func() {
			createNode("node1")
			createCalicoNodePod("node1", false)
			waitForSync()

			// Grace period passes -> patch.
			ctrl.checkNodes()
			now = now.Add(6 * time.Second)
			ctrl.checkNodes()
			Expect(patched).To(HaveKeyWithValue("node1", 1))

			// Pod recovers.
			_, err := fakeClient.CoreV1().Pods("kube-system").UpdateStatus(context.Background(), &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "calico-node-node1",
					Namespace: "kube-system",
					Labels:    map[string]string{calicoNodeLabel: calicoNodeLabelValue},
				},
				Spec: v1.PodSpec{NodeName: "node1"},
				Status: v1.PodStatus{
					Phase: v1.PodRunning,
					Conditions: []v1.PodCondition{{
						Type:   v1.PodReady,
						Status: v1.ConditionTrue,
					}},
				},
			}, metav1.UpdateOptions{})
			Expect(err).NotTo(HaveOccurred())
			waitForSync()
			ctrl.checkNodes()

			// Pod fails again.
			_, err = fakeClient.CoreV1().Pods("kube-system").UpdateStatus(context.Background(), &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "calico-node-node1",
					Namespace: "kube-system",
					Labels:    map[string]string{calicoNodeLabel: calicoNodeLabelValue},
				},
				Spec: v1.PodSpec{NodeName: "node1"},
				Status: v1.PodStatus{
					Phase: v1.PodRunning,
					Conditions: []v1.PodCondition{{
						Type:   v1.PodReady,
						Status: v1.ConditionFalse,
					}},
				},
			}, metav1.UpdateOptions{})
			Expect(err).NotTo(HaveOccurred())
			waitForSync()

			ctrl.checkNodes()
			now = now.Add(6 * time.Second)
			ctrl.checkNodes()
			Expect(patched).To(HaveKeyWithValue("node1", 2))
		})
	})
})
