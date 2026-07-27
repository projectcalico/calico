// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package podiprecovery

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
)

const ns = "calico-system"

var _ = Describe("PodIPRecovery controller", func() {
	var (
		ctx context.Context
		c   client.Client
		r   *Reconciler
	)

	newNode := func(name string, internalIPs ...string) *corev1.Node {
		n := &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: name},
		}
		for _, ip := range internalIPs {
			n.Status.Addresses = append(n.Status.Addresses, corev1.NodeAddress{
				Type:    corev1.NodeInternalIP,
				Address: ip,
			})
		}
		return n
	}

	// newPod creates a pod labeled with the operator's host-networked marker
	// label. Tests that need to assert behavior on a non-labeled pod can use
	// the lower-level newPodWithLabels helper.
	newPod := func(name, nodeName, podIP string, hostNetwork bool) *corev1.Pod {
		return newPodWithLabels(name, nodeName, podIP, hostNetwork, map[string]string{
			common.HostNetworkedPodLabel: "true",
		})
	}

	// newDefaultInstallation creates the Installation CR that the controller
	// gates on. Without it, Reconcile is a no-op.
	newDefaultInstallation := func() *operatorv1.Installation {
		return &operatorv1.Installation{
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
		}
	}

	BeforeEach(func() {
		ctx = context.Background()
		scheme := runtime.NewScheme()
		Expect(corev1.AddToScheme(scheme)).To(Succeed())
		Expect(apis.AddToScheme(scheme, false)).To(Succeed())
		c = ctrlrfake.DefaultFakeClientBuilder(scheme).
			// Mirror the cmd/main.go index registration so the fake client
			// can honor `client.MatchingFields{"spec.nodeName": ...}`.
			WithIndex(&corev1.Pod{}, podNodeNameIndex, func(obj client.Object) []string {
				return []string{obj.(*corev1.Pod).Spec.NodeName}
			}).
			Build()
		// In production the lister wraps a label-scoped cache; the fake client
		// (which carries the same spec.nodeName index) stands in for it here.
		// onNode keeps a redundant label selector, so unlabeled pods in this
		// unscoped fake client are still filtered out.
		r = &Reconciler{client: c, hostNetworkedPods: hostNetworkedPodLister{reader: c}}

		// By default, create the Installation so Reconcile proceeds.
		// The Installation-gate test overrides this expectation.
		Expect(c.Create(ctx, newDefaultInstallation())).To(Succeed())
	})

	reconcileNode := func(nodeName string) {
		_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: nodeName}})
		Expect(err).NotTo(HaveOccurred())
	}

	podExists := func(name string) bool {
		err := c.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, &corev1.Pod{})
		if apierrors.IsNotFound(err) {
			return false
		}
		Expect(err).NotTo(HaveOccurred())
		return true
	}

	Context("Reconcile", func() {
		It("leaves a pod alone when its IP matches the node InternalIP", func() {
			Expect(c.Create(ctx, newNode("node1", "10.0.0.1"))).To(Succeed())
			Expect(c.Create(ctx, newPod("typha", "node1", "10.0.0.1", true))).To(Succeed())

			reconcileNode("node1")
			Expect(podExists("typha")).To(BeTrue())
		})

		It("deletes a hostNetwork pod whose IP doesn't match the node InternalIP", func() {
			Expect(c.Create(ctx, newNode("node1", "10.0.0.2"))).To(Succeed())
			Expect(c.Create(ctx, newPod("typha", "node1", "10.0.0.1", true))).To(Succeed())

			reconcileNode("node1")
			Expect(podExists("typha")).To(BeFalse())
		})

		It("deletes stale pods of multiple workloads on the same node in one reconcile (no pacing)", func() {
			Expect(c.Create(ctx, newNode("node1", "10.0.0.2"))).To(Succeed())
			Expect(c.Create(ctx, newPod("typha-1", "node1", "10.0.0.1", true))).To(Succeed())
			Expect(c.Create(ctx, newPod("node-1", "node1", "10.0.0.1", true))).To(Succeed())
			Expect(c.Create(ctx, newPod("nodewin-1", "node1", "10.0.0.1", true))).To(Succeed())

			reconcileNode("node1")
			Expect(podExists("typha-1")).To(BeFalse())
			Expect(podExists("node-1")).To(BeFalse())
			Expect(podExists("nodewin-1")).To(BeFalse())
		})

		It("only touches pods on the reconciled node", func() {
			Expect(c.Create(ctx, newNode("node1", "10.0.0.2"))).To(Succeed())
			Expect(c.Create(ctx, newNode("node2", "10.0.0.3"))).To(Succeed())
			Expect(c.Create(ctx, newPod("typha-1", "node1", "10.0.0.1", true))).To(Succeed())
			Expect(c.Create(ctx, newPod("typha-2", "node2", "10.0.0.1", true))).To(Succeed())

			reconcileNode("node1")
			Expect(podExists("typha-1")).To(BeFalse(), "stale pod on node1 should be deleted")
			Expect(podExists("typha-2")).To(BeTrue(), "stale pod on node2 should be untouched")
		})

		It("returns without error when the node is gone", func() {
			// No node created; reconcile should be a no-op.
			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "missing"}})
			Expect(err).NotTo(HaveOccurred())
		})

		It("skips a non-hostNetwork pod even if its labels match", func() {
			// A pod that carries our label but doesn't actually have
			// hostNetwork set must not be deleted — its CNI-assigned IP
			// legitimately differs from the node's IP.
			Expect(c.Create(ctx, newNode("node1", "10.0.0.2"))).To(Succeed())
			Expect(c.Create(ctx, newPod("cnipod", "node1", "10.244.0.5", false))).To(Succeed())

			reconcileNode("node1")
			Expect(podExists("cnipod")).To(BeTrue())
		})

		It("ignores pods that don't carry the host-networked label", func() {
			// A pod without our label isn't operator-managed (or at least
			// isn't claiming to be host-networked); leave it alone.
			Expect(c.Create(ctx, newNode("node1", "10.0.0.2"))).To(Succeed())
			Expect(c.Create(ctx, newPodWithLabels("unmarked", "node1", "10.0.0.1", true,
				map[string]string{"k8s-app": "some-other-workload"}))).To(Succeed())

			reconcileNode("node1")
			Expect(podExists("unmarked")).To(BeTrue())
		})

		It("matches dual-stack pod IPs against any of the node's InternalIPs", func() {
			node := newNode("node1", "10.0.0.1", "fd00::1")
			Expect(c.Create(ctx, node)).To(Succeed())

			// Pod reports both v4 and v6; one matches, so the pod is healthy.
			pod := newPod("typha", "node1", "10.0.0.1", true)
			pod.Status.PodIPs = []corev1.PodIP{{IP: "10.0.0.1"}, {IP: "fd00::1"}}
			Expect(c.Create(ctx, pod)).To(Succeed())

			reconcileNode("node1")
			Expect(podExists("typha")).To(BeTrue())
		})

		It("skips reconcile when the node has no host IPs reported", func() {
			// Avoid deleting based on a transient empty status.
			Expect(c.Create(ctx, newNode("node1" /* no IPs */))).To(Succeed())
			Expect(c.Create(ctx, newPod("typha", "node1", "10.0.0.1", true))).To(Succeed())

			reconcileNode("node1")
			Expect(podExists("typha")).To(BeTrue())
		})

		It("falls back to ExternalIP when the node has no InternalIP (mirrors kubelet)", func() {
			// Mirror kubelet's GetNodeHostIPs: ExternalIP is used to populate
			// status.podIPs on a hostNetwork pod only when the node has no
			// InternalIP. Our comparison must use the same selection logic.
			node := newNode("node1" /* no InternalIPs */)
			node.Status.Addresses = append(node.Status.Addresses, corev1.NodeAddress{
				Type: corev1.NodeExternalIP, Address: "10.0.0.1",
			})
			Expect(c.Create(ctx, node)).To(Succeed())

			// Pod whose IP matches the ExternalIP is healthy — leave it alone.
			Expect(c.Create(ctx, newPod("matches-external", "node1", "10.0.0.1", true))).To(Succeed())
			// Pod with a different IP is stale — delete it.
			Expect(c.Create(ctx, newPod("stale", "node1", "10.0.0.2", true))).To(Succeed())

			reconcileNode("node1")
			Expect(podExists("matches-external")).To(BeTrue(),
				"ExternalIP-only node: pod matching the ExternalIP should be left alone")
			Expect(podExists("stale")).To(BeFalse(),
				"ExternalIP-only node: pod not matching any node IP should be deleted")
		})

		It("ignores ExternalIP when an InternalIP exists", func() {
			// If the node has both, InternalIP wins (mirroring kubelet). A pod
			// whose IP happens to match the ExternalIP but not the InternalIP
			// is considered stale.
			node := newNode("node1", "10.0.0.1")
			node.Status.Addresses = append(node.Status.Addresses, corev1.NodeAddress{
				Type: corev1.NodeExternalIP, Address: "203.0.113.1",
			})
			Expect(c.Create(ctx, node)).To(Succeed())

			Expect(c.Create(ctx, newPod("matches-external", "node1", "203.0.113.1", true))).To(Succeed())

			reconcileNode("node1")
			Expect(podExists("matches-external")).To(BeFalse(),
				"InternalIP present: ExternalIP must not satisfy the comparison")
		})

		It("leaves a pending pod (no podIPs reported yet) alone", func() {
			// A pod that was just scheduled but hasn't been admitted by the
			// kubelet yet has empty status.podIPs. Deleting it would race the
			// kubelet, which is about to populate the IPs correctly from the
			// node's current address.
			Expect(c.Create(ctx, newNode("node1", "10.0.0.1"))).To(Succeed())
			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "pending", Namespace: ns,
					Labels: map[string]string{common.HostNetworkedPodLabel: "true"}},
				Spec: corev1.PodSpec{NodeName: "node1", HostNetwork: true},
				// Intentionally no Status.PodIPs / Status.PodIP — pending pod.
			}
			Expect(c.Create(ctx, pod)).To(Succeed())

			reconcileNode("node1")
			Expect(podExists("pending")).To(BeTrue())
		})

		It("returns nil and skips work when no Installation exists (gate)", func() {
			// Override the BeforeEach default: delete the Installation we
			// created so the gate-check NotFound path fires.
			Expect(c.Delete(ctx, newDefaultInstallation())).To(Succeed())

			Expect(c.Create(ctx, newNode("node1", "10.0.0.2"))).To(Succeed())
			Expect(c.Create(ctx, newPod("typha", "node1", "10.0.0.1", true))).To(Succeed())

			// Reconcile should return cleanly without touching the pod.
			_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "node1"}})
			Expect(err).NotTo(HaveOccurred())
			Expect(podExists("typha")).To(BeTrue())
		})
	})

	Context("hostIPsChangedPredicate", func() {
		pred := hostIPsChangedPredicate()

		It("enqueues on Create", func() {
			Expect(pred.Create(event.CreateEvent{Object: newNode("n1", "10.0.0.1")})).To(BeTrue())
		})

		It("does not enqueue on Delete", func() {
			Expect(pred.Delete(event.DeleteEvent{Object: newNode("n1", "10.0.0.1")})).To(BeFalse())
		})

		It("enqueues on Update when InternalIPs change", func() {
			old := newNode("n1", "10.0.0.1")
			new := newNode("n1", "10.0.0.2")
			Expect(pred.Update(event.UpdateEvent{ObjectOld: old, ObjectNew: new})).To(BeTrue())
		})

		It("does not enqueue on Update when InternalIPs are unchanged (heartbeat-only)", func() {
			old := newNode("n1", "10.0.0.1")
			new := newNode("n1", "10.0.0.1")
			// Simulate a heartbeat that adds a Hostname address but keeps the InternalIP.
			new.Status.Addresses = append(new.Status.Addresses, corev1.NodeAddress{
				Type:    corev1.NodeHostName,
				Address: "n1",
			})
			Expect(pred.Update(event.UpdateEvent{ObjectOld: old, ObjectNew: new})).To(BeFalse())
		})

		It("treats InternalIPs as a set (order-insensitive)", func() {
			old := newNode("n1", "10.0.0.1", "fd00::1")
			new := newNode("n1", "fd00::1", "10.0.0.1")
			Expect(pred.Update(event.UpdateEvent{ObjectOld: old, ObjectNew: new})).To(BeFalse())
		})

		It("enqueues when a new InternalIP is added", func() {
			old := newNode("n1", "10.0.0.1")
			new := newNode("n1", "10.0.0.1", "fd00::1")
			Expect(pred.Update(event.UpdateEvent{ObjectOld: old, ObjectNew: new})).To(BeTrue())
		})

		It("does not enqueue on Update when only ExternalIP changes (InternalIP wins)", func() {
			// Cloud environments commonly reassign external IPs while the
			// node's internal IP stays put. With an InternalIP present, the
			// ExternalIP is ignored by the kubelet's host-IP selection, so
			// we shouldn't react either.
			old := newNode("n1", "10.0.0.1")
			old.Status.Addresses = append(old.Status.Addresses, corev1.NodeAddress{
				Type: corev1.NodeExternalIP, Address: "203.0.113.1",
			})
			new := newNode("n1", "10.0.0.1")
			new.Status.Addresses = append(new.Status.Addresses, corev1.NodeAddress{
				Type: corev1.NodeExternalIP, Address: "203.0.113.99",
			})
			Expect(pred.Update(event.UpdateEvent{ObjectOld: old, ObjectNew: new})).To(BeFalse())
		})

		It("enqueues on Update when ExternalIP changes on a node with no InternalIP", func() {
			// In the (rare) ExternalIP-only case, ExternalIP is what the
			// kubelet uses for status.podIPs, so changes to it matter.
			old := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n1"}}
			old.Status.Addresses = []corev1.NodeAddress{{Type: corev1.NodeExternalIP, Address: "10.0.0.1"}}
			new := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n1"}}
			new.Status.Addresses = []corev1.NodeAddress{{Type: corev1.NodeExternalIP, Address: "10.0.0.2"}}
			Expect(pred.Update(event.UpdateEvent{ObjectOld: old, ObjectNew: new})).To(BeTrue())
		})
	})

	Context("hostNetPodSettledPredicate", func() {
		pred := hostNetPodSettledPredicate()

		// settledPod builds a managed host-networked pod on node1 with the
		// given IPs and readiness. Tests override individual fields as needed.
		settledPod := func(podIPs []string, ready bool) *corev1.Pod {
			p := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "p1",
					Namespace: ns,
					Labels:    map[string]string{common.HostNetworkedPodLabel: "true"},
				},
				Spec: corev1.PodSpec{NodeName: "node1", HostNetwork: true},
			}
			for _, ip := range podIPs {
				p.Status.PodIPs = append(p.Status.PodIPs, corev1.PodIP{IP: ip})
			}
			cond := corev1.ConditionFalse
			if ready {
				cond = corev1.ConditionTrue
			}
			p.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: cond}}
			return p
		}

		It("enqueues on Create when a managed host-net pod already reports IPs", func() {
			Expect(pred.Create(event.CreateEvent{Object: settledPod([]string{"10.0.0.1"}, true)})).To(BeTrue())
		})

		It("does not enqueue on Create when the pod has no IPs yet", func() {
			Expect(pred.Create(event.CreateEvent{Object: settledPod(nil, false)})).To(BeFalse())
		})

		It("does not enqueue on Create for a pod without the host-net marker label", func() {
			p := settledPod([]string{"10.0.0.1"}, true)
			p.Labels = nil
			Expect(pred.Create(event.CreateEvent{Object: p})).To(BeFalse())
		})

		It("does not enqueue on Create for a non-hostNetwork pod", func() {
			p := settledPod([]string{"10.0.0.1"}, true)
			p.Spec.HostNetwork = false
			Expect(pred.Create(event.CreateEvent{Object: p})).To(BeFalse())
		})

		It("enqueues on Update when the pod's IPs appear (empty -> set)", func() {
			old := settledPod(nil, false)
			new := settledPod([]string{"10.0.0.1"}, false)
			Expect(pred.Update(event.UpdateEvent{ObjectOld: old, ObjectNew: new})).To(BeTrue())
		})

		It("enqueues on Update when the pod becomes Ready (this is the late-settling survivor case)", func() {
			// The surviving pod comes back reporting its old, now-stale IP;
			// its IPs don't change but it transitions to Ready. This is the
			// exact edge the Node watch alone would miss.
			old := settledPod([]string{"10.0.0.1"}, false)
			new := settledPod([]string{"10.0.0.1"}, true)
			Expect(pred.Update(event.UpdateEvent{ObjectOld: old, ObjectNew: new})).To(BeTrue())
		})

		It("does not enqueue on Update when nothing relevant changed (steady-state heartbeat)", func() {
			old := settledPod([]string{"10.0.0.1"}, true)
			new := settledPod([]string{"10.0.0.1"}, true)
			Expect(pred.Update(event.UpdateEvent{ObjectOld: old, ObjectNew: new})).To(BeFalse())
		})

		It("does not enqueue on Update for a pod without the host-net marker label", func() {
			old := settledPod(nil, false)
			old.Labels = nil
			new := settledPod([]string{"10.0.0.1"}, true)
			new.Labels = nil
			Expect(pred.Update(event.UpdateEvent{ObjectOld: old, ObjectNew: new})).To(BeFalse())
		})

		It("does not enqueue on Delete", func() {
			Expect(pred.Delete(event.DeleteEvent{Object: settledPod([]string{"10.0.0.1"}, true)})).To(BeFalse())
		})
	})

	Context("podToNode", func() {
		It("maps a pod to a reconcile request for its node", func() {
			pod := newPod("p1", "node7", "10.0.0.1", true)
			reqs := podToNode(ctx, pod)
			Expect(reqs).To(ConsistOf(reconcile.Request{NamespacedName: types.NamespacedName{Name: "node7"}}))
		})

		It("returns nothing for a pod not yet scheduled to a node", func() {
			pod := newPod("p1", "", "10.0.0.1", true)
			Expect(podToNode(ctx, pod)).To(BeEmpty())
		})

		It("returns nothing for a non-pod object", func() {
			Expect(podToNode(ctx, newNode("node1", "10.0.0.1"))).To(BeEmpty())
		})
	})
})

// newPodWithLabels is the lower-level helper used by the `newPod` shortcut.
// Tests that want to set non-default labels (e.g. to verify that pods missing
// the host-networked marker are ignored) call this directly.
func newPodWithLabels(name, nodeName, podIP string, hostNetwork bool, labels map[string]string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
			Labels:    labels,
		},
		Spec: corev1.PodSpec{
			NodeName:    nodeName,
			HostNetwork: hostNetwork,
		},
		Status: corev1.PodStatus{
			PodIP:  podIP,
			PodIPs: []corev1.PodIP{{IP: podIP}},
		},
	}
}
