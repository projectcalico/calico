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

// Package podiprecovery contains a small controller that watches Kubernetes
// Nodes for host-IP changes (the address set the kubelet would put in
// `status.podIPs` for a hostNetwork pod: InternalIP-preferred, ExternalIP
// fallback) and deletes operator-managed host-networked pods whose
// status.podIPs no longer matches that set.
//
// This works around an upstream Kubernetes behavior
// (https://github.com/kubernetes/kubernetes/issues/93897) where status.podIPs
// is immutable for hostNetwork pods once set. When a node's IP changes
// (e.g. after a KubeVirt VM reboot pulls a new DHCP lease), existing
// hostNetwork pods keep their stale IPs in their status, the Kubernetes
// EndpointSlice controller advertises the stale IPs, and Felix can't reach
// Typha. Only deleting and recreating the pod causes the kubelet to populate
// status.podIPs from the current node IP.
//
// Operator-managed pods are identified by the
// common.HostNetworkedPodLabel label, which the operator's shared
// setStandardSelectorAndLabels helper applies to any pod template with
// spec.hostNetwork == true as a side effect of the normal apply path.
// The controller additionally verifies spec.hostNetwork == true on each
// candidate as a safety net before deleting.
//
// Recovery is triggered by two watches so it stays level-triggered rather
// than reacting to a single node event: a Node watch (fires when a node's
// host IPs change) and a Pod watch (fires when a host-networked pod finishes
// (re)starting). The Pod watch is what catches a pod that was still
// restarting at the moment its node's IP changed and only later comes back
// reporting its old, stale IP — after which no further Node event would
// fire. Both watches enqueue the same Node key and share one idempotent
// Reconcile.
package podiprecovery

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/ctrlruntime"
)

var log = logf.Log.WithName("controller_podiprecovery")

// podNodeNameIndex is the field-index (registered on this controller's
// dedicated host-networked pod cache) that lets us list pods by their
// `spec.nodeName` with a server-side field selector.
const podNodeNameIndex = "spec.nodeName"

// Add wires the controller into the manager.
func Add(mgr manager.Manager, _ options.ControllerOptions) error {
	// Build a dedicated cache scoped server-side to operator-managed
	// host-networked pods. Both the Pod watch and the per-node pod List read
	// from this cache, so the controller only ever lists/watches/holds the
	// handful of host-networked pods cluster-wide — it does not force the
	// manager's shared cache to watch every pod in the cluster (which, at
	// scale, would be a sizable memory cost).
	podCache, err := cache.New(mgr.GetConfig(), cache.Options{
		Scheme: mgr.GetScheme(),
		Mapper: mgr.GetRESTMapper(),
		ByObject: map[client.Object]cache.ByObject{
			&corev1.Pod{}: {
				Label: labels.SelectorFromSet(labels.Set{common.HostNetworkedPodLabel: "true"}),
			},
		},
	})
	if err != nil {
		return fmt.Errorf("podiprecovery-controller failed to create host-networked pod cache: %w", err)
	}

	// Index the scoped cache by spec.nodeName so Reconcile can list a node's
	// pods with a server-side field selector.
	if err := podCache.IndexField(context.Background(), &corev1.Pod{}, podNodeNameIndex,
		func(obj client.Object) []string {
			return []string{obj.(*corev1.Pod).Spec.NodeName}
		},
	); err != nil {
		return fmt.Errorf("podiprecovery-controller failed to index host-networked pod cache: %w", err)
	}

	// Run the scoped cache as part of the manager so it starts/stops with it.
	if err := mgr.Add(podCache); err != nil {
		return fmt.Errorf("podiprecovery-controller failed to add host-networked pod cache to manager: %w", err)
	}

	r := &Reconciler{
		client:            mgr.GetClient(),
		hostNetworkedPods: hostNetworkedPodLister{reader: podCache},
	}

	c, err := ctrlruntime.NewController("podiprecovery-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return fmt.Errorf("failed to create podiprecovery-controller: %w", err)
	}

	// Watch Node objects. Only enqueue reconciliations when the set of
	// host IPs (what the kubelet would put in status.podIPs) has changed —
	// that is the only signal that interests us, and it avoids spurious
	// reconciles for routine kubelet heartbeats.
	if err := c.WatchObject(&corev1.Node{}, &handler.EnqueueRequestForObject{}, hostIPsChangedPredicate()); err != nil {
		return fmt.Errorf("podiprecovery-controller failed to watch Nodes: %w", err)
	}

	// The watch uses the label-scoped podCache above, so the informer only
	// receives events for host-networked pods.
	if err := c.WatchObjectInCache(podCache, &corev1.Pod{}, handler.EnqueueRequestsFromMapFunc(podToNode), hostNetPodSettledPredicate()); err != nil {
		return fmt.Errorf("podiprecovery-controller failed to watch Pods: %w", err)
	}

	return nil
}

// podToNode maps a Pod event to a reconcile request for the Node the pod
// runs on. Recovery is keyed on the Node, so a settling pod triggers a full
// re-evaluation of every host-networked pod on its node.
func podToNode(_ context.Context, obj client.Object) []reconcile.Request {
	pod, ok := obj.(*corev1.Pod)
	if !ok || pod.Spec.NodeName == "" {
		return nil
	}
	return []reconcile.Request{{NamespacedName: types.NamespacedName{Name: pod.Spec.NodeName}}}
}

// hostIPsChangedPredicate filters Node events so reconciles only fire when
// the node's host IPs change (including initial set / removal). New nodes
// are reconciled once to handle the case where pods are scheduled before the
// Node's status is populated.
func hostIPsChangedPredicate() predicate.Predicate {
	return predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			return true
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			return false
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldNode, oldOK := e.ObjectOld.(*corev1.Node)
			newNode, newOK := e.ObjectNew.(*corev1.Node)
			if !oldOK || !newOK {
				return false
			}
			return !nodeHostIPSet(oldNode.Status.Addresses).Equal(nodeHostIPSet(newNode.Status.Addresses))
		},
		GenericFunc: func(e event.GenericEvent) bool {
			return false
		},
	}
}

// hostNetPodSettledPredicate filters Pod events down to operator-managed
// hostNetwork pods that have just settled into a state where their
// status.podIPs can be meaningfully compared against their node's host IPs.
//
// This is the second half of the recovery trigger (see the Pod watch in
// Add). It fires when such a pod finishes (re)starting — either its reported
// IPs change, or it transitions to Ready — which is the moment a pod that
// survived a node-IP change comes back reporting its old, now-stale IP.
func hostNetPodSettledPredicate() predicate.Predicate {
	return predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			pod, ok := e.Object.(*corev1.Pod)
			// An already-running host-net pod observed on (re)start of the
			// controller: evaluate it if it already reports IPs.
			return ok && isManagedHostNetPod(pod) && len(pod.Status.PodIPs) > 0
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldPod, oldOK := e.ObjectOld.(*corev1.Pod)
			newPod, newOK := e.ObjectNew.(*corev1.Pod)
			if !oldOK || !newOK {
				return false
			}
			if !isManagedHostNetPod(newPod) || len(newPod.Status.PodIPs) == 0 {
				return false
			}
			// Re-evaluate when the pod's reported IPs change or when it
			// transitions to Ready — both mark the point at which a
			// (re)started pod's final status.podIPs becomes observable.
			if !podIPSet(oldPod).Equal(podIPSet(newPod)) {
				return true
			}
			return !podReady(oldPod) && podReady(newPod)
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			return false
		},
		GenericFunc: func(e event.GenericEvent) bool {
			return false
		},
	}
}

// isManagedHostNetPod reports whether the pod is an operator-managed
// hostNetwork pod — the only kind the recovery controller acts on.
// The label check is defense-in-depth: the Pod watch is backed by a cache
// scoped server-side to this same label (see Add), so events reaching the
// predicate already carry it. It's kept intentionally so the predicate stays
// correct independently of how the watch is wired — if the watch is ever
// pointed back at a non-label-scoped cache, this still prevents enqueuing a
// reconcile for every pod in the cluster. The spec.HostNetwork check is not
// covered by the label selector.
func isManagedHostNetPod(pod *corev1.Pod) bool {
	return pod.Spec.HostNetwork && pod.Labels[common.HostNetworkedPodLabel] == "true"
}

// podIPSet returns the set of IPs reported in the pod's status.podIPs.
func podIPSet(pod *corev1.Pod) sets.Set[string] {
	out := sets.New[string]()
	for _, pip := range pod.Status.PodIPs {
		out.Insert(pip.IP)
	}
	return out
}

// podReady reports whether the pod's Ready condition is currently True.
func podReady(pod *corev1.Pod) bool {
	for _, c := range pod.Status.Conditions {
		if c.Type == corev1.PodReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

// nodeHostIPSet returns the set of addresses that the kubelet would use to
// populate `status.podIPs` for a hostNetwork pod scheduled on this node.
//
// This mirrors upstream `k8s.io/kubernetes/pkg/util/node.GetNodeHostIPs`:
// InternalIPs are preferred; ExternalIPs are returned only when the node
// has no InternalIP at all. The upstream helper isn't importable from
// outside k8s.io/kubernetes, so we reimplement the few lines we need
// rather than vendor the package.
//
// In any cluster with normally-provisioned nodes the InternalIP branch
// always wins — but mirroring the kubelet's selection logic keeps our
// comparison faithful in the edge case where a node only has an ExternalIP.
func nodeHostIPSet(addrs []corev1.NodeAddress) sets.Set[string] {
	internal := sets.New[string]()
	external := sets.New[string]()
	for _, a := range addrs {
		switch a.Type {
		case corev1.NodeInternalIP:
			internal.Insert(a.Address)
		case corev1.NodeExternalIP:
			external.Insert(a.Address)
		}
	}
	if internal.Len() > 0 {
		return internal
	}
	return external
}

// Reconciler implements reconcile.Reconciler.
type Reconciler struct {
	// client is the manager's shared cached client, used for Node reads, the
	// Installation gate, and pod deletes.
	client client.Client
	// hostNetworkedPods reads operator-managed host-networked pods from a
	// label-scoped cache, so the controller never forces the shared cache to
	// watch every pod cluster-wide.
	hostNetworkedPods hostNetworkedPodLister
}

var _ reconcile.Reconciler = &Reconciler{}

// hostNetworkedPodLister lists operator-managed host-networked pods from a
// cache scoped server-side to the host-networked marker label.
//
// It deliberately wraps the scoped reader and exposes ONLY a node-scoped list
// of host-networked pods, rather than being a general client.Reader. This
// guards against the one dangerous mistake with a scoped cache: reading from
// it expecting the full set of cluster pods would silently drop every
// non-host-networked pod. There is intentionally no way to Get/List arbitrary
// pods through this type.
type hostNetworkedPodLister struct {
	reader client.Reader
}

// onNode returns the operator-managed host-networked pods scheduled on the
// given node. The label selector is a redundant guard (the backing cache is
// already label-scoped); the field selector narrows by node using the index
// registered on that cache.
func (l hostNetworkedPodLister) onNode(ctx context.Context, nodeName string) ([]corev1.Pod, error) {
	var pl corev1.PodList
	if err := l.reader.List(ctx, &pl,
		client.MatchingLabels{common.HostNetworkedPodLabel: "true"},
		client.MatchingFields{podNodeNameIndex: nodeName},
	); err != nil {
		return nil, err
	}
	return pl.Items, nil
}

// Reconcile is called for a Node when its host IPs change (or on initial
// creation). It lists operator-managed pods on the node and deletes any
// host-networked pod whose status.podIPs doesn't include any of the node's
// current host IPs (InternalIP-preferred, ExternalIP fallback).
func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.WithValues("node", req.Name)

	// Gate on Installation: if Calico hasn't been installed yet, the
	// operator-managed pods we'd act on don't exist. Bail out silently.
	if _, _, err := utils.GetInstallationSpec(ctx, r.client); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("failed to read Installation: %w", err)
	}

	node := &corev1.Node{}
	if err := r.client.Get(ctx, req.NamespacedName, node); err != nil {
		if apierrors.IsNotFound(err) {
			// Node is gone — Kubernetes garbage collection will clean up
			// the pods that ran on it. Nothing to do here.
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("failed to get Node %q: %w", req.Name, err)
	}

	nodeIPs := nodeHostIPSet(node.Status.Addresses)
	if nodeIPs.Len() == 0 {
		// Nothing to compare against; bail out to avoid deleting pods
		// based on a transient empty status.
		logger.V(1).Info("Node has no host IPs reported; skipping pod IP check")
		return ctrl.Result{}, nil
	}

	// List operator-managed host-networked pods on this node from the scoped
	// cache (host-networked pods only — never the full pod set).
	pods, err := r.hostNetworkedPods.onNode(ctx, node.Name)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to list pods on node %q: %w", node.Name, err)
	}

	var firstErr error
	deleted := 0
	for _, pod := range pods {
		if !pod.Spec.HostNetwork {
			// Safety check: only delete hostNetwork pods. A non-hostNetwork
			// pod that happens to carry our label has a CNI-assigned IP
			// that legitimately differs from the node's IP.
			continue
		}
		if len(pod.Status.PodIPs) == 0 {
			// Pod hasn't been status-populated yet (e.g. Pending, kubelet
			// has not admitted it). The kubelet will set the correct IPs on
			// admission; deleting now would just race that.
			continue
		}
		if podIPMatchesNode(&pod, nodeIPs) {
			continue
		}

		podIPs := make([]string, 0, len(pod.Status.PodIPs))
		for _, pip := range pod.Status.PodIPs {
			podIPs = append(podIPs, pip.IP)
		}
		logger.Info("Host networked Pod has stale IP, recreate",
			"pod", pod.Name, "namespace", pod.Namespace,
			"podIPs", podIPs, "nodeHostIPs", nodeIPs.UnsortedList())

		if delErr := r.client.Delete(ctx, &pod); delErr != nil && !apierrors.IsNotFound(delErr) {
			logger.Error(delErr, "Failed to delete pod with stale IP", "pod", pod.Name, "namespace", pod.Namespace)
			if firstErr == nil {
				firstErr = delErr
			}
			continue
		}
		deleted++
	}

	if deleted > 0 {
		logger.Info("Deleted stale-IP pods on node", "count", deleted)
	}
	return ctrl.Result{}, firstErr
}

// podIPMatchesNode returns true if any of the pod's reported IPs is in
// the node's host-IP set (see nodeHostIPSet for selection semantics).
func podIPMatchesNode(pod *corev1.Pod, nodeIPs sets.Set[string]) bool {
	for _, pip := range pod.Status.PodIPs {
		if nodeIPs.Has(pip.IP) {
			return true
		}
	}
	return false
}
