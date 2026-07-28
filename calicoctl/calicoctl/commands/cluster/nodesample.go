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

package cluster

import (
	"context"
	"fmt"
	"sort"
	"time"

	apiv1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/common"
)

// --sample-nodes exists for the operator who doesn't yet know where the problem
// is. Collecting from the whole cluster is what this command moved away from, so
// instead we pick a small set of nodes chosen to be *different from each other*:
// the broken ones, the odd kernel or version out, the calico-node that keeps
// restarting, the one that has been up longest — and some healthy nodes for
// contrast. A bundle spanning those is far more likely to contain the problem
// than the same number of arbitrary nodes.

// sampledNode is one node the sampler chose, with the reason it stood out. The
// reason is recorded in bundle-info.yaml so whoever reads the bundle knows these
// nodes were picked automatically, and on what grounds.
type sampledNode struct {
	Node   string `json:"node"`
	Reason string `json:"reason"`
}

// sampledNodeNames returns just the node names, for folding into --problem-nodes.
func sampledNodeNames(sampled []sampledNode) []string {
	names := make([]string, 0, len(sampled))
	for _, s := range sampled {
		names = append(names, s.Node)
	}
	return names
}

// nodeCandidate is a node the sampler may pick: its Node-derived facts, plus what
// we could learn about its calico-node pod (nil when it has none).
type nodeCandidate struct {
	nodeInfo
	Calico *calicoNodeStatus
}

// calicoNodeStatus is the per-node calico-node pod state the sampler selects on.
type calicoNodeStatus struct {
	Pod         string
	Ready       bool
	Restarts    int32
	LastRestart time.Time // zero when no container has terminated
	StartedAt   time.Time // zero when unknown
	Image       string
}

// sampleNodes picks up to n nodes that differ from each other along the axes in
// nodeSamplers, in that priority order. A cluster with n or fewer nodes yields
// all of them.
func sampleNodes(ctx context.Context, kubeClient kubernetes.Interface, n int) ([]sampledNode, error) {
	if n <= 0 {
		return nil, nil
	}
	nodes, err := gatherNodeInfo(ctx, kubeClient)
	if err != nil {
		return nil, fmt.Errorf("listing cluster nodes: %w", err)
	}
	if len(nodes) == 0 {
		return nil, nil
	}
	// calico-node state sharpens the sample a lot, but it is a second API call and
	// the sample is still worth having without it — so a failure here degrades to
	// the Node-only axes rather than aborting the whole collection.
	byNode, err := gatherCalicoNodeStatus(ctx, kubeClient)
	if err != nil {
		fmt.Printf("WARNING: could not list calico-node pods, sampling on node state alone: %v\n", err)
	}
	return pickSample(candidates(nodes, byNode), n), nil
}

// candidates joins the node list with the calico-node state, sorted by name so
// the sample is the same on every run against an unchanged cluster.
func candidates(nodes []nodeInfo, calicoByNode map[string]*calicoNodeStatus) []nodeCandidate {
	out := make([]nodeCandidate, 0, len(nodes))
	for _, ni := range nodes {
		out = append(out, nodeCandidate{nodeInfo: ni, Calico: calicoByNode[ni.Name]})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// gatherCalicoNodeStatus finds each node's calico-node pod and projects the bits
// the sampler uses. It searches every namespace so it works on both operator
// (calico-system) and manifest (kube-system) installs.
func gatherCalicoNodeStatus(ctx context.Context, kubeClient kubernetes.Interface) (map[string]*calicoNodeStatus, error) {
	pl, err := kubeClient.CoreV1().Pods("").List(ctx, v1.ListOptions{LabelSelector: common.LabelCalicoNode})
	if err != nil {
		return nil, err
	}
	byNode := make(map[string]*calicoNodeStatus, len(pl.Items))
	for i := range pl.Items {
		pod := &pl.Items[i]
		if pod.Spec.NodeName == "" {
			continue
		}
		byNode[pod.Spec.NodeName] = calicoNodeStatusFromPod(pod)
	}
	return byNode, nil
}

// calicoNodeStatusFromPod projects one calico-node pod. Restarts are summed
// across its containers and LastRestart is the most recent termination among
// them, so a pod whose sidecar is flapping is as visible as one whose main
// container is.
func calicoNodeStatusFromPod(pod *apiv1.Pod) *calicoNodeStatus {
	st := &calicoNodeStatus{Pod: pod.Name, Ready: podIsReady(pod)}
	if pod.Status.StartTime != nil {
		st.StartedAt = pod.Status.StartTime.Time
	}
	statuses := append([]apiv1.ContainerStatus{}, pod.Status.ContainerStatuses...)
	statuses = append(statuses, pod.Status.InitContainerStatuses...)
	for _, cs := range statuses {
		st.Restarts += cs.RestartCount
		if t := cs.LastTerminationState.Terminated; t != nil && t.FinishedAt.After(st.LastRestart) {
			st.LastRestart = t.FinishedAt.Time
		}
		if cs.Name == calicoNodeContainer {
			st.Image = cs.Image
		}
	}
	if st.Image == "" && len(pod.Spec.Containers) > 0 {
		st.Image = pod.Spec.Containers[0].Image
	}
	return st
}

// calicoNodeContainer is the container carrying the calico-node image, whose
// version identifies the install for skew detection.
const calicoNodeContainer = "calico-node"

// podIsReady reports whether the pod's Ready condition is True.
func podIsReady(pod *apiv1.Pod) bool {
	for _, c := range pod.Status.Conditions {
		if c.Type == apiv1.PodReady {
			return c.Status == apiv1.ConditionTrue
		}
	}
	return false
}

// nodeSampler is one axis of interest: given the candidates, it returns the nodes
// it considers notable, most notable first. Returning nothing is normal — a
// healthy cluster matches few axes.
type nodeSampler struct {
	// reason is recorded against whichever node this axis contributes.
	reason string
	pick   func(cands []nodeCandidate) []string
}

// nodeSamplers are the axes, in priority order. pickSample takes one node per
// axis per pass and repeats, so the earlier axes get their first choice before any
// axis gets a second — the sample spreads across axes rather than being consumed
// by whichever one matches most nodes.
var nodeSamplers = []nodeSampler{
	{"node is not Ready", func(c []nodeCandidate) []string {
		return namesWhere(c, func(n nodeCandidate) bool { return !n.Ready })
	}},
	{"node reports NetworkUnavailable", func(c []nodeCandidate) []string {
		return namesWhere(c, func(n nodeCandidate) bool { return n.NetworkUnavailable })
	}},
	{"calico-node pod is not ready", func(c []nodeCandidate) []string {
		return namesWhere(c, func(n nodeCandidate) bool { return n.Calico != nil && !n.Calico.Ready })
	}},
	{"most calico-node restarts", func(c []nodeCandidate) []string {
		return namesRankedBy(c,
			func(n nodeCandidate) bool { return n.Calico != nil && n.Calico.Restarts > 0 },
			func(a, b nodeCandidate) bool { return a.Calico.Restarts > b.Calico.Restarts })
	}},
	{"calico-node restarted most recently", func(c []nodeCandidate) []string {
		return namesRankedBy(c,
			func(n nodeCandidate) bool { return n.Calico != nil && !n.Calico.LastRestart.IsZero() },
			func(a, b nodeCandidate) bool { return a.Calico.LastRestart.After(b.Calico.LastRestart) })
	}},
	{"node is cordoned", func(c []nodeCandidate) []string {
		return namesWhere(c, func(n nodeCandidate) bool { return n.Unschedulable })
	}},
	{"rarest kernel version", func(c []nodeCandidate) []string {
		return namesByRarestValue(c, func(n nodeCandidate) string { return n.KernelVersion })
	}},
	{"rarest kubelet version", func(c []nodeCandidate) []string {
		return namesByRarestValue(c, func(n nodeCandidate) string { return n.KubeletVersion })
	}},
	{"rarest calico-node image", func(c []nodeCandidate) []string {
		return namesByRarestValue(c, func(n nodeCandidate) string {
			if n.Calico == nil {
				return ""
			}
			return n.Calico.Image
		})
	}},
	{"longest-running calico-node", func(c []nodeCandidate) []string {
		return namesRankedBy(c,
			func(n nodeCandidate) bool { return n.Calico != nil && !n.Calico.StartedAt.IsZero() },
			func(a, b nodeCandidate) bool { return a.Calico.StartedAt.Before(b.Calico.StartedAt) })
	}},
	{"control-plane node", func(c []nodeCandidate) []string {
		return namesWhere(c, func(n nodeCandidate) bool {
			for _, r := range n.Roles {
				if r == "control-plane" || r == "master" {
					return true
				}
			}
			return false
		})
	}},
	{"one per zone", func(c []nodeCandidate) []string {
		return namesByRarestValue(c, func(n nodeCandidate) string { return n.Zone })
	}},
	{"healthy node, for contrast", func(c []nodeCandidate) []string {
		return spread(namesWhere(c, func(n nodeCandidate) bool {
			return n.Ready && !n.NetworkUnavailable && (n.Calico == nil || n.Calico.Ready)
		}))
	}},
}

// pickSample walks nodeSamplers in priority order, taking one not-yet-chosen node
// per axis, and repeats until it has n nodes or a whole pass adds nothing. A final
// top-up covers the case where every axis is exhausted but the cluster still has
// nodes left, so --sample-nodes=n on a cluster of n nodes always yields all n.
func pickSample(cands []nodeCandidate, n int) []sampledNode {
	if n <= 0 || len(cands) == 0 {
		return nil
	}
	var out []sampledNode
	chosen := make(map[string]bool, n)
	take := func(name, reason string) {
		chosen[name] = true
		out = append(out, sampledNode{Node: name, Reason: reason})
	}
	full := func() bool { return len(out) >= n }

	for progress := true; progress && !full(); {
		progress = false
		for _, s := range nodeSamplers {
			if full() {
				return out
			}
			for _, name := range s.pick(cands) {
				if name == "" || chosen[name] {
					continue
				}
				take(name, s.reason)
				progress = true
				break // one node per axis per pass
			}
		}
	}

	// Every axis is exhausted but the caller asked for more, so this is a cluster
	// with fewer interesting nodes than the requested sample size.
	for _, c := range cands {
		if full() {
			break
		}
		if !chosen[c.Name] {
			take(c.Name, "making up the requested sample size")
		}
	}
	return out
}

// namesWhere returns the names of candidates matching keep, in candidate (name)
// order.
func namesWhere(cands []nodeCandidate, keep func(nodeCandidate) bool) []string {
	var out []string
	for _, c := range cands {
		if keep(c) {
			out = append(out, c.Name)
		}
	}
	return out
}

// namesRankedBy returns the names of candidates matching keep, best first by
// less. Ties break on name so repeated runs agree.
func namesRankedBy(cands []nodeCandidate, keep func(nodeCandidate) bool, less func(a, b nodeCandidate) bool) []string {
	var kept []nodeCandidate
	for _, c := range cands {
		if keep(c) {
			kept = append(kept, c)
		}
	}
	sort.SliceStable(kept, func(i, j int) bool {
		if less(kept[i], kept[j]) {
			return true
		}
		if less(kept[j], kept[i]) {
			return false
		}
		return kept[i].Name < kept[j].Name
	})
	out := make([]string, 0, len(kept))
	for _, c := range kept {
		out = append(out, c.Name)
	}
	return out
}

// namesByRarestValue groups candidates by value and returns one representative
// per group, rarest group first. The odd node out is the interesting one: a lone
// kernel, kubelet or image version among hundreds of uniform nodes is worth a
// look, whereas one more node from the majority group tells us nothing new.
// Candidates whose value is empty (unknown) are skipped.
func namesByRarestValue(cands []nodeCandidate, value func(nodeCandidate) string) []string {
	firstByValue := map[string]string{}
	counts := map[string]int{}
	var order []string
	for _, c := range cands {
		v := value(c)
		if v == "" {
			continue
		}
		if _, seen := firstByValue[v]; !seen {
			firstByValue[v] = c.Name
			order = append(order, v)
		}
		counts[v]++
	}
	// A single group means every node agrees, so there is no odd one out to find.
	if len(order) < 2 {
		return nil
	}
	sort.SliceStable(order, func(i, j int) bool {
		if counts[order[i]] != counts[order[j]] {
			return counts[order[i]] < counts[order[j]]
		}
		return order[i] < order[j]
	})
	out := make([]string, 0, len(order))
	for _, v := range order {
		out = append(out, firstByValue[v])
	}
	return out
}

// spread reorders names to walk the list in large strides rather than taking
// neighbours. Node names usually encode position (rack, subnet, AZ), so
// neighbouring names tend to be the least different nodes available — striding
// picks a wider variety while staying deterministic, which a random choice would
// not. Note that the caller takes one per pass, so the strides are what matters.
func spread(names []string) []string {
	if len(names) < 3 {
		return names
	}
	out := make([]string, 0, len(names))
	// Visit at halves, then quarters, then eighths, and so on: 0, n/2, n/4, 3n/4…
	for step := len(names); step > 0; step /= 2 {
		for i := 0; i < len(names); i += step {
			out = append(out, names[i])
		}
	}
	return dedupeStrings(out)
}

// dedupeStrings drops repeats, keeping first-seen order.
func dedupeStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
