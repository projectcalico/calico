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
	"strings"
	"time"

	apiv1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

// nodeInfo is the selection/display metadata we carry for a cluster node. It is
// a small projection of the Kubernetes Node object holding just what the picker
// needs to render and what suggestComparisonNodes uses to find similar nodes.
type nodeInfo struct {
	Name  string
	Roles []string
	Zone  string
	Ready bool
}

// selection is the outcome of node targeting: the nodes where the problem is
// (collected in full) and a handful of healthy nodes kept for contrast.
// ProblemPods records the pods the operator pointed at on the by-pod path (as
// "namespace/name" refs), so the bundle can show what the problem nodes were
// derived from; it is empty on the by-node path.
type selection struct {
	ProblemNodes    []string
	ComparisonNodes []string
	ProblemPods     []string
	// StartedAt is the operator's answer to "when did the problem start?", and
	// Description is their per-resource account of the roles involved. Both are
	// captured by the interactive wizard and saved with the bundle.
	StartedAt   string
	Description string
}

// podRef identifies a pod by namespace and name. An empty Namespace means "look
// in any namespace" when resolving.
type podRef struct {
	Namespace string
	Name      string
}

// Well-known node label keys used to group nodes for comparison suggestions.
const (
	nodeRoleLabelPrefix = "node-role.kubernetes.io/"
	zoneLabelKey        = "topology.kubernetes.io/zone"
)

// gatherNodeInfo lists the cluster's nodes and projects each into a nodeInfo.
func gatherNodeInfo(ctx context.Context, kubeClient kubernetes.Interface) ([]nodeInfo, error) {
	nl, err := kubeClient.CoreV1().Nodes().List(ctx, v1.ListOptions{})
	if err != nil {
		return nil, err
	}
	infos := make([]nodeInfo, 0, len(nl.Items))
	for i := range nl.Items {
		infos = append(infos, nodeInfoFromLabels(
			nl.Items[i].Name,
			nl.Items[i].Labels,
			nodeReady(&nl.Items[i]),
		))
	}
	return infos, nil
}

// podInfo is the display/selection metadata for a pod on the by-pod picker: its
// namespace/name identity, the node hosting it (empty if unscheduled) and its
// lifecycle phase (Running/Succeeded/Failed/…) so finished pods are visible and
// distinguishable rather than looking like running ones.
type podInfo struct {
	Namespace string
	Name      string
	Node      string
	Phase     string
}

// Ref returns the "namespace/name" identifier used as the picker's option value
// and parsed back by parsePodRefs.
func (p podInfo) Ref() string { return p.Namespace + "/" + p.Name }

// gatherPodInfo lists pods across all namespaces, projecting each into a podInfo
// sorted by namespace/name, for the by-pod picker. Pods of every phase are
// included — finished (Succeeded/Failed) pods are often exactly the ones being
// investigated, so they must not be filtered out.
func gatherPodInfo(ctx context.Context, kubeClient kubernetes.Interface) ([]podInfo, error) {
	pl, err := kubeClient.CoreV1().Pods("").List(ctx, v1.ListOptions{})
	if err != nil {
		return nil, err
	}
	pods := make([]podInfo, 0, len(pl.Items))
	for i := range pl.Items {
		pods = append(pods, podInfo{
			Namespace: pl.Items[i].Namespace,
			Name:      pl.Items[i].Name,
			Node:      pl.Items[i].Spec.NodeName,
			Phase:     string(pl.Items[i].Status.Phase),
		})
	}
	sort.Slice(pods, func(i, j int) bool {
		if pods[i].Namespace != pods[j].Namespace {
			return pods[i].Namespace < pods[j].Namespace
		}
		return pods[i].Name < pods[j].Name
	})
	return pods, nil
}

// nodeReady reports whether the node's Ready condition is True.
func nodeReady(node *apiv1.Node) bool {
	for _, c := range node.Status.Conditions {
		if c.Type == apiv1.NodeReady {
			return c.Status == apiv1.ConditionTrue
		}
	}
	return false
}

// isNotFound reports whether err is a Kubernetes "not found" API error.
func isNotFound(err error) bool {
	return apierrors.IsNotFound(err)
}

// nodeInfoFromLabels builds a nodeInfo from a node's name, labels and readiness.
// Split out from gatherNodeInfo so it can be unit-tested without a fake client.
func nodeInfoFromLabels(name string, labels map[string]string, ready bool) nodeInfo {
	ni := nodeInfo{Name: name, Ready: ready}
	for k, v := range labels {
		switch {
		case strings.HasPrefix(k, nodeRoleLabelPrefix):
			if role := strings.TrimPrefix(k, nodeRoleLabelPrefix); role != "" {
				ni.Roles = append(ni.Roles, role)
			}
		case k == zoneLabelKey:
			ni.Zone = v
		}
	}
	return ni
}

// parsePodRefs parses a comma-separated list of "namespace/pod" (or bare "pod")
// entries into podRefs. Blank entries are skipped. A bare name yields an empty
// Namespace, meaning resolvePodsToNodes will search all namespaces.
func parsePodRefs(s string) []podRef {
	var refs []podRef
	for _, entry := range strings.Split(s, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if ns, name, ok := strings.Cut(entry, "/"); ok {
			refs = append(refs, podRef{Namespace: strings.TrimSpace(ns), Name: strings.TrimSpace(name)})
		} else {
			refs = append(refs, podRef{Name: entry})
		}
	}
	return refs
}

// resolvePodsToNodes maps each podRef to the node hosting it (pod.Spec.NodeName),
// returning the de-duplicated node names in first-seen order. Pods that cannot
// be found (or that are not scheduled to a node) are returned in notFound so the
// caller can warn about them rather than silently dropping them.
func resolvePodsToNodes(ctx context.Context, kubeClient kubernetes.Interface, refs []podRef) (nodes []string, notFound []podRef, err error) {
	seen := set.New[string]()
	for _, ref := range refs {
		nodeName, ok, getErr := nodeForPod(ctx, kubeClient, ref)
		if getErr != nil {
			return nil, nil, getErr
		}
		if !ok {
			notFound = append(notFound, ref)
			continue
		}
		if !seen.Contains(nodeName) {
			seen.Add(nodeName)
			nodes = append(nodes, nodeName)
		}
	}
	return nodes, notFound, nil
}

// nodeForPod resolves a single podRef to its node name. When the ref has no
// namespace it searches all namespaces by field selector on the pod name.
func nodeForPod(ctx context.Context, kubeClient kubernetes.Interface, ref podRef) (string, bool, error) {
	if ref.Namespace != "" {
		pod, err := kubeClient.CoreV1().Pods(ref.Namespace).Get(ctx, ref.Name, v1.GetOptions{})
		if err != nil {
			if isNotFound(err) {
				return "", false, nil
			}
			return "", false, err
		}
		if pod.Spec.NodeName == "" {
			return "", false, nil
		}
		return pod.Spec.NodeName, true, nil
	}
	// No namespace: search all namespaces for a pod with this name.
	pods, err := kubeClient.CoreV1().Pods("").List(ctx, v1.ListOptions{
		FieldSelector: "metadata.name=" + ref.Name,
	})
	if err != nil {
		return "", false, err
	}
	for i := range pods.Items {
		if pods.Items[i].Spec.NodeName != "" {
			return pods.Items[i].Spec.NodeName, true, nil
		}
	}
	return "", false, nil
}

// nodesForPods maps selected pod refs ("namespace/name") to their hosting nodes
// using a ref→node lookup, de-duplicated in first-seen order. Pods with no known
// node (unscheduled, or absent from the lookup) are skipped. Lets the by-pod
// path resolve to nodes live, without a fresh API call.
func nodesForPods(podRefs []string, nodeByRef map[string]string) []string {
	seen := set.New[string]()
	var out []string
	for _, ref := range podRefs {
		node := nodeByRef[ref]
		if node == "" || seen.Contains(node) {
			continue
		}
		seen.Add(node)
		out = append(out, node)
	}
	return out
}

// comparisonNodesFromPods resolves comparison pod refs to their hosting nodes
// (via nodeByRef), dropping any that are already problem nodes. Used on the
// by-pod path where the operator picks healthy pods to contrast against.
func comparisonNodesFromPods(comparisonPods []string, nodeByRef map[string]string, problemNodes []string) []string {
	problemSet := set.FromArray(problemNodes)
	var out []string
	for _, n := range nodesForPods(comparisonPods, nodeByRef) {
		if !problemSet.Contains(n) {
			out = append(out, n)
		}
	}
	return out
}

// suggestComparisonNodes proposes up to n healthy nodes to collect alongside the
// problem nodes for contrast. It prefers Ready nodes that share a role or zone
// with one of the problem nodes (a like-for-like baseline), falling back to any
// Ready node if too few similar ones exist. Problem nodes are never suggested.
func suggestComparisonNodes(nodes []nodeInfo, problem []string, n int) []string {
	if n <= 0 {
		return nil
	}
	problemSet := set.FromArray(problem)

	wantRoles := set.New[string]()
	wantZones := set.New[string]()
	byName := make(map[string]nodeInfo, len(nodes))
	for _, ni := range nodes {
		byName[ni.Name] = ni
	}
	for _, p := range problem {
		ni, ok := byName[p]
		if !ok {
			continue
		}
		for _, r := range ni.Roles {
			wantRoles.Add(r)
		}
		if ni.Zone != "" {
			wantZones.Add(ni.Zone)
		}
	}

	var similar, other []string
	for _, ni := range nodes {
		if problemSet.Contains(ni.Name) || !ni.Ready {
			continue
		}
		if nodeSharesGroup(ni, wantRoles, wantZones) {
			similar = append(similar, ni.Name)
		} else {
			other = append(other, ni.Name)
		}
	}

	picks := append(similar, other...)
	if len(picks) > n {
		picks = picks[:n]
	}
	return picks
}

// nodeSharesGroup reports whether ni shares any role or zone with the wanted sets.
func nodeSharesGroup(ni nodeInfo, wantRoles, wantZones set.Set[string]) bool {
	for _, r := range ni.Roles {
		if wantRoles.Contains(r) {
			return true
		}
	}
	return ni.Zone != "" && wantZones.Contains(ni.Zone)
}

// buildNodeOrdering produces the ordered node list the collector walks and the
// set of nodes exempt from the --max-logs cap.
//
// Ordering: problem nodes, then comparison nodes, then legacy focus nodes, then
// every remaining cluster node — each de-duplicated against earlier groups.
// Nodes named in problem/comparison/focus that are not (yet) in allNodes are
// still included up front so targeting works even if the node list lookup
// failed or raced. The uncapped set is problem ∪ comparison: those are
// collected in full, while focus nodes retain their historical "priority but
// still capped" behaviour.
func buildNodeOrdering(allNodes, problem, comparison, focus []string) (nodeList []string, uncapped set.Set[string]) {
	uncapped = set.New[string]()
	added := set.New[string]()
	add := func(names []string, exempt bool) {
		for _, n := range names {
			if n == "" {
				continue
			}
			if exempt {
				uncapped.Add(n)
			}
			if added.Contains(n) {
				continue
			}
			added.Add(n)
			nodeList = append(nodeList, n)
		}
	}
	add(problem, true)
	add(comparison, true)
	add(focus, false)
	add(allNodes, false)
	return nodeList, uncapped
}

// mergeNodeNames appends src names onto dst, skipping blanks and duplicates,
// preserving order. Used to fold pod-resolved nodes into an existing list.
func mergeNodeNames(dst, src []string) []string {
	seen := set.FromArray(dst)
	for _, n := range src {
		if n == "" || seen.Contains(n) {
			continue
		}
		seen.Add(n)
		dst = append(dst, n)
	}
	return dst
}

// resolveNodeTargeting decides which nodes to target and updates opts in place.
//
//   - If no targeting flag was given and we're on an interactive terminal, it
//     runs the interactive picker; a user abort returns proceed=false (no error)
//     so the caller can stop without collecting anything.
//   - Otherwise (a targeting flag was given, or we're non-interactive) it leaves
//     the flags as-is, except that --problem-pods is resolved to node names and
//     folded into --problem-nodes.
//
// When no targeting is given in a non-interactive context, it returns
// proceed=true with opts unchanged, preserving the historical "collect from all
// nodes" behaviour.
//
// A failure to talk to the cluster (e.g. listing nodes or resolving pods)
// returns a non-nil error so the caller bails out rather than silently
// proceeding: if we can't reach the API server to pick targets, the collection
// that follows would fail too, and "collecting from all nodes" would be a
// misleading thing to print.
func resolveNodeTargeting(kubeClient kubernetes.Interface, opts *diagOpts) (proceed bool, err error) {
	explicit := opts.FocusNodes != "" || opts.ProblemNodes != "" ||
		opts.ProblemPods != "" || opts.ComparisonNodes != ""

	if !explicit && stdinIsInteractive() {
		sel, ok, err := runInteractiveSelection(kubeClient)
		if err != nil {
			return false, fmt.Errorf("interactive node selection failed: %w", err)
		}
		if !ok {
			return false, nil
		}
		opts.ProblemNodes = strings.Join(sel.ProblemNodes, ",")
		opts.ComparisonNodes = strings.Join(sel.ComparisonNodes, ",")
		opts.ProblemPods = strings.Join(sel.ProblemPods, ",")
		opts.StartedAt = sel.StartedAt
		opts.Description = sel.Description
		// Record when the operator finished answering the wizard's questions.
		opts.AnsweredAt = time.Now().UTC().Format(time.RFC3339)
		return true, nil
	}

	if opts.ProblemPods != "" {
		ctx, cancel := shortContext()
		nodes, notFound, err := resolvePodsToNodes(ctx, kubeClient, parsePodRefs(opts.ProblemPods))
		cancel()
		if err != nil {
			return false, fmt.Errorf("resolving --problem-pods: %w", err)
		}
		for _, nf := range notFound {
			fmt.Printf("WARNING: could not resolve pod %s to a node; skipping.\n", podRefString(nf))
		}
		opts.ProblemNodes = strings.Join(mergeNodeNames(parseCSV(opts.ProblemNodes), nodes), ",")
	}

	// Flag-driven path: the operator didn't see the interactive confirmation, so
	// surface the full-collection warning here if the selection is over budget.
	if w := fullCollectionWarning(selection{
		ProblemNodes:    parseCSV(opts.ProblemNodes),
		ComparisonNodes: parseCSV(opts.ComparisonNodes),
	}); w != "" {
		fmt.Println(w)
	}
	return true, nil
}

// parseCSV splits a comma-separated option value into trimmed, non-empty parts.
func parseCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// recommendedMaxFullNodes is the soft ceiling on nodes collected in full
// (problem ∪ comparison). Full collection is slow and produces a large bundle,
// so beyond this we warn the operator — but never block them.
const recommendedMaxFullNodes = 10

// fullCollectionCount is the number of distinct nodes that will be collected in
// full (problem ∪ comparison) — the slow, expensive part of a diags run.
func fullCollectionCount(sel selection) int {
	return len(mergeNodeNames(append([]string(nil), sel.ProblemNodes...), sel.ComparisonNodes))
}

// fullCollectionWarning returns a warning string when more than the recommended
// number of nodes would be collected in full, or "" when within budget.
func fullCollectionWarning(sel selection) string {
	if n := fullCollectionCount(sel); n > recommendedMaxFullNodes {
		return fmt.Sprintf("WARNING: %d nodes selected for full collection. Diagnostics collection is "+
			"slow and the bundle is large; %d or fewer is recommended. Consider narrowing the problem "+
			"and comparison nodes.", n, recommendedMaxFullNodes)
	}
	return ""
}

func joinOrNone(s []string) string {
	if len(s) == 0 {
		return "(none)"
	}
	return strings.Join(s, ", ")
}

// shortContext returns a context with a sensible default timeout for the
// interactive cluster lookups so the picker never hangs forever on a bad client.
func shortContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 30*time.Second)
}
