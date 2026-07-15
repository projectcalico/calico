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
	"strings"
	"testing"

	. "github.com/onsi/gomega"
	apiv1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestFullCollectionWarning(t *testing.T) {
	RegisterTestingT(t)

	// Within budget: no warning.
	small := selection{ProblemNodes: []string{"a", "b"}, ComparisonNodes: []string{"c"}}
	Expect(fullCollectionCount(small)).To(Equal(3))
	Expect(fullCollectionWarning(small)).To(BeEmpty())

	// A node listed as both problem and comparison is counted once.
	overlap := selection{ProblemNodes: []string{"a", "b"}, ComparisonNodes: []string{"b"}}
	Expect(fullCollectionCount(overlap)).To(Equal(2))

	// Over budget: warning names the count and the recommended ceiling.
	var many []string
	for i := 0; i < recommendedMaxFullNodes+1; i++ {
		many = append(many, fmt.Sprintf("n%d", i))
	}
	big := selection{ProblemNodes: many}
	Expect(fullCollectionCount(big)).To(Equal(recommendedMaxFullNodes + 1))
	w := fullCollectionWarning(big)
	Expect(w).To(ContainSubstring("WARNING"))
	Expect(w).To(ContainSubstring(fmt.Sprintf("%d nodes", recommendedMaxFullNodes+1)))
}

func TestOverBudgetWarning(t *testing.T) {
	RegisterTestingT(t)

	// At or under the limit: no warning.
	Expect(overBudgetWarning(recommendedMaxFullNodes)).To(BeEmpty())
	Expect(overBudgetWarning(0)).To(BeEmpty())

	// Over the limit: warning names the live count and the recommended ceiling.
	over := overBudgetWarning(recommendedMaxFullNodes + 5)
	Expect(over).To(ContainSubstring("⚠"))
	Expect(over).To(ContainSubstring(fmt.Sprintf("%d nodes", recommendedMaxFullNodes+5)))
}

func TestComparisonWarning(t *testing.T) {
	RegisterTestingT(t)

	// Over-budget full-collection set takes priority.
	Expect(comparisonWarning(recommendedMaxFullNodes+1, 0, 100)).To(ContainSubstring("full collection"))

	// Too few comparison nodes, but the cluster has plenty to choose from.
	w := comparisonWarning(1, 1, 50)
	Expect(w).To(ContainSubstring("baseline"))
	Expect(w).To(ContainSubstring("1 comparison"))

	// Enough comparison nodes selected: no warning.
	Expect(comparisonWarning(1, defaultComparisonNodeCount, 50)).To(BeEmpty())

	// Tiny cluster: not enough candidates to require a baseline, so no nag.
	Expect(comparisonWarning(1, 0, 2)).To(BeEmpty())
}

func TestParseCSV(t *testing.T) {
	RegisterTestingT(t)
	Expect(parseCSV("")).To(BeEmpty())
	Expect(parseCSV("a")).To(Equal([]string{"a"}))
	Expect(parseCSV("a,b,c")).To(Equal([]string{"a", "b", "c"}))
	Expect(parseCSV(" a , ,b ,")).To(Equal([]string{"a", "b"}), "trims and drops blanks")
}

func TestParsePodRefs(t *testing.T) {
	RegisterTestingT(t)
	Expect(parsePodRefs("")).To(BeEmpty())
	Expect(parsePodRefs("calico-system/calico-node-abc")).To(Equal([]podRef{
		{Namespace: "calico-system", Name: "calico-node-abc"},
	}))
	Expect(parsePodRefs("ns1/p1, ns2/p2")).To(Equal([]podRef{
		{Namespace: "ns1", Name: "p1"},
		{Namespace: "ns2", Name: "p2"},
	}))
	Expect(parsePodRefs("barepod")).To(Equal([]podRef{
		{Namespace: "", Name: "barepod"},
	}), "a bare name yields an empty namespace")
}

func TestNodeInfoFromLabels(t *testing.T) {
	RegisterTestingT(t)
	ni := nodeInfoFromLabels("nodeA", map[string]string{
		"node-role.kubernetes.io/worker": "",
		"topology.kubernetes.io/zone":    "us-east-1a",
		"unrelated":                      "x",
	}, true)
	Expect(ni.Name).To(Equal("nodeA"))
	Expect(ni.Roles).To(ConsistOf("worker"))
	Expect(ni.Zone).To(Equal("us-east-1a"))
	Expect(ni.Ready).To(BeTrue())

	// Empty role suffix is ignored; no zone leaves Zone blank.
	ni = nodeInfoFromLabels("nodeB", map[string]string{"node-role.kubernetes.io/": ""}, false)
	Expect(ni.Roles).To(BeEmpty())
	Expect(ni.Zone).To(Equal(""))
	Expect(ni.Ready).To(BeFalse())
}

func TestBuildNodeOrdering(t *testing.T) {
	RegisterTestingT(t)
	all := []string{"n1", "n2", "n3", "n4", "n5"}
	// problem n3; comparison n5; focus n2; rest follow.
	nodeList, uncapped := buildNodeOrdering(all, []string{"n3"}, []string{"n5"}, []string{"n2"})

	// Order: problem, comparison, focus, then remaining all-nodes (deduped).
	Expect(nodeList).To(Equal([]string{"n3", "n5", "n2", "n1", "n4"}))

	// Uncapped = problem ∪ comparison only (focus stays capped).
	Expect(uncapped.Contains("n3")).To(BeTrue())
	Expect(uncapped.Contains("n5")).To(BeTrue())
	Expect(uncapped.Contains("n2")).To(BeFalse(), "focus nodes are not uncapped")
	Expect(uncapped.Contains("n1")).To(BeFalse())
}

func TestBuildNodeOrdering_TargetNotInClusterList(t *testing.T) {
	RegisterTestingT(t)
	// A problem node that wasn't returned by the node list is still included.
	nodeList, uncapped := buildNodeOrdering([]string{"n1"}, []string{"ghost"}, nil, nil)
	Expect(nodeList).To(Equal([]string{"ghost", "n1"}))
	Expect(uncapped.Contains("ghost")).To(BeTrue())
}

func TestMergeNodeNames(t *testing.T) {
	RegisterTestingT(t)
	Expect(mergeNodeNames([]string{"a", "b"}, []string{"b", "c", "", "a", "d"})).
		To(Equal([]string{"a", "b", "c", "d"}), "dedupes against dst and src, drops blanks, keeps order")
}

func TestSuggestComparisonNodes(t *testing.T) {
	RegisterTestingT(t)
	nodes := []nodeInfo{
		{Name: "prob", Roles: []string{"worker"}, Zone: "z1", Ready: true},
		{Name: "sameRole", Roles: []string{"worker"}, Zone: "z2", Ready: true},
		{Name: "sameZone", Roles: []string{"control"}, Zone: "z1", Ready: true},
		{Name: "different", Roles: []string{"control"}, Zone: "z9", Ready: true},
		{Name: "notReady", Roles: []string{"worker"}, Zone: "z1", Ready: false},
	}
	// Similar (role or zone) nodes are preferred over different ones; the
	// problem node and NotReady nodes are excluded.
	got := suggestComparisonNodes(nodes, []string{"prob"}, 2)
	Expect(got).To(Equal([]string{"sameRole", "sameZone"}))

	// n caps the count.
	Expect(suggestComparisonNodes(nodes, []string{"prob"}, 1)).To(Equal([]string{"sameRole"}))

	// When no similar nodes exist, fall back to any Ready non-problem node.
	got = suggestComparisonNodes([]nodeInfo{
		{Name: "prob", Roles: []string{"worker"}, Zone: "z1", Ready: true},
		{Name: "other", Roles: []string{"control"}, Zone: "z9", Ready: true},
	}, []string{"prob"}, 2)
	Expect(got).To(Equal([]string{"other"}))

	// n <= 0 yields nothing.
	Expect(suggestComparisonNodes(nodes, []string{"prob"}, 0)).To(BeNil())
}

func TestResolvePodsToNodes(t *testing.T) {
	RegisterTestingT(t)
	client := fake.NewSimpleClientset(
		pod("calico-system", "p1", "nodeA"),
		pod("calico-system", "p2", "nodeA"),
		pod("calico-system", "p3", "nodeB"),
		pod("calico-system", "unscheduled", ""),
	)
	refs := []podRef{
		{Namespace: "calico-system", Name: "p1"},
		{Namespace: "calico-system", Name: "p3"},
		{Namespace: "calico-system", Name: "p2"}, // same node as p1 -> deduped
		{Namespace: "calico-system", Name: "missing"},
		{Namespace: "calico-system", Name: "unscheduled"}, // no node -> notFound
	}
	nodes, notFound, err := resolvePodsToNodes(context.Background(), client, refs)
	Expect(err).NotTo(HaveOccurred())
	Expect(nodes).To(Equal([]string{"nodeA", "nodeB"}), "deduped, first-seen order")
	Expect(notFound).To(ConsistOf(
		podRef{Namespace: "calico-system", Name: "missing"},
		podRef{Namespace: "calico-system", Name: "unscheduled"},
	))
}

func TestGatherNodeInfo(t *testing.T) {
	RegisterTestingT(t)
	readyNode := &apiv1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "nodeA",
			Labels: map[string]string{"node-role.kubernetes.io/worker": "", "topology.kubernetes.io/zone": "z1"},
		},
		Status: apiv1.NodeStatus{Conditions: []apiv1.NodeCondition{
			{Type: apiv1.NodeReady, Status: apiv1.ConditionTrue},
		}},
	}
	notReadyNode := &apiv1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "nodeB"},
		Status: apiv1.NodeStatus{Conditions: []apiv1.NodeCondition{
			{Type: apiv1.NodeReady, Status: apiv1.ConditionFalse},
		}},
	}
	client := fake.NewSimpleClientset(readyNode, notReadyNode)
	infos, err := gatherNodeInfo(context.Background(), client)
	Expect(err).NotTo(HaveOccurred())
	Expect(infos).To(ConsistOf(
		nodeInfo{Name: "nodeA", Roles: []string{"worker"}, Zone: "z1", Ready: true},
		nodeInfo{Name: "nodeB", Ready: false},
	))
}

func TestDescribeInteractive_ByNode(t *testing.T) {
	RegisterTestingT(t)
	// n1/n2 are the problem nodes, n3 chosen for comparison.
	out := describeInteractive(false, nil, []string{"n1", "n2"}, []string{"n3"})

	Expect(out).To(ContainSubstring("These diagnostics will be collected:"))
	Expect(out).To(ContainSubstring("- General cluster diagnostics."))
	Expect(out).To(ContainSubstring("- Logs and diagnostics from all cluster-scoped Calico components."))
	Expect(out).To(ContainSubstring("- Detailed per-node diagnostics from the problem nodes:"))
	Expect(out).To(ContainSubstring("  - n1"))
	Expect(out).To(ContainSubstring("  - n2"))
	Expect(out).To(ContainSubstring("- Detailed per-node diagnostics from the comparison nodes:"))
	Expect(out).To(ContainSubstring("  - n3"))
	// The capped-sweep line was removed from the plan.
	Expect(out).NotTo(ContainSubstring("capped log sweep"))

	// No comparison nodes: the comparison line is omitted entirely.
	out = describeInteractive(false, nil, []string{"n1"}, nil)
	Expect(out).NotTo(ContainSubstring("comparison nodes:"))
}

func TestDescribeInteractive_ByPod(t *testing.T) {
	RegisterTestingT(t)
	// The picker has already mapped the two pods to nodes n1/n2, so the by-pod
	// plan looks like the by-node plan plus a note of which pods they came from.
	out := describeInteractive(true,
		[]string{"calico-system/p1", "calico-system/p2"}, // pods
		[]string{"n1", "n2"},                             // resolved problem nodes
		[]string{"n3"})                                   // resolved comparison nodes

	Expect(out).To(ContainSubstring("- Detailed per-node diagnostics from the nodes hosting the problem pods:"))
	Expect(out).To(ContainSubstring("  - n1"))
	Expect(out).To(ContainSubstring("  - n2"))
	Expect(out).To(ContainSubstring("(pods: calico-system/p1, calico-system/p2)"))
	Expect(out).To(ContainSubstring("- Detailed per-node diagnostics from the comparison nodes:"))
	Expect(out).To(ContainSubstring("  - n3"))
}

func TestDescribeComparisonChoice(t *testing.T) {
	RegisterTestingT(t)
	// Recaps the problem nodes, then frames the suggestions as additional.
	out := describeComparisonChoice([]string{"nodeX", "nodeY"}, []string{"nodeP", "nodeQ"})
	Expect(out).To(ContainSubstring("Problem nodes selected:"))
	Expect(out).To(ContainSubstring("  - nodeX"))
	Expect(out).To(ContainSubstring("  - nodeY"))
	Expect(out).To(ContainSubstring("For comparison"))
	Expect(out).To(ContainSubstring("  - nodeP"))
	Expect(out).To(ContainSubstring("  - nodeQ"))

	// No suggestions available: still recaps problem nodes, no "suggested" list.
	out = describeComparisonChoice([]string{"nodeX"}, nil)
	Expect(out).To(ContainSubstring("  - nodeX"))
	Expect(out).To(ContainSubstring("spot what's different"))
}

func TestRoleScaffold(t *testing.T) {
	RegisterTestingT(t)
	trailer := "\n\n" + externalEndpointsPrompt
	// By-pod: one "Pod <ref>: " line per pod, then the external-endpoints trailer.
	Expect(roleScaffold(true, []string{"ns/p1", "ns/p2"}, nil)).
		To(Equal("Pod ns/p1: \nPod ns/p2: " + trailer))
	// By-node: one "Node <name>: " line per node.
	Expect(roleScaffold(false, nil, []string{"n1"})).To(Equal("Node n1: " + trailer))
	// With nothing selected, only the external-endpoints trailer is shown.
	Expect(roleScaffold(true, nil, nil)).To(Equal(externalEndpointsPrompt))
}

func TestNodesForPods(t *testing.T) {
	RegisterTestingT(t)
	byRef := map[string]string{
		"ns/p1": "nodeA",
		"ns/p2": "nodeA", // same node -> deduped
		"ns/p3": "nodeB",
		"ns/p4": "", // unscheduled -> skipped
	}
	// First-seen order, deduped, unscheduled and unknown refs dropped.
	got := nodesForPods([]string{"ns/p3", "ns/p1", "ns/p2", "ns/p4", "ns/missing"}, byRef)
	Expect(got).To(Equal([]string{"nodeB", "nodeA"}))
	Expect(nodesForPods(nil, byRef)).To(BeEmpty())
}

func TestComparisonNodesFromPods(t *testing.T) {
	RegisterTestingT(t)
	byRef := map[string]string{
		"ns/cmp1":    "nodeC",
		"ns/cmp2":    "nodeD",
		"ns/onProb":  "nodeA", // already a problem node -> excluded
		"ns/dupe":    "nodeC", // same node as cmp1 -> deduped
		"ns/unsched": "",      // unscheduled -> skipped
	}
	got := comparisonNodesFromPods(
		[]string{"ns/cmp1", "ns/onProb", "ns/cmp2", "ns/dupe", "ns/unsched"},
		byRef, []string{"nodeA", "nodeB"})
	Expect(got).To(Equal([]string{"nodeC", "nodeD"}))
}

func TestWriteNodeBullets_Truncates(t *testing.T) {
	RegisterTestingT(t)
	var names []string
	for i := 0; i < maxListedNodes+5; i++ {
		names = append(names, fmt.Sprintf("n%d", i))
	}
	var b strings.Builder
	writeNodeBullets(&b, names)
	out := b.String()
	Expect(out).To(ContainSubstring("  - n0"))
	Expect(out).To(ContainSubstring(fmt.Sprintf("  - n%d", maxListedNodes-1)))
	Expect(out).NotTo(ContainSubstring(fmt.Sprintf("  - n%d\n", maxListedNodes)))
	Expect(out).To(ContainSubstring("... and 5 more"))

	b.Reset()
	writeNodeBullets(&b, nil)
	Expect(b.String()).To(ContainSubstring("  - (none)"))
}

func TestGatherPodInfo(t *testing.T) {
	RegisterTestingT(t)
	client := fake.NewSimpleClientset(
		podPhase("calico-system", "b-pod", "nodeB", apiv1.PodRunning),
		podPhase("calico-system", "a-pod", "nodeA", apiv1.PodRunning),
		podPhase("batch", "done-pod", "nodeA", apiv1.PodSucceeded), // finished, kept
		pod("kube-system", "z-pod", ""),                            // unscheduled -> empty Node
	)
	pods, err := gatherPodInfo(context.Background(), client)
	Expect(err).NotTo(HaveOccurred())
	// Sorted by namespace then name; finished (Succeeded) pods are not filtered out.
	Expect(pods).To(Equal([]podInfo{
		{Namespace: "batch", Name: "done-pod", Node: "nodeA", Phase: "Succeeded"},
		{Namespace: "calico-system", Name: "a-pod", Node: "nodeA", Phase: "Running"},
		{Namespace: "calico-system", Name: "b-pod", Node: "nodeB", Phase: "Running"},
		{Namespace: "kube-system", Name: "z-pod", Node: ""},
	}))
}

func TestPodOptions(t *testing.T) {
	RegisterTestingT(t)
	opts := podOptions([]podInfo{
		{Namespace: "calico-system", Name: "p1", Node: "nodeA", Phase: "Running"},
		{Namespace: "batch", Name: "done", Node: "nodeA", Phase: "Succeeded"},
		{Namespace: "kube-system", Name: "unscheduled", Node: ""},
	})
	Expect(opts).To(HaveLen(3))
	// Value is the "namespace/pod" ref parsePodRefs understands.
	Expect(opts[0].Value).To(Equal("calico-system/p1"))
	Expect(opts[0].Key).To(ContainSubstring("calico-system/p1"))
	Expect(opts[0].Key).To(ContainSubstring("nodeA"))
	Expect(opts[0].Key).To(ContainSubstring("Running"))
	// Finished pods carry their phase so they stand out.
	Expect(opts[1].Key).To(ContainSubstring("Succeeded"))
	// Unscheduled pods are labelled rather than dropped.
	Expect(opts[2].Value).To(Equal("kube-system/unscheduled"))
	Expect(opts[2].Key).To(ContainSubstring("(no node)"))
}

func pod(ns, name, node string) *apiv1.Pod {
	return &apiv1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec:       apiv1.PodSpec{NodeName: node},
	}
}

func podPhase(ns, name, node string, phase apiv1.PodPhase) *apiv1.Pod {
	p := pod(ns, name, node)
	p.Status.Phase = phase
	return p
}
