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
	"testing"
	"time"

	. "github.com/onsi/gomega"
	apiv1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// --- the capability gate -----------------------------------------------------

func TestWizardUnavailableReason(t *testing.T) {
	RegisterTestingT(t)

	// A usable terminal: no reason to refuse.
	Expect(wizardUnavailableReasonFor(true, true, "xterm-256color")).To(BeEmpty())
	Expect(wizardUnavailableReasonFor(true, true, "")).To(BeEmpty())

	// Redirected input or output rules the picker out; stdin is reported first
	// because it is the one the operator is most likely to have piped by accident.
	Expect(wizardUnavailableReasonFor(false, true, "xterm")).To(Equal("stdin is not a terminal"))
	Expect(wizardUnavailableReasonFor(true, false, "xterm")).To(Equal("stdout is not a terminal"))
	Expect(wizardUnavailableReasonFor(false, false, "xterm")).To(Equal("stdin is not a terminal"))

	// The reported bug: a real terminal, but TERM=dumb, where huh silently
	// switches to accessible mode and our custom pickers cannot collect anything.
	// Coupled to huh/v2 form.go's own `TERM == "dumb"` check; huh exposes no way to
	// ask, so if this ever diverges the symptom is the wizard collecting nothing.
	Expect(wizardUnavailableReasonFor(true, true, dumbTerm)).To(ContainSubstring("TERM=dumb"))
}

func TestTargetingRequiredError(t *testing.T) {
	RegisterTestingT(t)
	err := targetingRequiredError("stdout is not a terminal")

	// The message must say what went wrong and every way forward, because the
	// operator hitting it is mid-incident and this is all they get.
	Expect(err.Error()).To(ContainSubstring("stdout is not a terminal"))
	Expect(err.Error()).To(ContainSubstring("--problem-nodes"))
	Expect(err.Error()).To(ContainSubstring("--problem-pods"))
	Expect(err.Error()).To(ContainSubstring("--comparison-nodes"))
	Expect(err.Error()).To(ContainSubstring(fmt.Sprintf("--sample-nodes=%d", recommendedMaxFullNodes)))
}

func TestResolveNodeTargeting_RefusesWithoutTargetingOrTerminal(t *testing.T) {
	RegisterTestingT(t)
	// Under `go test` stdin is not a terminal, so this exercises the real gate.
	client := fake.NewSimpleClientset(sampleNode("nodeA", ready))

	_, err := resolveNodeTargeting(client, &diagOpts{})
	Expect(err).To(HaveOccurred(), "no targeting and no usable terminal must refuse")
	Expect(err.Error()).To(ContainSubstring("cannot ask which nodes to collect from"))

	// Any targeting flag satisfies the gate, so the refusal never fires.
	for _, opts := range []Options{
		{ProblemNodes: "nodeA"},
		{ProblemPods: "calico-system/p1"},
		{ComparisonNodes: "nodeA"},
		{FocusNodes: "nodeA"},
		{SampleNodes: 1},
	} {
		proceed, err := resolveNodeTargeting(client, &diagOpts{Options: opts})
		Expect(err).NotTo(HaveOccurred(), "opts %+v should be accepted", opts)
		Expect(proceed).To(BeTrue())
	}
}

func TestResolveNodeTargeting_SampleFoldsIntoProblemNodes(t *testing.T) {
	RegisterTestingT(t)
	client := fake.NewSimpleClientset(
		sampleNode("nodeA", ready),
		sampleNode("nodeB", notReady),
	)

	opts := &diagOpts{Options: Options{SampleNodes: 2}}
	proceed, err := resolveNodeTargeting(client, opts)
	Expect(err).NotTo(HaveOccurred())
	Expect(proceed).To(BeTrue())

	// The sample becomes problem nodes (collected in full) and is recorded with
	// its reasons for the bundle.
	Expect(parseCSV(opts.ProblemNodes)).To(ConsistOf("nodeA", "nodeB"))
	Expect(opts.Sampled).To(HaveLen(2))
	Expect(sampledNodeNames(opts.Sampled)).To(ConsistOf("nodeA", "nodeB"))
	Expect(reasonFor(opts.Sampled, "nodeB")).To(Equal("node is not Ready"))
}

// --- the sampler ------------------------------------------------------------

func TestPickSample_PrefersUnhealthyThenSpreads(t *testing.T) {
	RegisterTestingT(t)
	cands := candidates([]nodeInfo{
		{Name: "broken", Ready: false},
		{Name: "netdown", Ready: true, NetworkUnavailable: true},
		{Name: "cordoned", Ready: true, Unschedulable: true},
		{Name: "fine-1", Ready: true},
		{Name: "fine-2", Ready: true},
		{Name: "fine-3", Ready: true},
	}, nil)

	// With room for three, the three broken-in-different-ways nodes win over any
	// healthy node.
	got := pickSample(cands, 3)
	Expect(sampledNodeNames(got)).To(ConsistOf("broken", "netdown", "cordoned"))
	Expect(reasonFor(got, "broken")).To(Equal("node is not Ready"))
	Expect(reasonFor(got, "netdown")).To(Equal("node reports NetworkUnavailable"))
	Expect(reasonFor(got, "cordoned")).To(Equal("node is cordoned"))

	// Given more room, healthy nodes fill the rest so the bundle has a baseline.
	got = pickSample(cands, 5)
	Expect(sampledNodeNames(got)).To(HaveLen(5))
	Expect(sampledNodeNames(got)).To(ContainElement("broken"))
	Expect(sampledNodeNames(got)).To(SatisfyAny(
		ContainElement("fine-1"), ContainElement("fine-2"), ContainElement("fine-3")))
}

func TestPickSample_CalicoNodeAxes(t *testing.T) {
	RegisterTestingT(t)
	old := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	recent := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)

	cands := candidates(
		[]nodeInfo{
			{Name: "n-notready-pod", Ready: true},
			{Name: "n-restarts", Ready: true},
			{Name: "n-recent", Ready: true},
			{Name: "n-oldest", Ready: true},
			{Name: "n-plain", Ready: true},
		},
		map[string]*calicoNodeStatus{
			"n-notready-pod": {Ready: false, StartedAt: recent},
			"n-restarts":     {Ready: true, Restarts: 42, StartedAt: recent},
			"n-recent":       {Ready: true, Restarts: 1, LastRestart: recent, StartedAt: recent},
			"n-oldest":       {Ready: true, StartedAt: old},
			"n-plain":        {Ready: true, StartedAt: recent},
		})

	got := pickSample(cands, 4)
	byNode := map[string]string{}
	for _, s := range got {
		byNode[s.Node] = s.Reason
	}
	Expect(byNode).To(HaveKeyWithValue("n-notready-pod", "calico-node pod is not ready"))
	Expect(byNode).To(HaveKeyWithValue("n-restarts", "most calico-node restarts"))
	Expect(byNode).To(HaveKeyWithValue("n-recent", "calico-node restarted most recently"))
	Expect(byNode).To(HaveKeyWithValue("n-oldest", "longest-running calico-node"))
}

func TestPickSample_RarestVersionWins(t *testing.T) {
	RegisterTestingT(t)
	// Ninety-nine nodes agree on the kernel; one does not. The odd one out is the
	// interesting node, so it must be picked ahead of any of the ninety-nine.
	var infos []nodeInfo
	for i := 0; i < 99; i++ {
		infos = append(infos, nodeInfo{
			Name: fmt.Sprintf("node-%02d", i), Ready: true, KernelVersion: "6.8.0-generic",
		})
	}
	infos = append(infos, nodeInfo{Name: "node-odd", Ready: true, KernelVersion: "6.1.0-oddball"})

	got := pickSample(candidates(infos, nil), 2)
	Expect(sampledNodeNames(got)).To(ContainElement("node-odd"))
	Expect(reasonFor(got, "node-odd")).To(Equal("rarest kernel version"))
}

func TestNamesByRarestValue_UniformClusterHasNoOddOneOut(t *testing.T) {
	RegisterTestingT(t)
	uniform := candidates([]nodeInfo{
		{Name: "a", KernelVersion: "6.8"},
		{Name: "b", KernelVersion: "6.8"},
	}, nil)
	// Every node agrees, so there is nothing to learn from this axis.
	Expect(namesByRarestValue(uniform, func(n nodeCandidate) string { return n.KernelVersion })).
		To(BeEmpty())

	// Unknown (empty) values are skipped rather than forming their own group.
	mixed := candidates([]nodeInfo{
		{Name: "a", KernelVersion: ""},
		{Name: "b", KernelVersion: "6.8"},
		{Name: "c", KernelVersion: "6.8"},
		{Name: "d", KernelVersion: "6.1"},
	}, nil)
	Expect(namesByRarestValue(mixed, func(n nodeCandidate) string { return n.KernelVersion })).
		To(Equal([]string{"d", "b"}), "rarest group first, one representative each")
}

func TestPickSample_BoundsAndSmallClusters(t *testing.T) {
	RegisterTestingT(t)
	cands := candidates([]nodeInfo{
		{Name: "a", Ready: true}, {Name: "b", Ready: true}, {Name: "c", Ready: true},
	}, nil)

	// Never more than asked for.
	Expect(pickSample(cands, 2)).To(HaveLen(2))

	// A cluster smaller than the request yields all of it, with no duplicates.
	got := pickSample(cands, 10)
	Expect(sampledNodeNames(got)).To(ConsistOf("a", "b", "c"))

	// Degenerate requests are refused rather than defaulted.
	Expect(pickSample(cands, 0)).To(BeEmpty())
	Expect(pickSample(nil, 5)).To(BeEmpty())
}

func TestPickSample_IsDeterministic(t *testing.T) {
	RegisterTestingT(t)
	// Two engineers running this against an unchanged cluster should get the same
	// bundle, so the sample must not depend on map or list ordering.
	var infos []nodeInfo
	for i := 0; i < 40; i++ {
		infos = append(infos, nodeInfo{
			Name:  fmt.Sprintf("node-%02d", i),
			Ready: true,
			Zone:  fmt.Sprintf("zone-%d", i%4),
		})
	}
	first := sampledNodeNames(pickSample(candidates(infos, nil), 7))
	for i := 0; i < 5; i++ {
		Expect(sampledNodeNames(pickSample(candidates(infos, nil), 7))).To(Equal(first))
	}
}

func TestSpread_StridesRatherThanTakingNeighbours(t *testing.T) {
	RegisterTestingT(t)
	// Node names usually encode position, so neighbours are the least different
	// nodes available. Striding must put distant entries first, and must neither
	// drop nor duplicate anything.
	in := []string{"a", "b", "c", "d", "e", "f", "g", "h"}
	got := spread(in)
	Expect(got).To(ConsistOf(in))
	Expect(got).To(HaveLen(len(in)))
	Expect(got[0]).To(Equal("a"))
	Expect(got[1]).To(Equal("e"), "second pick comes from halfway down the list")

	// Short lists have nothing to stride over.
	Expect(spread([]string{"a", "b"})).To(Equal([]string{"a", "b"}))
	Expect(spread(nil)).To(BeEmpty())
}

// --- projections ------------------------------------------------------------

func TestNodeInfoFromNode(t *testing.T) {
	RegisterTestingT(t)
	node := &apiv1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "nodeA",
			Labels: map[string]string{"node-role.kubernetes.io/worker": ""},
		},
		Spec: apiv1.NodeSpec{Unschedulable: true},
		Status: apiv1.NodeStatus{
			Conditions: []apiv1.NodeCondition{
				{Type: apiv1.NodeReady, Status: apiv1.ConditionTrue},
				{Type: apiv1.NodeNetworkUnavailable, Status: apiv1.ConditionTrue},
			},
			NodeInfo: apiv1.NodeSystemInfo{KernelVersion: "6.8.0", KubeletVersion: "v1.33.1"},
		},
	}
	ni := nodeInfoFromNode(node)
	Expect(ni.Name).To(Equal("nodeA"))
	Expect(ni.Roles).To(ConsistOf("worker"))
	Expect(ni.Ready).To(BeTrue())
	Expect(ni.NetworkUnavailable).To(BeTrue())
	Expect(ni.Unschedulable).To(BeTrue())
	Expect(ni.KernelVersion).To(Equal("6.8.0"))
	Expect(ni.KubeletVersion).To(Equal("v1.33.1"))

	// An absent NetworkUnavailable condition is not "unavailable".
	Expect(nodeInfoFromNode(&apiv1.Node{}).NetworkUnavailable).To(BeFalse())
}

func TestCalicoNodeStatusFromPod(t *testing.T) {
	RegisterTestingT(t)
	started := time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC)
	older := time.Date(2026, 6, 2, 9, 0, 0, 0, time.UTC)
	newer := time.Date(2026, 6, 3, 9, 0, 0, 0, time.UTC)

	pod := &apiv1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "calico-system", Name: "calico-node-abc"},
		Spec: apiv1.PodSpec{
			Containers: []apiv1.Container{{Name: "calico-node", Image: "calico/node:v3.30.0"}},
		},
		Status: apiv1.PodStatus{
			StartTime:  &metav1.Time{Time: started},
			Conditions: []apiv1.PodCondition{{Type: apiv1.PodReady, Status: apiv1.ConditionFalse}},
			ContainerStatuses: []apiv1.ContainerStatus{
				{
					Name: "calico-node", Image: "calico/node:v3.30.0", RestartCount: 2,
					LastTerminationState: apiv1.ContainerState{
						Terminated: &apiv1.ContainerStateTerminated{FinishedAt: metav1.Time{Time: older}},
					},
				},
				{
					Name: "sidecar", RestartCount: 3,
					LastTerminationState: apiv1.ContainerState{
						Terminated: &apiv1.ContainerStateTerminated{FinishedAt: metav1.Time{Time: newer}},
					},
				},
			},
			InitContainerStatuses: []apiv1.ContainerStatus{{Name: "install-cni", RestartCount: 1}},
		},
	}

	st := calicoNodeStatusFromPod(pod)
	Expect(st.Pod).To(Equal("calico-node-abc"))
	Expect(st.Ready).To(BeFalse())
	Expect(st.StartedAt).To(Equal(started))
	Expect(st.Restarts).To(Equal(int32(6)), "restarts are summed across all containers")
	Expect(st.LastRestart).To(Equal(newer), "the most recent termination wins, whichever container")
	Expect(st.Image).To(Equal("calico/node:v3.30.0"))

	// No status at all: zero values, not a panic.
	bare := calicoNodeStatusFromPod(&apiv1.Pod{})
	Expect(bare.Ready).To(BeFalse())
	Expect(bare.Restarts).To(BeZero())
	Expect(bare.LastRestart.IsZero()).To(BeTrue())
	Expect(bare.StartedAt.IsZero()).To(BeTrue())
}

func TestGatherCalicoNodeStatus(t *testing.T) {
	RegisterTestingT(t)
	// The label selector is what finds calico-node across operator and manifest
	// installs, so pods without it must be ignored and unscheduled ones skipped.
	client := fake.NewSimpleClientset(
		calicoNodePod("calico-system", "calico-node-a", "nodeA", true),
		calicoNodePod("kube-system", "calico-node-b", "nodeB", true),
		calicoNodePod("calico-system", "calico-node-unsched", "", true),
	)
	byNode, err := gatherCalicoNodeStatus(context.Background(), client)
	Expect(err).NotTo(HaveOccurred())
	Expect(byNode).To(HaveLen(2))
	Expect(byNode).To(HaveKey("nodeA"))
	Expect(byNode).To(HaveKey("nodeB"), "manifest installs put calico-node in kube-system")
}

func TestSampleNodes_SurvivesMissingCalicoNodePods(t *testing.T) {
	RegisterTestingT(t)
	// A cluster where calico-node isn't found at all still yields a Node-only
	// sample rather than failing the whole collection.
	client := fake.NewSimpleClientset(sampleNode("nodeA", notReady), sampleNode("nodeB", ready))
	got, err := sampleNodes(context.Background(), client, 2)
	Expect(err).NotTo(HaveOccurred())
	Expect(sampledNodeNames(got)).To(ConsistOf("nodeA", "nodeB"))

	// An empty cluster samples nothing, and says so via an empty result.
	got, err = sampleNodes(context.Background(), fake.NewSimpleClientset(), 5)
	Expect(err).NotTo(HaveOccurred())
	Expect(got).To(BeEmpty())
}

// --- helpers ----------------------------------------------------------------

type readiness bool

const (
	ready    readiness = true
	notReady readiness = false
)

func sampleNode(name string, r readiness) *apiv1.Node {
	status := apiv1.ConditionFalse
	if r == ready {
		status = apiv1.ConditionTrue
	}
	return &apiv1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Status: apiv1.NodeStatus{Conditions: []apiv1.NodeCondition{
			{Type: apiv1.NodeReady, Status: status},
		}},
	}
}

func calicoNodePod(ns, name, node string, podReady bool) *apiv1.Pod {
	status := apiv1.ConditionFalse
	if podReady {
		status = apiv1.ConditionTrue
	}
	return &apiv1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns, Name: name,
			Labels: map[string]string{"k8s-app": "calico-node"},
		},
		Spec: apiv1.PodSpec{NodeName: node},
		Status: apiv1.PodStatus{
			Conditions: []apiv1.PodCondition{{Type: apiv1.PodReady, Status: status}},
		},
	}
}

func reasonFor(sampled []sampledNode, node string) string {
	for _, s := range sampled {
		if s.Node == node {
			return s.Reason
		}
	}
	return ""
}
