// Copyright (c) 2022-2026 Tigera, Inc. All rights reserved.

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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	apiv1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"

	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/common"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

func TestWriteBundleInfo(t *testing.T) {
	RegisterTestingT(t)

	dir := t.TempDir()
	opts := &diagOpts{
		Options: Options{
			MaxLogs:         5,
			MaxParallelism:  10,
			ProblemNodes:    "nodeA,nodeB",
			ComparisonNodes: "nodeC",
			ProblemPods:     "calico-system/calico-node-abcde,calico-system/calico-node-fghij",
		},
		StartedAt:   "10:30am today",
		Description: "Pod ns/widget-runner: source, sends TCP to backend",
		AnsweredAt:  "2026-06-18T10:35:00Z",
	}
	timedOut := []common.TimedOutCommand{{
		Info:    "Collect nftables for node nodeA",
		Command: "kubectl exec -n calico-system -t calico-node-abcde -c calico-node -- nft -n -a list ruleset",
		File:    "/nodes/nodeA/nft-ruleset.txt",
	}}
	writeBundleInfo(dir, opts, true, outcomeTimedOut, timedOut)

	data, err := os.ReadFile(filepath.Join(dir, "bundle-info.yaml"))
	Expect(err).NotTo(HaveOccurred())

	var info bundleInfo
	Expect(yaml.Unmarshal(data, &info)).To(Succeed())
	Expect(info.BPFDataplane).To(BeTrue())
	Expect(info.CollectedAt).NotTo(BeEmpty())
	Expect(info.CollectionOutcome).To(Equal(outcomeTimedOut))
	Expect(info.TimedOutCommands).To(Equal(timedOut))
	Expect(info.Options.MaxLogs).To(Equal(5))
	Expect(info.Targeting.ProblemNodes).To(Equal([]string{"nodeA", "nodeB"}))
	Expect(info.Targeting.ComparisonNodes).To(Equal([]string{"nodeC"}))
	Expect(info.Targeting.ProblemPods).To(Equal([]string{
		"calico-system/calico-node-abcde", "calico-system/calico-node-fghij",
	}))
	Expect(info.Targeting.FullCollectionNodeCount).To(Equal(3))
	Expect(info.ProblemStartedAt).To(Equal("10:30am today"))
	Expect(info.ProblemDescription).To(Equal("Pod ns/widget-runner: source, sends TCP to backend"))
	Expect(info.QuestionsAnsweredAt).To(Equal("2026-06-18T10:35:00Z"))
	// The operator named these, so nothing was auto-sampled.
	Expect(info.Targeting.SampledNodes).To(BeEmpty())
}

// A --sample-nodes run must be distinguishable in the bundle from one where the
// operator identified the nodes: the reader needs to know nobody had found the
// problem yet, and on what grounds each node was picked.
func TestWriteBundleInfo_SampledNodes(t *testing.T) {
	RegisterTestingT(t)

	dir := t.TempDir()
	sampled := []sampledNode{
		{Node: "nodeA", Reason: "node is not Ready"},
		{Node: "nodeB", Reason: "most calico-node restarts"},
	}
	writeBundleInfo(dir, &diagOpts{
		Options: Options{MaxLogs: 5, SampleNodes: 2, ProblemNodes: "nodeA,nodeB"},
		Sampled: sampled,
	}, false, outcomeComplete, nil)

	data, err := os.ReadFile(filepath.Join(dir, "bundle-info.yaml"))
	Expect(err).NotTo(HaveOccurred())
	var info bundleInfo
	Expect(yaml.Unmarshal(data, &info)).To(Succeed())

	Expect(info.Targeting.SampledNodes).To(Equal(sampled))
	Expect(info.Targeting.ProblemNodes).To(Equal([]string{"nodeA", "nodeB"}),
		"sampled nodes are collected in full, like problem nodes")
	// The reasons must survive into the YAML, not just the names.
	Expect(string(data)).To(ContainSubstring("most calico-node restarts"))
}

func init() {
	logutils.ConfigureFormatter("test")
}

func TestBpfJSONCmd_CollectsJSONWithTextFallback(t *testing.T) {
	RegisterTestingT(t)

	// Each calico-bpf dump must request JSON via the combined-binary path and
	// land in a .json file, with a fallback to the legacy `calico-node -bpf`
	// text form (.txt file) for older calico-node versions that have neither
	// the `calico component node bpf` path nor --json.
	cmd := bpfJSONCmd("/node-dir", "nodeA", "calico-system", "calico-node-xyz", "nat maglev table", "nat maglev", "bpf-nat-maglev")

	Expect(cmd.CmdStr).To(ContainSubstring("calico component node bpf nat maglev"))
	Expect(cmd.CmdStr).To(HaveSuffix("--json"))
	Expect(cmd.FilePath).To(Equal("/node-dir/bpf-nat-maglev.json"))

	Expect(cmd.FallbackCmdStr).To(ContainSubstring("calico-node -bpf nat maglev"))
	Expect(cmd.FallbackCmdStr).NotTo(ContainSubstring("calico component node bpf"),
		"fallback must use the legacy calico-node -bpf invocation")
	Expect(cmd.FallbackCmdStr).NotTo(ContainSubstring("--json"),
		"legacy fallback predates --json")
	Expect(cmd.FallbackFilePath).To(Equal("/node-dir/bpf-nat-maglev.txt"))
}

// parseTimeout is the only validation left on the flag path now that cobra owns
// parsing: it must reject anything that would silently disable the bound, and
// name the flag so the operator knows which one to correct.
func TestParseTimeout(t *testing.T) {
	RegisterTestingT(t)

	d, err := parseTimeout("30s", "--command-timeout")
	Expect(err).NotTo(HaveOccurred())
	Expect(d).To(Equal(30 * time.Second))

	d, err = parseTimeout("1h30m", "--overall-timeout")
	Expect(err).NotTo(HaveOccurred())
	Expect(d).To(Equal(90 * time.Minute))

	// Unparseable, zero and negative values are all refused, and the message
	// names the offending flag.
	for _, bad := range []string{"", "soon", "5", "0s", "-1m"} {
		_, err := parseTimeout(bad, "--command-timeout")
		Expect(err).To(HaveOccurred(), "expected %q to be rejected", bad)
		Expect(err.Error()).To(ContainSubstring("--command-timeout"))
	}
}

func TestDiagsCmdsForPod_Previous(t *testing.T) {
	RegisterTestingT(t)

	// A pod with no restarts gets only the current-log and describe commands.
	steady := &apiv1.Pod{}
	steady.Name = "calico-typha-0"
	steady.Status.ContainerStatuses = []apiv1.ContainerStatus{{Name: "calico-typha", RestartCount: 0}}
	cmds := diagsCmdsForPod("/dir", "/links", "nodeA", "calico-system", steady)
	Expect(cmdStrs(cmds)).NotTo(ContainElement(ContainSubstring("--previous")))

	// A pod whose container has restarted picks up an extra previous-log
	// command, scoped to that specific container (not --all-containers), so a
	// crashed container's logs survive even when sibling containers have no
	// previous incarnation.
	restarted := &apiv1.Pod{}
	restarted.Name = "calico-apiserver-0"
	restarted.Status.ContainerStatuses = []apiv1.ContainerStatus{
		{Name: "calico-apiserver", RestartCount: 2},
		{Name: "calico-apiserver-sidecar", RestartCount: 0},
	}
	cmds = diagsCmdsForPod("/dir", "/links", "nodeA", "calico-apiserver", restarted)
	prev := filterStrs(cmdStrs(cmds), "--previous")
	// Only the restarted container is fetched, and it is scoped with -c.
	Expect(prev).To(HaveLen(1))
	Expect(prev[0]).To(ContainSubstring("kubectl logs --previous"))
	Expect(prev[0]).To(ContainSubstring("-c calico-apiserver"))
	Expect(prev[0]).NotTo(ContainSubstring("--all-containers"))
	// --since is gone, so the previous-log command must not carry it either.
	Expect(prev[0]).NotTo(ContainSubstring("--since"))

	// An init container that previously terminated also gets its previous logs.
	initTerminated := &apiv1.Pod{}
	initTerminated.Name = "calico-node-xyz"
	initTerminated.Status.InitContainerStatuses = []apiv1.ContainerStatus{{
		Name:                 "install-cni",
		LastTerminationState: apiv1.ContainerState{Terminated: &apiv1.ContainerStateTerminated{ExitCode: 1}},
	}}
	cmds = diagsCmdsForPod("/dir", "/links", "nodeA", "calico-system", initTerminated)
	Expect(cmdStrs(cmds)).To(ContainElement(And(
		ContainSubstring("kubectl logs --previous"),
		ContainSubstring("-c install-cni"),
	)))
}

func filterStrs(strs []string, substr string) []string {
	var out []string
	for _, s := range strs {
		if strings.Contains(s, substr) {
			out = append(out, s)
		}
	}
	return out
}

func TestSelectPodsForCollection(t *testing.T) {
	RegisterTestingT(t)

	mkPods := func(names ...string) []apiv1.Pod {
		pods := make([]apiv1.Pod, len(names))
		for i, n := range names {
			pods[i].Name = n
		}
		return pods
	}
	podsByNode := map[string][]apiv1.Pod{
		"problemA": mkPods("pA1", "pA2"),
		"compB":    mkPods("pB1"),
		"n1":       mkPods("p1"),
		"n2":       mkPods("p2"),
		"n3":       mkPods("p3"),
	}
	// Ordering as buildNodeOrdering would produce: uncapped first.
	nodeList := []string{"problemA", "compB", "n1", "n2", "n3"}
	uncapped := set.From("problemA", "compB")

	names := func(sel []podOnNode) []string {
		out := make([]string, len(sel))
		for i, s := range sel {
			out[i] = s.node + "/" + s.pod.Name
		}
		return out
	}

	// maxLogs=1: both pods on the uncapped problem node are collected (exempt),
	// the single comparison-node pod is collected, plus exactly one capped pod.
	sel := selectPodsForCollection(nodeList, uncapped, podsByNode, 1)
	Expect(names(sel)).To(Equal([]string{"problemA/pA1", "problemA/pA2", "compB/pB1", "n1/p1"}))

	// maxLogs=0: only the uncapped nodes are collected.
	sel = selectPodsForCollection(nodeList, uncapped, podsByNode, 0)
	Expect(names(sel)).To(Equal([]string{"problemA/pA1", "problemA/pA2", "compB/pB1"}))

	// No targeting (empty uncapped set): pure capped sweep, max 2 pods.
	sel = selectPodsForCollection([]string{"n1", "n2", "n3"}, set.New[string](), podsByNode, 2)
	Expect(names(sel)).To(Equal([]string{"n1/p1", "n2/p2"}))
}

func cmdStrs(cmds []common.Cmd) []string {
	out := make([]string, len(cmds))
	for i, c := range cmds {
		out[i] = c.CmdStr
	}
	return out
}
