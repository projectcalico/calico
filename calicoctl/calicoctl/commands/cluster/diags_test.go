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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
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
		MaxLogs:         5,
		MaxParallelism:  10,
		ProblemNodes:    "nodeA,nodeB",
		ComparisonNodes: "nodeC",
		ProblemPods:     "calico-system/calico-node-abcde,calico-system/calico-node-fghij",
		StartedAt:       "10:30am today",
		Description:     "Pod ns/widget-runner: source, sends TCP to backend",
		AnsweredAt:      "2026-06-18T10:35:00Z",
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

func TestDiags(t *testing.T) {
	RegisterTestingT(t)
	test := func(invocation string, expectedErr error, expectedOutput string, expectedOpts *diagOpts) {
		logrus.Infof("Test case: %v", invocation)
		output := ""
		opts := (*diagOpts)(nil)
		err := diagsTestable(
			strings.Split(invocation, " "),
			func(a ...any) (int, error) {
				output = fmt.Sprint(a...)
				return 0, nil
			}, func(o *diagOpts) error {
				opts = o
				return nil
			})
		if expectedErr == nil {
			Expect(err).To(BeNil())
		} else {
			Expect(err).NotTo(BeNil())
			Expect(err.Error()).To(Equal(expectedErr.Error()))
		}
		Expect(output).To(Equal(expectedOutput))
		if expectedOpts != nil {
			// Save having to specify Cluster and Diags in all of the cases below.
			expectedOpts.Cluster = true
			expectedOpts.Diags = true
			// Timeout flags default via docopt; only the overriding case sets them.
			if expectedOpts.CommandTimeout == "" {
				expectedOpts.CommandTimeout = "5m"
			}
			if expectedOpts.OverallTimeout == "" {
				expectedOpts.OverallTimeout = "10m"
			}
		}
		Expect(opts).To(Equal(expectedOpts))
	}
	test("cluster diags",
		nil,
		"",
		&diagOpts{
			Config:               "/etc/calico/calicoctl.cfg",
			MaxLogs:              5,
			MaxParallelism:       10,
			FocusNodes:           "",
			AllowVersionMismatch: false,
		})
	test("cluster diags -h",
		nil,
		doc,
		nil)
	test("cluster diags --help",
		nil,
		doc,
		nil)
	test("cluster diags rubbish",
		errors.New("invalid option: 'calicoctl cluster diags rubbish'.\n\n"+usage),
		"",
		nil)
	test("cluster diags --rubbish",
		errors.New("invalid option: 'calicoctl cluster diags --rubbish'.\n\n"+usage),
		"",
		nil)
	test("cluster diags -c /configfile",
		nil,
		"",
		&diagOpts{
			Config:               "/configfile",
			MaxLogs:              5,
			MaxParallelism:       10,
			FocusNodes:           "",
			AllowVersionMismatch: false,
		})
	test("cluster diags --config /configfile",
		nil,
		"",
		&diagOpts{
			Config:               "/configfile",
			MaxLogs:              5,
			MaxParallelism:       10,
			FocusNodes:           "",
			AllowVersionMismatch: false,
		})
	test("cluster diags --max-logs 1 --max-parallelism 2",
		nil,
		"",
		&diagOpts{
			Config:               "/etc/calico/calicoctl.cfg",
			MaxLogs:              1,
			MaxParallelism:       2,
			FocusNodes:           "",
			AllowVersionMismatch: false,
		})
	test("cluster diags --max-logs=1",
		nil,
		"",
		&diagOpts{
			Config:               "/etc/calico/calicoctl.cfg",
			MaxLogs:              1,
			MaxParallelism:       10,
			FocusNodes:           "",
			AllowVersionMismatch: false,
		})
	test("cluster diags --focus-node=infra1,control2",
		nil,
		"",
		&diagOpts{
			Config:               "/etc/calico/calicoctl.cfg",
			MaxLogs:              5,
			MaxParallelism:       10,
			FocusNodes:           "infra1,control2",
			AllowVersionMismatch: false,
		})
	test("cluster diags --command-timeout=30s --overall-timeout=20m",
		nil,
		"",
		&diagOpts{
			Config:               "/etc/calico/calicoctl.cfg",
			MaxLogs:              5,
			MaxParallelism:       10,
			CommandTimeout:       "30s",
			OverallTimeout:       "20m",
			AllowVersionMismatch: false,
		})
}

func TestDiagsCmdsForPod_Previous(t *testing.T) {
	RegisterTestingT(t)

	// A pod with no restarts gets only the current-log and describe commands.
	steady := &apiv1.Pod{}
	steady.Name = "calico-typha-0"
	steady.Status.ContainerStatuses = []apiv1.ContainerStatus{{RestartCount: 0}}
	cmds := diagsCmdsForPod("/dir", "/links", "nodeA", "calico-system", steady)
	Expect(cmdStrs(cmds)).NotTo(ContainElement(ContainSubstring("--previous")))

	// A pod whose container has restarted picks up an extra previous-log
	// command alongside the usual current-log + describe.
	restarted := &apiv1.Pod{}
	restarted.Name = "calico-apiserver-0"
	restarted.Status.ContainerStatuses = []apiv1.ContainerStatus{{RestartCount: 2}}
	cmds = diagsCmdsForPod("/dir", "/links", "nodeA", "calico-apiserver", restarted)
	Expect(cmdStrs(cmds)).To(ContainElement(ContainSubstring("kubectl logs --previous")))

	// An init container that previously terminated also flips the flag.
	initTerminated := &apiv1.Pod{}
	initTerminated.Name = "calico-node-xyz"
	initTerminated.Status.InitContainerStatuses = []apiv1.ContainerStatus{{
		LastTerminationState: apiv1.ContainerState{Terminated: &apiv1.ContainerStateTerminated{ExitCode: 1}},
	}}
	cmds = diagsCmdsForPod("/dir", "/links", "nodeA", "calico-system", initTerminated)
	Expect(cmdStrs(cmds)).To(ContainElement(ContainSubstring("kubectl logs --previous")))
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
