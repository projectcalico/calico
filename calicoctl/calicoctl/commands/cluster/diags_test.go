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
	"testing"

	. "github.com/onsi/gomega"
	apiv1 "k8s.io/api/core/v1"

	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/common"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
)

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

// buildDiagOpts defaults an empty since to "0s" (which kubectl reads as all
// logs) and otherwise passes its inputs straight through. Flag parsing itself
// is cobra's responsibility now, so it isn't re-tested here.
func TestBuildDiagOpts(t *testing.T) {
	RegisterTestingT(t)

	Expect(buildDiagOpts("/etc/calico/calicoctl.cfg", "", 5, 10, "", false)).To(Equal(&diagOpts{
		Config:         "/etc/calico/calicoctl.cfg",
		Since:          "0s",
		MaxLogs:        5,
		MaxParallelism: 10,
	}))
	Expect(buildDiagOpts("/configfile", "3h", 1, 2, "infra1,control2", true)).To(Equal(&diagOpts{
		Config:             "/configfile",
		Since:              "3h",
		MaxLogs:            1,
		MaxParallelism:     2,
		FocusNodes:         "infra1,control2",
		SkipTempDirCleanup: true,
	}))
}

func TestDiagsCmdsForPod_Previous(t *testing.T) {
	RegisterTestingT(t)

	opts := &diagOpts{Since: "0s"}

	// A pod with no restarts gets only the current-log and describe commands.
	steady := &apiv1.Pod{}
	steady.Name = "calico-typha-0"
	steady.Status.ContainerStatuses = []apiv1.ContainerStatus{{RestartCount: 0}}
	cmds := diagsCmdsForPod("/dir", "/links", opts, "nodeA", "calico-system", steady)
	Expect(cmdStrs(cmds)).NotTo(ContainElement(ContainSubstring("--previous")))

	// A pod whose container has restarted picks up an extra previous-log
	// command alongside the usual current-log + describe.
	restarted := &apiv1.Pod{}
	restarted.Name = "calico-apiserver-0"
	restarted.Status.ContainerStatuses = []apiv1.ContainerStatus{{RestartCount: 2}}
	cmds = diagsCmdsForPod("/dir", "/links", opts, "nodeA", "calico-apiserver", restarted)
	Expect(cmdStrs(cmds)).To(ContainElement(ContainSubstring("kubectl logs --previous")))

	// An init container that previously terminated also flips the flag.
	initTerminated := &apiv1.Pod{}
	initTerminated.Name = "calico-node-xyz"
	initTerminated.Status.InitContainerStatuses = []apiv1.ContainerStatus{{
		LastTerminationState: apiv1.ContainerState{Terminated: &apiv1.ContainerStateTerminated{ExitCode: 1}},
	}}
	cmds = diagsCmdsForPod("/dir", "/links", opts, "nodeA", "calico-system", initTerminated)
	Expect(cmdStrs(cmds)).To(ContainElement(ContainSubstring("kubectl logs --previous")))
}

func cmdStrs(cmds []common.Cmd) []string {
	out := make([]string, len(cmds))
	for i, c := range cmds {
		out[i] = c.CmdStr
	}
	return out
}
