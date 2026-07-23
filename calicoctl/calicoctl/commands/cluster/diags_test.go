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
	"strings"
	"testing"

	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
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
		}
		Expect(opts).To(Equal(expectedOpts))
	}
	test("cluster diags",
		nil,
		"",
		&diagOpts{
			Config:               "/etc/calico/calicoctl.cfg",
			Since:                "0s",
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
			Since:                "0s",
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
			Since:                "0s",
			MaxLogs:              5,
			MaxParallelism:       10,
			FocusNodes:           "",
			AllowVersionMismatch: false,
		})
	test("cluster diags --since 3h",
		nil,
		"",
		&diagOpts{
			Config:               "/etc/calico/calicoctl.cfg",
			Since:                "3h",
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
			Since:                "0s",
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
			Since:                "0s",
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
			Since:                "0s",
			MaxLogs:              5,
			MaxParallelism:       10,
			FocusNodes:           "infra1,control2",
			AllowVersionMismatch: false,
		})
}

func TestDiagsCmdsForPod_Previous(t *testing.T) {
	RegisterTestingT(t)

	opts := &diagOpts{Since: "0s"}

	// A pod with no restarts gets only the current-log and describe commands.
	steady := &apiv1.Pod{}
	steady.Name = "calico-typha-0"
	steady.Status.ContainerStatuses = []apiv1.ContainerStatus{{Name: "calico-typha", RestartCount: 0}}
	cmds := diagsCmdsForPod("/dir", "/links", opts, "nodeA", "calico-system", steady)
	Expect(cmdStrs(cmds)).NotTo(ContainElement(ContainSubstring("--previous")))

	// A pod where even one container has restarted picks up previous-log
	// commands for *every* container in the pod, each scoped with -c (not
	// --all-containers). Per-container commands are independent, so a healthy
	// sibling that has no previous incarnation fails harmlessly on its own
	// without discarding the crashed container's logs — exactly the ones the
	// bundle needs to explain the restart.
	restarted := &apiv1.Pod{}
	restarted.Name = "calico-apiserver-0"
	restarted.Status.ContainerStatuses = []apiv1.ContainerStatus{
		{Name: "calico-apiserver", RestartCount: 2},
		{Name: "calico-apiserver-sidecar", RestartCount: 0},
	}
	cmds = diagsCmdsForPod("/dir", "/links", opts, "nodeA", "calico-apiserver", restarted)
	prev := filterStrs(cmdStrs(cmds), "--previous")
	// Both the restarted container and its never-restarted sibling are fetched,
	// each scoped with -c, and none use --all-containers.
	Expect(prev).To(HaveLen(2))
	for _, p := range prev {
		Expect(p).To(ContainSubstring("kubectl logs --previous"))
		Expect(p).NotTo(ContainSubstring("--all-containers"))
	}
	Expect(prev).To(ContainElement(ContainSubstring("-c calico-apiserver")))
	Expect(prev).To(ContainElement(ContainSubstring("-c calico-apiserver-sidecar")))

	// An init container that previously terminated also triggers collection,
	// and its previous logs are fetched by name.
	initTerminated := &apiv1.Pod{}
	initTerminated.Name = "calico-node-xyz"
	initTerminated.Status.ContainerStatuses = []apiv1.ContainerStatus{{Name: "calico-node", RestartCount: 0}}
	initTerminated.Status.InitContainerStatuses = []apiv1.ContainerStatus{{
		Name:                 "install-cni",
		LastTerminationState: apiv1.ContainerState{Terminated: &apiv1.ContainerStateTerminated{ExitCode: 1}},
	}}
	cmds = diagsCmdsForPod("/dir", "/links", opts, "nodeA", "calico-system", initTerminated)
	prev = filterStrs(cmdStrs(cmds), "--previous")
	// The terminated init container triggers collection for the whole pod, so
	// the never-restarted main container is fetched too.
	Expect(prev).To(ContainElement(And(
		ContainSubstring("kubectl logs --previous"),
		ContainSubstring("-c install-cni"),
	)))
	Expect(prev).To(ContainElement(ContainSubstring("-c calico-node")))
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

func cmdStrs(cmds []common.Cmd) []string {
	out := make([]string, len(cmds))
	for i, c := range cmds {
		out[i] = c.CmdStr
	}
	return out
}
