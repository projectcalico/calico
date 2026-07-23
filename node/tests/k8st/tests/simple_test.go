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

// Package k8stests is the Go port of node/tests/k8st/tests. Each Test*
// function corresponds to one Python test method. Shared fixtures live in
// per-file helper functions; cross-file infrastructure is in
// node/tests/k8st/utils.
package k8stests

import (
	"errors"
	"fmt"
	"testing"
	"time"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/node/tests/k8st/utils"
)

// TestGracefulRestartMethodology verifies that the route-churn methodology
// itself works: killing BIRD with SIGTERM must produce route churn. If this
// test stops failing-on-no-churn, the graceful-restart test would silently
// pass even when GR is broken.
//
// Port of test_simple.py:TestGracefulRestart.test_methodology.
func TestGracefulRestartMethodology(t *testing.T) {
	defer utils.CollectDiagsOnFailure(t)()

	restart := func(state *restartChurnState) {
		utils.MustRun(t, "docker exec "+state.restartNode+" pkill bird")
		NewWithT(t).Eventually(func() error {
			_, err := utils.Run(t, "docker exec "+state.restartNode+" pgrep bird",
				utils.RunOptions{AllowFail: true, SuppressErrLog: true})
			return err
		}, 15*time.Second, time.Second).Should(Succeed(), "BIRD did not restart within 15s")
		time.Sleep(5 * time.Second)
	}

	runRestartChurnTest(t, 3, restart, true)
}

// TestGracefulRestart verifies that deleting a calico-node pod does NOT
// produce route churn on a neighbour node, i.e. that graceful restart is
// configured and working end-to-end.
//
// Port of test_simple.py:TestGracefulRestart.test_graceful_restart.
func TestGracefulRestart(t *testing.T) {
	defer utils.CollectDiagsOnFailure(t)()

	restart := func(state *restartChurnState) {
		utils.DeletePodAndWait(t, "calico-system", state.restartPodName, 2*time.Minute)

		// Wait until a replacement calico-node pod has been created.
		NewWithT(t).Eventually(func() error {
			return state.refreshRestartPodName(t)
		}, 15*time.Second, time.Second).Should(Succeed(), "replacement calico-node pod did not appear within 15s")

		// Wait until it is ready, before returning.
		utils.WaitForPodReady(t, "calico-system", state.restartPodName, 2*time.Minute)
	}

	runRestartChurnTest(t, 3, restart, false)
}

// restartChurnState holds the mutable fields the Python TestGracefulRestart
// class stored on `self`. Captures the node being restarted and the latest
// pod name (which changes across pod replacements in the GR test).
type restartChurnState struct {
	restartNode    string
	restartNodeIP  string
	restartPodName string
}

func (s *restartChurnState) refreshRestartPodName(t testing.TB) error {
	t.Helper()
	// calico-node is host-networked, so the pod IP equals the node IP.
	names, err := utils.PodNames(t, "calico-system",
		"k8s-app=calico-node", "status.podIP="+s.restartNodeIP)
	if err != nil {
		return err
	}
	if len(names) == 0 {
		return errors.New("calico-node pod name not yet observable")
	}
	s.restartPodName = names[0]
	return nil
}

// runRestartChurnTest implements the shared body of test_methodology and
// test_graceful_restart. It picks two worker nodes, runs `ip monitor route`
// on the first, and invokes restartFn against the second the requested
// number of times. If expectChurn is true the captured monitor output must
// be non-empty; otherwise it must be empty.
func runRestartChurnTest(t *testing.T, numRepeats int, restartFn func(*restartChurnState), expectChurn bool) {
	t.Helper()
	g := NewWithT(t)
	nodes, ips, _ := utils.NodeInfo(t)
	g.Expect(len(nodes)).To(BeNumerically(">", 2), "need at least one control-plane and two workers")

	monitorNode := nodes[1]
	state := &restartChurnState{
		restartNode:   nodes[2],
		restartNodeIP: ips[2],
	}

	// Start `ip monitor route` in the background on the monitor node. We
	// exclude IPv6 workload-block routes (fd00:10:244) because they
	// currently flap on block-host restart for reasons that are not yet
	// understood and that aren't what this test is exercising. See
	// https://marc.info/?l=bird-users&m=158298182509702&w=2.
	utils.MustRun(t, fmt.Sprintf(
		"docker exec -d %s sh -c 'stdbuf -oL ip -ts monitor route | "+
			"stdbuf -oL grep -v fd00:10:244 > rmon.txt'", monitorNode))

	// Find the name of the calico-node pod on the restart node.
	g.Expect(state.refreshRestartPodName(t)).NotTo(HaveOccurred(),
		"could not find calico-node pod on %s", state.restartNode)

	for i := 0; i < numRepeats; i++ {
		t.Logf("Iteration %d: restart pod %s", i, state.restartPodName)
		restartFn(state)
	}

	// Kill the ip monitor process and dump its output.
	utils.MustRun(t, "docker exec "+monitorNode+" pkill ip")
	monitorOutput := utils.MustRun(t, "docker exec "+monitorNode+" cat rmon.txt")

	if expectChurn {
		g.Expect(monitorOutput).NotTo(BeEmpty(), "expected route churn but observed none")
	} else {
		g.Expect(monitorOutput).To(BeEmpty(), "expected no route churn but observed: %s", monitorOutput)
	}
}

// TestCalicoSystemPodsRunning fails if any pod in the calico-system
// namespace is not Running.
//
// Port of test_simple.py:TestAllRunning.test_calicosystem_pods_running.
func TestCalicoSystemPodsRunning(t *testing.T) {
	defer utils.CollectDiagsOnFailure(t)()
	utils.CheckPodStatus(t, "calico-system")
}

// TestDefaultPodsRunning fails if any pod in the default namespace is not
// Running.
//
// Port of test_simple.py:TestAllRunning.test_default_pods_running.
func TestDefaultPodsRunning(t *testing.T) {
	defer utils.CollectDiagsOnFailure(t)()
	utils.CheckPodStatus(t, "default")
}

// TestCalicoMonitoringPodsRunning fails if any pod in the calico-monitoring
// namespace is not Running.
//
// Port of test_simple.py:TestAllRunning.test_calico_monitoring_pods_running.
func TestCalicoMonitoringPodsRunning(t *testing.T) {
	defer utils.CollectDiagsOnFailure(t)()
	utils.CheckPodStatus(t, "calico-monitoring")
}
