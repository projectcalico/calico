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

package k8stests

import (
	"testing"
	"time"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/node/tests/k8st/utils"
)

// TestReadinessBirdDown stops the bird runit service on one node and
// confirms that `calico component node health --bird-ready` then exits
// non-zero. Mirrors test_health.py:TestReadiness.test_readiness_bird_down.
func TestReadinessBirdDown(t *testing.T) {
	nodes := readinessFixture(t)
	assertReadiness(t, nodes[0], "bird", true)
	utils.MustExecInCalicoNode(t, nodes[0], "sv stop /etc/service/enabled/bird")
	assertReadiness(t, nodes[0], "bird", false)
	utils.MustExecInCalicoNode(t, nodes[0], "sv start /etc/service/enabled/bird")
}

// TestReadinessBird6Down is the IPv6 analogue of TestReadinessBirdDown.
// Mirrors test_health.py:TestReadiness.test_readiness_bird6_down.
func TestReadinessBird6Down(t *testing.T) {
	nodes := readinessFixture(t)
	assertReadiness(t, nodes[0], "bird6", true)
	utils.MustExecInCalicoNode(t, nodes[0], "sv stop /etc/service/enabled/bird6")
	assertReadiness(t, nodes[0], "bird6", false)
	utils.MustExecInCalicoNode(t, nodes[0], "sv start /etc/service/enabled/bird6")
}

// TestReadinessConfdDown stops confd and checks that BIRD's *liveness*
// flag flips to not-live. (The Python test asserts liveness, not
// readiness, despite the class name — confd going away makes BIRD's
// generated config stale, which is treated as a liveness signal.)
// Mirrors test_health.py:TestReadiness.test_readiness_confd_down.
func TestReadinessConfdDown(t *testing.T) {
	nodes := readinessFixture(t)
	assertLiveness(t, nodes[0], "bird", true)
	utils.MustExecInCalicoNode(t, nodes[0], "sv stop /etc/service/enabled/confd")
	assertLiveness(t, nodes[0], "bird", false)
	utils.MustExecInCalicoNode(t, nodes[0], "sv start /etc/service/enabled/confd")
}

// TestFelixDown stops felix and confirms that its readiness flag flips
// to not-ready. Mirrors test_health.py:TestReadiness.test_felix_down.
func TestFelixDown(t *testing.T) {
	nodes := readinessFixture(t)
	assertReadiness(t, nodes[0], "felix", true)
	utils.MustExecInCalicoNode(t, nodes[0], "sv stop /etc/service/enabled/felix")
	assertReadiness(t, nodes[0], "felix", false)
	utils.MustExecInCalicoNode(t, nodes[0], "sv start /etc/service/enabled/felix")
}

// readinessFixture is the shared per-test setup + teardown for
// TestReadiness*. It waits for the calico-system namespace to be Ready,
// then registers a cleanup that restarts every monitored service on every
// node — a belt-and-braces safety net so a failed test does not leave a
// node degraded for the next one. Mirrors the setUp/tearDown pair in
// test_health.py:TestReadiness.
func readinessFixture(t *testing.T) []string {
	t.Helper()
	defer utils.CollectDiagsOnFailure(t)()

	// Wait for all Calico pods to be ready before exercising the health
	// flags — otherwise the "before" assertion can spuriously fail on
	// slow CI nodes.
	utils.WaitForPodsReady(t, "calico-system", "", 120*time.Second)

	nodes, _, _ := utils.NodeInfo(t)
	NewWithT(t).Expect(nodes).NotTo(BeEmpty(), "no nodes returned from NodeInfo")

	t.Cleanup(func() {
		for _, node := range nodes {
			for _, svc := range []string{"bird", "bird6", "confd", "felix"} {
				_, _ = utils.ExecInCalicoNode(t, node,
					"sv start /etc/service/enabled/"+svc,
					utils.RunOptions{AllowFail: true, SuppressErrLog: true})
			}
		}
	})
	return nodes
}

// assertReadiness invokes `calico component node health --<flag>-ready`
// inside the calico-node pod on the given node and verifies the exit code
// matches the expected readiness. Mirrors the assert_readiness helper in
// test_health.py.
func assertReadiness(t *testing.T, node, flag string, ready bool) {
	t.Helper()
	cmd := "/usr/bin/calico component node health --" + flag + "-ready"
	_, err := utils.ExecInCalicoNode(t, node, cmd,
		utils.RunOptions{AllowFail: true, SuppressErrLog: true})
	g := NewWithT(t)
	if ready {
		g.Expect(err).NotTo(HaveOccurred(), "expected %s to be ready", flag)
	} else {
		g.Expect(err).To(HaveOccurred(), "expected %s NOT to be ready", flag)
	}
}

// assertLiveness is the liveness counterpart of assertReadiness.
// Mirrors the assert_liveness helper in test_health.py.
func assertLiveness(t *testing.T, node, flag string, live bool) {
	t.Helper()
	cmd := "/usr/bin/calico component node health --" + flag + "-live"
	_, err := utils.ExecInCalicoNode(t, node, cmd,
		utils.RunOptions{AllowFail: true, SuppressErrLog: true})
	g := NewWithT(t)
	if live {
		g.Expect(err).NotTo(HaveOccurred(), "expected %s to be live", flag)
	} else {
		g.Expect(err).To(HaveOccurred(), "expected %s NOT to be live", flag)
	}
}
