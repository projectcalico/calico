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

package typha

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	e2ekubectl "k8s.io/kubernetes/test/e2e/framework/kubectl"

	"github.com/projectcalico/calico/e2e/pkg/describe"
	"github.com/projectcalico/calico/e2e/pkg/utils"
)

// This test verifies the Typha snapshot-dump diagnostic end to end against a
// live cluster: it execs "calico component typha client dump" inside a
// calico-typha pod and checks that the pod-private unix socket
// (/var/run/calico/typha.sock) serves a complete, in-sync snapshot.  Unit and
// FV tests cover the dump logic in isolation, but only an E2E test catches the
// environment-dependent failure modes the feature depends on: the image
// pre-creating a writable runtime directory, Typha opening the socket as a
// non-root, all-caps-dropped process, and the platform permitting the
// sync-protocol-over-unix-socket path at all.
//
// The test is gated by the RequiresTypha label so it is only selected on
// clusters that actually deploy Typha; clusters without Typha exclude it in
// their test-selection config rather than having the test self-skip.
var _ = describe.CalicoDescribe(
	describe.WithTeam(describe.Core),
	describe.WithFeature("Typha"),
	describe.WithCategory(describe.Configuration),
	describe.RequiresTypha(),
	"Typha snapshot dump",
	func() {
		f := utils.NewDefaultFramework("typha-dump")

		ginkgo.It("dumps an in-sync felix snapshot from a typha pod over the local socket", func() {
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()

			// Typha lives in calico-system for operator installs and kube-system
			// for manifest installs; match by label across all namespaces.
			ginkgo.By("finding a running calico-typha pod")
			pods, err := f.ClientSet.CoreV1().Pods(metav1.NamespaceAll).List(ctx, metav1.ListOptions{
				LabelSelector: "k8s-app=calico-typha",
			})
			gomega.Expect(err).NotTo(gomega.HaveOccurred(), "failed to list calico-typha pods")
			// This test is gated by the RequiresTypha label, so it only runs on
			// clusters that deploy Typha. A missing Typha pod is a real failure
			// here, not a reason to skip (self-skipping is banned).
			gomega.Expect(pods.Items).NotTo(
				gomega.BeEmpty(),
				"no calico-typha pods found, but this test is gated by RequiresTypha; "+
					"check the cluster's Typha deployment or the RequiresTypha exclusion in the test config",
			)
			pod := firstRunning(pods.Items)
			gomega.Expect(pod).NotTo(gomega.BeNil(), "found calico-typha pods but none are Running")

			// Exec the dump directly: the calico image has no shell, so we pass
			// the binary and its arguments as explicit argv tokens after "--".
			// The dump logs to stderr and writes NDJSON to stdout, which Exec()
			// returns.
			ginkgo.By("running 'calico component typha client dump' in the typha pod")
			args := []string{
				"exec", pod.Name, "-n", pod.Namespace, "-c", "calico-typha", "--",
				"calico", "component", "typha", "client", "dump", "--type=felix",
			}
			out, err := e2ekubectl.NewKubectlCommand(pod.Namespace, args...).
				WithTimeout(time.After(75 * time.Second)).
				Exec()
			gomega.Expect(err).NotTo(gomega.HaveOccurred(), "typha dump command failed: %s", out)

			// Parse the NDJSON stream.  We only care about the felix section: at
			// least one key line, plus an "end" marker reporting in-sync with a
			// non-empty snapshot.  Parsing into a map keeps this robust to
			// encoder field reordering.
			ginkgo.By("verifying the felix snapshot is framed, in-sync, and non-empty")
			sawKey := false
			var end map[string]any
			for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
				var m map[string]any
				if json.Unmarshal([]byte(line), &m) != nil || m["section"] != "felix" {
					continue // Skip any stray non-JSON line (e.g. leaked log output).
				}
				if m["event"] == "end" {
					end = m
				}
				if _, ok := m["key"]; ok {
					sawKey = true
				}
			}

			gomega.Expect(end).NotTo(gomega.BeNil(), "no felix end marker in dump:\n%s", out)
			gomega.Expect(end["status"]).To(gomega.Equal("in-sync"), "felix snapshot did not reach in-sync:\n%s", out)
			gomega.Expect(end["numKVs"]).To(gomega.BeNumerically(">", 0), "felix snapshot reported no KVs:\n%s", out)
			gomega.Expect(sawKey).To(gomega.BeTrue(), "felix snapshot had no key lines:\n%s", out)
		})
	})

// firstRunning returns a pointer to the first pod in the Running phase, or nil
// if there is none.
func firstRunning(pods []corev1.Pod) *corev1.Pod {
	for i := range pods {
		if pods[i].Status.Phase == corev1.PodRunning {
			return &pods[i]
		}
	}
	return nil
}
