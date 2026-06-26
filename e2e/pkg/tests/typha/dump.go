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

	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/gomega"
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
// environment-dependent failure modes that the feature depends on: the image
// pre-creating a writable /var/run/calico, Typha opening the socket as a
// non-root, all-caps-dropped process, and the platform permitting the
// sync-protocol-over-UDS path at all.
var _ = describe.CalicoDescribe(
	describe.WithTeam(describe.Core),
	describe.WithFeature("Typha"),
	describe.WithCategory(describe.Configuration),
	"Typha snapshot dump",
	func() {
		f := utils.NewDefaultFramework("typha-dump")

		ginkgo.It("dumps an in-sync felix snapshot from a typha pod over the local socket", func() {
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()

			// Typha lives in calico-system for operator installs and kube-system
			// for manifest installs; match by label across all namespaces.
			pods, err := f.ClientSet.CoreV1().Pods(metav1.NamespaceAll).List(ctx, metav1.ListOptions{
				LabelSelector: "k8s-app=calico-typha",
			})
			Expect(err).NotTo(HaveOccurred())

			pod := firstRunning(pods.Items)
			if pod == nil {
				ginkgo.Skip("no running calico-typha pod; cluster has no Typha")
			}

			// Exec the dump directly: the calico image has no shell, so we pass
			// the binary and its arguments as explicit argv tokens after "--".
			// The dump logs to stderr and writes NDJSON to stdout, which Exec()
			// returns.
			args := []string{
				"exec", pod.Name, "-n", pod.Namespace, "-c", "calico-typha", "--",
				"calico", "component", "typha", "client", "dump", "--type=felix",
			}
			out, err := e2ekubectl.NewKubectlCommand(pod.Namespace, args...).
				WithTimeout(time.After(75 * time.Second)).
				Exec()
			Expect(err).NotTo(HaveOccurred(), "dump command failed: %s", out)

			// Parse the NDJSON stream.  Each line is one event; we only care
			// about the felix section: at least one key line, plus an "end"
			// marker reporting in-sync with a non-empty snapshot.  Parsing into
			// a map keeps this robust to field reordering in the encoder.
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

			Expect(end).NotTo(BeNil(), "no felix end marker in dump:\n%s", out)
			Expect(end["status"]).To(Equal("in-sync"), "felix snapshot did not reach in-sync:\n%s", out)
			Expect(end["numKVs"]).To(BeNumerically(">", 0), "felix snapshot reported no KVs:\n%s", out)
			Expect(sawKey).To(BeTrue(), "felix snapshot had no key lines:\n%s", out)
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
