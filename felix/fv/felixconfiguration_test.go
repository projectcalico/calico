// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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

package fv_test

import (
	"context"
	"regexp"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

var _ = infrastructure.DatastoreDescribe(
	"FelixConfiguration nodeSelector tests",
	[]apiconfig.DatastoreType{apiconfig.EtcdV3},
	func(getInfra infrastructure.InfraFactory) {
		var (
			infra  infrastructure.DatastoreInfra
			tc     infrastructure.TopologyContainers
			client client.Interface
		)

		BeforeEach(func() {
			infra = getInfra()
			opts := infrastructure.DefaultTopologyOptions()
			opts.FelixLogSeverity = "debug"
			tc, client = infrastructure.StartNNodeTopology(2, opts, infra)
		})

		AfterEach(func() {
			tc.Stop()
			infra.Stop()
		})

		setNodeLabels := func(felixIdx int, labels map[string]string) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			node, err := client.Nodes().Get(ctx, tc.Felixes[felixIdx].Hostname, options.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			node.Labels = labels
			_, err = client.Nodes().Update(ctx, node, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())
		}

		createSelectorFelixConfig := func(name, selector string, deltaFn func(*api.FelixConfigurationSpec)) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cfg := api.NewFelixConfiguration()
			cfg.Name = name
			cfg.Spec.NodeSelector = selector
			deltaFn(&cfg.Spec)
			_, err := client.FelixConfigurations().Create(ctx, cfg, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())
		}

		It("should apply selector-scoped config only to matching nodes", func() {
			// Set up watches BEFORE making changes.
			matchedC := tc.Felixes[0].WatchStdoutFor(
				regexp.MustCompile(`Selector-scoped FelixConfiguration matches local node`))
			unmatchedC := tc.Felixes[1].WatchStdoutFor(
				regexp.MustCompile(`Selector-scoped FelixConfiguration matches local node`))

			By("Labelling node 0 as role=gpu and node 1 as role=standard")
			setNodeLabels(0, map[string]string{"role": "gpu"})
			setNodeLabels(1, map[string]string{"role": "standard"})

			By("Creating a selector-scoped FelixConfiguration targeting role == 'gpu'")
			createSelectorFelixConfig("gpu-nodes", "role == 'gpu'", func(spec *api.FelixConfigurationSpec) {
				enabled := true
				spec.BPFEnabled = &enabled
			})

			By("Verifying node 0 (gpu) picks up the selector config")
			Eventually(matchedC, "15s").Should(BeClosed())

			By("Verifying node 1 (standard) does NOT pick up the selector config")
			Consistently(unmatchedC, "5s").ShouldNot(BeClosed())
		})

		It("should restart only the matching node when selector-scoped config changes a restart-triggering field", func() {
			By("Waiting for both nodes to be in sync")
			waitForFelixInSync(tc.Felixes[0])
			waitForFelixInSync(tc.Felixes[1])

			By("Recording initial PIDs")
			felix0PID := tc.Felixes[0].GetSinglePID("calico-felix")
			felix1PID := tc.Felixes[1].GetSinglePID("calico-felix")

			By("Labelling node 0 as role=gpu and node 1 as role=standard")
			setNodeLabels(0, map[string]string{"role": "gpu"})
			setNodeLabels(1, map[string]string{"role": "standard"})

			By("Creating a selector-scoped FelixConfiguration with IptablesRefreshInterval targeting role == 'gpu'")
			createSelectorFelixConfig("gpu-nodes", "role == 'gpu'", func(spec *api.FelixConfigurationSpec) {
				iptRefresh := metav1.Duration{Duration: 15 * time.Second}
				spec.IptablesRefreshInterval = &iptRefresh
			})

			By("Verifying node 0 (gpu) restarts due to config change")
			Eventually(tc.Felixes[0].GetFelixPIDs, "10s", "100ms").ShouldNot(ContainElement(felix0PID))

			By("Verifying node 1 (standard) does NOT restart")
			Consistently(tc.Felixes[1].GetFelixPIDs, "5s", "200ms").Should(ContainElement(felix1PID))
		})

		It("should re-evaluate config when node labels change", func() {
			By("Waiting for both nodes to be in sync")
			waitForFelixInSync(tc.Felixes[0])
			waitForFelixInSync(tc.Felixes[1])

			By("Labelling both nodes as role=standard initially")
			setNodeLabels(0, map[string]string{"role": "standard"})
			setNodeLabels(1, map[string]string{"role": "standard"})

			By("Creating a selector-scoped FelixConfiguration targeting role == 'gpu'")
			createSelectorFelixConfig("gpu-nodes", "role == 'gpu'", func(spec *api.FelixConfigurationSpec) {
				iptRefresh := metav1.Duration{Duration: 15 * time.Second}
				spec.IptablesRefreshInterval = &iptRefresh
			})

			By("Verifying neither node restarts initially")
			felix0PID := tc.Felixes[0].GetSinglePID("calico-felix")
			felix1PID := tc.Felixes[1].GetSinglePID("calico-felix")
			Consistently(tc.Felixes[0].GetFelixPIDs, "5s", "200ms").Should(ContainElement(felix0PID))
			Consistently(tc.Felixes[1].GetFelixPIDs, "5s", "200ms").Should(ContainElement(felix1PID))

			By("Changing node 0's label to role=gpu")
			setNodeLabels(0, map[string]string{"role": "gpu"})

			By("Verifying node 0 restarts after label change makes the selector match")
			Eventually(tc.Felixes[0].GetFelixPIDs, "10s", "100ms").ShouldNot(ContainElement(felix0PID))

			By("Verifying node 1 still does not restart")
			Consistently(tc.Felixes[1].GetFelixPIDs, "5s", "200ms").Should(ContainElement(felix1PID))
		})
	},
)
