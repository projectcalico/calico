// Copyright (c) 2023 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fv_test

import (
	"context"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/fv/connectivity"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

var _ = infrastructure.DatastoreDescribe("_BPF-SAFE_ BPF policy scale tests", []apiconfig.DatastoreType{apiconfig.EtcdV3}, func(getInfra infrastructure.InfraFactory) {
	if !BPFMode() {
		// Non-BPF run.
		return
	}

	var (
		tc       infrastructure.TopologyContainers
		felixPID int
		client   client.Interface
		infra    infrastructure.DatastoreInfra
		w        [2]*workload.Workload
		cc       *connectivity.Checker
	)

	BeforeEach(func() {
		infra = getInfra()
		topologyOptions := infrastructure.DefaultTopologyOptions()
		topologyOptions.FelixLogSeverity = "Info"
		topologyOptions.EnableIPv6 = false
		topologyOptions.ExtraEnvVars["FELIX_BPFLogLevel"] = "off"
		topologyOptions.ExtraEnvVars["FELIX_BPFMapSizeIPSets"] = "10000000"
		logrus.SetLevel(logrus.InfoLevel)
		tc, client = infrastructure.StartSingleNodeTopology(topologyOptions, infra)
		felixPID = tc.Felixes[0].GetFelixPID()
		_ = felixPID
		w[0] = workload.Run(tc.Felixes[0], "w0", "default", "10.65.0.2", "8085", "tcp")
		w[1] = workload.Run(tc.Felixes[0], "w1", "default", "10.65.0.3", "8085", "tcp")
		cc = &connectivity.Checker{}
	})

	addW0NetSet := func(numSets int) {
		ns := api.NewGlobalNetworkSet()
		ns.Name = "netset-extra"
		ns.Labels = map[string]string{
			"netset": fmt.Sprintf("netset-%d", numSets-42),
		}
		ns.Spec.Nets = []string{w[0].IPNet()}
		_, err := client.GlobalNetworkSets().Create(context.TODO(), ns, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())
	}

	It("should handle thousands of policy rules", func() {
		// This test activates thousands of rules on one endpoint, which
		// requires the policy program to be split into sub-programs.

		// 12500 rules
		const (
			numPols        = 250
			numRulesPerPol = 50
			numSets        = numPols * numRulesPerPol
		)
		createNetworkSetPolicies(client, numPols, numRulesPerPol)

		By("Creating a workload, activating the policies")
		// Create a workload that uses the policy.
		w[0].ConfigureInInfra(infra)
		w[1].ConfigureInInfra(infra)

		// This test does take some time to converge, make sure that we wait for
		// convergence before doing policy tests.
		const expectedNumberOfPolicySubprogs = 5
		Eventually(tc.Felixes[0].BPFNumContiguousPolProgramsFn(w[0].InterfaceName, "ingress", 4), "240s", "1s").Should(
			BeNumerically(">", expectedNumberOfPolicySubprogs))
		Eventually(tc.Felixes[0].BPFNumContiguousPolProgramsFn(w[1].InterfaceName, "ingress", 4), "20s", "1s").Should(
			BeNumerically(">", expectedNumberOfPolicySubprogs))

		// The network sets use IPs from outside the IP pool so we get no
		// connectivity to start with.
		cc.ExpectNone(w[0], w[1])
		cc.ExpectNone(w[1], w[0])
		cc.CheckConnectivityWithTimeout(30 * time.Second)

		// Add a network set that matches one fo the rule labels and contains
		// one of the workload's IPs.
		cc.ResetExpectations()
		addW0NetSet(numSets)

		// Should now get one-way connectivity.
		cc.ExpectSome(w[0], w[1])
		cc.ExpectNone(w[1], w[0])
		cc.CheckConnectivityWithTimeout(30 * time.Second)
	})

	Describe("sub-program cleanup tests", func() {
		const (
			numPols        = 100
			numRulesPerPol = 25
			numSets        = numPols * numRulesPerPol
		)
		var (
			w0PolIdxIngress, w0PolIdxEgress int
		)
		BeforeEach(func() {
			// This test activates enough rules to trigger sub-programs, then
			// verifies that they get cleaned up properly.
			createNetworkSetPolicies(client, numPols, numRulesPerPol)

			By("Creating a workload, activating the policies")
			// Create a workload that uses the policy.
			w[0].ConfigureInInfra(infra)
			w[1].ConfigureInInfra(infra)

			const expectedNumberOfPolicySubprogs = 2
			Eventually(tc.Felixes[0].BPFNumContiguousPolProgramsFn(w[0].InterfaceName, "ingress", 4), "60s", "1s").Should(
				BeNumerically(">=", expectedNumberOfPolicySubprogs))
			Eventually(tc.Felixes[0].BPFNumContiguousPolProgramsFn(w[1].InterfaceName, "ingress", 4), "20s", "1s").Should(
				BeNumerically(">=", expectedNumberOfPolicySubprogs))
			addW0NetSet(numSets)

			// Verify the policy really has converged.
			cc.ExpectSome(w[0], w[1])
			cc.ExpectNone(w[1], w[0])
			cc.CheckConnectivityWithTimeout(30 * time.Second)

			// Find the index of the policy program for w[0].
			w0PolIdxIngress = tc.Felixes[0].BPFIfState(4)[w[0].InterfaceName].IngressPolicyV4
			w0PolIdxEgress = tc.Felixes[0].BPFIfState(4)[w[0].InterfaceName].EgressPolicyV4
		})

		It("should clean up policy sub-programs: remove then stop", func() {
			// Remove one EP.
			w[0].RemoveFromInfra(infra)
			// After removing workload, we get a dummy "drop all" policy program.
			Eventually(tc.Felixes[0].BPFNumPolProgramsTotalByEntryPointFn(w0PolIdxIngress, "ingress"), "60s", "1s").Should(Equal(1),
				"w[0] ingress policy programs not cleaned up after removing ep?")
			Eventually(tc.Felixes[0].BPFNumPolProgramsTotalByEntryPointFn(w0PolIdxEgress, "egress"), "60s", "1s").Should(Equal(1),
				"w[0] egress policy programs not cleaned up after removing ep?")

			// Stop it, should get full cleanup now.
			w[0].Stop()
			w[0] = nil // Prevent second call to Stop in AfterEach.
			Eventually(tc.Felixes[0].BPFNumPolProgramsTotalByEntryPointFn(w0PolIdxIngress, "ingress"), "60s", "1s").Should(Equal(0),
				"w[0] ingress policy programs not cleaned up?")
			Eventually(tc.Felixes[0].BPFNumPolProgramsTotalByEntryPointFn(w0PolIdxEgress, "egress"), "60s", "1s").Should(Equal(0),
				"w[0] egress policy programs not cleaned up?")
		})

		It("should clean up policy sub-programs: stop then remove", func() {
			w[0].Stop()
			// Stop the workload (remove its cali interface).
			defer func() {
				// Prevent second call to Stop in AfterEach.
				w[0] = nil
			}()
			// After stopping workload, interface is gone and programs get cleaned up.
			Eventually(tc.Felixes[0].BPFNumPolProgramsTotalByEntryPointFn(w0PolIdxIngress, "ingress"), "60s", "1s").Should(Equal(0),
				"w[0] ingress policy programs not cleaned up?")
			Eventually(tc.Felixes[0].BPFNumPolProgramsTotalByEntryPointFn(w0PolIdxEgress, "egress"), "60s", "1s").Should(Equal(0),
				"w[0] egress policy programs not cleaned up?")

			// Remove should have no further effect.
			w[0].RemoveFromInfra(infra)
			Consistently(tc.Felixes[0].BPFNumPolProgramsTotalByEntryPointFn(w0PolIdxIngress, "ingress"), "10s", "1s").Should(Equal(0),
				"w[0] ingress policy programs came back?")
			Consistently(tc.Felixes[0].BPFNumPolProgramsTotalByEntryPointFn(w0PolIdxEgress, "egress"), "10s", "1s").Should(Equal(0),
				"w[0] egress policy programs came back?")
		})
	})
})
