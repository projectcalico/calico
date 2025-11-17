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

	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

var _ = infrastructure.DatastoreDescribe("_IPSets_ Tests for IPset rendering", []apiconfig.DatastoreType{apiconfig.EtcdV3}, func(getInfra infrastructure.InfraFactory) {
	var (
		tc       infrastructure.TopologyContainers
		felixPID int
		client   client.Interface
		infra    infrastructure.DatastoreInfra
		w        *workload.Workload
	)

	BeforeEach(func() {
		topologyOptions := infrastructure.DefaultTopologyOptions()
		topologyOptions.FelixLogSeverity = "Info"
		topologyOptions.EnableIPv6 = false
		if NFTMode() {
			// Nftables resyncs are currently ineffeicient and can cause delays in normal IP set programming.
			// We can remove this override once we have a more efficient resync mechanism.
			topologyOptions.ExtraEnvVars = map[string]string{
				"FELIX_IPSETSREFRESHINTERVAL": "0",
			}
		}
		logrus.SetLevel(logrus.InfoLevel)
		infra = getInfra()
		tc, client = infrastructure.StartSingleNodeTopology(topologyOptions, infra)
		felixPID = tc.Felixes[0].GetFelixPID()
		_ = felixPID
		w = workload.Run(tc.Felixes[0], "w", "default", "10.65.0.2", "8085", "tcp")
	})

	It("should handle thousands of IP sets flapping", func() {
		// This test activates thousands of selectors all at once, simulating
		// a very large policy set that applies to all pods.
		//
		// Then it deactivates the whole policy set, simulating the last
		// endpoint being removed before re-adding it again.
		//
		// Overall, it verifies that we rate limit deletions of IP sets
		// and that we're able to cope with such a flap without blocking
		// all processing on the int-dataplane main loop.
		const numSets = 2000
		createNetworkSetPolicies(client, numSets, 1)

		By("Creating a workload, activating the policies")
		// Create a workload that uses the policy.
		baseNumSets := tc.Felixes[0].NumIPSets()
		wep := w.WorkloadEndpoint.DeepCopy()
		w.ConfigureInInfra(infra)
		startTime := time.Now()

		By("Waiting for the first IP set to be programmed...")
		Eventually(tc.Felixes[0].NumIPSets, "240s", "1s").Should(BeNumerically(">", baseNumSets))
		By(fmt.Sprint("First IP set programmed after ", time.Since(startTime)))
		Eventually(tc.Felixes[0].NumIPSets, "240s", "1s").Should(BeNumerically(">=", numSets+baseNumSets))
		timeToCreateAll := time.Since(startTime)
		By(fmt.Sprint("All IP sets programmed after ", timeToCreateAll))

		By("Deleting workload, deactivating the policies")
		w.RemoveFromInfra(infra)
		startTime = time.Now()
		By("Waiting for first IP set to be deleted...")

		// Before we reworked the IP sets logic to rate limit deletions, all the
		// deletions would happen in one cycle of the internal dataplane.
		// Since deletions are (weirdly) slow in the kernel, we'd then block
		// for a long time, preventing recreation of the IP sets.
		Eventually(tc.Felixes[0].NumIPSets, "240s", "1s").Should(BeNumerically("<", numSets+baseNumSets))
		timeToDeleteFirst := time.Since(startTime)
		By(fmt.Sprint("First IP set deleted after ", timeToDeleteFirst))

		// As soon as we see the first IP set deleted, recreate the workload.
		By("Recreating workload... ")
		w.WorkloadEndpoint = wep
		w.ConfigureInInfra(infra)
		startTime = time.Now()

		By("Waiting for all IP sets to be recreated")
		Eventually(tc.Felixes[0].NumIPSets, "240s", "1s").Should(BeNumerically(">=", numSets+baseNumSets))
		timeToRecreateAll := time.Since(startTime)
		By(fmt.Sprint("All IP sets programmed after ", timeToRecreateAll))

		// This should take 10-30s, but leave some headroom for inconsistent CI performance
		timeout := 90 * time.Second
		if NFTMode() {
			// nftables mode is a bit slower here, so use a longer timeout
			// until we can optimize nftables set programming.
			timeout = 120 * time.Second
		}
		Expect(timeToCreateAll).To(BeNumerically("<", timeout),
			"Creating IP sets succeeded but slower than expected")

		Expect(timeToRecreateAll).To(BeNumerically("<", timeout),
			"Recreating IP sets succeeded but slower than expected")
	})
})

func createNetworkSetPolicies(c client.Interface, numPols, numRulesPerPol int) {
	By("Creating network sets")
	sizes := []int{1, 1, 1, 2, 3, 4, 5, 5, 5, 5, 5, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 100, 200, 1000}
	numSets := numPols * numRulesPerPol
	for i := 0; i < numSets; i++ {
		ns := api.NewGlobalNetworkSet()
		ns.Name = fmt.Sprintf("netset-%d", i)
		ns.Labels = map[string]string{
			"netset": fmt.Sprintf("netset-%d", i),
		}
		ns.Spec.Nets = generateIPv4s(sizes[i%len(sizes)])
		_, err := c.GlobalNetworkSets().Create(context.TODO(), ns, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())
	}

	By("Creating policies with selectors")
	// Make a policy that activates them
	for i := 0; i < numPols; i++ {
		rules := make([]api.Rule, numRulesPerPol)
		for j := 0; j < numRulesPerPol; j++ {
			rules[j] = api.Rule{
				Action: "Allow",
				Source: api.EntityRule{
					Selector: fmt.Sprintf("netset == 'netset-%d'", i*numRulesPerPol+j),
				},
			}
		}
		pol := api.NewGlobalNetworkPolicy()
		pol.Name = fmt.Sprintf("pol-%d", i)
		pol.Spec.Ingress = rules
		pol.Spec.Egress = []api.Rule{
			{Action: "Allow"},
		}
		pol.Spec.Selector = "all()"
		order := 1000.0
		pol.Spec.Order = &order
		_, err := c.GlobalNetworkPolicies().Create(context.TODO(), pol, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())
	}
}
