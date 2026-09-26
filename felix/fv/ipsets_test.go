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

	. "github.com/onsi/ginkgo/v2"
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

var _ = infrastructure.DatastoreDescribe("_IPSets_ periodic resync repairs dataplane drift",
	[]apiconfig.DatastoreType{apiconfig.EtcdV3}, func(getInfra infrastructure.InfraFactory) {
		// A short refresh interval so the periodic resync fires promptly; the
		// assertions below still allow many multiples of it to avoid flakes.
		const refreshInterval = 5 * time.Second
		// Two distinctive set sizes so we can pick our sets out of the full
		// 'ipset list' by member count, including default Calico sets.
		const setASize = 41
		const setBSize = 53
		const bogusMember = "10.123.123.123"

		var (
			tc    infrastructure.TopologyContainers
			felix *infrastructure.Felix
			c     client.Interface
			infra infrastructure.DatastoreInfra
			w     *workload.Workload
		)

		BeforeEach(func() {
			if NFTMode() || BPFMode() {
				// The incremental periodic resync being exercised here belongs
				// to the legacy (iptables) ipsets driver.  nftables has its own
				// resync path and the BPF dataplane doesn't program these IP
				// sets.
				Skip("legacy (iptables) ipsets driver only")
			}
			topologyOptions := infrastructure.DefaultTopologyOptions()
			topologyOptions.FelixLogSeverity = "Info"
			topologyOptions.EnableIPv6 = false
			topologyOptions.ExtraEnvVars = map[string]string{
				"FELIX_IPSETSREFRESHINTERVAL": fmt.Sprintf("%d", int(refreshInterval.Seconds())),
			}
			logrus.SetLevel(logrus.InfoLevel)
			infra = getInfra()
			tc, c = infrastructure.StartSingleNodeTopology(topologyOptions, infra)
			felix = tc.Felixes[0]
			w = workload.Run(felix, "w", "default", "10.65.0.2", "8085", "tcp")
		})

		AfterEach(func() {
			if infra == nil {
				// Skipped before the topology started.
				return
			}
			w.Stop()
			tc.Stop()
			infra.Stop()
		})

		It("should repair externally-modified IP sets on the next periodic resync", func() {
			// Program two network sets of distinct, identifiable sizes and a
			// policy that references both and applies to our workload, so both
			// IP sets get rendered into the dataplane.
			makeNetSet := func(name string, size int) {
				ns := api.NewGlobalNetworkSet()
				ns.Name = name
				ns.Labels = map[string]string{"netset": name}
				ns.Spec.Nets = generateIPv4s(size)
				_, err := c.GlobalNetworkSets().Create(context.TODO(), ns, options.SetOptions{})
				Expect(err).NotTo(HaveOccurred())
			}
			makeNetSet("netset-a", setASize)
			makeNetSet("netset-b", setBSize)

			pol := api.NewGlobalNetworkPolicy()
			pol.Name = "pol-repair"
			pol.Spec.Selector = "all()"
			pol.Spec.Ingress = []api.Rule{
				{Action: "Allow", Source: api.EntityRule{Selector: "netset == 'netset-a'"}},
				{Action: "Allow", Source: api.EntityRule{Selector: "netset == 'netset-b'"}},
			}
			pol.Spec.Egress = []api.Rule{{Action: "Allow"}}
			order := 1000.0
			pol.Spec.Order = &order
			_, err := c.GlobalNetworkPolicies().Create(context.TODO(), pol, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())

			w.ConfigureInInfra(infra)

			By("Waiting for both IP sets to be programmed")
			// Identify our sets by their (unique) member counts.
			findSetOfSize := func(size int) string {
				match := ""
				for name, sz := range felix.IPSetSizes() {
					if sz != size {
						continue
					}
					if match != "" && match != name {
						Fail(fmt.Sprintf("multiple IP sets have size %d: %s and %s", size, match, name))
					}
					match = name
				}
				return match
			}
			Eventually(func() string { return findSetOfSize(setASize) }, "60s", "1s").ShouldNot(BeEmpty())
			Eventually(func() string { return findSetOfSize(setBSize) }, "60s", "1s").ShouldNot(BeEmpty())
			setA := findSetOfSize(setASize)
			setB := findSetOfSize(setBSize)
			Expect(setA).NotTo(Equal(setB))

			By("Corrupting the IP sets behind Felix's back")
			// Add a bogus member to one set (Felix should remove it) and flush
			// the other (Felix should re-add its members).  We deliberately do
			// not destroy a set: an in-use set can't be destroyed, and the
			// whole-set-missing path is covered by the unit tests.
			// Exec fails the test if the commands themselves fail; we don't
			// assert on the corrupted sizes because the refresh timer may
			// repair them before we could read them back.
			felix.Exec("ipset", "add", setA, bogusMember)
			felix.Exec("ipset", "flush", setB)

			By("Waiting for the periodic resync to repair both sets")
			Eventually(func() map[string]int {
				sizes := felix.IPSetSizes()
				return map[string]int{"a": sizes[setA], "b": sizes[setB]}
			}, "60s", "1s").Should(Equal(map[string]int{"a": setASize, "b": setBSize}))
		})
	})

func createNetworkSetPolicies(c client.Interface, numPols, numRulesPerPol int) {
	By("Creating network sets")
	sizes := []int{1, 1, 1, 2, 3, 4, 5, 5, 5, 5, 5, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 100, 200, 1000}
	numSets := numPols * numRulesPerPol
	for i := range numSets {
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
	for i := range numPols {
		rules := make([]api.Rule, numRulesPerPol)
		for j := range numRulesPerPol {
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
