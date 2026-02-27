// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.
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
	"fmt"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/utils"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

var _ = infrastructure.DatastoreDescribe("_BPF-SAFE_ policy tests", []apiconfig.DatastoreType{apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
	const (
		wepPortStr = "8055"
	)

	var (
		infra        infrastructure.DatastoreInfra
		tc           infrastructure.TopologyContainers
		client       client.Interface
		ep1_1, ep2_1 *workload.Workload // Workloads on Felix0
	)

	BeforeEach(func() {
		infra = getInfra()

		options := infrastructure.DefaultTopologyOptions()
		options.IPIPMode = api.IPIPModeNever
		tc, client = infrastructure.StartSingleNodeTopology(options, infra)

		// Install a default profile that allows all ingress and egress, in the absence of any Policy.
		infra.AddDefaultAllow()

		// Create workload on host 1 (Felix0).
		ep1_1 = workload.Run(tc.Felixes[0], "ep1-1", "default", "10.65.0.0", wepPortStr, "tcp")
		ep1_1.ConfigureInInfra(infra)

		ep2_1 = workload.Run(tc.Felixes[0], "ep2-1", "default", "10.65.0.1", wepPortStr, "tcp")
		ep2_1.ConfigureInInfra(infra)

		if BPFMode() {
			ensureAllNodesBPFProgramsAttached(tc.Felixes)
		}
	})

	It("LOG action rule should reflect logPrefix correctly", func() {
		if BPFMode() {
			Skip("Skipping for BPF dataplane.")
		}

		// Explicitly configure the MTU.
		felixConfig := api.NewFelixConfiguration() // Create a default FelixConfiguration
		felixConfig.Name = "default"
		felixConfig.Spec.LogPrefix = "aXy9%n%%t %k %p"
		LogActionRateLimitBurst := 9_999
		felixConfig.Spec.LogActionRateLimitBurst = &LogActionRateLimitBurst
		logActionRateLimit := "9999/day"
		felixConfig.Spec.LogActionRateLimit = &logActionRateLimit
		_, err := client.FelixConfigurations().Create(context.Background(), felixConfig, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		// gnp2-4 egress(N1-1) ingress(N1-1)
		gnp := api.NewGlobalNetworkPolicy()
		gnp.Name = "ep2-4"
		gnp.Spec.Order = &float1_0
		gnp.Spec.Tier = "default"
		gnp.Spec.Selector = ep1_1.NameSelector()
		gnp.Spec.Types = []api.PolicyType{api.PolicyTypeIngress, api.PolicyTypeEgress}
		gnp.Spec.Ingress = []api.Rule{
			{Action: api.Log, Source: api.EntityRule{Selector: ep2_1.NameSelector()}},
		}
		gnp.Spec.Egress = []api.Rule{
			{Action: api.Allow, Destination: api.EntityRule{Selector: ep2_1.NameSelector()}},
		}
		_, err = client.GlobalNetworkPolicies().Create(utils.Ctx, gnp, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

		expectedPattern := "aXy9ep2-4%default gnp ep2-4: "
		detectIptablesRule := func(felix *infrastructure.Felix, ipVersion uint8) {
			binary := "iptables-save"
			if ipVersion == 6 {
				binary = "ip6tables-save"
			}

			logLimitPattern := fmt.Sprintf("-m limit --limit %s --limit-burst %d",
				logActionRateLimit, LogActionRateLimitBurst,
			)
			getRules := func() bool {
				output, err := felix.ExecOutput(binary, "-t", "filter")
				Expect(err).NotTo(HaveOccurred())
				return strings.Contains(output, expectedPattern) && strings.Contains(output, logLimitPattern)
			}
			Eventually(getRules, 5*time.Second, 100*time.Millisecond).Should(BeTrue())
			Consistently(getRules, 3*time.Second, 100*time.Millisecond).Should(BeTrue())
		}

		detectNftablesRule := func(felix *infrastructure.Felix, ipVersion uint8) {
			ipFamily := "ip"
			if ipVersion == 6 {
				ipFamily = "ip6"
			}
			logLimitPattern := fmt.Sprintf("limit rate %s burst %d packets",
				logActionRateLimit, LogActionRateLimitBurst,
			)
			getRules := func() bool {
				output, err := felix.ExecOutput("nft", "list", "table", ipFamily, "calico")
				Expect(err).NotTo(HaveOccurred())
				return strings.Contains(output, expectedPattern) && strings.Contains(output, logLimitPattern)
			}
			Eventually(getRules, 5*time.Second, 100*time.Millisecond).Should(BeTrue())
			Consistently(getRules, 3*time.Second, 100*time.Millisecond).Should(BeTrue())
		}

		if NFTMode() {
			detectNftablesRule(tc.Felixes[0], 4)
			detectNftablesRule(tc.Felixes[0], 6)
		} else {
			detectIptablesRule(tc.Felixes[0], 4)
			detectIptablesRule(tc.Felixes[0], 6)
		}
	})
})
