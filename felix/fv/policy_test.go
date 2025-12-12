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
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

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
		iOpts := []infrastructure.CreateOption{}
		infra = getInfra(iOpts...)

		options := infrastructure.DefaultTopologyOptions()
		options.IPIPMode = apiv3.IPIPModeNever
		options.EnableIPv6 = true
		options.BPFEnableIPv6 = true
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

	AfterEach(func() {
		if CurrentGinkgoTestDescription().Failed {
			for _, felix := range tc.Felixes {
				if NFTMode() {
					logNFTDiags(felix)
				} else {
					felix.Exec("iptables-save", "-c")
					felix.Exec("ip6tables-save", "-c")
				}
				felix.Exec("ip", "r")
				felix.Exec("ip", "-6", "r")
				felix.Exec("calico-bpf", "policy", "dump", "eth0", "all", "--asm")
				felix.Exec("calico-bpf", "-6", "policy", "dump", "eth0", "all", "--asm")
				felix.Exec("calico-bpf", "counters", "dump")
			}
		}

		ep1_1.Stop()
		ep2_1.Stop()
		tc.Stop()
		if CurrentGinkgoTestDescription().Failed {
			infra.DumpErrorData()
		}
		infra.Stop()
	})

	It("pepper should have expected restriction on the rule jumping to DSCP chain static rules", func() {
		if BPFMode() {
			Skip("Skipping for BPF dataplane.")
		}

		// Explicitly configure the MTU.
		felixConfig := api.NewFelixConfiguration() // Create a default FelixConfiguration
		felixConfig.Name = "default"
		rate := 20
		felixConfig.Spec.LogActionRate = &rate
		_, err := client.FelixConfigurations().Create(context.Background(), felixConfig, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		// gnp2-4 egress(N1-1) ingress(N1-1)
		gnp := api.NewGlobalNetworkPolicy()
		gnp.Name = "default.ep2-4"
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

		detecIptablesRule := func(felix *infrastructure.Felix, ipVersion uint8) {
			binary := "iptables-save"
			if ipVersion == 6 {
				binary = "ip6tables-save"
			}
			// -m limit --limit 20/min ... -j LOG --log-prefix "calico-packet: " --log-level 5
			expectedRule := "-m limit --limit 20/min"
			getRules := func() string {
				output, _ := felix.ExecOutput(binary, "-t", "filter")
				return output
			}
			Eventually(getRules, 5*time.Second, 100*time.Millisecond).Should(ContainSubstring(expectedRule))
			Consistently(getRules, 3*time.Second, 100*time.Millisecond).Should(ContainSubstring(expectedRule))
		}

		detectNftablesRule := func(felix *infrastructure.Felix, ipVersion uint8) {
			ipFamily := "ip"
			if ipVersion == 6 {
				ipFamily = "ip6"
			}
			// limit rate 20/minute ... log prefix "calico-packet" level info ... GlobalNetworkPolicy default.ep2-4 ingress"
			// TODO (mazdak): also check for LOG action and calico-packet
			pattern := "limit rate 20/minute"
			getRules := func() string {
				output, _ := felix.ExecOutput("nft", "list", "table", ipFamily, "calico")
				return output
			}
			Eventually(getRules, 5*time.Second, 100*time.Millisecond).Should(MatchRegexp(pattern))
			Consistently(getRules, 3*time.Second, 100*time.Millisecond).Should(MatchRegexp(pattern))
		}

		if NFTMode() {
			detectNftablesRule(tc.Felixes[0], 4)
			detectNftablesRule(tc.Felixes[0], 6)
		} else {
			detecIptablesRule(tc.Felixes[0], 4)
			detecIptablesRule(tc.Felixes[0], 6)
		}
	})
})
