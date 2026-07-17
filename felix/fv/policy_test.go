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
	"regexp"
	"strconv"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/fv/connectivity"
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

	It("should log connection state transitions when enabled", func() {
		if BPFMode() {
			Skip("Skipping for BPF dataplane.")
		}

		felix := tc.Felixes[0]

		enabled := true
		felixConfig := api.NewFelixConfiguration()
		felixConfig.Name = "default"
		felixConfig.Spec.LogConnectionStateTransitions = &enabled
		_, err := client.FelixConfigurations().Create(context.Background(), felixConfig, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		// Log+Allow ingress policy on ep1_1; every connection from ep2_1 gets the
		// initial LOG and the "no response seen yet" connmark bit.
		gnp := api.NewGlobalNetworkPolicy()
		gnp.Name = "log-conn-state"
		gnp.Spec.Order = &float1_0
		gnp.Spec.Tier = "default"
		gnp.Spec.Selector = ep1_1.NameSelector()
		gnp.Spec.Types = []api.PolicyType{api.PolicyTypeIngress, api.PolicyTypeEgress}
		gnp.Spec.Ingress = []api.Rule{
			{Action: api.Log, Source: api.EntityRule{Selector: ep2_1.NameSelector()}},
			{Action: api.Allow, Source: api.EntityRule{Selector: ep2_1.NameSelector()}},
		}
		gnp.Spec.Egress = []api.Rule{
			{Action: api.Allow},
		}
		_, err = client.GlobalNetworkPolicies().Create(utils.Ctx, gnp, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

		// Wait for the connection state log rules to be programmed: the shared log chain
		// with its three prefixes, the connmark-set rule in the policy chain and the
		// check rule that diverts response packets to the log chain.
		rulesProgrammed := func() bool {
			var output string
			var err error
			if NFTMode() {
				output, err = felix.ExecOutput("nft", "list", "table", "ip", "calico")
				Expect(err).NotTo(HaveOccurred())
				return strings.Contains(output, `log prefix "calico-packet-est: "`) &&
					strings.Contains(output, `log prefix "calico-packet-rst: "`) &&
					strings.Contains(output, `log prefix "calico-packet-icmp-err: "`) &&
					strings.Contains(output, "ct mark set") &&
					strings.Contains(output, "cali-log-conn")
			}
			output, err = felix.ExecOutput("iptables-save", "-t", "filter")
			Expect(err).NotTo(HaveOccurred())
			return strings.Contains(output, `--log-prefix "calico-packet-est: "`) &&
				strings.Contains(output, `--log-prefix "calico-packet-rst: "`) &&
				strings.Contains(output, `--log-prefix "calico-packet-icmp-err: "`) &&
				strings.Contains(output, "-j CONNMARK") &&
				strings.Contains(output, "-j cali-log-conn")
		}
		Eventually(rulesProgrammed, 10*time.Second, 100*time.Millisecond).Should(BeTrue(),
			"connection state log rules were not programmed")
		// The rules must also be stable, i.e. no rule-flapping caused by a
		// programmed-vs-rendered mismatch on resync.
		Consistently(rulesProgrammed, 3*time.Second, 100*time.Millisecond).Should(BeTrue(),
			"connection state log rules flapped after programming")

		// Reads the total packet count of the LOG rules with the given prefix suffix in
		// the cali-log-conn chain(s).
		logConnCounter := func(suffix string) int {
			var re *regexp.Regexp
			var output string
			var err error
			if NFTMode() {
				output, err = felix.ExecOutput("nft", "list", "table", "ip", "calico")
				Expect(err).NotTo(HaveOccurred())
				re = regexp.MustCompile(`counter packets (\d+) bytes \d+ log prefix "calico-packet` + suffix + `: "`)
			} else {
				output, err = felix.ExecOutput("iptables-save", "-c", "-t", "filter")
				Expect(err).NotTo(HaveOccurred())
				re = regexp.MustCompile(`\[(\d+):\d+\] -A cali-log-conn .*--log-prefix "calico-packet` + suffix + `: "`)
			}
			total := 0
			for _, m := range re.FindAllStringSubmatch(output, -1) {
				n, err := strconv.Atoi(m[1])
				Expect(err).NotTo(HaveOccurred())
				total += n
			}
			return total
		}

		// A successful connection: the SYN-ACK is the first response packet and must hit
		// the "-est" branch.
		cc := &connectivity.Checker{}
		cc.ExpectSome(ep2_1, ep1_1)
		cc.CheckConnectivity()
		Eventually(func() int { return logConnCounter("-est") }, 5*time.Second, 100*time.Millisecond).
			Should(BeNumerically(">", 0), "expected established log for a successful connection")

		// A connection to a closed TCP port: the workload's RST response must hit the
		// "-rst" branch.  This also proves that inbound RSTs traverse our chains rather
		// than being short-circuited by the kernel.
		ccRST := &connectivity.Checker{}
		ccRST.ExpectNone(ep2_1, connectivity.TargetIP(ep1_1.IP), 8066)
		ccRST.CheckConnectivity()
		Eventually(func() int { return logConnCounter("-rst") }, 5*time.Second, 100*time.Millisecond).
			Should(BeNumerically(">", 0), "expected RST log for a refused connection")

		// A UDP probe to a closed port: the ICMP port-unreachable is associated by
		// conntrack with the original connection so it must hit the "-icmp-err" branch.
		ccUDP := &connectivity.Checker{}
		ccUDP.Protocol = "udp"
		ccUDP.ExpectNone(ep2_1, connectivity.TargetIP(ep1_1.IP), 8066)
		ccUDP.CheckConnectivity()
		Eventually(func() int { return logConnCounter("-icmp-err") }, 5*time.Second, 100*time.Millisecond).
			Should(BeNumerically(">", 0), "expected ICMP error log for a UDP probe to a closed port")
	})
})
