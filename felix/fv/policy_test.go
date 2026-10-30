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
	"k8s.io/utils/ptr"

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

	It("should log connection transitions when enabled", func() {
		if BPFMode() {
			Skip("Skipping for BPF dataplane.")
		}

		felix := tc.Felixes[0]
		defer enableNetnsNetfilterLogging()()

		felixConfig := api.NewFelixConfiguration()
		felixConfig.Name = "default"
		felixConfig.Spec.LogConnectionTransitions = ptr.To(api.LogConnectionTransitionsFirstResponseAfterLog)
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

		waitForConnLogRulesProgrammed(felix)

		// A successful connection: the SYN-ACK is the first response packet and must hit
		// the "-est" branch, logging the response's 5-tuple (ep1_1's server port back to
		// our pinned source port).
		estLogRE := regexp.MustCompile(fmt.Sprintf(
			`calico-response-est: .*SRC=%s DST=%s .*PROTO=TCP SPT=%s DPT=43210`,
			regexp.QuoteMeta(ep1_1.IP), regexp.QuoteMeta(ep2_1.IP), wepPortStr))
		estLogsBefore := kernelLogCount(felix, estLogRE)
		cc := &connectivity.Checker{}
		cc.Expect(connectivity.Some, ep2_1, ep1_1, connectivity.ExpectWithSrcPort(43210))
		cc.CheckConnectivity()
		Eventually(func() int { return logConnCounter(felix, "-est") }, 5*time.Second, 100*time.Millisecond).
			Should(BeNumerically(">", 0), "expected established log rule to fire for a successful connection")
		Eventually(func() int { return kernelLogCount(felix, estLogRE) }, 5*time.Second, 200*time.Millisecond).
			Should(BeNumerically(">", estLogsBefore), "expected a kernel log recording the SYN-ACK response")

		// A connection to a closed TCP port: the workload's RST response must hit the
		// "-rst" branch.  This also proves that inbound RSTs traverse our chains rather
		// than being short-circuited by the kernel.
		rstLogRE := regexp.MustCompile(fmt.Sprintf(
			`calico-response-rst: .*SRC=%s DST=%s .*PROTO=TCP SPT=8066 DPT=43211 .*RST`,
			regexp.QuoteMeta(ep1_1.IP), regexp.QuoteMeta(ep2_1.IP)))
		rstLogsBefore := kernelLogCount(felix, rstLogRE)
		ccRST := &connectivity.Checker{}
		ccRST.Expect(connectivity.None, ep2_1, connectivity.TargetIP(ep1_1.IP),
			connectivity.ExpectWithPorts(8066), connectivity.ExpectWithSrcPort(43211))
		ccRST.CheckConnectivity()
		Eventually(func() int { return logConnCounter(felix, "-rst") }, 5*time.Second, 100*time.Millisecond).
			Should(BeNumerically(">", 0), "expected RST log rule to fire for a refused connection")
		Eventually(func() int { return kernelLogCount(felix, rstLogRE) }, 5*time.Second, 200*time.Millisecond).
			Should(BeNumerically(">", rstLogsBefore), "expected a kernel log recording the RST response")

		// A UDP probe to a closed port: the ICMP port-unreachable is associated by
		// conntrack with the original connection so it must hit the "-icmp-err" branch.
		// The kernel logs the ICMP error's outer header plus the embedded original
		// packet's header, which carries the probe's 5-tuple.
		icmpLogRE := regexp.MustCompile(fmt.Sprintf(
			`calico-response-icmp-err: .*SRC=%s DST=%s .*PROTO=ICMP TYPE=3 CODE=3 .*\[SRC=%s DST=%s .*PROTO=UDP SPT=43212 DPT=8066`,
			regexp.QuoteMeta(ep1_1.IP), regexp.QuoteMeta(ep2_1.IP),
			regexp.QuoteMeta(ep2_1.IP), regexp.QuoteMeta(ep1_1.IP)))
		icmpLogsBefore := kernelLogCount(felix, icmpLogRE)
		ccUDP := &connectivity.Checker{}
		ccUDP.Protocol = "udp"
		ccUDP.Expect(connectivity.None, ep2_1, connectivity.TargetIP(ep1_1.IP),
			connectivity.ExpectWithPorts(8066), connectivity.ExpectWithSrcPort(43212))
		ccUDP.CheckConnectivity()
		Eventually(func() int { return logConnCounter(felix, "-icmp-err") }, 5*time.Second, 100*time.Millisecond).
			Should(BeNumerically(">", 0), "expected ICMP error log rule to fire for a UDP probe to a closed port")
		Eventually(func() int { return kernelLogCount(felix, icmpLogRE) }, 5*time.Second, 200*time.Millisecond).
			Should(BeNumerically(">", icmpLogsBefore), "expected a kernel log recording the ICMP error response")
	})

	It("should log connection transitions for workload-to-host connections via cali-OUTPUT", func() {
		if BPFMode() {
			Skip("Skipping for BPF dataplane.")
		}

		felix := tc.Felixes[0]
		defer enableNetnsNetfilterLogging()()

		// DefaultEndpointToHostAction=Return lets the workload's SYN reach the host's
		// TCP stack (which will answer a closed port with an RST).
		felixConfig := api.NewFelixConfiguration()
		felixConfig.Name = "default"
		felixConfig.Spec.LogConnectionTransitions = ptr.To(api.LogConnectionTransitionsFirstResponseAfterLog)
		felixConfig.Spec.DefaultEndpointToHostAction = "Return"
		_, err := client.FelixConfigurations().Create(context.Background(), felixConfig, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		// Egress Log+Allow policy on ep2_1: its connections to the host get the initial
		// LOG and the "no response seen yet" connmark bit in the cali-fw- chain.
		gnp := api.NewGlobalNetworkPolicy()
		gnp.Name = "log-conn-wl-to-host"
		gnp.Spec.Order = &float1_0
		gnp.Spec.Tier = "default"
		gnp.Spec.Selector = ep2_1.NameSelector()
		gnp.Spec.Types = []api.PolicyType{api.PolicyTypeEgress}
		gnp.Spec.Egress = []api.Rule{
			{Action: api.Log},
			{Action: api.Allow},
		}
		_, err = client.GlobalNetworkPolicies().Create(utils.Ctx, gnp, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

		waitForConnLogRulesProgrammed(felix)

		// Connect to a closed port on the host itself.  The host's RST leaves via
		// filter cali-OUTPUT and RETURNs at the workload-interface rule without
		// traversing any per-endpoint chain, so this scenario is covered only by the
		// check rule at the top of cali-OUTPUT.
		rstLogRE := regexp.MustCompile(fmt.Sprintf(
			`calico-response-rst: .*SRC=%s DST=%s .*PROTO=TCP SPT=8067 DPT=43213 .*RST`,
			regexp.QuoteMeta(felix.IP), regexp.QuoteMeta(ep2_1.IP)))
		rstLogsBefore := kernelLogCount(felix, rstLogRE)
		cc := &connectivity.Checker{}
		cc.Expect(connectivity.None, ep2_1, connectivity.TargetIP(felix.IP),
			connectivity.ExpectWithPorts(8067), connectivity.ExpectWithSrcPort(43213))
		cc.CheckConnectivity()
		Eventually(func() int { return logConnCounter(felix, "-rst") }, 5*time.Second, 100*time.Millisecond).
			Should(BeNumerically(">", 0), "expected RST log rule to fire for a refused workload-to-host connection")
		Eventually(func() int { return kernelLogCount(felix, rstLogRE) }, 5*time.Second, 200*time.Millisecond).
			Should(BeNumerically(">", rstLogsBefore), "expected a kernel log recording the host's RST response")
	})
})

// waitForConnLogRulesProgrammed waits until the connection transition log rules are
// programmed — the shared log chain with its three prefixes, the connmark-set rule in
// the policy chain and the check rule that diverts response packets to the log chain —
// and then verifies they are stable, i.e. no rule-flapping caused by a
// programmed-vs-rendered mismatch on resync.
func waitForConnLogRulesProgrammed(felix *infrastructure.Felix) {
	rulesProgrammed := func() bool {
		var output string
		var err error
		if NFTMode() {
			output, err = felix.ExecOutput("nft", "list", "table", "ip", "calico")
			Expect(err).NotTo(HaveOccurred())
			return strings.Contains(output, `log prefix "calico-response-est: "`) &&
				strings.Contains(output, `log prefix "calico-response-rst: "`) &&
				strings.Contains(output, `log prefix "calico-response-icmp-err: "`) &&
				strings.Contains(output, "ct mark set") &&
				strings.Contains(output, "cali-log-conn")
		}
		output, err = felix.ExecOutput("iptables-save", "-t", "filter")
		Expect(err).NotTo(HaveOccurred())
		return strings.Contains(output, `--log-prefix "calico-response-est: "`) &&
			strings.Contains(output, `--log-prefix "calico-response-rst: "`) &&
			strings.Contains(output, `--log-prefix "calico-response-icmp-err: "`) &&
			strings.Contains(output, "-j CONNMARK") &&
			strings.Contains(output, "-j cali-log-conn")
	}
	EventuallyWithOffset(1, rulesProgrammed, 10*time.Second, 100*time.Millisecond).Should(BeTrue(),
		"connection transition log rules were not programmed")
	ConsistentlyWithOffset(1, rulesProgrammed, 3*time.Second, 100*time.Millisecond).Should(BeTrue(),
		"connection transition log rules flapped after programming")
}

// logConnCounter reads the total packet count of the LOG rules with the given prefix
// suffix in the cali-log-conn chain(s).
func logConnCounter(felix *infrastructure.Felix, suffix string) int {
	var re *regexp.Regexp
	var output string
	var err error
	if NFTMode() {
		output, err = felix.ExecOutput("nft", "list", "table", "ip", "calico")
		Expect(err).NotTo(HaveOccurred())
		re = regexp.MustCompile(`counter packets (\d+) bytes \d+ log prefix "calico-response` + suffix + `: "`)
	} else {
		output, err = felix.ExecOutput("iptables-save", "-c", "-t", "filter")
		Expect(err).NotTo(HaveOccurred())
		re = regexp.MustCompile(`\[(\d+):\d+\] -A cali-log-conn .*--log-prefix "calico-response` + suffix + `: "`)
	}
	total := 0
	for _, m := range re.FindAllStringSubmatch(output, -1) {
		n, err := strconv.Atoi(m[1])
		Expect(err).NotTo(HaveOccurred())
		total += n
	}
	return total
}

// kernelLogCount returns the number of kernel log lines matching re.  dmesg inside the
// (privileged) felix container reads the host's ring buffer, which is shared with other
// containers and past tests, so callers should compare against a before-count rather
// than asserting that matches exist at all.
func kernelLogCount(felix *infrastructure.Felix, re *regexp.Regexp) int {
	output, err := felix.ExecOutput("dmesg")
	Expect(err).NotTo(HaveOccurred())
	return len(re.FindAllString(output, -1))
}

// enableNetnsNetfilterLogging turns on net.netfilter.nf_log_all_netns on the host so
// that netfilter LOG output from the felix containers' network namespaces reaches the
// (host-global) kernel ring buffer; without it the kernel suppresses LOG output from
// non-init network namespaces entirely.  The sysctl only exists in the init network
// namespace, and the test process itself runs in a container, so it is accessed via a
// one-shot privileged host-network container.  Returns a func that restores the
// original setting.
func enableNetnsNetfilterLogging() func() {
	const sysctlPath = "/proc/sys/net/netfilter/nf_log_all_netns"
	runInInitNetns := func(shellCmd string) (string, error) {
		out, err := utils.Command("docker", "run", "--rm", "--privileged", "--net=host",
			utils.Config.FelixImage, "sh", "-c", shellCmd).Output()
		return strings.TrimSpace(string(out)), err
	}
	origValue, err := runInInitNetns("cat " + sysctlPath)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "failed to read "+sysctlPath)
	_, err = runInInitNetns("echo 1 > " + sysctlPath)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "failed to set "+sysctlPath)
	return func() {
		_, _ = runInInitNetns("echo " + origValue + " > " + sysctlPath)
	}
}
