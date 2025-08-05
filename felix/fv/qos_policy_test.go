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

//go:build fvtests

package fv_test

import (
	"fmt"
	"strings"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"

	"github.com/projectcalico/calico/felix/fv/connectivity"
	"github.com/projectcalico/calico/felix/fv/containers"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/utils"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	api "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
)

var _ = infrastructure.DatastoreDescribe("_BPF-SAFE_ qos policy tests", []apiconfig.DatastoreType{apiconfig.EtcdV3, apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
	const (
		wepPortStr = "8055"
	)

	var (
		infra        infrastructure.DatastoreInfra
		tc           infrastructure.TopologyContainers
		ep1_1, ep2_1 *workload.Workload // Workloads on Felix0
		ep1_2, ep2_2 *workload.Workload // Dual stack workloads on Felix1
		extClient    *containers.Container
		cc           *connectivity.Checker
	)

	BeforeEach(func() {
		iOpts := []infrastructure.CreateOption{}
		infra = getInfra(iOpts...)
		if (NFTMode() || BPFMode()) && getDataStoreType(infra) == "etcdv3" {
			Skip("Skipping NFT / BPF test for etcdv3 backend.")
		}

		// TODO (mazdak): Add support for bpf
		if BPFMode() {
			Skip("Not supported yet in bpf")
		}

		options := infrastructure.DefaultTopologyOptions()
		options.IPIPMode = apiv3.IPIPModeNever
		options.FelixLogSeverity = "Debug"
		options.EnableIPv6 = true
		tc, _ = infrastructure.StartNNodeTopology(2, options, infra)

		// Install a default profile that allows all ingress and egress, in the absence of any Policy.
		infra.AddDefaultAllow()

		// Create workload on host 1 (Felix0).
		ep1_1 = workload.Run(tc.Felixes[0], "ep1-1", "default", "10.65.0.0", wepPortStr, "tcp")
		ep1_1.ConfigureInInfra(infra)

		ep2_1 = workload.Run(tc.Felixes[0], "ep2-1", "default", "10.65.0.1", wepPortStr, "tcp")
		ep2_1.ConfigureInInfra(infra)

		// Create workload on host 2 (Felix1)
		ep1_2Opts := workload.WithIPv6Address("dead:beef::1:0")
		ep1_2 = workload.Run(tc.Felixes[1], "ep1-2", "default", "10.65.1.0", wepPortStr, "tcp", ep1_2Opts)
		ep1_2.ConfigureInInfra(infra)

		ep2_2Opts := workload.WithIPv6Address("dead:beef::1:1")
		ep2_2 = workload.Run(tc.Felixes[1], "ep2-2", "default", "10.65.1.1", wepPortStr, "tcp", ep2_2Opts)
		ep2_2.ConfigureInInfra(infra)

		cc = &connectivity.Checker{}

		// We will use this container to model an external client trying to connect into
		// workloads on a host.  Create a route in the container for the workload CIDR.
		extClientOpts := infrastructure.ExtClientOpts{
			Image: utils.Config.FelixImage,
		}
		extClient = infrastructure.RunExtClientWithOpts("ext-client1", extClientOpts)
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
		ep1_2.Stop()
		ep2_2.Stop()
		tc.Stop()
		if CurrentGinkgoTestDescription().Failed {
			infra.DumpErrorData()
		}
		infra.Stop()
		extClient.Stop()
	})

	It("should have expected restriction on the rule jumping to QoS policy rules", func() {
		detecIptablesRule := func(felix *infrastructure.Felix, ipv6 bool) {
			binary := "iptables-save"
			ipsetName := "cali40all-ipam-pools"
			if ipv6 {
				binary = "ip6tables-save"
				ipsetName = "cali60all-ipam-pools"
			}
			expectedRule := fmt.Sprintf(
				"-m set --match-set %v src -m set ! --match-set %v dst -j cali-qos-policy", ipsetName, ipsetName)
			getRules := func() string {
				output, _ := felix.ExecOutput(binary, "-t", "mangle")
				return output
			}
			Eventually(getRules, 5*time.Second, 100*time.Millisecond).Should(ContainSubstring(expectedRule))
			Consistently(getRules, 5*time.Second, 100*time.Millisecond).Should(ContainSubstring(expectedRule))
		}

		detectNftablesRule := func(felix *infrastructure.Felix, ipv6 bool) {
			ipsetName := "@cali40all-ipam-pools"
			ipFamily := "ip"
			if ipv6 {
				ipsetName = "@cali60all-ipam-pools"
				ipFamily = "ip6"
			}
			pattern := fmt.Sprintf(
				"%v saddr %v %v daddr != %v .* jump mangle-cali-qos-policy", ipFamily, ipsetName, ipFamily, ipsetName)
			getRules := func() string {
				output, _ := felix.ExecOutput("nft", "list", "chain", ipFamily, "calico", "mangle-cali-POSTROUTING")
				return output
			}
			Eventually(getRules, 5*time.Second, 100*time.Millisecond).Should(MatchRegexp(pattern))
			Consistently(getRules, 5*time.Second, 100*time.Millisecond).Should(MatchRegexp(pattern))
		}

		if NFTMode() {
			detectNftablesRule(tc.Felixes[0], false)
			detectNftablesRule(tc.Felixes[0], true)
		} else {
			detecIptablesRule(tc.Felixes[0], false)
			detecIptablesRule(tc.Felixes[0], true)
		}
	})

	It("applying DSCP annotation should result is adding correct rules", func() {
		dscp0 := numorstring.DSCPFromInt(0)   // 0x0
		dscp20 := numorstring.DSCPFromInt(20) // 0x14
		dscp32 := numorstring.DSCPFromInt(32) // 0x20
		dscp40 := numorstring.DSCPFromInt(40) // 0x28

		By("configurging external client to only accept packets with specific DSCP value")
		extClient.Exec("ip", "route", "add", ep1_1.IP, "via", tc.Felixes[0].IP)
		extClient.Exec("ip", "route", "add", ep2_1.IP, "via", tc.Felixes[0].IP)
		extClient.Exec("iptables", "-A", "INPUT", "-m", "dscp", "!", "--dscp", "0x14", "-j", "DROP")

		// Configure external client to only accept ipv4 packets with 0x14 DSCP value.
		extClient.Exec("ip", "-6", "route", "add", ep1_2.IP6, "via", tc.Felixes[1].IPv6)
		extClient.Exec("ip", "-6", "route", "add", ep2_2.IP6, "via", tc.Felixes[1].IPv6)

		// Configure external client to only accept ipv6 packets with 0x28 DSCP value. ICMPv6 needs to be allowed
		// regardless for neighbor discovery.
		extClient.Exec("ip6tables", "-A", "INPUT", "-p", "ipv6-icmp", "-j", "ACCEPT")
		extClient.Exec("ip6tables", "-A", "INPUT", "-m", "dscp", "!", "--dscp", "0x28", "-j", "DROP")

		cc.ResetExpectations()
		cc.ExpectNone(extClient, ep1_1)
		cc.ExpectNone(extClient, ep2_1)

		ccOpts := connectivity.ExpectWithIPVersion(6)
		cc.Expect(connectivity.None, extClient, ep1_2, ccOpts)
		cc.Expect(connectivity.None, extClient, ep2_2, ccOpts)
		cc.CheckConnectivity()

		verifyQoSPolicies(tc.Felixes[0], nil, nil)
		verifyQoSPolicies(tc.Felixes[1], nil, nil)

		By("setting the initial DSCP values")
		ep1_1.WorkloadEndpoint.Spec.QoSControls = &api.QoSControls{
			DSCP: &dscp20,
		}
		ep1_1.UpdateInInfra(infra)

		ep2_2.WorkloadEndpoint.Spec.QoSControls = &api.QoSControls{
			DSCP: &dscp40,
		}
		ep2_2.UpdateInInfra(infra)

		cc.ResetExpectations()
		cc.ExpectSome(extClient, ep1_1)
		cc.ExpectNone(extClient, ep2_1)

		cc.Expect(connectivity.None, extClient, ep1_2, ccOpts)
		cc.Expect(connectivity.Some, extClient, ep2_2, ccOpts)
		cc.CheckConnectivity()

		verifyQoSPolicies(tc.Felixes[0], []string{"0x14"}, nil)
		verifyQoSPolicies(tc.Felixes[1], []string{"0x28"}, []string{"0x28"})

		By("updating DSCP values on some workloads")
		ep2_1.WorkloadEndpoint.Spec.QoSControls = &api.QoSControls{
			DSCP: &dscp0,
		}
		ep2_1.UpdateInInfra(infra)

		ep1_2.WorkloadEndpoint.Spec.QoSControls = &api.QoSControls{
			DSCP: &dscp40,
		}
		ep1_2.UpdateInInfra(infra)

		cc.ResetExpectations()
		cc.ExpectSome(extClient, ep1_1)
		cc.ExpectNone(extClient, ep2_1)

		cc.Expect(connectivity.Some, extClient, ep1_2, ccOpts)
		cc.Expect(connectivity.Some, extClient, ep2_2, ccOpts)
		cc.CheckConnectivity()

		verifyQoSPolicies(tc.Felixes[0], []string{"0x0", "0x14"}, nil)
		verifyQoSPolicies(tc.Felixes[1], []string{"0x28", "0x28"}, []string{"0x28", "0x28"}) // 0x28 used by two workloads

		By("updating DSCP values on other workloads")
		ep1_1.WorkloadEndpoint.Spec.QoSControls = &api.QoSControls{
			DSCP: &dscp32,
		}
		ep1_1.UpdateInInfra(infra)

		ep1_2.WorkloadEndpoint.Spec.QoSControls = &api.QoSControls{
			DSCP: &dscp20,
		}
		ep1_2.UpdateInInfra(infra)

		cc.ResetExpectations()
		cc.ExpectNone(extClient, ep1_1)
		cc.ExpectNone(extClient, ep2_1)

		cc.Expect(connectivity.None, extClient, ep1_2, ccOpts)
		cc.Expect(connectivity.Some, extClient, ep2_2, ccOpts)
		cc.CheckConnectivity()

		verifyQoSPolicies(tc.Felixes[0], []string{"0x0", "0x20"}, nil)
		verifyQoSPolicies(tc.Felixes[1], []string{"0x14", "0x28"}, []string{"0x14", "0x28"})

		By("reverting the DSCP values")
		ep1_1.WorkloadEndpoint.Spec.QoSControls = &api.QoSControls{
			DSCP: &dscp20,
		}
		ep1_1.UpdateInInfra(infra)

		ep1_2.WorkloadEndpoint.Spec.QoSControls = &api.QoSControls{
			DSCP: &dscp40,
		}
		ep1_2.UpdateInInfra(infra)

		cc.ResetExpectations()
		cc.ExpectSome(extClient, ep1_1)
		cc.ExpectNone(extClient, ep2_1)

		cc.Expect(connectivity.Some, extClient, ep1_2, ccOpts)
		cc.Expect(connectivity.Some, extClient, ep2_2, ccOpts)
		cc.CheckConnectivity()

		verifyQoSPolicies(tc.Felixes[0], []string{"0x0", "0x14"}, nil)
		verifyQoSPolicies(tc.Felixes[1], []string{"0x28", "0x28"}, []string{"0x28", "0x28"}) // 0x28 used by two workloads
		By("resetting DSCP value on some workloads")
		ep2_1.WorkloadEndpoint.Spec.QoSControls = &api.QoSControls{}
		ep2_1.UpdateInInfra(infra)

		ep1_2.WorkloadEndpoint.Spec.QoSControls = &api.QoSControls{}
		ep1_2.UpdateInInfra(infra)

		cc.ResetExpectations()
		cc.ExpectSome(extClient, ep1_1)
		cc.ExpectNone(extClient, ep2_1)

		cc.Expect(connectivity.None, extClient, ep1_2, ccOpts)
		cc.Expect(connectivity.Some, extClient, ep2_2, ccOpts)
		cc.CheckConnectivity()

		verifyQoSPolicies(tc.Felixes[0], []string{"0x14"}, nil)
		verifyQoSPolicies(tc.Felixes[1], []string{"0x28"}, []string{"0x28"})

		By("stopping the last workloads")
		ep1_1.Stop()
		ep1_1.RemoveFromInfra(infra)

		ep2_2.Stop()
		ep2_2.RemoveFromInfra(infra)

		cc.ResetExpectations()
		cc.ExpectNone(extClient, ep1_1)
		cc.ExpectNone(extClient, ep2_1)

		cc.Expect(connectivity.None, extClient, ep1_2, ccOpts)
		cc.Expect(connectivity.None, extClient, ep2_2, ccOpts)
		cc.CheckConnectivity()

		verifyQoSPolicies(tc.Felixes[0], nil, nil)
		verifyQoSPolicies(tc.Felixes[1], nil, nil)
	})

	It("should be able to use all DSCP string values", func() {
		// We only need to run this once for iptables dataplane, and once for nftables.
		if BPFMode() || getDataStoreType(infra) == "etcdv3" {
			Skip("Skipping for BPF dataplane and etcdv3 backend.")
		}
		for dscpStr, dscpVal := range numorstring.AllDSCPValues {
			// Use a workload on host2 since it's configured as dual stack.
			dscp := numorstring.DSCPFromString(dscpStr)
			ep1_2.WorkloadEndpoint.Spec.QoSControls = &api.QoSControls{
				DSCP: &dscp,
			}
			ep1_2.UpdateInInfra(infra)

			hexStr := fmt.Sprintf("0x%02x", dscpVal)
			verifyQoSPolicies(tc.Felixes[1], []string{hexStr}, []string{hexStr})
		}
	})
})

func verifyQoSPolicies(felix *infrastructure.Felix, policies []string, policiesv6 []string) {
	verifyQoSPoliciesWithIPFamily(felix, false, policies...)
	verifyQoSPoliciesWithIPFamily(felix, true, policiesv6...)
}

func verifyQoSPoliciesWithIPFamily(felix *infrastructure.Felix, ipv6 bool, values ...string) {
	var (
		cmd         []string
		rulePattern string
	)

	assertRules := func() bool {
		output, _ := felix.ExecOutput(cmd...)
		if strings.Count(output, rulePattern) != len(values) {
			return false
		}

		for _, val := range values {
			expectedRule := fmt.Sprintf("%v %v", rulePattern, val)
			if !strings.Contains(output, expectedRule) {
				return false
			}
		}

		return true
	}

	if NFTMode() {
		ipFamily := "ip"
		if ipv6 {
			ipFamily = "ip6"
		}
		cmd = []string{"nft", "-n", "list", "chain", ipFamily, "calico", "mangle-cali-qos-policy"}
		rulePattern = fmt.Sprintf("%v dscp set", ipFamily)
	} else {
		binary := "iptables-save"
		if ipv6 {
			binary = "ip6tables-save"
		}
		cmd = []string{binary, "-t", "mangle"}
		rulePattern = "DSCP --set-dscp"
	}

	EventuallyWithOffset(1, assertRules, 5*time.Second, 100*time.Millisecond).
		Should(BeTrue())
	ConsistentlyWithOffset(1, assertRules, 3*time.Second, 100*time.Millisecond).
		Should(BeTrue())
}
