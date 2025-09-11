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
	"context"
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
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

var _ = infrastructure.DatastoreDescribe("_BPF-SAFE_ dscp tests", []apiconfig.DatastoreType{apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
	const (
		wepPortStr = "8055"
	)

	var (
		infra               infrastructure.DatastoreInfra
		tc                  infrastructure.TopologyContainers
		client              client.Interface
		ep1_1, ep2_1, hostw *workload.Workload // Workloads on Felix0
		ep1_2, ep2_2        *workload.Workload // Dual stack workloads on Felix1
		extClient           *containers.Container
		extWorkload         *workload.Workload
		cc                  *connectivity.Checker
	)

	BeforeEach(func() {
		iOpts := []infrastructure.CreateOption{}
		infra = getInfra(iOpts...)

		options := infrastructure.DefaultTopologyOptions()
		options.IPIPMode = apiv3.IPIPModeNever
		options.EnableIPv6 = true
		options.BPFEnableIPv6 = true
		tc, client = infrastructure.StartNNodeTopology(2, options, infra)

		// Install a default profile that allows all ingress and egress, in the absence of any Policy.
		infra.AddDefaultAllow()

		// Create workload on host 1 (Felix0).
		ep1_1 = workload.Run(tc.Felixes[0], "ep1-1", "default", "10.65.0.0", wepPortStr, "tcp")
		ep1_1.ConfigureInInfra(infra)

		ep2_1 = workload.Run(tc.Felixes[0], "ep2-1", "default", "10.65.0.1", wepPortStr, "tcp")
		ep2_1.ConfigureInInfra(infra)

		hostw = workload.Run(tc.Felixes[0], "host0", "", tc.Felixes[0].IP, wepPortStr, "tcp")
		hostw.ConfigureInInfra(infra)

		// Create workload on host 2 (Felix1)
		ep1_2Opts := workload.WithIPv6Address("dead:beef::1:0")
		ep1_2 = workload.Run(tc.Felixes[1], "ep1-2", "default", "10.65.1.0", wepPortStr, "tcp", ep1_2Opts)
		ep1_2.ConfigureInInfra(infra)

		ep2_2Opts := workload.WithIPv6Address("dead:beef::1:1")
		ep2_2 = workload.Run(tc.Felixes[1], "ep2-2", "default", "10.65.1.1", wepPortStr, "tcp", ep2_2Opts)
		ep2_2.ConfigureInInfra(infra)

		cc = &connectivity.Checker{}

		if BPFMode() {
			ensureAllNodesBPFProgramsAttached(tc.Felixes)
		}

		// We will use this container to model an external client trying to connect into
		// workloads on a host.  Create a route in the container for the workload CIDR.
		extClientOpts := infrastructure.ExtClientOpts{
			Image: utils.Config.FelixImage,
		}
		extClient = infrastructure.RunExtClientWithOpts("ext-client1", extClientOpts)
		extWorkload = &workload.Workload{
			C:        extClient,
			Name:     "ext-workload",
			Ports:    wepPortStr,
			Protocol: "tcp",
			IP:       extClient.IP,
			IP6:      extClient.IPv6,
		}
		err := extWorkload.Start()
		Expect(err).NotTo(HaveOccurred())
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

		hostw.Stop()
		ep1_1.Stop()
		ep2_1.Stop()
		ep1_2.Stop()
		ep2_2.Stop()
		tc.Stop()
		if CurrentGinkgoTestDescription().Failed {
			infra.DumpErrorData()
		}
		infra.Stop()
		extWorkload.Stop()
		extClient.Stop()
	})

	It("should have expected restriction on the rule jumping to DSCP chain static rules", func() {
		if BPFMode() {
			Skip("Skipping for BPF dataplane.")
		}

		detecIptablesRule := func(felix *infrastructure.Felix, ipVersion uint8) {
			binary := "iptables-save"
			if ipVersion == 6 {
				binary = "ip6tables-save"
			}
			allPoolsIPSet := fmt.Sprintf("cali%v0all-ipam-pools", ipVersion)
			allHostsIPSet := fmt.Sprintf("cali%v0all-hosts-net", ipVersion)
			dscpIPSet := fmt.Sprintf("cali%v0dscp-src-net", ipVersion)
			tmpl := "-m set --match-set %v src -m set ! --match-set %v dst -m set ! --match-set %v dst -j cali-egress-dscp"
			expectedRule := fmt.Sprintf(tmpl, dscpIPSet, allPoolsIPSet, allHostsIPSet)
			getRules := func() string {
				output, _ := felix.ExecOutput(binary, "-t", "mangle")
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
			allPoolsIPSet := fmt.Sprintf("@cali%v0all-ipam-pools", ipVersion)
			allHostsIPSet := fmt.Sprintf("@cali%v0all-hosts-net", ipVersion)
			dscpIPSet := fmt.Sprintf("@cali%v0dscp-src-net", ipVersion)
			tmpl := "%v saddr %v %v daddr != %v %v daddr != %v .* jump mangle-cali-egress-dscp"
			pattern := fmt.Sprintf(tmpl, ipFamily, dscpIPSet, ipFamily, allPoolsIPSet, ipFamily, allHostsIPSet)
			getRules := func() string {
				output, _ := felix.ExecOutput("nft", "list", "chain", ipFamily, "calico", "mangle-cali-POSTROUTING")
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

	It("applying DSCP annotation should result in correct dataplane state", func() {
		dscp0 := numorstring.DSCPFromInt(0)   // 0x0
		dscp20 := numorstring.DSCPFromInt(20) // 0x14
		dscp32 := numorstring.DSCPFromInt(32) // 0x20
		dscp40 := numorstring.DSCPFromInt(40) // 0x28

		By("configurging external client to only accept packets with specific DSCP value")
		extClient.Exec("ip", "route", "add", ep1_1.IP, "via", tc.Felixes[0].IP)
		extClient.Exec("ip", "route", "add", ep2_1.IP, "via", tc.Felixes[0].IP)

		// Configure external client to only accept ipv4 packets with 0x14 DSCP value.
		extClient.Exec("iptables", "-A", "INPUT", "-m", "dscp", "!", "--dscp", "0x14", "-j", "DROP")

		extClient.Exec("ip", "-6", "route", "add", ep1_2.IP6, "via", tc.Felixes[1].IPv6)
		extClient.Exec("ip", "-6", "route", "add", ep2_2.IP6, "via", tc.Felixes[1].IPv6)

		// Configure external client to only accept ipv6 packets with 0x28 DSCP value. ICMPv6 needs to be allowed
		// regardless for neighbor discovery.
		extClient.Exec("ip6tables", "-A", "INPUT", "-p", "ipv6-icmp", "-j", "ACCEPT")
		extClient.Exec("ip6tables", "-A", "INPUT", "-m", "dscp", "!", "--dscp", "0x28", "-j", "DROP")

		if !BPFMode() {
			verifyQoSPolicies(tc.Felixes[0], nil, nil)
			verifyQoSPolicies(tc.Felixes[1], nil, nil)
		}

		cc.ResetExpectations()
		cc.ExpectNone(hostw, extWorkload)
		cc.ExpectNone(ep1_1, extWorkload)
		cc.ExpectNone(ep2_1, extWorkload)

		ccOpts := connectivity.ExpectWithIPVersion(6)
		cc.Expect(connectivity.None, ep1_2, extWorkload, ccOpts)
		cc.Expect(connectivity.None, ep2_2, extWorkload, ccOpts)
		cc.CheckConnectivity()

		By("adding a host endpoint to felix 0")
		hep := apiv3.NewHostEndpoint()
		hep.Name = "host1-eth0"
		hep.Labels = map[string]string{
			"name":          hep.Name,
			"host-endpoint": "true",
		}
		hep.Spec.Node = tc.Felixes[0].Hostname
		hep.Spec.ExpectedIPs = []string{tc.Felixes[0].IP}
		hep.Annotations = map[string]string{
			"qos.projectcalico.org/dscp": "20",
		}
		_, err := client.HostEndpoints().Create(utils.Ctx, hep, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		gnp := apiv3.NewGlobalNetworkPolicy()
		gnp.Name = "gnp-1"
		gnp.Spec.Selector = "host-endpoint=='true'"
		gnp.Spec.Ingress = []apiv3.Rule{{Action: apiv3.Allow}}
		gnp.Spec.Egress = []apiv3.Rule{{Action: apiv3.Allow}}
		_, err = client.GlobalNetworkPolicies().Create(utils.Ctx, gnp, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

		By("setting the initial DSCP values")
		ep1_1.WorkloadEndpoint.Spec.QoSControls = &api.QoSControls{
			DSCP: &dscp20,
		}
		ep1_1.UpdateInInfra(infra)

		ep2_2.WorkloadEndpoint.Spec.QoSControls = &api.QoSControls{
			DSCP: &dscp40,
		}
		ep2_2.UpdateInInfra(infra)

		if !BPFMode() {
			verifyQoSPolicies(tc.Felixes[0], []string{"0x14", "0x14"}, nil)
			verifyQoSPolicies(tc.Felixes[1], []string{"0x28"}, []string{"0x28"})
		}

		cc.ResetExpectations()
		cc.ExpectSome(hostw, extWorkload)
		cc.ExpectSome(ep1_1, extWorkload)
		cc.ExpectNone(ep2_1, extWorkload)

		cc.Expect(connectivity.None, ep1_2, extWorkload, ccOpts)
		cc.Expect(connectivity.Some, ep2_2, extWorkload, ccOpts)
		cc.CheckConnectivity()

		By("updating DSCP values on some workloads")
		ep2_1.WorkloadEndpoint.Spec.QoSControls = &api.QoSControls{
			DSCP: &dscp0,
		}
		ep2_1.UpdateInInfra(infra)

		ep1_2.WorkloadEndpoint.Spec.QoSControls = &api.QoSControls{
			DSCP: &dscp40,
		}
		ep1_2.UpdateInInfra(infra)

		if !BPFMode() {
			verifyQoSPolicies(tc.Felixes[0], []string{"0x0", "0x14", "0x14"}, nil)
			verifyQoSPolicies(tc.Felixes[1], []string{"0x28", "0x28"}, []string{"0x28", "0x28"}) // 0x28 used by two workloads
		}

		cc.ResetExpectations()
		cc.ExpectSome(hostw, extWorkload)
		cc.ExpectSome(ep1_1, extWorkload)
		cc.ExpectNone(ep2_1, extWorkload)

		cc.Expect(connectivity.Some, ep1_2, extWorkload, ccOpts)
		cc.Expect(connectivity.Some, ep2_2, extWorkload, ccOpts)
		cc.CheckConnectivity()

		By("updating DSCP values on other workloads")
		ep1_1.WorkloadEndpoint.Spec.QoSControls = &api.QoSControls{
			DSCP: &dscp32,
		}
		ep1_1.UpdateInInfra(infra)

		ep1_2.WorkloadEndpoint.Spec.QoSControls = &api.QoSControls{
			DSCP: &dscp20,
		}
		ep1_2.UpdateInInfra(infra)

		if !BPFMode() {
			verifyQoSPolicies(tc.Felixes[0], []string{"0x0", "0x14", "0x20"}, nil)
			verifyQoSPolicies(tc.Felixes[1], []string{"0x14", "0x28"}, []string{"0x14", "0x28"})
		}

		cc.ResetExpectations()
		cc.ExpectSome(hostw, extWorkload)
		cc.ExpectNone(ep1_1, extWorkload)
		cc.ExpectNone(ep2_1, extWorkload)

		cc.Expect(connectivity.None, ep1_2, extWorkload, ccOpts)
		cc.Expect(connectivity.Some, ep2_2, extWorkload, ccOpts)
		cc.CheckConnectivity()

		By("reverting the DSCP values")
		ep1_1.WorkloadEndpoint.Spec.QoSControls = &api.QoSControls{
			DSCP: &dscp20,
		}
		ep1_1.UpdateInInfra(infra)

		ep1_2.WorkloadEndpoint.Spec.QoSControls = &api.QoSControls{
			DSCP: &dscp40,
		}
		ep1_2.UpdateInInfra(infra)

		if !BPFMode() {
			verifyQoSPolicies(tc.Felixes[0], []string{"0x0", "0x14", "0x14"}, nil)
			verifyQoSPolicies(tc.Felixes[1], []string{"0x28", "0x28"}, []string{"0x28", "0x28"}) // 0x28 used by two workloads
		}

		cc.ResetExpectations()
		cc.ExpectSome(hostw, extWorkload)
		cc.ExpectSome(ep1_1, extWorkload)
		cc.ExpectNone(ep2_1, extWorkload)

		cc.Expect(connectivity.Some, ep1_2, extWorkload, ccOpts)
		cc.Expect(connectivity.Some, ep2_2, extWorkload, ccOpts)
		cc.CheckConnectivity()

		By("checking DSCP values are applied to return traffic of connections initiated outside cluster")
		cc.ResetExpectations()
		cc.ExpectSome(extClient, hostw)
		cc.ExpectSome(extClient, ep1_1)
		cc.ExpectNone(extClient, ep2_1)

		cc.Expect(connectivity.Some, extClient, ep1_2, ccOpts)
		cc.Expect(connectivity.Some, extClient, ep2_2, ccOpts)
		cc.CheckConnectivity()

		By("removing host endpoint")
		_, err = client.HostEndpoints().Delete(utils.Ctx, hep.Name, options.DeleteOptions{})
		Expect(err).NotTo(HaveOccurred())

		if !BPFMode() {
			verifyQoSPolicies(tc.Felixes[0], []string{"0x0", "0x14"}, nil)
			verifyQoSPolicies(tc.Felixes[1], []string{"0x28", "0x28"}, []string{"0x28", "0x28"}) // 0x28 used by two workloads
		}

		cc.ResetExpectations()
		cc.ExpectNone(hostw, extWorkload)
		cc.ExpectSome(ep1_1, extWorkload)
		cc.ExpectNone(ep2_1, extWorkload)

		cc.Expect(connectivity.Some, ep1_2, extWorkload, ccOpts)
		cc.Expect(connectivity.Some, ep2_2, extWorkload, ccOpts)
		cc.CheckConnectivity()

		By("resetting DSCP value on some workloads")
		ep2_1.WorkloadEndpoint.Spec.QoSControls = &api.QoSControls{}
		ep2_1.UpdateInInfra(infra)

		ep1_2.WorkloadEndpoint.Spec.QoSControls = &api.QoSControls{}
		ep1_2.UpdateInInfra(infra)

		if !BPFMode() {
			verifyQoSPolicies(tc.Felixes[0], []string{"0x14"}, nil)
			verifyQoSPolicies(tc.Felixes[1], []string{"0x28"}, []string{"0x28"})
		}

		cc.ResetExpectations()
		cc.ExpectNone(hostw, extWorkload)
		cc.ExpectSome(ep1_1, extWorkload)
		cc.ExpectNone(ep2_1, extWorkload)

		cc.Expect(connectivity.None, ep1_2, extWorkload, ccOpts)
		cc.Expect(connectivity.Some, ep2_2, extWorkload, ccOpts)
		cc.CheckConnectivity()

		By("stopping the last workloads")
		ep1_1.Stop()
		ep1_1.RemoveFromInfra(infra)

		ep2_2.Stop()
		ep2_2.RemoveFromInfra(infra)

		if !BPFMode() {
			verifyQoSPolicies(tc.Felixes[0], nil, nil)
			verifyQoSPolicies(tc.Felixes[1], nil, nil)
		}

		cc.ResetExpectations()
		cc.ExpectNone(hostw, extWorkload)
		cc.ExpectNone(ep1_1, extWorkload)
		cc.ExpectNone(ep2_1, extWorkload)

		cc.Expect(connectivity.None, ep1_2, extWorkload, ccOpts)
		cc.Expect(connectivity.None, ep2_2, extWorkload, ccOpts)
		cc.CheckConnectivity()
	})

	It("should be able to use all DSCP string values", func() {
		// We only need to run this once for iptables dataplane, and once for nftables.
		if BPFMode() {
			Skip("Skipping for BPF dataplane.")
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

	It("pepper should keep DSCP value when NAT outgoing is enabled", func() {
		ctx := context.Background()
		ippool, err := client.IPPools().Get(ctx, infrastructure.DefaultIPPoolName, options.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		ippool.Spec.NATOutgoing = true
		_, err = client.IPPools().Update(ctx, ippool, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		ippoolv6, err := client.IPPools().Get(ctx, infrastructure.DefaultIPv6PoolName, options.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		ippoolv6.Spec.NATOutgoing = true
		_, err = client.IPPools().Update(ctx, ippoolv6, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		dscpAF11 := numorstring.DSCPFromString("AF11") // 0A
		dscpEF := numorstring.DSCPFromString("EF")     // 2E

		extClient.Exec("ip", "route", "add", ep1_1.IP, "via", tc.Felixes[0].IP)
		extClient.Exec("ip", "route", "add", ep2_1.IP, "via", tc.Felixes[0].IP)

		// Configure external client to only accept ipv4 packets with AF11(0x0A) DSCP value.
		extClient.Exec("iptables", "-A", "INPUT", "-m", "dscp", "!", "--dscp", "0x0a", "-j", "DROP")

		extClient.Exec("ip", "-6", "route", "add", ep1_2.IP6, "via", tc.Felixes[1].IPv6)
		extClient.Exec("ip", "-6", "route", "add", ep2_2.IP6, "via", tc.Felixes[1].IPv6)

		// Configure external client to only accept ipv6 packets with EF(0x2E) DSCP value. ICMPv6 needs to be allowed
		// regardless for neighbor discovery.
		extClient.Exec("ip6tables", "-A", "INPUT", "-p", "ipv6-icmp", "-j", "ACCEPT")
		extClient.Exec("ip6tables", "-A", "INPUT", "-m", "dscp", "!", "--dscp", "0x2e", "-j", "DROP")

		if !BPFMode() {
			verifyQoSPolicies(tc.Felixes[0], nil, nil)
			verifyQoSPolicies(tc.Felixes[1], nil, nil)
		}

		ep1_1.WorkloadEndpoint.Spec.QoSControls = &api.QoSControls{
			DSCP: &dscpAF11,
		}
		ep1_1.UpdateInInfra(infra)

		ep2_2.WorkloadEndpoint.Spec.QoSControls = &api.QoSControls{
			DSCP: &dscpEF,
		}
		ep2_2.UpdateInInfra(infra)

		if !BPFMode() {
			verifyQoSPolicies(tc.Felixes[0], []string{"0x0a"}, nil)
			verifyQoSPolicies(tc.Felixes[1], []string{"0x2e"}, []string{"0x2e"})
		}

		cc.ResetExpectations()
		cc.ExpectSNAT(ep1_1, tc.Felixes[0].IP, extWorkload)
		cc.ExpectNone(ep2_1, extWorkload)

		ccOptsIPv6 := connectivity.ExpectWithIPVersion(6)
		ccOptsSrc := connectivity.ExpectWithSrcIPs(tc.Felixes[1].IPv6)
		cc.Expect(connectivity.None, ep1_2, extWorkload, ccOptsIPv6, ccOptsSrc)
		cc.Expect(connectivity.Some, ep2_2, extWorkload, ccOptsIPv6, ccOptsSrc)
		cc.CheckConnectivity()
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
		cmd = []string{"nft", "-n", "list", "chain", ipFamily, "calico", "mangle-cali-egress-dscp"}
		rulePattern = fmt.Sprintf("%v dscp set", ipFamily)
	} else {
		binary := "iptables-save"
		if ipv6 {
			binary = "ip6tables-save"
		}
		cmd = []string{binary, "-t", "mangle"}
		rulePattern = "DSCP --set-dscp"
	}

	EventuallyWithOffset(2, assertRules, 10*time.Second, 100*time.Millisecond).
		Should(BeTrue())
	ConsistentlyWithOffset(2, assertRules, 3*time.Second, 100*time.Millisecond).
		Should(BeTrue())
}
