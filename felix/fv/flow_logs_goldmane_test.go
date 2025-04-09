//go:build fvtests
// +build fvtests

// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/bpf/conntrack"
	"github.com/projectcalico/calico/felix/collector/flowlog"
	"github.com/projectcalico/calico/felix/collector/types/endpoint"
	"github.com/projectcalico/calico/felix/collector/types/tuple"
	"github.com/projectcalico/calico/felix/fv/connectivity"
	"github.com/projectcalico/calico/felix/fv/flowlogs"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/utils"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

// Config variations covered here:
//
// - Non-default group name.
// - Non-default stream name.
// - Include endpoint labels.
//
// With those variations in place,
//
//   - Generate denied flows, as well as allowed.
//   - Generate flows from multiple client pods, sharing a prefix, each
//     of which makes multiple connections to an IP that matches a wep, hep
//     or ns.
//
// Verifications:
//
// - group and stream names
// - endpoint labels included or not
// - aggregation as expected
// - metrics are zero or non-zero as expected
// - correct counts of flows started and completed
// - action allow or deny as expected
//
// Still needed elsewhere:
//
// - Timing variations
// - start_time and end_time fields
//
//	        Host 1                              Host 2
//
//	wl-client-1                              wl-server-1 (allowed)
//	wl-client-2                              wl-server-2 (denied)
//	wl-client-3                              hep-IP
//	wl-client-4
//	      ns-IP

// Flow logs have little to do with the backend, and these tests are relatively slow, so
// better to run with one backend only.  etcdv3 is easier because we create a fresh
// datastore for every test and so don't need to worry about cleaning resources up.
var _ = infrastructure.DatastoreDescribe("_BPF-SAFE_ goldmane flow log tests", []apiconfig.DatastoreType{apiconfig.EtcdV3}, func(getInfra infrastructure.InfraFactory) {
	bpfEnabled := os.Getenv("FELIX_FV_ENABLE_BPF") == "true"

	var (
		infra   infrastructure.DatastoreInfra
		tc      infrastructure.TopologyContainers
		opts    infrastructure.TopologyOptions
		client  client.Interface
		wlHost1 [4]*workload.Workload
		wlHost2 [2]*workload.Workload
		hostW   [2]*workload.Workload
		cc      *connectivity.Checker
	)

	BeforeEach(func() {
		infra = getInfra()
		opts.FelixLogSeverity = "Debug"
		opts = infrastructure.DefaultTopologyOptions()
		opts.IPIPEnabled = false
		opts.FlowLogSource = infrastructure.FlowLogSourceGoldmane

		opts.ExtraEnvVars["FELIX_FLOWLOGSCOLLECTORDEBUGTRACE"] = "true"
		opts.ExtraEnvVars["FELIX_FLOWLOGSFLUSHINTERVAL"] = "2"
		opts.ExtraEnvVars["FELIX_FLOWLOGSGOLDMANESERVER"] = flowlogs.LocalGoldmaneServer
	})

	JustBeforeEach(func() {
		numNodes := 2
		tc, client = infrastructure.StartNNodeTopology(numNodes, opts, infra)

		// Install a default profile that allows all ingress and egress, in the absence of any Policy.
		infra.AddDefaultAllow()

		// Create workloads on host 1.
		for ii := range wlHost1 {
			wIP := fmt.Sprintf("10.65.0.%d", ii)
			wName := fmt.Sprintf("wl-host1-%d", ii)
			wlHost1[ii] = workload.Run(tc.Felixes[0], wName, "default", wIP, "8055", "tcp")
			wlHost1[ii].WorkloadEndpoint.GenerateName = "wl-host1-"
			wlHost1[ii].ConfigureInInfra(infra)
		}

		// Create workloads on host 2.
		for ii := range wlHost2 {
			wIP := fmt.Sprintf("10.65.1.%d", ii)
			wName := fmt.Sprintf("wl-host2-%d", ii)
			wlHost2[ii] = workload.Run(tc.Felixes[1], wName, "default", wIP, "8055", "tcp")
			wlHost2[ii].WorkloadEndpoint.GenerateName = "wl-host2-"
			wlHost2[ii].ConfigureInInfra(infra)
		}

		// Create a non-workload server on each host.
		for ii := range hostW {
			hostW[ii] = workload.Run(tc.Felixes[ii], fmt.Sprintf("host%d", ii), "", tc.Felixes[ii].IP, "8055", "tcp")
		}

		// Create a GlobalNetworkSet that includes host 1's IP.
		ns := api.NewGlobalNetworkSet()
		ns.Name = "ns-1"
		ns.Spec.Nets = []string{tc.Felixes[0].IP + "/32"}
		ns.Labels = map[string]string{
			"ips-for": "host1",
		}
		_, err := client.GlobalNetworkSets().Create(utils.Ctx, ns, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

		// Create a HostEndpoint for host 2, with apply-on-forward ingress policy
		// that denies to the second workload on host 2, but allows everything
		// else.
		gnp := api.NewGlobalNetworkPolicy()
		gnp.Name = "gnp-1"
		gnp.Spec.Selector = "host-endpoint=='true'"
		// ApplyOnForward policy doesn't generate deny flow logs, so we'll
		// use a regular NetworkPolicy below instead, and just allow
		// through the HostEndpoint.
		gnp.Spec.Ingress = []api.Rule{
			{
				Action: api.Allow,
			},
		}
		gnp.Spec.Egress = []api.Rule{
			{
				Action: api.Allow,
			},
		}
		gnp.Spec.ApplyOnForward = true
		_, err = client.GlobalNetworkPolicies().Create(utils.Ctx, gnp, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

		np := api.NewNetworkPolicy()
		np.Name = "default.np-1"
		np.Namespace = "default"
		np.Spec.Selector = "name=='" + wlHost2[1].Name + "'"
		np.Spec.Ingress = []api.Rule{
			{
				Action: api.Deny,
			},
		}
		_, err = client.NetworkPolicies().Create(utils.Ctx, np, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

		hep := api.NewHostEndpoint()
		hep.Name = "host2-eth0"
		hep.Labels = map[string]string{
			"name":          hep.Name,
			"host-endpoint": "true",
		}
		hep.Spec.Node = tc.Felixes[1].Hostname
		hep.Spec.ExpectedIPs = []string{tc.Felixes[1].IP}
		_, err = client.HostEndpoints().Create(utils.Ctx, hep, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		if BPFMode() {
			ensureAllNodesBPFProgramsAttached(tc.Felixes)
		}

		count := func() int {
			return countNodesWithNodeIP(client)
		}
		Eventually(count, "1m").Should(BeEquivalentTo(numNodes), "Not all nodes got a NodeIP")

		hostEndpointProgrammed := func() bool {
			if BPFMode() {
				return tc.Felixes[1].NumTCBPFProgsEth0() == 2
			} else if NFTMode() {
				out, err := tc.Felixes[1].ExecOutput("nft", "list", "ruleset")
				Expect(err).NotTo(HaveOccurred())
				return (strings.Count(out, "cali-thfw-eth0") > 0)
			} else {
				out, err := tc.Felixes[1].ExecOutput("iptables-save", "-t", "filter")
				Expect(err).NotTo(HaveOccurred())
				return (strings.Count(out, "cali-thfw-eth0") > 0)
			}
		}
		Eventually(hostEndpointProgrammed, "30s", "1s").Should(BeTrue(),
			"Expected HostEndpoint iptables rules to appear")
		if !BPFMode() {
			rulesProgrammed := func() bool {
				out0, err := tc.Felixes[0].ExecOutput("iptables-save", "-t", "filter")
				Expect(err).NotTo(HaveOccurred())
				out1, err := tc.Felixes[1].ExecOutput("iptables-save", "-t", "filter")
				Expect(err).NotTo(HaveOccurred())
				if strings.Count(out0, "ARE0|default") == 0 {
					return false
				}
				if strings.Count(out1, "default.gnp-1") == 0 {
					return false
				}
				return true
			}
			if NFTMode() {
				rulesProgrammed = func() bool {
					out0, err := tc.Felixes[0].ExecOutput("nft", "list", "ruleset")
					Expect(err).NotTo(HaveOccurred())
					out1, err := tc.Felixes[1].ExecOutput("nft", "list", "ruleset")
					Expect(err).NotTo(HaveOccurred())
					if strings.Count(out0, "ARE0|default") == 0 {
						return false
					}
					if strings.Count(out1, "default.gnp-1") == 0 {
						return false
					}
					return true
				}
			}
			Eventually(rulesProgrammed, "10s", "1s").Should(BeTrue(),
				"Expected iptables rules to appear on the correct felix instances")
		} else {
			Eventually(func() bool {
				return bpfCheckIfPolicyProgrammed(tc.Felixes[1], "eth0", "egress", "default.gnp-1", "allow", false)
			}, "5s", "200ms").Should(BeTrue())

			Eventually(func() bool {
				return bpfCheckIfPolicyProgrammed(tc.Felixes[1], "eth0", "ingress", "default.gnp-1", "allow", false)
			}, "5s", "200ms").Should(BeTrue())

			Eventually(func() bool {
				return bpfCheckIfPolicyProgrammed(tc.Felixes[1], wlHost2[1].InterfaceName, "ingress", "default/default.np-1", "deny", true)
			}, "5s", "200ms").Should(BeTrue())

			Eventually(func() bool {
				return bpfCheckIfRuleProgrammed(tc.Felixes[0], wlHost1[0].InterfaceName, "ingress", "default", "allow", true)
			}, "15s", "200ms").Should(BeTrue())

			Eventually(func() bool {
				return bpfCheckIfRuleProgrammed(tc.Felixes[0], wlHost1[0].InterfaceName, "egress", "default", "allow", true)
			}, "15s", "200ms").Should(BeTrue())
		}

		// Describe the connectivity that we now expect.
		cc = &connectivity.Checker{}
		for _, source := range wlHost1 {
			// Workloads on host 1 can connect to the first workload on host 2.
			cc.ExpectSome(source, wlHost2[0])
			// But not the second.
			cc.ExpectNone(source, wlHost2[1])
		}
		// A workload on host 1 can connect to a non-workload server on host 2.
		cc.ExpectSome(wlHost1[0], hostW[1])
		// A workload on host 2 can connect to a non-workload server on host 1.
		cc.ExpectSome(wlHost2[0], hostW[0])

		// Do 3 rounds of connectivity checking.
		cc.CheckConnectivity()
		for ii := range tc.Felixes {
			tc.Felixes[ii].Exec("conntrack", "-L")
		}
		cc.CheckConnectivity()
		for ii := range tc.Felixes {
			tc.Felixes[ii].Exec("conntrack", "-L")
		}
		cc.CheckConnectivity()
		for ii := range tc.Felixes {
			tc.Felixes[ii].Exec("conntrack", "-L")
		}

		if bpfEnabled {
			// Make sure that conntrack scanning ticks at least once
			time.Sleep(3 * conntrack.ScanPeriod)
		} else {
			// Allow 6 seconds for the containers.Felix to poll conntrack.  (This is conntrack polling time plus 20%, which gives us
			// 10% leeway over the polling jitter of 10%)
			time.Sleep(6 * time.Second)
		}

		// Delete conntrack state so that we don't keep seeing 0-metric copies of the logs.  This will allow the flows
		// to expire quickly.
		for ii := range tc.Felixes {
			tc.Felixes[ii].Exec("conntrack", "-F")
		}
		for ii := range tc.Felixes {
			tc.Felixes[ii].Exec("conntrack", "-L")
		}
	})

	checkFlowLogs := func() {
		// Here, by way of illustrating what we need to check for, are the allowed
		// flow logs that we actually see for this test, as grouped and logged by
		// the code below that includes "started:" and "completed:".
		//
		// Host 1:
		// started: 48 {{[--] [--] 6 0 8055} {wep default wl-host1-* -} {wep default wl-host2-* -} allow src}
		// started: 6 {{[--] [--] 6 0 8055} {wep default wl-host1-* -} {hep - host2-eth0 -} allow src}
		// completed: 3 {{[--] [--] 6 0 8055} {wep default wl-host1-* -} {hep - host2-eth0 -} allow src}
		// completed: 24 {{[--] [--] 6 0 8055} {wep default wl-host1-* -} {wep default wl-host2-* -} allow src}
		// Host 2:
		// started: 3 {{[--] [--] 6 0 8055} {wep default wl-host1-* -} {hep - host2-eth0 -} allow dst}
		// started: 12 {{[--] [--] 6 0 8055} {wep default wl-host1-* -} {wep default wl-host2-* -} allow dst}
		// started: 3 {{[--] [--] 6 0 8055} {wep default wl-host2-* -} {net - pvt -} allow src}
		// completed: 3 {{[--] [--] 6 0 8055} {wep default wl-host1-* -} {hep - host2-eth0 -} allow dst}
		// completed: 12 {{[--] [--] 6 0 8055} {wep default wl-host1-* -} {wep default wl-host2-* -} allow dst}
		// completed: 3 {{[--] [--] 6 0 8055} {wep default wl-host2-* -} {net - pvt -} allow src}

		// Within 30s we should see the complete set of expected allow and deny
		// flow logs.
		Eventually(func() error {
			wepPort := 8055
			flowTester := flowlogs.NewFlowTester(flowlogs.FlowTesterOptions{
				ExpectLabels:           true,
				ExpectEnforcedPolicies: true,
				MatchEnforcedPolicies:  true,
				MatchLabels:            false,
				Includes:               []flowlogs.IncludeFilter{flowlogs.IncludeByDestPort(wepPort)},
				CheckNumFlowsStarted:   true,
				CheckFlowsCompleted:    true,
			})

			err := flowTester.PopulateFromFlowLogs(tc.Felixes[0])
			if err != nil {
				return fmt.Errorf("error populating flow logs from Felix[0]: %s", err)
			}

			aggrTuple := tuple.Make(flowlog.EmptyIP, flowlog.EmptyIP, 6, flowlogs.SourcePortIsNotIncluded, wepPort)

			host1_wl_Meta := endpoint.Metadata{
				Type:           "wep",
				Namespace:      "default",
				Name:           flowlog.FieldNotIncluded,
				AggregatedName: "wl-host1-*",
			}
			host2_wl_Meta := endpoint.Metadata{
				Type:           "wep",
				Namespace:      "default",
				Name:           flowlog.FieldNotIncluded,
				AggregatedName: "wl-host2-*",
			}

			// Now we tick off each FlowMeta that we expect, and check that
			// the log(s) for each one are present and as expected.
			flowTester.CheckFlow(
				flowlog.FlowLog{
					FlowMeta: flowlog.FlowMeta{
						Tuple:      aggrTuple,
						SrcMeta:    host1_wl_Meta,
						DstMeta:    host2_wl_Meta,
						DstService: flowlog.EmptyService,
						Action:     "allow",
						Reporter:   "src",
					},
					FlowEnforcedPolicySet: flowlog.FlowPolicySet{
						"0|__PROFILE__|__PROFILE__.default|allow|0": {},
					},
					FlowProcessReportedStats: flowlog.FlowProcessReportedStats{
						FlowReportedStats: flowlog.FlowReportedStats{
							NumFlowsStarted: 24,
						},
					},
				})

			hep1_Meta := endpoint.Metadata{
				Type:           "hep",
				Namespace:      flowlog.FieldNotIncluded,
				Name:           flowlog.FieldNotIncluded,
				AggregatedName: tc.Felixes[1].Hostname,
			}

			// This entry is different in Enterprise implemenatation due to differences of HEP flowlogs.
			flowTester.CheckFlow(
				flowlog.FlowLog{
					FlowMeta: flowlog.FlowMeta{
						Tuple:      aggrTuple,
						SrcMeta:    host1_wl_Meta,
						DstMeta:    hep1_Meta,
						DstService: flowlog.EmptyService,
						Action:     "allow",
						Reporter:   "src",
					},
					FlowEnforcedPolicySet: flowlog.FlowPolicySet{
						"0|__PROFILE__|__PROFILE__.default|allow|0": {},
					},
					FlowProcessReportedStats: flowlog.FlowProcessReportedStats{
						FlowReportedStats: flowlog.FlowReportedStats{
							NumFlowsStarted: 3,
						},
					},
				})

			if err := flowTester.Finish(); err != nil {
				return fmt.Errorf("Flows incorrect on Felix[0]:\n%v", err)
			}

			err = flowTester.PopulateFromFlowLogs(tc.Felixes[1])
			if err != nil {
				return fmt.Errorf("error populating flow logs from Felix[1]: %s", err)
			}

			flowTester.CheckFlow(
				flowlog.FlowLog{
					FlowMeta: flowlog.FlowMeta{
						Tuple:      aggrTuple,
						SrcMeta:    host1_wl_Meta,
						DstMeta:    host2_wl_Meta,
						DstService: flowlog.EmptyService,
						Action:     "allow",
						Reporter:   "dst",
					},
					FlowEnforcedPolicySet: flowlog.FlowPolicySet{
						"0|__PROFILE__|__PROFILE__.default|allow|0": {},
					},
					FlowProcessReportedStats: flowlog.FlowProcessReportedStats{
						FlowReportedStats: flowlog.FlowReportedStats{
							NumFlowsStarted: 12,
						},
					},
				})

			flowTester.CheckFlow(
				flowlog.FlowLog{
					FlowMeta: flowlog.FlowMeta{
						Tuple:      aggrTuple,
						SrcMeta:    host1_wl_Meta,
						DstMeta:    host2_wl_Meta,
						DstService: flowlog.EmptyService,
						Action:     "deny",
						Reporter:   "dst",
					},
					FlowEnforcedPolicySet: flowlog.FlowPolicySet{
						"0|default|default/default.np-1|deny|0": {},
					},
					FlowProcessReportedStats: flowlog.FlowProcessReportedStats{
						FlowReportedStats: flowlog.FlowReportedStats{
							NumFlowsStarted: 12,
						},
					},
				})

			ns_meta := endpoint.Metadata{
				Type:           "ns",
				Namespace:      flowlog.FieldNotIncluded,
				Name:           flowlog.FieldNotIncluded,
				AggregatedName: "ns-1",
			}

			// The following entries are not available in Enterprise implemenatation due to differences of HEP flowlogs.
			flowTester.CheckFlow(
				flowlog.FlowLog{
					FlowMeta: flowlog.FlowMeta{
						Tuple:      aggrTuple,
						SrcMeta:    host2_wl_Meta,
						DstMeta:    ns_meta,
						DstService: flowlog.EmptyService,
						Action:     "allow",
						Reporter:   "src",
					},
					FlowEnforcedPolicySet: flowlog.FlowPolicySet{
						"0|__PROFILE__|__PROFILE__.default|allow|0": {},
					},
					FlowProcessReportedStats: flowlog.FlowProcessReportedStats{
						FlowReportedStats: flowlog.FlowReportedStats{
							NumFlowsStarted: 3,
						},
					},
				})

			if err := flowTester.Finish(); err != nil {
				return fmt.Errorf("Flows incorrect on Felix[1]:\n%v", err)
			}

			return nil
		}, "30s", "3s").ShouldNot(HaveOccurred())
	}

	It("should get expected flow logs", func() {
		checkFlowLogs()
	})

	AfterEach(func() {
		if CurrentGinkgoTestDescription().Failed {
			for _, felix := range tc.Felixes {
				logNFTDiags(felix)
				felix.Exec("iptables-save", "-c")
				felix.Exec("ipset", "list")
				felix.Exec("ip", "r")
				felix.Exec("ip", "a")
			}
			if bpfEnabled {
				for _, felix := range tc.Felixes {
					felix.Exec("calico-bpf", "ipsets", "dump")
					felix.Exec("calico-bpf", "routes", "dump")
					felix.Exec("calico-bpf", "nat", "dump")
					felix.Exec("calico-bpf", "nat", "aff")
					felix.Exec("calico-bpf", "conntrack", "dump")
					felix.Exec("calico-bpf", "arp", "dump")
					felix.Exec("calico-bpf", "counters", "dump")
					felix.Exec("calico-bpf", "ifstate", "dump")
					felix.Exec("calico-bpf", "policy", "dump", "eth0", "all")
				}
				for _, w := range wlHost1 {
					tc.Felixes[0].Exec("calico-bpf", "policy", "dump", w.InterfaceName, "all")
				}
				for _, w := range wlHost1 {
					tc.Felixes[1].Exec("calico-bpf", "policy", "dump", w.InterfaceName, "all")
				}
			}
		}

		for _, wl := range wlHost1 {
			wl.Stop()
		}
		for _, wl := range wlHost2 {
			wl.Stop()
		}
		for _, wl := range hostW {
			wl.Stop()
		}
		for _, felix := range tc.Felixes {
			if bpfEnabled {
				felix.Exec("calico-bpf", "connect-time", "clean")
			}
			felix.Stop()
		}

		if CurrentGinkgoTestDescription().Failed {
			infra.DumpErrorData()
		}
		infra.Stop()
	})
})

var _ = infrastructure.DatastoreDescribe("goldmane flow log ipv6 tests", []apiconfig.DatastoreType{apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
	var (
		infra  infrastructure.DatastoreInfra
		tc     infrastructure.TopologyContainers
		client client.Interface

		w [2][2]*workload.Workload
	)

	BeforeEach(func() {
		var err error

		iOpts := []infrastructure.CreateOption{
			infrastructure.K8sWithDualStack(),
			infrastructure.K8sWithAPIServerBindAddress("::"),
			infrastructure.K8sWithServiceClusterIPRange("dead:beef::abcd:0:0:0/112,10.101.0.0/16"),
		}

		infra = getInfra(iOpts...)
		opts := infrastructure.DefaultTopologyOptions()
		opts.FlowLogSource = infrastructure.FlowLogSourceGoldmane

		opts.EnableIPv6 = true
		opts.IPIPEnabled = false
		opts.NATOutgoingEnabled = true
		opts.AutoHEPsEnabled = false
		opts.IPIPRoutesEnabled = false
		opts.ExtraEnvVars["FELIX_FLOWLOGSFLUSHINTERVAL"] = "2"
		opts.ExtraEnvVars["FELIX_IPV6SUPPORT"] = "true"
		opts.ExtraEnvVars["FELIX_DefaultEndpointToHostAction"] = "RETURN"
		opts.ExtraEnvVars["FELIX_FLOWLOGSGOLDMANESERVER"] = flowlogs.LocalGoldmaneServer

		tc, client = infrastructure.StartNNodeTopology(2, opts, infra)

		addWorkload := func(run bool, ii, wi, port int, labels map[string]string) *workload.Workload {
			if labels == nil {
				labels = make(map[string]string)
			}

			wIP := fmt.Sprintf("10.65.%d.%d", ii, wi+2)
			wName := fmt.Sprintf("w%d%d", ii, wi)

			w := workload.New(tc.Felixes[ii], wName, "default",
				wIP, strconv.Itoa(port), "tcp", workload.WithIPv6Address(net.ParseIP(fmt.Sprintf("dead:beef::%d:%d", ii, wi+2)).String()))

			labels["name"] = w.Name
			labels["workload"] = "regular"

			w.WorkloadEndpoint.Labels = labels
			if run {
				err := w.Start()
				Expect(err).NotTo(HaveOccurred())
				w.ConfigureInInfra(infra)
			}
			return w
		}

		for ii := range tc.Felixes {
			// Two workloads on each host so we can check the same host and other host cases.
			w[ii][0] = addWorkload(true, ii, 0, 8055, map[string]string{"port": "8055"})
			w[ii][1] = addWorkload(true, ii, 1, 8056, nil)
		}

		err = infra.AddDefaultDeny()
		Expect(err).NotTo(HaveOccurred())

		if BPFMode() {
			ensureAllNodesBPFProgramsAttached(tc.Felixes)
		}

		var gnp1Order float64 = 100
		var gnp2Order float64 = 1

		gnp := api.NewGlobalNetworkPolicy()
		gnp.Name = "gnp-1"
		gnp.Spec.Selector = "all()"

		gnp.Spec.Ingress = []api.Rule{
			{
				Action: api.Allow,
			},
		}
		gnp.Spec.Egress = []api.Rule{
			{
				Action: api.Allow,
			},
		}
		gnp.Spec.Order = &gnp1Order
		_, err = client.GlobalNetworkPolicies().Create(utils.Ctx, gnp, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

		np := api.NewGlobalNetworkPolicy()
		np.Name = "gnp-2"
		np.Spec.Selector = "name=='" + w[0][1].Name + "'"
		np.Spec.Ingress = []api.Rule{
			{
				Action: api.Deny,
			},
		}
		np.Spec.Egress = []api.Rule{
			{
				Action: api.Deny,
			},
		}
		np.Spec.Order = &gnp2Order
		_, err = client.GlobalNetworkPolicies().Create(utils.Ctx, np, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

		if !BPFMode() {
			rulesProgrammed := func() bool {
				var out string
				var err error
				if NFTMode() {
					out, err = tc.Felixes[0].ExecOutput("nft", "list", "ruleset")
				} else {
					out, err = tc.Felixes[0].ExecOutput("iptables-save", "-t", "filter")
				}
				Expect(err).NotTo(HaveOccurred())
				if strings.Count(out, "default.gnp-1") == 0 {
					return false
				}
				if strings.Count(out, "default.gnp-2") == 0 {
					return false
				}
				return true
			}
			Eventually(rulesProgrammed, "10s", "1s").Should(BeTrue(),
				"Expected iptables rules to appear on the correct felix instances")
		} else {
			Eventually(func() bool {
				return bpfCheckIfPolicyProgrammed(tc.Felixes[0], w[0][0].InterfaceName, "egress", "default.gnp-1", "allow", true)
			}, "15s", "200ms").Should(BeTrue())

			Eventually(func() bool {
				return bpfCheckIfPolicyProgrammed(tc.Felixes[0], w[0][0].InterfaceName, "ingress", "default.gnp-1", "allow", true)
			}, "5s", "200ms").Should(BeTrue())

			Eventually(func() bool {
				return bpfCheckIfPolicyProgrammed(tc.Felixes[0], w[0][1].InterfaceName, "egress", "default.gnp-2", "deny", true)
			}, "5s", "200ms").Should(BeTrue())

			Eventually(func() bool {
				return bpfCheckIfPolicyProgrammed(tc.Felixes[0], w[0][1].InterfaceName, "ingress", "default.gnp-2", "deny", true)
			}, "5s", "200ms").Should(BeTrue())
		}

		// Describe the connectivity that we now expect.
		cc := &connectivity.Checker{}
		cc.Protocol = "tcp"
		cc.Expect(connectivity.Some, w[0][0], w[1][0], connectivity.ExpectWithIPVersion(6))
		cc.Expect(connectivity.None, w[0][1], w[1][0], connectivity.ExpectWithIPVersion(6))
		cc.CheckConnectivity()
	})

	AfterEach(func() {
		if CurrentGinkgoTestDescription().Failed {
			for _, felix := range tc.Felixes {
				logNFTDiags(felix)
				felix.Exec("ip6tables-save", "-c")
				felix.Exec("ipset", "list")
				felix.Exec("ip", "-6", "r")
				felix.Exec("ip", "a")
				felix.Exec("iptables-save", "-c")
				felix.Exec("ip", "r")
			}
		}
		tc.Stop()
		infra.Stop()
	})

	It("Should report the ipv6 flow logs", func() {
		var flows []flowlog.FlowLog
		var err error
		Eventually(func() int {
			flows, err = tc.Felixes[0].FlowLogs()
			if err != nil {
				return 0
			}
			return len(flows)
		}, "20s", "1s").Should(Equal(2))

		Expect(flows).ShouldNot(BeEmpty())

		numExpectedFlows := 0
		for _, flow := range flows {
			switch flow.Action {
			case flowlog.ActionAllow:
				if flow.Tuple.Proto == 6 &&
					flow.SrcMeta.AggregatedName == w[0][0].Name &&
					flow.DstMeta.AggregatedName == w[1][0].Name {
					if flow.PacketsIn > 0 || flow.PacketsOut > 0 || flow.BytesIn > 0 || flow.BytesOut > 0 {
						numExpectedFlows = numExpectedFlows + 1
					}
				}
			case flowlog.ActionDeny:
				if flow.Tuple.Proto == 6 &&
					flow.SrcMeta.AggregatedName == w[0][1].Name &&
					flow.DstMeta.AggregatedName == w[1][0].Name {
					if flow.PacketsIn > 0 || flow.PacketsOut > 0 || flow.BytesIn > 0 || flow.BytesOut > 0 {
						numExpectedFlows = numExpectedFlows + 1
					}
				}
			}
		}
		Expect(numExpectedFlows).Should(Equal(2))
	})
})

func countNodesWithNodeIP(c client.Interface) int {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	nodeList, err := c.Nodes().List(ctx, options.ListOptions{})
	Expect(err).NotTo(HaveOccurred())

	count := 0
	for _, n := range nodeList.Items {
		if n.Spec.BGP.IPv4Address != "" {
			count++
		}
	}

	return count
}
