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
	"os"
	"strconv"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/felix/collector/flowlog"
	"github.com/projectcalico/calico/felix/collector/local"
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
		opts.IPIPMode = api.IPIPModeNever
		opts.FlowLogSource = infrastructure.FlowLogSourceLocalSocket

		opts.ExtraEnvVars["FELIX_FLOWLOGSCOLLECTORDEBUGTRACE"] = "true"
		opts.ExtraEnvVars["FELIX_FLOWLOGSFLUSHINTERVAL"] = "2"
		opts.ExtraEnvVars["FELIX_FLOWLOGSGOLDMANESERVER"] = local.SocketAddress
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
			infrastructure.AssignIP(wName, wIP, tc.Felixes[0].Hostname, client)
			wlHost1[ii] = workload.Run(tc.Felixes[0], wName, "default", wIP, "8055", "tcp")
			wlHost1[ii].WorkloadEndpoint.GenerateName = "wl-host1-"
			wlHost1[ii].ConfigureInInfra(infra)
		}

		// Create workloads on host 2.
		for ii := range wlHost2 {
			wIP := fmt.Sprintf("10.65.1.%d", ii)
			wName := fmt.Sprintf("wl-host2-%d", ii)
			infrastructure.AssignIP(wName, wIP, tc.Felixes[1].Hostname, client)
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
			rulesProgrammed := func() error {
				out0, err := tc.Felixes[0].ExecOutput("iptables-save", "-t", "filter")
				if err != nil {
					return err
				}
				out1, err := tc.Felixes[1].ExecOutput("iptables-save", "-t", "filter")
				if err != nil {
					return err
				}
				if strings.Count(out0, "ARE0|default") == 0 {
					return fmt.Errorf("ARE0|default rule not found on felix 0")
				}
				if strings.Count(out1, "gnp-1") == 0 {
					return fmt.Errorf("gnp-1 rule not found on felix 1")
				}
				return nil
			}
			if NFTMode() {
				rulesProgrammed = func() error {
					out0, err := tc.Felixes[0].ExecOutput("nft", "list", "ruleset")
					Expect(err).NotTo(HaveOccurred())
					out1, err := tc.Felixes[1].ExecOutput("nft", "list", "ruleset")
					Expect(err).NotTo(HaveOccurred())
					if strings.Count(out0, "ARE0|default") == 0 {
						return fmt.Errorf("ARE0|default rule not found on felix 0")
					}
					if strings.Count(out1, "gnp-1") == 0 {
						return fmt.Errorf("gnp-1 rule not found on felix 1")
					}
					return nil
				}
			}
			Eventually(rulesProgrammed, "10s", "1s").ShouldNot(HaveOccurred(),
				"Expected iptables rules to appear on the correct felix instances")
		} else {
			Eventually(func() bool {
				return bpfCheckIfGlobalNetworkPolicyProgrammed(tc.Felixes[1], "eth0", "egress", "gnp-1", "allow", false)
			}, "5s", "200ms").Should(BeTrue())

			Eventually(func() bool {
				return bpfCheckIfGlobalNetworkPolicyProgrammed(tc.Felixes[1], "eth0", "ingress", "gnp-1", "allow", false)
			}, "5s", "200ms").Should(BeTrue())

			Eventually(func() bool {
				return bpfCheckIfNetworkPolicyProgrammed(tc.Felixes[1], wlHost2[1].InterfaceName, "ingress", "default", "default.np-1", "deny", true)
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

		flowlogs.WaitForConntrackScan(bpfEnabled)

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
						"0|__PROFILE__|pro:default|allow|0": {},
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
						"0|__PROFILE__|pro:default|allow|0": {},
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
						"0|__PROFILE__|pro:default|allow|0": {},
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
						"0|default|np:default/default.np-1|deny|0": {},
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
						"0|__PROFILE__|pro:default|allow|0": {},
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
		opts.FlowLogSource = infrastructure.FlowLogSourceLocalSocket

		opts.EnableIPv6 = true
		opts.IPIPMode = api.IPIPModeAlways
		opts.NATOutgoingEnabled = true
		opts.AutoHEPsEnabled = false
		opts.ExtraEnvVars["FELIX_FLOWLOGSFLUSHINTERVAL"] = "2"
		opts.ExtraEnvVars["FELIX_IPV6SUPPORT"] = "true"
		opts.ExtraEnvVars["FELIX_DefaultEndpointToHostAction"] = "RETURN"
		opts.ExtraEnvVars["FELIX_FLOWLOGSGOLDMANESERVER"] = local.SocketAddress

		tc, client = infrastructure.StartNNodeTopology(2, opts, infra)

		addWorkload := func(hostname string, ii, wi, port int, labels map[string]string) *workload.Workload {
			if labels == nil {
				labels = make(map[string]string)
			}

			wIP := fmt.Sprintf("10.65.%d.%d", ii, wi+2)
			wIPv6 := fmt.Sprintf("dead:beef::%d:%d", ii, wi+2)
			wName := fmt.Sprintf("w%d%d", ii, wi)

			infrastructure.AssignIP(wName, wIP, hostname, client)
			infrastructure.AssignIP(wName, wIPv6, hostname, client)
			w := workload.New(tc.Felixes[ii], wName, "default",
				wIP, strconv.Itoa(port), "tcp", workload.WithIPv6Address(wIPv6))

			labels["name"] = w.Name
			labels["workload"] = "regular"
			w.WorkloadEndpoint.Labels = labels
			err := w.Start(infra)
			Expect(err).NotTo(HaveOccurred())
			w.ConfigureInInfra(infra)
			return w
		}

		for ii := range tc.Felixes {
			// Two workloads on each host so we can check the same host and other host cases.
			w[ii][0] = addWorkload(tc.Felixes[ii].Hostname, ii, 0, 8055, map[string]string{"port": "8055"})
			w[ii][1] = addWorkload(tc.Felixes[ii].Hostname, ii, 1, 8056, nil)
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
				if strings.Count(out, "gnp-1") == 0 {
					return false
				}
				if strings.Count(out, "gnp-2") == 0 {
					return false
				}
				return true
			}
			Eventually(rulesProgrammed, "10s", "1s").Should(BeTrue(),
				"Expected iptables rules to appear on the correct felix instances")
		} else {
			Eventually(func() bool {
				return bpfCheckIfGlobalNetworkPolicyProgrammed(tc.Felixes[0], w[0][0].InterfaceName, "egress", "gnp-1", "allow", true)
			}, "15s", "200ms").Should(BeTrue())

			Eventually(func() bool {
				return bpfCheckIfGlobalNetworkPolicyProgrammed(tc.Felixes[0], w[0][0].InterfaceName, "ingress", "gnp-1", "allow", true)
			}, "5s", "200ms").Should(BeTrue())

			Eventually(func() bool {
				return bpfCheckIfGlobalNetworkPolicyProgrammed(tc.Felixes[0], w[0][1].InterfaceName, "egress", "gnp-2", "deny", true)
			}, "5s", "200ms").Should(BeTrue())

			Eventually(func() bool {
				return bpfCheckIfGlobalNetworkPolicyProgrammed(tc.Felixes[0], w[0][1].InterfaceName, "ingress", "gnp-2", "deny", true)
			}, "5s", "200ms").Should(BeTrue())
		}

		// Describe the connectivity that we now expect.
		cc := &connectivity.Checker{}
		cc.Protocol = "tcp"
		cc.Expect(connectivity.Some, w[0][0], w[1][0], connectivity.ExpectWithIPVersion(6))
		cc.Expect(connectivity.None, w[0][1], w[1][0], connectivity.ExpectWithIPVersion(6))
		cc.CheckConnectivity()
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

var _ = infrastructure.DatastoreDescribe("_BPF-SAFE_ goldmane local server tests", []apiconfig.DatastoreType{apiconfig.EtcdV3}, func(getInfra infrastructure.InfraFactory) {
	bpfEnabled := os.Getenv("FELIX_FV_ENABLE_BPF") == "true"

	var (
		infra   infrastructure.DatastoreInfra
		tc      infrastructure.TopologyContainers
		opts    infrastructure.TopologyOptions
		wlHost1 [2]*workload.Workload
		wlHost2 [2]*workload.Workload
		cc      *connectivity.Checker
		client  client.Interface
	)

	BeforeEach(func() {
		infra = getInfra()
		opts.FelixLogSeverity = "Debug"
		opts = infrastructure.DefaultTopologyOptions()
		opts.IPIPMode = api.IPIPModeNever
		opts.FlowLogSource = infrastructure.FlowLogSourceLocalSocket
		opts.DelayFelixStart = true

		opts.ExtraEnvVars["FELIX_FLOWLOGSCOLLECTORDEBUGTRACE"] = "true"
		opts.ExtraEnvVars["FELIX_FLOWLOGSFLUSHINTERVAL"] = "2"
		opts.ExtraEnvVars["FELIX_FLOWLOGSLOCALREPORTER"] = "Enabled"

		numNodes := 2
		tc, client = infrastructure.StartNNodeTopology(numNodes, opts, infra)

		// Install a default profile that allows all ingress and egress, in the absence of any Policy.
		infra.AddDefaultAllow()

		// Create workloads on host 1.
		for ii := range wlHost1 {
			wIP := fmt.Sprintf("10.65.0.%d", ii)
			wName := fmt.Sprintf("wl-host1-%d", ii)
			infrastructure.AssignIP(wName, wIP, tc.Felixes[0].Hostname, client)
			wlHost1[ii] = workload.Run(tc.Felixes[0], wName, "default", wIP, "8055", "tcp")
			wlHost1[ii].WorkloadEndpoint.GenerateName = "wl-host1-"
			wlHost1[ii].ConfigureInInfra(infra)
		}

		// Create workloads on host 2.
		for ii := range wlHost2 {
			wIP := fmt.Sprintf("10.65.1.%d", ii)
			wName := fmt.Sprintf("wl-host2-%d", ii)
			infrastructure.AssignIP(wName, wIP, tc.Felixes[1].Hostname, client)
			wlHost2[ii] = workload.Run(tc.Felixes[1], wName, "default", wIP, "8055", "tcp")
			wlHost2[ii].WorkloadEndpoint.GenerateName = "wl-host2-"
			wlHost2[ii].ConfigureInInfra(infra)
		}

		// Describe the connectivity that we now expect.
		cc = &connectivity.Checker{}
		for _, source := range wlHost1 {
			// Workloads on host 1 can connect to the first workload on host 2.
			cc.ExpectSome(source, wlHost2[0])
			// But not the second.
			cc.ExpectSome(source, wlHost2[1])
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

	readFlowlogs := func() bool {
		for _, felix := range tc.Felixes {
			flogs, err := felix.FlowLogs()
			return err == nil && len(flogs) > 0
		}
		return false
	}

	nodeSocketExists := func() bool {
		for _, felix := range tc.Felixes {
			_, err := os.Stat(felix.FlowServerAddress())
			return err == nil
		}
		return false
	}

	It("should connect and get some flow logs", func() {
		// No goldmane node server must exist.
		Eventually(nodeSocketExists, "15s", "3s").Should(BeFalse())
		Consistently(nodeSocketExists, "10s", "2s").Should(BeFalse())

		for _, felix := range tc.Felixes {
			felix.TriggerDelayedStart()
		}

		// After Felix start, goldmane node server must exist.
		Eventually(nodeSocketExists, "15s", "3s").Should(BeTrue())
		Consistently(nodeSocketExists, "10s", "2s").Should(BeTrue())

		// Do 1 rounds of connectivity checking.
		cc.CheckConnectivity()
		for ii := range tc.Felixes {
			tc.Felixes[ii].Exec("conntrack", "-L")
		}

		flowlogs.WaitForConntrackScan(bpfEnabled)

		Eventually(readFlowlogs, "15s", "3s").Should(BeTrue())
		Consistently(readFlowlogs, "10s", "2s").Should(BeTrue())

		for _, felix := range tc.Felixes {
			felix.FlowServerStop()
		}

		// After stoping goldmane node server, socket file must be cleaned up.
		Eventually(nodeSocketExists, "15s", "3s").Should(BeFalse())
		Consistently(nodeSocketExists, "10s", "2s").Should(BeFalse())

		// ... and reading flowlogs must return no flowlog.
		Eventually(readFlowlogs, "15s", "3s").Should(BeFalse())
		Consistently(readFlowlogs, "10s", "2s").Should(BeFalse())
	})

	AfterEach(func() {
		// FIXME

		for _, felix := range tc.Felixes {
			if bpfEnabled {
				felix.Exec("calico-bpf", "connect-time", "clean")
			}
		}
	})
})

var _ = infrastructure.DatastoreDescribe("flow log with deleted service pod test", []apiconfig.DatastoreType{apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
	const (
		wepPort = 8055
		svcPort = 8066
	)
	wepPortStr := fmt.Sprintf("%d", wepPort)
	svcPortStr := fmt.Sprintf("%d", svcPort)
	clusterIP := "10.101.0.10"

	var (
		infra        infrastructure.DatastoreInfra
		opts         infrastructure.TopologyOptions
		tc           infrastructure.TopologyContainers
		client       client.Interface
		ep1_1, ep2_1 *workload.Workload
		cc           *connectivity.Checker
	)

	bpfEnabled := os.Getenv("FELIX_FV_ENABLE_BPF") == "true"

	BeforeEach(func() {
		infra = getInfra()
		opts = infrastructure.DefaultTopologyOptions()
		opts.FlowLogSource = infrastructure.FlowLogSourceLocalSocket
		opts.IPIPMode = api.IPIPModeNever
		opts.NATOutgoingEnabled = true
		opts.ExtraEnvVars["FELIX_FLOWLOGSFLUSHINTERVAL"] = "25"
		opts.ExtraEnvVars["FELIX_FLOWLOGSENABLEHOSTENDPOINT"] = "true"
		opts.ExtraEnvVars["FELIX_FLOWLOGSFILEINCLUDELABELS"] = "true"
		opts.ExtraEnvVars["FELIX_FLOWLOGSFILEINCLUDEPOLICIES"] = "true"
		opts.ExtraEnvVars["FELIX_FLOWLOGSCOLLECTORDEBUGTRACE"] = "true"
		opts.ExtraEnvVars["FELIX_FLOWLOGSFILEENABLED"] = "true"
		opts.ExtraEnvVars["FELIX_FLOWLOGSFILEINCLUDESERVICE"] = "true"
		opts.ExtraEnvVars["FELIX_FLOWLOGSGOLDMANESERVER"] = local.SocketAddress

		// Start felix instances.
		tc, client = infrastructure.StartNNodeTopology(2, opts, infra)

		if bpfEnabled {
			ensureBPFProgramsAttached(tc.Felixes[0])
			ensureBPFProgramsAttached(tc.Felixes[1])
		}

		// Install a default profile that allows all ingress and egress, in the absence of any Policy.
		infra.AddDefaultAllow()

		// Create workload on host 1.
		infrastructure.AssignIP("ep1-1", "10.65.0.0", tc.Felixes[0].Hostname, client)
		ep1_1 = workload.Run(tc.Felixes[0], "ep1-1", "default", "10.65.0.0", wepPortStr, "tcp")
		ep1_1.ConfigureInInfra(infra)

		infrastructure.AssignIP("ep2-1", "10.65.1.0", tc.Felixes[1].Hostname, client)
		ep2_1 = workload.Run(tc.Felixes[1], "ep2-1", "default", "10.65.1.0", wepPortStr, "tcp")
		ep2_1.ConfigureInInfra(infra)

		ensureRoutesProgrammed(tc.Felixes)

		// Create a service that maps to ep2_1. Rather than checking connectivity to the endpoint we'll go via
		// the service to test the destination service name handling.
		svcName := "test-service"
		k8sClient := infra.(*infrastructure.K8sDatastoreInfra).K8sClient
		tSvc := k8sService(svcName, clusterIP, ep2_1, svcPort, wepPort, 0, "tcp")
		tSvcNamespace := tSvc.Namespace
		_, err := k8sClient.CoreV1().Services(tSvcNamespace).Create(context.Background(), tSvc, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		// Wait for the endpoints to be updated and for the address to be ready.
		Expect(ep2_1.IP).NotTo(Equal(""))
		getEpsFunc := k8sGetEpsForServiceFunc(k8sClient, tSvc)
		epCorrectFn := func() error {
			eps := getEpsFunc()
			if len(eps) != 1 {
				return fmt.Errorf("Wrong number of endpointslices: %#v", eps)
			}
			if len(eps[0].Endpoints) != 1 {
				return fmt.Errorf("Wrong number of endpoints: %#v", eps[0])
			}
			endpoints := eps[0].Endpoints
			addrs := endpoints[0].Addresses
			if len(addrs) != 1 {
				return fmt.Errorf("Wrong number of addresses: %#v", eps[0])
			}
			if addrs[0] != ep2_1.IP {
				return fmt.Errorf("Unexpected IP: %s != %s", addrs[0], ep2_1.IP)
			}
			ports := eps[0].Ports
			if len(ports) != 1 {
				return fmt.Errorf("Wrong number of ports: %#v", eps[0])
			}
			if *ports[0].Port != int32(wepPort) {
				return fmt.Errorf("Wrong port %d != svcPort", *ports[0].Port)
			}
			return nil
		}
		Eventually(epCorrectFn, "10s").ShouldNot(HaveOccurred())

		// Create a policy that allows ep1-1 to communicate with test-service using label matching
		gnpServiceAllow := api.NewGlobalNetworkPolicy()
		gnpServiceAllow.Name = "ep1-1-allow-test-service"
		gnpServiceAllow.Spec.Order = &float2_0
		gnpServiceAllow.Spec.Tier = "default"
		gnpServiceAllow.Spec.Selector = ep1_1.NameSelector()
		gnpServiceAllow.Spec.Types = []api.PolicyType{api.PolicyTypeEgress}
		gnpServiceAllow.Spec.Egress = []api.Rule{
			{
				Action: api.Allow,
				Destination: api.EntityRule{
					Services: &api.ServiceMatch{
						Namespace: "default",
						Name:      svcName,
					},
				},
			},
		}
		_, err = client.GlobalNetworkPolicies().Create(utils.Ctx, gnpServiceAllow, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

		if !bpfEnabled {
			// Wait for felix to see and program some expected nflog entries, and for the cluster IP to appear.
			Eventually(getRuleFunc(tc.Felixes[0], "APE0|gnp/ep1-1-allow-test-service"), "10s", "1s").ShouldNot(HaveOccurred())
		} else {
			checkNat := func() bool {
				for _, f := range tc.Felixes {
					if !f.BPFNATHasBackendForService(clusterIP, svcPort, 6, ep2_1.IP, wepPort) {
						return false
					}
				}
				return true
			}

			Eventually(checkNat, "10s", "1s").Should(BeTrue(), "Expected NAT to be programmed")

			bpfWaitForGlobalNetworkPolicy(tc.Felixes[0], ep1_1.InterfaceName, "egress", "ep1-1-allow-test-service")
		}

		if !bpfEnabled {
			// Mimic the kube-proxy service iptable clusterIP rule.
			for _, f := range tc.Felixes {
				f.Exec("iptables", "-t", "nat", "-A", "PREROUTING",
					"-p", "tcp",
					"-d", clusterIP,
					"-m", "tcp", "--dport", svcPortStr,
					"-j", "DNAT", "--to-destination",
					ep2_1.IP+":"+wepPortStr)
			}
		}
	})

	It("should get expected flow logs", func() {
		// Describe the connectivity that we now expect.
		// For ep1_1 -> ep2_1 we use the service cluster IP to test service info in the flow log
		cc = &connectivity.Checker{}
		cc.ExpectSome(ep1_1, connectivity.TargetIP(clusterIP), uint16(svcPort)) // allowed by np1-1

		// Do 3 rounds of connectivity checking.
		cc.CheckConnectivity()
		cc.CheckConnectivity()
		cc.CheckConnectivity()

		flowlogs.WaitForConntrackScan(bpfEnabled)

		// Verify we have allowed flow logs before deleting the backing pod
		Eventually(func() error {
			flows, err := tc.Felixes[0].FlowLogs()
			if err != nil {
				return err
			}
			foundAllowed := false
			for _, fl := range flows {
				if fl.Action == "allow" && fl.DstService.PortNum == int(svcPort) {
					foundAllowed = true
					break
				}
			}
			if !foundAllowed {
				return fmt.Errorf("no allowed flow log found for service port %d", svcPort)
			}
			return nil
		}, "20s", "1s").ShouldNot(HaveOccurred())

		// Verify that the workload endpoint for ep2_1 exists
		Eventually(func() error {
			wlList, _ := client.WorkloadEndpoints().List(utils.Ctx, options.ListOptions{})
			for _, wl := range wlList.Items {
				if strings.Contains(wl.Name, "ep2--1") {
					return nil
				}
			}
			return fmt.Errorf("workload endpoint default/%s still exists", ep2_1.Name)
		}, "10s", "1s").ShouldNot(HaveOccurred())

		// Delete the backing pod (ep2_1) to test flow logs when service has no endpoints
		ep2_1.RemoveFromInfra(infra)

		// Wait a moment for the endpoint deletion to propagate
		Eventually(func() error {
			wlList, _ := client.WorkloadEndpoints().List(utils.Ctx, options.ListOptions{})
			for _, wl := range wlList.Items {
				if strings.Contains(wl.Name, "ep2--1") {
					return fmt.Errorf("workload endpoint default/%s still exists", ep2_1.Name)
				}
			}
			return nil
		}, "10s", "1s").ShouldNot(HaveOccurred())

		// Now expect connectivity to fail since there's no backing pod
		cc = &connectivity.Checker{}
		cc.ExpectNone(ep1_1, connectivity.TargetIP(clusterIP), uint16(svcPort))

		// Do more rounds of connectivity checking - these should fail
		cc.CheckConnectivity()
		cc.CheckConnectivity()
		cc.CheckConnectivity()

		flowlogs.WaitForConntrackScan(bpfEnabled)

		// Verify we get denied or failed flow logs after deleting the backing pod
		Consistently(func() error {
			var flows []flowlog.FlowLog
			var err error
			if flows, err = tc.Felixes[0].FlowLogs(); err != nil {
				return err
			}
			for _, fl := range flows {
				// After pod deletion, should not see denied flows for the service port
				if fl.DstService.PortNum == int(svcPort) && fl.Action == "deny" {
					return fmt.Errorf("found denied flow log for service port %d", svcPort)
				}
			}
			return nil
		}, "1m", "1s").ShouldNot(HaveOccurred())

		// Delete conntrack state so that we don't keep seeing 0-metric copies of the logs.  This will allow the flows
		// to expire quickly.
		for ii := range tc.Felixes {
			tc.Felixes[ii].Exec("conntrack", "-F")
		}
	})

	AfterEach(func() {
		if CurrentGinkgoTestDescription().Failed {
			if bpfEnabled {
				tc.Felixes[0].Exec("calico-bpf", "policy", "dump", ep1_1.InterfaceName, "all", "--asm")
			}
		}
	})
})

var _ = infrastructure.DatastoreDescribe("_BPF-SAFE_ goldmane flow log networkset precedence tests", []apiconfig.DatastoreType{apiconfig.EtcdV3}, func(getInfra infrastructure.InfraFactory) {
	bpfEnabled := os.Getenv("FELIX_FV_ENABLE_BPF") == "true"

	var (
		infra                  infrastructure.DatastoreInfra
		tc                     infrastructure.TopologyContainers
		opts                   infrastructure.TopologyOptions
		client                 client.Interface
		swl1, swl2, swl3, swl4 *workload.Workload
		dwl1, dwl2             *workload.Workload
		cc                     *connectivity.Checker
	)

	BeforeEach(func() {
		infra = getInfra()
		opts.FelixLogSeverity = "Debug"
		opts = infrastructure.DefaultTopologyOptions()
		opts.IPIPMode = api.IPIPModeNever
		opts.FlowLogSource = infrastructure.FlowLogSourceLocalSocket

		opts.ExtraEnvVars["FELIX_FLOWLOGSCOLLECTORDEBUGTRACE"] = "true"
		opts.ExtraEnvVars["FELIX_FLOWLOGSFLUSHINTERVAL"] = "2"
		opts.ExtraEnvVars["FELIX_FLOWLOGSGOLDMANESERVER"] = local.SocketAddress
		opts.ExtraEnvVars["FELIX_FLOWLOGSENABLENETWORKSETS"] = "true"
	})

	JustBeforeEach(func() {
		var err error
		numNodes := 2
		tc, client = infrastructure.StartNNodeTopology(numNodes, opts, infra)

		if BPFMode() {
			ensureBPFProgramsAttached(tc.Felixes[0])
			ensureBPFProgramsAttached(tc.Felixes[1])
		}

		infra.AddDefaultAllow()

		// Source workloads on Node 0
		// swl1 in ns1
		infrastructure.AssignIP("swl1", "10.65.0.2", tc.Felixes[0].Hostname, client)
		swl1 = workload.Run(tc.Felixes[0], "swl1", "ns1", "10.65.0.2", "8055", "tcp")
		swl1.WorkloadEndpoint.GenerateName = "swl1-"
		swl1.WorkloadEndpoint.Namespace = "ns1"
		swl1.ConfigureInInfra(infra)

		// swl2 in ns2
		infrastructure.AssignIP("swl2", "10.65.0.3", tc.Felixes[0].Hostname, client)
		swl2 = workload.Run(tc.Felixes[0], "swl2", "ns2", "10.65.0.3", "8055", "tcp")
		swl2.WorkloadEndpoint.GenerateName = "swl2-"
		swl2.WorkloadEndpoint.Namespace = "ns2"
		swl2.ConfigureInInfra(infra)

		// swl3 in ns3
		infrastructure.AssignIP("swl3", "10.65.0.4", tc.Felixes[0].Hostname, client)
		swl3 = workload.Run(tc.Felixes[0], "swl3", "ns3", "10.65.0.4", "8055", "tcp")
		swl3.WorkloadEndpoint.GenerateName = "swl3-"
		swl3.WorkloadEndpoint.Namespace = "ns3"
		swl3.ConfigureInInfra(infra)

		// swl4 in ns3
		infrastructure.AssignIP("swl4", "10.65.0.5", tc.Felixes[0].Hostname, client)
		swl4 = workload.Run(tc.Felixes[0], "swl4", "ns3", "10.65.0.5", "8055", "tcp")
		swl4.WorkloadEndpoint.GenerateName = "swl4-"
		swl4.WorkloadEndpoint.Namespace = "ns3"
		swl4.ConfigureInInfra(infra)

		// Destination workloads on Node 1 (Host Networked to simulate external/non-WEP IPs)

		// dwl1
		infrastructure.AssignIP("dwl1", "10.65.1.2", tc.Felixes[1].Hostname, client)
		dwl1 = workload.New(tc.Felixes[1], "dwl1", "", "10.65.1.2", "8055", "tcp", workload.WithHostNetworked())
		// Add IP before starting workload so it can bind
		err = tc.Felixes[1].ExecMayFail("ip", "addr", "add", "10.65.1.2/32", "dev", "lo")
		Expect(err).NotTo(HaveOccurred())
		Expect(dwl1.Start(tc.Felixes[1])).NotTo(HaveOccurred())

		// dwl2
		infrastructure.AssignIP("dwl2", "10.65.1.3", tc.Felixes[1].Hostname, client)
		dwl2 = workload.New(tc.Felixes[1], "dwl2", "", "10.65.1.3", "8055", "tcp", workload.WithHostNetworked())
		// Add IP before starting workload so it can bind
		err = tc.Felixes[1].ExecMayFail("ip", "addr", "add", "10.65.1.3/32", "dev", "lo")
		Expect(err).NotTo(HaveOccurred())
		Expect(dwl2.Start(tc.Felixes[1])).NotTo(HaveOccurred())

		// Add a policy to allow all traffic
		policy := api.NewGlobalNetworkPolicy()
		policy.Name = "allow-all"
		order := float64(20)
		policy.Spec.Order = &order
		policy.Spec.Selector = "all()"
		policy.Spec.Ingress = []api.Rule{{Action: api.Allow}}
		policy.Spec.Egress = []api.Rule{{Action: api.Allow}}
		_, err = client.GlobalNetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

		if !BPFMode() {
			Eventually(getRuleFuncTable(tc.Felixes[0], "API0|gnp/allow-all", "filter"), "10s", "1s").ShouldNot(HaveOccurred())
			Eventually(getRuleFuncTable(tc.Felixes[0], "APE0|gnp/allow-all", "filter"), "10s", "1s").ShouldNot(HaveOccurred())
		} else {
			bpfWaitForPolicy(tc.Felixes[0], swl1.InterfaceName, "ingress", "allow-all")
			bpfWaitForPolicy(tc.Felixes[0], swl1.InterfaceName, "egress", "allow-all")
		}

		// NetworkSets
		// netset-1 in ns1 matches dwl1
		netset1 := api.NewNetworkSet()
		netset1.Name = "netset-1"
		netset1.Namespace = "ns1"
		netset1.Spec.Nets = []string{dwl1.IP + "/32"}
		_, err = client.NetworkSets().Create(utils.Ctx, netset1, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

		// netset-2 in ns2 matches dwl1
		netset2 := api.NewNetworkSet()
		netset2.Name = "netset-2"
		netset2.Namespace = "ns2"
		netset2.Spec.Nets = []string{dwl1.IP + "/32"}
		_, err = client.NetworkSets().Create(utils.Ctx, netset2, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

		// gns-1 (global) matches dwl1
		gnetset := api.NewGlobalNetworkSet()
		gnetset.Name = "gns-1"
		gnetset.Spec.Nets = []string{dwl1.IP + "/32"}
		_, err = client.GlobalNetworkSets().Create(utils.Ctx, gnetset, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

		// netset-4 in ns4 matches dwl2
		netset4 := api.NewNetworkSet()
		netset4.Name = "netset-4"
		netset4.Namespace = "ns4"
		netset4.Spec.Nets = []string{dwl2.IP + "/32"}
		_, err = client.NetworkSets().Create(utils.Ctx, netset4, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

		if BPFMode() {
			ensureAllNodesBPFProgramsAttached(tc.Felixes)
		}
	})

	It("should report correct network sets based on namespace precedence", func() {
		// Connectivity check
		cc = &connectivity.Checker{}
		cc.ExpectSome(swl1, dwl1)
		cc.ExpectSome(swl2, dwl1)
		cc.ExpectSome(swl3, dwl1)
		cc.ExpectSome(swl4, dwl2)
		cc.CheckConnectivity()

		flowlogs.WaitForConntrackScan(bpfEnabled)

		for ii := range tc.Felixes {
			tc.Felixes[ii].Exec("conntrack", "-F")
		}

		Eventually(func() error {
			wepPort := 8055
			flowTester := flowlogs.NewFlowTester(flowlogs.FlowTesterOptions{
				ExpectLabels:           true,
				ExpectEnforcedPolicies: true,
				MatchEnforcedPolicies:  true,
				MatchLabels:            false,
				Includes:               []flowlogs.IncludeFilter{flowlogs.IncludeByDestPort(wepPort)},
			})

			err := flowTester.PopulateFromFlowLogs(tc.Felixes[0])
			if err != nil {
				return fmt.Errorf("error populating flow logs from Felix[0]: %s", err)
			}

			aggrTuple := tuple.Make(flowlog.EmptyIP, flowlog.EmptyIP, 6, flowlogs.SourcePortIsNotIncluded, wepPort)

			type checkArgs struct {
				desc       string
				srcNS      string
				srcAggName string
				dstNS      string
				dstAggName string
			}
			check := func(args checkArgs) {
				flowTester.CheckFlow(flowlog.FlowLog{
					FlowMeta: flowlog.FlowMeta{
						Tuple:      aggrTuple,
						SrcMeta:    endpoint.Metadata{Type: "wep", Namespace: args.srcNS, Name: flowlog.FieldNotIncluded, AggregatedName: args.srcAggName},
						DstMeta:    endpoint.Metadata{Type: "ns", Namespace: args.dstNS, Name: flowlog.FieldNotIncluded, AggregatedName: args.dstAggName},
						DstService: flowlog.FlowService{Namespace: flowlog.FieldNotIncluded, Name: flowlog.FieldNotIncluded, PortName: flowlog.FieldNotIncluded, PortNum: 0},
						Action:     "allow", Reporter: "src",
					},
					FlowEnforcedPolicySet: flowlog.FlowPolicySet{"0|default|gnp:allow-all|allow|0": {}},
				})
			}

			check(checkArgs{desc: "ns1 -> netset-1", srcNS: "ns1", srcAggName: "swl1-*", dstNS: "ns1", dstAggName: "netset-1"})
			check(checkArgs{desc: "ns2 -> netset-2", srcNS: "ns2", srcAggName: "swl2-*", dstNS: "ns2", dstAggName: "netset-2"})
			check(checkArgs{desc: "ns3 -> gns-1", srcNS: "ns3", srcAggName: "swl3-*", dstNS: flowlog.FieldNotIncluded, dstAggName: "gns-1"})
			check(checkArgs{desc: "ns3 -> netset-4", srcNS: "ns3", srcAggName: "swl4-*", dstNS: "ns4", dstAggName: "netset-4"})

			if err := flowTester.Finish(); err != nil {
				return fmt.Errorf("Flows incorrect on Felix[0]:\n%v", err)
			}
			return nil
		}, "30s", "3s").ShouldNot(HaveOccurred())
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

func getRuleFuncTable(felix *infrastructure.Felix, chain string, table string) func() error {
	return func() error {
		if NFTMode() {
			out, err := felix.ExecOutput("nft", "list", "ruleset")
			if err != nil {
				return err
			}
			if strings.Contains(out, chain) {
				return nil
			}
			return fmt.Errorf("chain %s not found in nft ruleset", chain)
		}

		out, err := felix.ExecOutput("iptables-save", "-t", table)
		if err != nil {
			return err
		}
		if strings.Contains(out, chain) {
			return nil
		}
		return fmt.Errorf("chain %s not found in table %s", chain, table)
	}
}
