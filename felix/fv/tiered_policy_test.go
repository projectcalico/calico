// Copyright (c) 2018-2025 Tigera, Inc. All rights reserved.
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
	"os"
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

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

var (
	float0_0 = float64(0.0)
	float1_0 = float64(1.0)
	float2_0 = float64(2.0)
	float3_0 = float64(3.0)

	actionPass = api.Pass
	actionDeny = api.Deny
)

// Felix1             Felix2
//  EP1-1 <-+-------> EP2-1
//          \-------> EP2-2
//           `------> EP2-3
//            `-----> EP2-4
//
//       ^           ^-- Apply test policies here (for ingress and egress)
//       `-------------- Allow all policy
//
// Egress Policies (dest ep1-1)
//   Tier1             |   Tier2             | Default         | Profile
//   np1-1 (P2-1,D2-2) |  snp2-1 (A2-1)      | sknp3.1 (N2-1)  | (default A)
//   gnp2-4 (N1-1)     |  gnp2-2 (D2-3)      |  -> sknp3.9     |
//
// Ingress Policies (source ep1-1)
//
//   Tier1             |   Tier2             | Default         | Profile
//   np1-1 (A2-1,P2-2) | sgnp2-2 (N2-3)      |  snp3.2 (A2-2)  | (default A)
//   gnp2-4 (N1-1)     |  snp2-3 (A2-2,D2-3) |   np3.3 (A2-2)  |
//                     |   np2-4 (D2-3)      |  snp3.4 (A2-2)  |
//
// A=allow; D=deny; P=pass; N=no-match

// These tests include tests of Kubernetes policies as well as other policy types. To ensure we have the correct
// behavior, run using the Kubernetes infrastructure only.
var _ = infrastructure.DatastoreDescribe("connectivity tests and flow logs with policy tiers _BPF-SAFE_", []apiconfig.DatastoreType{apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
	const (
		wepPort = 8055
		svcPort = 8066
	)
	wepPortStr := fmt.Sprintf("%d", wepPort)
	svcPortStr := fmt.Sprintf("%d", svcPort)

	var (
		infra                             infrastructure.DatastoreInfra
		opts                              infrastructure.TopologyOptions
		tc                                infrastructure.TopologyContainers
		client                            client.Interface
		ep1_1, ep2_1, ep2_2, ep2_3, ep2_4 *workload.Workload
		cc                                *connectivity.Checker
		rulesProgrammed                   func() bool
	)
	clusterIP := "10.101.0.10"

	testSetup := func() {
		// Start felix instances.
		tc, client = infrastructure.StartNNodeTopology(2, opts, infra)

		// Install a default profile that allows all ingress and egress, in the absence of any Policy.
		infra.AddDefaultAllow()

		// Create workload on host 1.
		infrastructure.AssignIP("ep1-1", "10.65.0.0", tc.Felixes[0].Hostname, client)
		ep1_1 = workload.Run(tc.Felixes[0], "ep1-1", "default", "10.65.0.0", wepPortStr, "tcp")
		ep1_1.ConfigureInInfra(infra)

		infrastructure.AssignIP("ep2-1", "10.65.1.0", tc.Felixes[1].Hostname, client)
		ep2_1 = workload.Run(tc.Felixes[1], "ep2-1", "default", "10.65.1.0", wepPortStr, "tcp")
		ep2_1.ConfigureInInfra(infra)

		infrastructure.AssignIP("ep2-2", "10.65.1.1", tc.Felixes[1].Hostname, client)
		ep2_2 = workload.Run(tc.Felixes[1], "ep2-2", "default", "10.65.1.1", wepPortStr, "tcp")
		ep2_2.ConfigureInInfra(infra)

		infrastructure.AssignIP("ep2-3", "10.65.1.2", tc.Felixes[1].Hostname, client)
		ep2_3 = workload.Run(tc.Felixes[1], "ep2-3", "default", "10.65.1.2", wepPortStr, "tcp")
		ep2_3.ConfigureInInfra(infra)

		infrastructure.AssignIP("ep2-3", "10.65.1.3", tc.Felixes[1].Hostname, client)
		ep2_4 = workload.Run(tc.Felixes[1], "ep2-4", "default", "10.65.1.3", wepPortStr, "tcp")
		ep2_4.ConfigureInInfra(infra)

		ensureRoutesProgrammed(tc.Felixes)

		// Create tiers tier1 and tier2
		tier := api.NewTier()
		tier.Name = "tier1"
		tier.Spec.Order = &float1_0
		_, err := client.Tiers().Create(utils.Ctx, tier, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

		tier = api.NewTier()
		tier.Name = "tier2"
		tier.Spec.Order = &float2_0
		tier.Spec.DefaultAction = &actionDeny
		_, err = client.Tiers().Create(utils.Ctx, tier, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

		// Allow all traffic to/from ep1-1
		gnp := api.NewGlobalNetworkPolicy()
		gnp.Name = "default.ep1-1-allow-all"
		gnp.Spec.Order = &float1_0
		gnp.Spec.Tier = "default"
		gnp.Spec.Selector = ep1_1.NameSelector()
		gnp.Spec.Types = []api.PolicyType{api.PolicyTypeIngress, api.PolicyTypeEgress}
		gnp.Spec.Egress = []api.Rule{{Action: api.Allow}}
		gnp.Spec.Ingress = []api.Rule{{Action: api.Allow}}
		_, err = client.GlobalNetworkPolicies().Create(utils.Ctx, gnp, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

		// gnp2-4 egress(N1-1) ingress(N1-1)
		gnp = api.NewGlobalNetworkPolicy()
		gnp.Name = "tier1.ep2-4"
		gnp.Spec.Order = &float1_0
		gnp.Spec.Tier = "tier1"
		gnp.Spec.Selector = ep2_4.NameSelector()
		gnp.Spec.Types = []api.PolicyType{api.PolicyTypeIngress, api.PolicyTypeEgress}
		gnp.Spec.Ingress = []api.Rule{
			{Action: api.Allow, Source: api.EntityRule{Selector: ep2_1.NameSelector()}},
		}
		gnp.Spec.Egress = []api.Rule{
			{Action: api.Allow, Destination: api.EntityRule{Selector: ep2_1.NameSelector()}},
		}
		_, err = client.GlobalNetworkPolicies().Create(utils.Ctx, gnp, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

		// np1-1  egress: (P2-1,D2-2) ingress: (A2-1,P2-2)
		np := api.NewNetworkPolicy()
		np.Name = "tier1.np1-1"
		np.Namespace = "default"
		np.Spec.Order = &float1_0
		np.Spec.Tier = "tier1"
		np.Spec.Selector = "name in {'" + ep2_1.Name + "', '" + ep2_2.Name + "'}"
		np.Spec.Types = []api.PolicyType{api.PolicyTypeIngress, api.PolicyTypeEgress}
		np.Spec.Egress = []api.Rule{
			{Action: api.Pass, Source: api.EntityRule{Selector: ep2_1.NameSelector()}},
			{Action: api.Deny, Source: api.EntityRule{Selector: ep2_2.NameSelector()}},
		}
		np.Spec.Ingress = []api.Rule{
			{Action: api.Allow, Destination: api.EntityRule{Selector: ep2_1.NameSelector()}},
			{Action: api.Pass, Destination: api.EntityRule{Selector: ep2_2.NameSelector()}},
		}
		_, err = client.NetworkPolicies().Create(utils.Ctx, np, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

		// (s)np2.1 egress: (A2-1)
		snp := api.NewStagedNetworkPolicy()
		snp.Name = "tier2.np2-1"
		snp.Namespace = "default"
		snp.Spec.Order = &float1_0
		snp.Spec.Tier = "tier2"
		snp.Spec.Selector = ep2_1.NameSelector()
		snp.Spec.Types = []api.PolicyType{api.PolicyTypeEgress}
		snp.Spec.Egress = []api.Rule{{Action: api.Allow}}
		_, err = client.StagedNetworkPolicies().Create(utils.Ctx, snp, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

		// gnp2-2 egress: (A2-3)
		gnp = api.NewGlobalNetworkPolicy()
		gnp.Name = "tier2.gnp2-2"
		gnp.Spec.Order = &float2_0
		gnp.Spec.Tier = "tier2"
		gnp.Spec.Selector = ep2_3.NameSelector()
		gnp.Spec.Types = []api.PolicyType{api.PolicyTypeEgress}
		gnp.Spec.Egress = []api.Rule{{Action: api.Deny}}
		_, err = client.GlobalNetworkPolicies().Create(utils.Ctx, gnp, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

		// (s)gnp2-2 ingress: (N2-3)
		sgnp := api.NewStagedGlobalNetworkPolicy()
		sgnp.Name = "tier2.gnp2-2"
		sgnp.Spec.Order = &float2_0
		sgnp.Spec.Tier = "tier2"
		sgnp.Spec.Selector = ep2_3.NameSelector()
		sgnp.Spec.Types = []api.PolicyType{api.PolicyTypeIngress}
		_, err = client.StagedGlobalNetworkPolicies().Create(utils.Ctx, sgnp, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

		// (s)np2-3 ingress: (A2-2, D2-3)
		snp = api.NewStagedNetworkPolicy()
		snp.Name = "tier2.np2-3"
		snp.Namespace = "default"
		snp.Spec.Order = &float3_0
		snp.Spec.Tier = "tier2"
		snp.Spec.Selector = "name in {'" + ep2_2.Name + "', '" + ep2_3.Name + "'}"
		snp.Spec.Types = []api.PolicyType{api.PolicyTypeIngress}
		snp.Spec.Ingress = []api.Rule{
			{Action: api.Allow, Destination: api.EntityRule{Selector: ep2_2.NameSelector()}},
			{Action: api.Deny, Destination: api.EntityRule{Selector: ep2_3.NameSelector()}},
		}
		_, err = client.StagedNetworkPolicies().Create(utils.Ctx, snp, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

		// np2-4 ingress: (D2-3)
		np = api.NewNetworkPolicy()
		np.Name = "tier2.np2-4"
		np.Namespace = "default"
		np.Spec.Order = &float3_0
		np.Spec.Tier = "tier2"
		np.Spec.Selector = ep2_3.NameSelector()
		np.Spec.Types = []api.PolicyType{api.PolicyTypeIngress}
		np.Spec.Ingress = []api.Rule{{Action: api.Deny}}
		_, err = client.NetworkPolicies().Create(utils.Ctx, np, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

		// (s)knp3.1->sknp3.9 egress: (N2-1)
		for i := 0; i < 9; i++ {
			sknp := api.NewStagedKubernetesNetworkPolicy()
			sknp.Name = fmt.Sprintf("knp3-%d", i+1)
			sknp.Namespace = "default"
			sknp.Spec.PodSelector = metav1.LabelSelector{
				MatchLabels: map[string]string{
					"name": ep2_1.Name,
				},
			}
			sknp.Spec.PolicyTypes = []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}
			_, err = client.StagedKubernetesNetworkPolicies().Create(utils.Ctx, sknp, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())
		}

		// (s)np3.2 ingress: (A2-2)
		snp = api.NewStagedNetworkPolicy()
		snp.Name = "default.np3-2"
		snp.Namespace = "default"
		snp.Spec.Order = &float1_0
		snp.Spec.Tier = "default"
		snp.Spec.Selector = ep2_2.NameSelector()
		snp.Spec.Types = []api.PolicyType{api.PolicyTypeIngress}
		snp.Spec.Ingress = []api.Rule{{Action: api.Allow}}
		_, err = client.StagedNetworkPolicies().Create(utils.Ctx, snp, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

		// np3.3 ingress: (A2-2)
		np = api.NewNetworkPolicy()
		np.Name = "default.np3-3"
		np.Namespace = "default"
		np.Spec.Order = &float2_0
		np.Spec.Tier = "default"
		np.Spec.Selector = ep2_2.NameSelector()
		np.Spec.Types = []api.PolicyType{api.PolicyTypeIngress}
		np.Spec.Ingress = []api.Rule{{Action: api.Allow}}
		_, err = client.NetworkPolicies().Create(utils.Ctx, np, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

		// (s)np3.4 ingress: (A2-2)
		snp = api.NewStagedNetworkPolicy()
		snp.Name = "default.np3-4"
		snp.Namespace = "default"
		snp.Spec.Order = &float3_0
		snp.Spec.Tier = "default"
		snp.Spec.Selector = ep2_2.NameSelector()
		snp.Spec.Types = []api.PolicyType{api.PolicyTypeIngress}
		snp.Spec.Ingress = []api.Rule{{Action: api.Allow}}
		_, err = client.StagedNetworkPolicies().Create(utils.Ctx, snp, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())
		// Create a service that maps to ep2_1. Rather than checking connectivity to the endpoint we'll go via
		// the service to test the destination service name handling.
		svcName := "test-service"
		k8sClient := infra.(*infrastructure.K8sDatastoreInfra).K8sClient
		tSvc := k8sService(svcName, clusterIP, ep2_1, svcPort, wepPort, 0, "tcp")
		tSvcNamespace := tSvc.Namespace
		_, err = k8sClient.CoreV1().Services(tSvcNamespace).Create(context.Background(), tSvc, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		// Wait for the endpoints to be updated and for the address to be ready.
		Expect(ep2_1.IP).NotTo(Equal(""))
		getEpsFunc := k8sGetEpsForServiceFunc(k8sClient, tSvc)
		epCorrectFn := func() error {
			epslices := getEpsFunc()
			if len(epslices) != 1 {
				return fmt.Errorf("Wrong number of endpoints: %#v", epslices)
			}
			eps := epslices[0].Endpoints
			if len(eps) != 1 {
				return fmt.Errorf("Wrong number of endpoint addresses: %#v", epslices[0])
			}
			addrs := eps[0].Addresses
			if len(addrs) != 1 {
				return fmt.Errorf("Wrong number of addresses: %#v", eps[0])
			}
			if addrs[0] != ep2_1.IP {
				return fmt.Errorf("Unexpected IP: %s != %s", addrs[0], ep2_1.IP)
			}
			ports := epslices[0].Ports
			if len(ports) != 1 {
				return fmt.Errorf("Wrong number of ports: %#v", eps[0])
			}
			if *ports[0].Port != int32(wepPort) {
				return fmt.Errorf("Wrong port %d != svcPort", *ports[0].Port)
			}
			return nil
		}
		Eventually(epCorrectFn, "10s").ShouldNot(HaveOccurred())

		if os.Getenv("FELIX_FV_ENABLE_BPF") != "true" {
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

		rulesProgrammed = func() bool {
			if !BPFMode() {
				if NFTMode() {
					// Nftables
					out0, err := tc.Felixes[1].ExecOutput("nft", "list", "ruleset")
					Expect(err).NotTo(HaveOccurred())
					return strings.Contains(out0, "End of tier tier1. Drop if no policies passed packet")
				}

				// Iptables
				out0, err := tc.Felixes[1].ExecOutput("iptables-save", "-t", "filter")
				Expect(err).NotTo(HaveOccurred())

				return strings.Contains(out0, "End of tier tier1. Drop if no policies passed packet")
			}

			// BPF
			out0 := bpfDumpPolicy(tc.Felixes[1], ep2_4.InterfaceName, "ingress")
			out1 := bpfDumpPolicy(tc.Felixes[1], ep2_4.InterfaceName, "egress")
			return strings.Contains(out0, "End of tier tier1: deny") &&
				strings.Contains(out1, "End of tier tier1: deny")
		}
		if BPFMode() {
			ensureAllNodesBPFProgramsAttached(tc.Felixes)
		}
	}

	createBaseConnectivityChecker := func() *connectivity.Checker {
		cc = &connectivity.Checker{}
		cc.ExpectSome(ep1_1, connectivity.TargetIP(clusterIP), uint16(svcPort)) // allowed by np1-1
		cc.ExpectSome(ep1_1, ep2_2)                                             // allowed by np3-3
		cc.ExpectNone(ep1_1, ep2_3)                                             // denied by np2-4

		cc.ExpectSome(ep2_1, ep1_1) // allowed by profile
		cc.ExpectNone(ep2_2, ep1_1) // denied by np1-1
		cc.ExpectNone(ep2_3, ep1_1) // denied by gnp2-2

		return cc
	}

	Context("with multiple tiers and policies", func() {
		JustBeforeEach(func() {
			infra = getInfra()
			opts = infrastructure.DefaultTopologyOptions()
			opts.IPIPMode = api.IPIPModeNever

			testSetup()
		})

		It("connectivity should be correct between workloads", func() {
			By("checking the initial connectivity")
			cc := createBaseConnectivityChecker()
			cc.ExpectNone(ep1_1, ep2_4) // denied by end of tier1 deny
			cc.ExpectNone(ep2_4, ep1_1) // denied by end of tier1 deny

			Eventually(rulesProgrammed, "15s", "200ms").Should(BeTrue())
			Consistently(rulesProgrammed, "10s", "200ms").Should(BeTrue())

			// Do 3 rounds of connectivity checking.
			cc.CheckConnectivity()

			By("changing the tier's default action to Pass")
			tier, err := client.Tiers().Get(utils.Ctx, "tier1", options.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			tier.Spec.DefaultAction = &actionPass
			_, err = client.Tiers().Update(utils.Ctx, tier, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())

			Eventually(rulesProgrammed, "15s", "200ms").Should(BeFalse())
			Consistently(rulesProgrammed, "10s", "200ms").Should(BeFalse())

			cc = createBaseConnectivityChecker()
			cc.ExpectSome(ep1_1, ep2_4) // allowed by profile, as tier1 DefaultAction is set to Pass.
			cc.ExpectSome(ep2_4, ep1_1) // allowed by profile, as tier1 DefaultAction is set to Pass.

			cc.CheckConnectivity()

			By("changing the tier's default action back to Deny")
			tier, err = client.Tiers().Get(utils.Ctx, "tier1", options.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			tier.Spec.DefaultAction = &actionDeny
			_, err = client.Tiers().Update(utils.Ctx, tier, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())

			Eventually(rulesProgrammed, "15s", "200ms").Should(BeTrue())
			Consistently(rulesProgrammed, "10s", "200ms").Should(BeTrue())

			cc = createBaseConnectivityChecker()
			cc.ExpectNone(ep1_1, ep2_4) // denied by end of tier1 deny
			cc.ExpectNone(ep2_4, ep1_1) // denied by end of tier1 deny

			cc.CheckConnectivity()
		})
	})

	Context("with tier default action set to pass", func() {
		JustBeforeEach(func() {
			infra = getInfra()
			opts = infrastructure.DefaultTopologyOptions()
			opts.IPIPMode = api.IPIPModeNever
			opts.FlowLogSource = infrastructure.FlowLogSourceLocalSocket

			opts.ExtraEnvVars["FELIX_FLOWLOGSCOLLECTORDEBUGTRACE"] = "true"
			opts.ExtraEnvVars["FELIX_FLOWLOGSFLUSHINTERVAL"] = "2"
			opts.ExtraEnvVars["FELIX_FLOWLOGSLOCALREPORTER"] = "Enabled"

			testSetup()

			// Delete conntrack state so that we don't keep seeing 0-metric copies of the logs.
			// This will allow the flows to expire quickly.
			for i := range tc.Felixes {
				tc.Felixes[i].Exec("conntrack", "-F")
			}
			for ii := range tc.Felixes {
				tc.Felixes[ii].Exec("conntrack", "-L")
			}
		})

		checkFlowLogs := func() error {
			aggrTuple := tuple.Make(flowlog.EmptyIP, flowlog.EmptyIP, 6, flowlogs.SourcePortIsNotIncluded, wepPort)

			host1_wl1_Meta := endpoint.Metadata{
				Type:           "wep",
				Namespace:      "default",
				Name:           flowlog.FieldNotIncluded,
				AggregatedName: ep1_1.Name,
			}
			host2_wl1_Meta := endpoint.Metadata{
				Type:           "wep",
				Namespace:      "default",
				Name:           flowlog.FieldNotIncluded,
				AggregatedName: ep2_1.Name,
			}
			host2_wl2_Meta := endpoint.Metadata{
				Type:           "wep",
				Namespace:      "default",
				Name:           flowlog.FieldNotIncluded,
				AggregatedName: ep2_2.Name,
			}
			host2_wl3_Meta := endpoint.Metadata{
				Type:           "wep",
				Namespace:      "default",
				Name:           flowlog.FieldNotIncluded,
				AggregatedName: ep2_3.Name,
			}
			host2_wl4_Meta := endpoint.Metadata{
				Type:           "wep",
				Namespace:      "default",
				Name:           flowlog.FieldNotIncluded,
				AggregatedName: ep2_4.Name,
			}
			dstService := flowlog.FlowService{
				Namespace: "default",
				Name:      "test-service",
				PortName:  "port-8055",
				PortNum:   8066,
			}

			flowTester := flowlogs.NewFlowTester(flowlogs.FlowTesterOptions{
				ExpectLabels:           true,
				ExpectEnforcedPolicies: true,
				MatchEnforcedPolicies:  true,
				ExpectPendingPolicies:  true,
				MatchPendingPolicies:   true,
				Includes:               []flowlogs.IncludeFilter{flowlogs.IncludeByDestPort(wepPort)},
			})

			err := flowTester.PopulateFromFlowLogs(tc.Felixes[0])
			if err != nil {
				return fmt.Errorf("error populating flow logs from Felix[0]: %s", err)
			}

			// Flow logs expected to be seen with tier default action set to either Deny or Pass.
			flowTester.CheckFlow(
				flowlog.FlowLog{
					FlowMeta: flowlog.FlowMeta{
						Tuple:      aggrTuple,
						SrcMeta:    host1_wl1_Meta,
						DstMeta:    host2_wl2_Meta,
						DstService: flowlog.EmptyService,
						Action:     "allow",
						Reporter:   "src",
					},
					FlowEnforcedPolicySet: flowlog.FlowPolicySet{
						"0|default|default.ep1-1-allow-all|allow|0": {},
					},
					FlowPendingPolicySet: flowlog.FlowPolicySet{
						"0|default|default.ep1-1-allow-all|allow|0": {},
					},
				})

			flowTester.CheckFlow(
				flowlog.FlowLog{
					FlowMeta: flowlog.FlowMeta{
						Tuple:      aggrTuple,
						SrcMeta:    host1_wl1_Meta,
						DstMeta:    host2_wl1_Meta,
						DstService: dstService,
						Action:     "allow",
						Reporter:   "src",
					},
					FlowEnforcedPolicySet: flowlog.FlowPolicySet{
						"0|default|default.ep1-1-allow-all|allow|0": {},
					},
					FlowPendingPolicySet: flowlog.FlowPolicySet{
						"0|default|default.ep1-1-allow-all|allow|0": {},
					},
				})

			flowTester.CheckFlow(
				flowlog.FlowLog{
					FlowMeta: flowlog.FlowMeta{
						Tuple:      aggrTuple,
						SrcMeta:    host2_wl1_Meta,
						DstMeta:    host1_wl1_Meta,
						DstService: flowlog.EmptyService,
						Action:     "allow",
						Reporter:   "dst",
					},
					FlowEnforcedPolicySet: flowlog.FlowPolicySet{
						"0|default|default.ep1-1-allow-all|allow|0": {},
					},
					FlowPendingPolicySet: flowlog.FlowPolicySet{
						"0|default|default.ep1-1-allow-all|allow|0": {},
					},
				})

			flowTester.CheckFlow(
				flowlog.FlowLog{
					FlowMeta: flowlog.FlowMeta{
						Tuple:      aggrTuple,
						SrcMeta:    host1_wl1_Meta,
						DstMeta:    host2_wl3_Meta,
						DstService: flowlog.EmptyService,
						Action:     "allow",
						Reporter:   "src",
					},
					FlowEnforcedPolicySet: flowlog.FlowPolicySet{
						"0|default|default.ep1-1-allow-all|allow|0": {},
					},
					FlowPendingPolicySet: flowlog.FlowPolicySet{
						"0|default|default.ep1-1-allow-all|allow|0": {},
					},
				})

			flowTester.CheckFlow(
				flowlog.FlowLog{
					FlowMeta: flowlog.FlowMeta{
						Tuple:      aggrTuple,
						SrcMeta:    host1_wl1_Meta,
						DstMeta:    host2_wl4_Meta,
						DstService: flowlog.EmptyService,
						Action:     "allow",
						Reporter:   "src",
					},
					FlowEnforcedPolicySet: flowlog.FlowPolicySet{
						"0|default|default.ep1-1-allow-all|allow|0": {},
					},
					FlowPendingPolicySet: flowlog.FlowPolicySet{
						"0|default|default.ep1-1-allow-all|allow|0": {},
					},
				})

			// Flow logs expected to be seen only with tier default action set to Pass.
			flowTester.CheckFlow(
				flowlog.FlowLog{
					FlowMeta: flowlog.FlowMeta{
						Tuple:      aggrTuple,
						SrcMeta:    host2_wl4_Meta,
						DstMeta:    host1_wl1_Meta,
						DstService: flowlog.EmptyService,
						Action:     "allow",
						Reporter:   "dst",
					},
					FlowEnforcedPolicySet: flowlog.FlowPolicySet{
						"0|default|default.ep1-1-allow-all|allow|0": {},
					},
					FlowPendingPolicySet: flowlog.FlowPolicySet{
						"0|default|default.ep1-1-allow-all|allow|0": {},
					},
				})

			if err := flowTester.Finish(); err != nil {
				return fmt.Errorf("Flows incorrect on Felix[0]:\n%v", err)
			}

			err = flowTester.PopulateFromFlowLogs(tc.Felixes[1])
			if err != nil {
				return fmt.Errorf("error populating flow logs from Felix[1]: %s", err)
			}

			// Flow logs expected to be seen with tier default action set to either Deny or Pass.
			flowTester.CheckFlow(
				flowlog.FlowLog{
					FlowMeta: flowlog.FlowMeta{
						Tuple:      aggrTuple,
						SrcMeta:    host2_wl2_Meta,
						DstMeta:    host1_wl1_Meta,
						DstService: flowlog.EmptyService,
						Action:     "deny",
						Reporter:   "src",
					},
					FlowEnforcedPolicySet: flowlog.FlowPolicySet{
						"0|tier1|default/tier1.np1-1|deny|1": {},
					},
					FlowPendingPolicySet: flowlog.FlowPolicySet{
						"0|tier1|default/tier1.np1-1|deny|1": {},
					},
				})

			flowTester.CheckFlow(
				flowlog.FlowLog{
					FlowMeta: flowlog.FlowMeta{
						Tuple:      aggrTuple,
						SrcMeta:    host2_wl3_Meta,
						DstMeta:    host1_wl1_Meta,
						DstService: flowlog.EmptyService,
						Action:     "deny",
						Reporter:   "src",
					},
					FlowEnforcedPolicySet: flowlog.FlowPolicySet{
						"0|tier2|tier2.gnp2-2|deny|0": {},
					},
					FlowPendingPolicySet: flowlog.FlowPolicySet{
						"0|tier2|tier2.gnp2-2|deny|0": {},
					},
				})

			flowTester.CheckFlow(
				flowlog.FlowLog{
					FlowMeta: flowlog.FlowMeta{
						Tuple:      aggrTuple,
						SrcMeta:    host2_wl1_Meta,
						DstMeta:    host1_wl1_Meta,
						DstService: flowlog.EmptyService,
						Action:     "allow",
						Reporter:   "src",
					},
					FlowEnforcedPolicySet: flowlog.FlowPolicySet{
						"0|tier1|default/tier1.np1-1|pass|0":            {},
						"1|__PROFILE__|__PROFILE__.kns.default|allow|0": {},
					},
					FlowPendingPolicySet: flowlog.FlowPolicySet{
						"0|tier1|default/tier1.np1-1|pass|0":               {},
						"1|tier2|default/tier2.staged:tier2.np2-1|allow|0": {},
					},
				})

			flowTester.CheckFlow(
				flowlog.FlowLog{
					FlowMeta: flowlog.FlowMeta{
						Tuple:      aggrTuple,
						SrcMeta:    host1_wl1_Meta,
						DstMeta:    host2_wl3_Meta,
						DstService: flowlog.EmptyService,
						Action:     "deny",
						Reporter:   "dst",
					},
					FlowEnforcedPolicySet: flowlog.FlowPolicySet{
						"0|tier2|default/tier2.np2-4|deny|0": {},
					},
					FlowPendingPolicySet: flowlog.FlowPolicySet{
						"0|tier2|default/tier2.staged:tier2.np2-3|deny|1": {},
					},
				})

			flowTester.CheckFlow(
				flowlog.FlowLog{
					FlowMeta: flowlog.FlowMeta{
						Tuple:      aggrTuple,
						SrcMeta:    host1_wl1_Meta,
						DstMeta:    host2_wl2_Meta,
						DstService: flowlog.EmptyService,
						Action:     "allow",
						Reporter:   "dst",
					},
					FlowEnforcedPolicySet: flowlog.FlowPolicySet{
						"0|tier1|default/tier1.np1-1|pass|1":      {},
						"1|default|default/default.np3-3|allow|0": {},
					},
					FlowPendingPolicySet: flowlog.FlowPolicySet{
						"0|tier1|default/tier1.np1-1|pass|1":               {},
						"1|tier2|default/tier2.staged:tier2.np2-3|allow|0": {},
					},
				})

			flowTester.CheckFlow(
				flowlog.FlowLog{
					FlowMeta: flowlog.FlowMeta{
						Tuple:      aggrTuple,
						SrcMeta:    host1_wl1_Meta,
						DstMeta:    host2_wl1_Meta,
						DstService: flowlog.EmptyService,
						Action:     "allow",
						Reporter:   "dst",
					},
					FlowEnforcedPolicySet: flowlog.FlowPolicySet{
						"0|tier1|default/tier1.np1-1|allow|0": {},
					},
					FlowPendingPolicySet: flowlog.FlowPolicySet{
						"0|tier1|default/tier1.np1-1|allow|0": {},
					},
				})

			// Flow logs expected to be seen only with tier default action set to Pass.
			flowTester.CheckFlow(
				flowlog.FlowLog{
					FlowMeta: flowlog.FlowMeta{
						Tuple:      aggrTuple,
						SrcMeta:    host2_wl4_Meta,
						DstMeta:    host1_wl1_Meta,
						DstService: flowlog.EmptyService,
						Action:     "allow",
						Reporter:   "src",
					},
					// Enforced and pending policy sets must be identical.
					FlowEnforcedPolicySet: flowlog.FlowPolicySet{
						"0|tier1|tier1.ep2-4|pass|-1":                   {},
						"1|__PROFILE__|__PROFILE__.kns.default|allow|0": {},
					},
					FlowPendingPolicySet: flowlog.FlowPolicySet{
						"0|tier1|tier1.ep2-4|pass|-1":                   {},
						"1|__PROFILE__|__PROFILE__.kns.default|allow|0": {},
					},
				})

			flowTester.CheckFlow(
				flowlog.FlowLog{
					FlowMeta: flowlog.FlowMeta{
						Tuple:      aggrTuple,
						SrcMeta:    host1_wl1_Meta,
						DstMeta:    host2_wl4_Meta,
						DstService: flowlog.EmptyService,
						Action:     "allow",
						Reporter:   "dst",
					},
					// Enforced and pending policy sets must be identical.
					FlowEnforcedPolicySet: flowlog.FlowPolicySet{
						"0|tier1|tier1.ep2-4|pass|-1":                   {},
						"1|__PROFILE__|__PROFILE__.kns.default|allow|0": {},
					},
					FlowPendingPolicySet: flowlog.FlowPolicySet{
						"0|tier1|tier1.ep2-4|pass|-1":                   {},
						"1|__PROFILE__|__PROFILE__.kns.default|allow|0": {},
					},
				})

			if err := flowTester.Finish(); err != nil {
				return fmt.Errorf("Flows incorrect on Felix[1]:\n%v", err)
			}

			return nil
		}

		It("should generate correct flow logs", func() {
			tier, err := client.Tiers().Get(utils.Ctx, "tier1", options.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			tier.Spec.DefaultAction = &actionPass
			_, err = client.Tiers().Update(utils.Ctx, tier, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())

			Eventually(rulesProgrammed, "30s", "200ms").Should(BeFalse())
			Consistently(rulesProgrammed, "10s", "200ms").Should(BeFalse())

			cc = createBaseConnectivityChecker()
			cc.ExpectSome(ep1_1, ep2_4) // allowed by profile, as tier1 DefaultAction is set to Pass.
			cc.ExpectSome(ep2_4, ep1_1) // allowed by profile, as tier1 DefaultAction is set to Pass.

			cc.CheckConnectivity()
			Eventually(checkFlowLogs, "30s", "3s").ShouldNot(HaveOccurred())
		})
	})
})
