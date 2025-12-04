// Copyright (c) 2018-2025 Tigera, Inc. All rights reserved.
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
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"
	networkingv1 "k8s.io/api/networking/v1"
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

// This is an extension of the flow_logs_tests.go file to test flow logs from staged policies.
//
// Felix1             Felix2
//  EP1-1 <-+-------> EP2-1
//          \-------> EP2-2
//           `------> EP2-3
//
//       ^           ^-- Apply test policies here (for ingress and egress)
//       `-------------- Allow all policy
//
// Egress Policies (dest ep1-1)
//   Tier1             |   Tier2             | Default         | Profile
//   np1-1 (P2-1,D2-2) |  snp2-1 (A2-1)      | sknp3.1 (N2-1)  | (default A)
//                     |  gnp2-2 (D2-3)      |  -> sknp3.9     |
//
// Ingress Policies (source ep1-1)
//
//   Tier1             |   Tier2             | Default         | Profile
//   np1-1 (A2-1,P2-2) | sgnp2-2 (N2-3)      |  snp3.2 (A2-2)  | (default A)
//                     |  snp2-3 (A2-2,D2-3) |   np3.3 (A2-2)  |
//                     |   np2-4 (D2-3)      |  snp3.4 (A2-2)  |
//
// A=allow; D=deny; N=no-match

// These tests include tests of Kubernetes policies as well as other policy types. To ensure we have the correct
// behavior, run using the Kubernetes infrastructure only.
var _ = infrastructure.DatastoreDescribe("_BPF-SAFE_ goldmane flow log with staged policy tests", []apiconfig.DatastoreType{apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
	const (
		wepPort = 8055
		svcPort = 8066
	)
	wepPortStr := fmt.Sprintf("%d", wepPort)
	svcPortStr := fmt.Sprintf("%d", svcPort)
	clusterIP := "10.101.0.10"

	var (
		infra                      infrastructure.DatastoreInfra
		opts                       infrastructure.TopologyOptions
		tc                         infrastructure.TopologyContainers
		client                     client.Interface
		ep1_1, ep2_1, ep2_2, ep2_3 *workload.Workload
		cc                         *connectivity.Checker
	)

	bpfEnabled := os.Getenv("FELIX_FV_ENABLE_BPF") == "true"

	BeforeEach(func() {
		infra = getInfra()
		opts = infrastructure.DefaultTopologyOptions()
		opts.IPIPMode = api.IPIPModeNever
		opts.FlowLogSource = infrastructure.FlowLogSourceLocalSocket

		opts.ExtraEnvVars["FELIX_FLOWLOGSFLUSHINTERVAL"] = "5"
		opts.ExtraEnvVars["FELIX_FLOWLOGSCOLLECTORDEBUGTRACE"] = "true"
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

		infrastructure.AssignIP("ep2-2", "10.65.1.1", tc.Felixes[1].Hostname, client)
		ep2_2 = workload.Run(tc.Felixes[1], "ep2-2", "default", "10.65.1.1", wepPortStr, "tcp")
		ep2_2.ConfigureInInfra(infra)

		infrastructure.AssignIP("ep2-3", "10.65.1.2", tc.Felixes[1].Hostname, client)
		ep2_3 = workload.Run(tc.Felixes[1], "ep2-3", "default", "10.65.1.2", wepPortStr, "tcp")
		ep2_3.ConfigureInInfra(infra)

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

		if !bpfEnabled {
			// Wait for felix to see and program some expected nflog entries, and for the cluster IP to appear.
			Eventually(getRuleFunc(tc.Felixes[0], "APE0|gnp/default.ep1-1-allow-all"), "10s", "1s").ShouldNot(HaveOccurred())
			Eventually(getRuleFunc(tc.Felixes[1], "APE0|gnp/default.ep1-1-allow-all"), "10s", "1s").Should(HaveOccurred())
			// When policies are programmed, make sure no staged policy is programmed. Staged policies must be skipped.
			Consistently(getRuleFunc(tc.Felixes[0], "staged"), "5s", "1s").Should(HaveOccurred())
			Consistently(getRuleFunc(tc.Felixes[1], "staged"), "5s", "1s").Should(HaveOccurred())
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

			bpfWaitForGlobalNetworkPolicy(tc.Felixes[0], ep1_1.InterfaceName, "ingress", "default.ep1-1-allow-all")
			bpfWaitForNetworkPolicy(tc.Felixes[1], ep2_2.InterfaceName, "ingress", "default", "tier1.np1-1")

			// When policies are programmed, make sure no staged policy is programmed. Staged policies must be skipped.
			Consistently(bpfDumpPolicy(tc.Felixes[0], ep1_1.InterfaceName, "ingress"), "5s", "1s").ShouldNot(ContainSubstring("staged"))
			Consistently(bpfDumpPolicy(tc.Felixes[0], ep1_1.InterfaceName, "egress"), "5s", "1s").ShouldNot(ContainSubstring("staged"))
			Consistently(bpfDumpPolicy(tc.Felixes[1], ep2_1.InterfaceName, "ingress"), "5s", "1s").ShouldNot(ContainSubstring("staged"))
			Consistently(bpfDumpPolicy(tc.Felixes[1], ep2_1.InterfaceName, "egress"), "5s", "1s").ShouldNot(ContainSubstring("staged"))
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
		cc.ExpectSome(ep1_1, ep2_2)                                             // allowed by np3-3
		cc.ExpectNone(ep1_1, ep2_3)                                             // denied by np2-4

		cc.ExpectSome(ep2_1, ep1_1) // allowed by profile
		cc.ExpectNone(ep2_2, ep1_1) // denied by np1-1
		cc.ExpectNone(ep2_3, ep1_1) // denied by gnp2-2

		// Do 3 rounds of connectivity checking.
		cc.CheckConnectivity()
		cc.CheckConnectivity()
		cc.CheckConnectivity()

		flowlogs.WaitForConntrackScan(bpfEnabled)

		// Delete conntrack state so that we don't keep seeing 0-metric copies of the logs.  This will allow the flows
		// to expire quickly.
		for ii := range tc.Felixes {
			tc.Felixes[ii].Exec("conntrack", "-F")
		}

		flowTester := flowlogs.NewFlowTester(flowlogs.FlowTesterOptions{
			ExpectLabels:           true,
			ExpectPendingPolicies:  true,
			ExpectEnforcedPolicies: true,
			MatchLabels:            false,
			MatchEnforcedPolicies:  true,
			MatchPendingPolicies:   true,
			Includes:               []flowlogs.IncludeFilter{flowlogs.IncludeByDestPort(wepPort)},
		})

		ep1_1_Meta := endpoint.Metadata{
			Type:           "wep",
			Namespace:      "default",
			Name:           flowlog.FieldNotIncluded,
			AggregatedName: ep1_1.Name,
		}
		ep2_1_Meta := endpoint.Metadata{
			Type:           "wep",
			Namespace:      "default",
			Name:           flowlog.FieldNotIncluded,
			AggregatedName: ep2_1.Name,
		}
		ep2_2_Meta := endpoint.Metadata{
			Type:           "wep",
			Namespace:      "default",
			Name:           flowlog.FieldNotIncluded,
			AggregatedName: ep2_2.Name,
		}
		ep2_3_Meta := endpoint.Metadata{
			Type:           "wep",
			Namespace:      "default",
			Name:           flowlog.FieldNotIncluded,
			AggregatedName: ep2_3.Name,
		}

		aggrTuple := tuple.Make(flowlog.EmptyIP, flowlog.EmptyIP, 6, flowlogs.SourcePortIsNotIncluded, wepPort)

		dstService := flowlog.FlowService{
			Namespace: "default",
			Name:      "test-service",
			PortName:  fmt.Sprintf("port-%d", wepPort),
			PortNum:   svcPort,
		}

		Eventually(func() error {
			// Felix 0.
			if err := flowTester.PopulateFromFlowLogs(tc.Felixes[0]); err != nil {
				return fmt.Errorf("Unable to populate flow tester from flow logs: %v", err)
			}

			// Ingress Policies (source ep1-1)
			//
			//   Tier1             |   Tier2             | Default        | Profile
			//   np1-1 (A2-1,P2-2) | sgnp2-2 (N2-3)      |  snp3.2 (A2-2) | (default A)
			//                     |  snp2-3 (A2-2,D2-3) |   np3.3 (A2-2) |
			//                     |   np2-4 (D2-3)      |  snp3.4 (A2-2) |

			// 1-1 -> 2-1 Allow
			// This was via the service cluster IP and therefore should contain the service name on the source side
			// where the DNAT occurs.
			flowTester.CheckFlow(
				flowlog.FlowLog{
					FlowMeta: flowlog.FlowMeta{
						Tuple:      aggrTuple,
						SrcMeta:    ep1_1_Meta,
						DstMeta:    ep2_1_Meta,
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
				},
			)

			// 1-1 -> 2-2 Allow
			flowTester.CheckFlow(
				flowlog.FlowLog{
					FlowMeta: flowlog.FlowMeta{
						Tuple:      aggrTuple,
						SrcMeta:    ep1_1_Meta,
						DstMeta:    ep2_2_Meta,
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
				},
			)

			// 1-1 -> 2-3 Allow
			flowTester.CheckFlow(
				flowlog.FlowLog{
					FlowMeta: flowlog.FlowMeta{
						Tuple:      aggrTuple,
						SrcMeta:    ep1_1_Meta,
						DstMeta:    ep2_3_Meta,
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
				},
			)

			// 2-1 -> 1-1 Allow
			flowTester.CheckFlow(
				flowlog.FlowLog{
					FlowMeta: flowlog.FlowMeta{
						Tuple:      aggrTuple,
						SrcMeta:    ep2_1_Meta,
						DstMeta:    ep1_1_Meta,
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
				},
			)

			if err := flowTester.Finish(); err != nil {
				return fmt.Errorf("Flows incorrect on Felix[0]:\n%v", err)
			}

			// Felix 1.
			if err := flowTester.PopulateFromFlowLogs(tc.Felixes[1]); err != nil {
				return fmt.Errorf("Unable to populate flow tester from flow logs: %v", err)
			}

			// 1-1 -> 2-3 Deny
			flowTester.CheckFlow(
				flowlog.FlowLog{
					FlowMeta: flowlog.FlowMeta{
						Tuple:      aggrTuple,
						SrcMeta:    ep1_1_Meta,
						DstMeta:    ep2_3_Meta,
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
				},
			)

			// 2-3 -> 1-1 Deny
			flowTester.CheckFlow(
				flowlog.FlowLog{
					FlowMeta: flowlog.FlowMeta{
						Tuple:      aggrTuple,
						SrcMeta:    ep2_3_Meta,
						DstMeta:    ep1_1_Meta,
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
				},
			)

			// 2-2 -> 1-1 Deny
			flowTester.CheckFlow(
				flowlog.FlowLog{
					FlowMeta: flowlog.FlowMeta{
						Tuple:      aggrTuple,
						SrcMeta:    ep2_2_Meta,
						DstMeta:    ep1_1_Meta,
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
				},
			)

			// 1-1 -> 2-2 Allow
			flowTester.CheckFlow(
				flowlog.FlowLog{
					FlowMeta: flowlog.FlowMeta{
						Tuple:      aggrTuple,
						SrcMeta:    ep1_1_Meta,
						DstMeta:    ep2_2_Meta,
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
				},
			)

			// 1-1 -> 2-1 Allow
			flowTester.CheckFlow(
				flowlog.FlowLog{
					FlowMeta: flowlog.FlowMeta{
						Tuple:      aggrTuple,
						SrcMeta:    ep1_1_Meta,
						DstMeta:    ep2_1_Meta,
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
				},
			)

			// 2-1 -> 1-1 Allow
			flowTester.CheckFlow(
				flowlog.FlowLog{
					FlowMeta: flowlog.FlowMeta{
						Tuple:      aggrTuple,
						SrcMeta:    ep2_1_Meta,
						DstMeta:    ep1_1_Meta,
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
				},
			)

			if err := flowTester.Finish(); err != nil {
				return fmt.Errorf("Flows incorrect on Felix[1]:\n%v", err)
			}

			return nil
		}, "30s", "3s").ShouldNot(HaveOccurred())
	})
})

// Felix1             Felix2
//
//	EP1-1 <-+-------> EP2-1
//
//	     ^           ^-- Apply test policies here (for ingress and egress)
//	     `-------------- Allow all policy
//
// Ingress/Egress Policies (dest ep1-1)
//
//	Tier1 | Tier2  | Default | Profile
//	np1-1 | snp2-1 |         | (default A)
//
// np1-1 will pass ingress and egress
// snp2-1 will be modified so that:
// - ingress and egress have no hits - so staged end of tier drop
// - ingress moved to a staged allow
// - egress moved to a staged allow
// - ingress moved to staged deny
// - egress moved to staged deny
//
// Each change to staged policy should result in a change of aggregation level.
var _ = infrastructure.DatastoreDescribe("_BPF-SAFE_ aggregation of flow log with staged policy tests", []apiconfig.DatastoreType{apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
	const (
		wepPort = 8055
		svcPort = 8066
	)
	wepPortStr := fmt.Sprintf("%d", wepPort)

	var (
		infra        infrastructure.DatastoreInfra
		opts         infrastructure.TopologyOptions
		tc           infrastructure.TopologyContainers
		client       client.Interface
		ep1_1, ep2_1 *workload.Workload
		cc           *connectivity.Checker
		snp          *api.StagedNetworkPolicy
	)

	bpfEnabled := os.Getenv("FELIX_FV_ENABLE_BPF") == "true"

	BeforeEach(func() {
		infra = getInfra()
		opts = infrastructure.DefaultTopologyOptions()
		opts.IPIPMode = api.IPIPModeNever
		opts.FlowLogSource = infrastructure.FlowLogSourceLocalSocket

		opts.ExtraEnvVars["FELIX_FLOWLOGSFLUSHINTERVAL"] = "5"
		opts.ExtraEnvVars["FELIX_FLOWLOGSCOLLECTORDEBUGTRACE"] = "true"
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

		// Create tiers tier1 and tier2
		tier := api.NewTier()
		tier.Name = "tier1"
		tier.Spec.Order = &float1_0
		_, err := client.Tiers().Create(utils.Ctx, tier, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

		tier = api.NewTier()
		tier.Name = "tier2"
		tier.Spec.Order = &float2_0
		_, err = client.Tiers().Create(utils.Ctx, tier, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

		// np1-1  egress/ingress pass
		np := api.NewNetworkPolicy()
		np.Name = "tier1.np1-1"
		np.Namespace = "default"
		np.Spec.Order = &float1_0
		np.Spec.Tier = "tier1"
		np.Spec.Selector = "name in {'" + ep1_1.Name + "', '" + ep2_1.Name + "'}"
		np.Spec.Types = []api.PolicyType{api.PolicyTypeIngress, api.PolicyTypeEgress}
		np.Spec.Egress = []api.Rule{
			{Action: api.Pass},
		}
		np.Spec.Ingress = []api.Rule{
			{Action: api.Pass},
		}
		_, err = client.NetworkPolicies().Create(utils.Ctx, np, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

		// Configure staged policy with EOT drop.
		snp = api.NewStagedNetworkPolicy()
		snp.Name = "tier2.np2-1"
		snp.Namespace = "default"
		snp.Spec.Order = &float1_0
		snp.Spec.Tier = "tier2"
		np.Spec.Selector = "name in {'" + ep1_1.Name + "', '" + ep2_1.Name + "'}"
		snp.Spec.Types = []api.PolicyType{api.PolicyTypeIngress, api.PolicyTypeEgress}
		snp, err = client.StagedNetworkPolicies().Create(utils.Ctx, snp, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

		if !bpfEnabled {
			Eventually(getRuleFunc(tc.Felixes[0], "PPI0|np/default/tier1.np1-1"), "10s", "1s").ShouldNot(HaveOccurred())
			Eventually(getRuleFunc(tc.Felixes[0], "PPE0|np/default/tier1.np1-1"), "10s", "1s").ShouldNot(HaveOccurred())
			Eventually(getRuleFunc(tc.Felixes[1], "PPI0|np/default/tier1.np1-1"), "10s", "1s").ShouldNot(HaveOccurred())
			Eventually(getRuleFunc(tc.Felixes[1], "PPE0|np/default/tier1.np1-1"), "10s", "1s").ShouldNot(HaveOccurred())
			// When policies are programmed, make sure no staged policy is programmed. Staged policies must be skipped.
			Consistently(getRuleFunc(tc.Felixes[0], "staged"), "5s", "1s").Should(HaveOccurred())
			Consistently(getRuleFunc(tc.Felixes[1], "staged"), "5s", "1s").Should(HaveOccurred())
		} else {
			bpfWaitForNetworkPolicy(tc.Felixes[0], ep1_1.InterfaceName, "egress", "default", "tier1.np1-1")
			bpfWaitForNetworkPolicy(tc.Felixes[0], ep1_1.InterfaceName, "ingress", "default", "tier1.np1-1")
			bpfWaitForNetworkPolicy(tc.Felixes[1], ep2_1.InterfaceName, "egress", "default", "tier1.np1-1")
			bpfWaitForNetworkPolicy(tc.Felixes[1], ep2_1.InterfaceName, "ingress", "default", "tier1.np1-1")
			// When policies are programmed, make sure no staged policy is programmed. Staged policies must be skipped.
			Consistently(bpfDumpPolicy(tc.Felixes[0], ep1_1.InterfaceName, "ingress"), "5s", "1s").ShouldNot(ContainSubstring("staged"))
			Consistently(bpfDumpPolicy(tc.Felixes[0], ep1_1.InterfaceName, "egress"), "5s", "1s").ShouldNot(ContainSubstring("staged"))
			Consistently(bpfDumpPolicy(tc.Felixes[1], ep2_1.InterfaceName, "ingress"), "5s", "1s").ShouldNot(ContainSubstring("staged"))
			Consistently(bpfDumpPolicy(tc.Felixes[1], ep2_1.InterfaceName, "egress"), "5s", "1s").ShouldNot(ContainSubstring("staged"))
		}
	})

	confugureTier2Pass := func() {
		// Update staged network policy to allow ingress and egress.
		// Use a multitude of rule specs to test that the flow logs are correctly selected.
		var err error
		actionPass := api.Pass
		tier, err := client.Tiers().Get(utils.Ctx, "tier2", options.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		tier.Spec.DefaultAction = &actionPass
		_, err = client.Tiers().Update(utils.Ctx, tier, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

		if !bpfEnabled {
			// Wait for felix to see and program some expected nflog entries, and for the cluster IP to appear.
			Eventually(getRuleFunc(tc.Felixes[0], "PPI0|np/default/tier1.np1-1"), "10s", "1s").ShouldNot(HaveOccurred())
			Eventually(getRuleFunc(tc.Felixes[0], "PPE0|np/default/tier1.np1-1"), "10s", "1s").ShouldNot(HaveOccurred())
			Eventually(getRuleFunc(tc.Felixes[1], "PPI0|np/default/tier1.np1-1"), "10s", "1s").ShouldNot(HaveOccurred())
			Eventually(getRuleFunc(tc.Felixes[1], "PPE0|np/default/tier1.np1-1"), "10s", "1s").ShouldNot(HaveOccurred())
			// When policies are programmed, make sure no staged policy is programmed. Staged policies must be skipped.
			Consistently(getRuleFunc(tc.Felixes[0], "staged"), "5s", "1s").Should(HaveOccurred())
			Consistently(getRuleFunc(tc.Felixes[1], "staged"), "5s", "1s").Should(HaveOccurred())
		} else {
			bpfWaitForNetworkPolicy(tc.Felixes[0], ep1_1.InterfaceName, "egress", "default", "tier1.np1-1")
			bpfWaitForNetworkPolicy(tc.Felixes[0], ep1_1.InterfaceName, "ingress", "default", "tier1.np1-1")
			bpfWaitForNetworkPolicy(tc.Felixes[1], ep2_1.InterfaceName, "egress", "default", "tier1.np1-1")
			bpfWaitForNetworkPolicy(tc.Felixes[1], ep2_1.InterfaceName, "ingress", "default", "tier1.np1-1")
			// When policies are programmed, make sure no staged policy is programmed. Staged policies must be skipped.
			Consistently(bpfDumpPolicy(tc.Felixes[0], ep1_1.InterfaceName, "ingress"), "5s", "1s").ShouldNot(ContainSubstring("staged"))
			Consistently(bpfDumpPolicy(tc.Felixes[0], ep1_1.InterfaceName, "egress"), "5s", "1s").ShouldNot(ContainSubstring("staged"))
			Consistently(bpfDumpPolicy(tc.Felixes[1], ep2_1.InterfaceName, "ingress"), "5s", "1s").ShouldNot(ContainSubstring("staged"))
			Consistently(bpfDumpPolicy(tc.Felixes[1], ep2_1.InterfaceName, "egress"), "5s", "1s").ShouldNot(ContainSubstring("staged"))
		}
	}

	configureStagedAllow := func() {
		// Update staged network policy to allow ingress and egress.
		var err error
		snp.Spec.Egress = []api.Rule{{Action: api.Allow}}
		snp.Spec.Ingress = []api.Rule{{Action: api.Allow}}
		snp, err = client.StagedNetworkPolicies().Update(utils.Ctx, snp, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

		if !bpfEnabled {
			// Wait for felix to see and program some expected nflog entries, and for the cluster IP to appear.
			Eventually(getRuleFunc(tc.Felixes[0], "PPI0|np/default/tier1.np1-1"), "10s", "1s").ShouldNot(HaveOccurred())
			Eventually(getRuleFunc(tc.Felixes[0], "PPE0|np/default/tier1.np1-1"), "10s", "1s").ShouldNot(HaveOccurred())
			Eventually(getRuleFunc(tc.Felixes[1], "PPI0|np/default/tier1.np1-1"), "10s", "1s").ShouldNot(HaveOccurred())
			Eventually(getRuleFunc(tc.Felixes[1], "PPE0|np/default/tier1.np1-1"), "10s", "1s").ShouldNot(HaveOccurred())
			// When policies are programmed, make sure no staged policy is programmed. Staged policies must be skipped.
			Consistently(getRuleFunc(tc.Felixes[0], "staged"), "5s", "1s").Should(HaveOccurred())
			Consistently(getRuleFunc(tc.Felixes[1], "staged"), "5s", "1s").Should(HaveOccurred())
		} else {
			bpfWaitForNetworkPolicy(tc.Felixes[0], ep1_1.InterfaceName, "egress", "default", "tier1.np1-1")
			bpfWaitForNetworkPolicy(tc.Felixes[0], ep1_1.InterfaceName, "ingress", "default", "tier1.np1-1")
			bpfWaitForNetworkPolicy(tc.Felixes[1], ep2_1.InterfaceName, "egress", "default", "tier1.np1-1")
			bpfWaitForNetworkPolicy(tc.Felixes[1], ep2_1.InterfaceName, "ingress", "default", "tier1.np1-1")
			// When policies are programmed, make sure no staged policy is programmed. Staged policies must be skipped.
			Consistently(bpfDumpPolicy(tc.Felixes[0], ep1_1.InterfaceName, "ingress"), "5s", "1s").ShouldNot(ContainSubstring("staged"))
			Consistently(bpfDumpPolicy(tc.Felixes[0], ep1_1.InterfaceName, "egress"), "5s", "1s").ShouldNot(ContainSubstring("staged"))
			Consistently(bpfDumpPolicy(tc.Felixes[1], ep2_1.InterfaceName, "ingress"), "5s", "1s").ShouldNot(ContainSubstring("staged"))
			Consistently(bpfDumpPolicy(tc.Felixes[1], ep2_1.InterfaceName, "egress"), "5s", "1s").ShouldNot(ContainSubstring("staged"))
		}

		time.Sleep(3 * time.Second)
	}

	configureStagedDrop := func() {
		// Update staged network policy to deny ingress and egress.
		var err error
		snp.Spec.Egress = []api.Rule{{Action: api.Deny}}
		snp.Spec.Ingress = []api.Rule{{Action: api.Deny}}
		snp, err = client.StagedNetworkPolicies().Update(utils.Ctx, snp, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

		if !bpfEnabled {
			// Wait for felix to see and program some expected nflog entries, and for the cluster IP to appear.
			Eventually(getRuleFunc(tc.Felixes[0], "PPI0|np/default/tier1.np1-1"), "10s", "1s").ShouldNot(HaveOccurred())
			Eventually(getRuleFunc(tc.Felixes[0], "PPE0|np/default/tier1.np1-1"), "10s", "1s").ShouldNot(HaveOccurred())
			Eventually(getRuleFunc(tc.Felixes[1], "PPI0|np/default/tier1.np1-1"), "10s", "1s").ShouldNot(HaveOccurred())
			Eventually(getRuleFunc(tc.Felixes[1], "PPE0|np/default/tier1.np1-1"), "10s", "1s").ShouldNot(HaveOccurred())
			// When policies are programmed, make sure no staged policy is programmed. Staged policies must be skipped.
			Consistently(getRuleFunc(tc.Felixes[0], "staged"), "5s", "1s").Should(HaveOccurred())
			Consistently(getRuleFunc(tc.Felixes[1], "staged"), "5s", "1s").Should(HaveOccurred())
		} else {
			bpfWaitForNetworkPolicy(tc.Felixes[0], ep1_1.InterfaceName, "egress", "default", "tier1.np1-1")
			bpfWaitForNetworkPolicy(tc.Felixes[0], ep1_1.InterfaceName, "ingress", "default", "tier1.np1-1")
			bpfWaitForNetworkPolicy(tc.Felixes[1], ep2_1.InterfaceName, "egress", "default", "tier1.np1-1")
			bpfWaitForNetworkPolicy(tc.Felixes[1], ep2_1.InterfaceName, "ingress", "default", "tier1.np1-1")

			// When policies are programmed, make sure no staged policy is programmed. Staged policies must be skipped.
			Consistently(bpfDumpPolicy(tc.Felixes[0], ep1_1.InterfaceName, "ingress"), "5s", "1s").ShouldNot(ContainSubstring("staged"))
			Consistently(bpfDumpPolicy(tc.Felixes[0], ep1_1.InterfaceName, "egress"), "5s", "1s").ShouldNot(ContainSubstring("staged"))
			Consistently(bpfDumpPolicy(tc.Felixes[1], ep2_1.InterfaceName, "ingress"), "5s", "1s").ShouldNot(ContainSubstring("staged"))
			Consistently(bpfDumpPolicy(tc.Felixes[1], ep2_1.InterfaceName, "egress"), "5s", "1s").ShouldNot(ContainSubstring("staged"))
		}
	}

	It("should get expected flow logs going from Staged EOT drop to Staged Allow", func() {
		// Describe the connectivity that we now expect.
		// For ep1_1 -> ep2_1 we use the service cluster IP to test service info in the flow log
		cc = &connectivity.Checker{}
		cc.ExpectSome(ep1_1, ep2_1)
		// Do 3 rounds of connectivity checking.
		cc.CheckConnectivity()
		cc.CheckConnectivity()
		cc.CheckConnectivity()

		flowlogs.WaitForConntrackScan(bpfEnabled)

		// Configured staged allow.
		configureStagedAllow()

		// Do 3 rounds of connectivity checking.
		cc.CheckConnectivity()
		cc.CheckConnectivity()
		cc.CheckConnectivity()

		flowlogs.WaitForConntrackScan(bpfEnabled)

		// Delete conntrack state so that we don't keep seeing 0-metric copies of the logs.  This will allow the flows
		// to expire quickly.
		for ii := range tc.Felixes {
			tc.Felixes[ii].Exec("conntrack", "-F")
		}

		flowTester := flowlogs.NewFlowTester(flowlogs.FlowTesterOptions{
			ExpectLabels:           true,
			ExpectPendingPolicies:  true,
			ExpectEnforcedPolicies: true,
			MatchLabels:            false,
			MatchPendingPolicies:   false,
			Includes:               []flowlogs.IncludeFilter{flowlogs.IncludeByDestPort(wepPort)},
		})

		ep1_1_Meta := endpoint.Metadata{
			Type:           "wep",
			Namespace:      "default",
			Name:           flowlog.FieldNotIncluded,
			AggregatedName: ep1_1.Name,
		}
		ep2_1_Meta := endpoint.Metadata{
			Type:           "wep",
			Namespace:      "default",
			Name:           flowlog.FieldNotIncluded,
			AggregatedName: ep2_1.Name,
		}

		aggrTuple := tuple.Make(flowlog.EmptyIP, flowlog.EmptyIP, 6, flowlogs.SourcePortIsNotIncluded, wepPort)

		Eventually(func() error {
			// Felix 0.
			if err := flowTester.PopulateFromFlowLogs(tc.Felixes[0]); err != nil {
				return fmt.Errorf("Unable to populate flow tester from flow logs: %v", err)
			}

			flowTester.CheckFlow(
				flowlog.FlowLog{
					FlowMeta: flowlog.FlowMeta{
						Tuple:      aggrTuple,
						SrcMeta:    ep1_1_Meta,
						DstMeta:    ep2_1_Meta,
						DstService: flowlog.EmptyService,
						Action:     "allow",
						Reporter:   "src",
					},
					FlowEnforcedPolicySet: flowlog.FlowPolicySet{
						"0|tier1|default/tier1.np1-1|pass|0":            {},
						"1|__PROFILE__|__PROFILE__.kns.default|allow|0": {},
					},
				},
			)

			if err := flowTester.Finish(); err != nil {
				return fmt.Errorf("Flows incorrect on Felix[0]:\n%v", err)
			}

			// Felix 1.
			if err := flowTester.PopulateFromFlowLogs(tc.Felixes[1]); err != nil {
				return fmt.Errorf("Unable to populate flow tester from flow logs: %v", err)
			}

			flowTester.CheckFlow(
				flowlog.FlowLog{
					FlowMeta: flowlog.FlowMeta{
						Tuple:      aggrTuple,
						SrcMeta:    ep1_1_Meta,
						DstService: flowlog.EmptyService,
						DstMeta:    ep2_1_Meta,
						Action:     "allow",
						Reporter:   "dst",
					},
					FlowEnforcedPolicySet: flowlog.FlowPolicySet{
						"0|tier1|default/tier1.np1-1|pass|0":            {},
						"1|__PROFILE__|__PROFILE__.kns.default|allow|0": {},
					},
				},
			)

			if err := flowTester.Finish(); err != nil {
				return fmt.Errorf("Flows incorrect on Felix[1]:\n%v", err)
			}

			return nil
		}, "60s", "1s").ShouldNot(HaveOccurred())
	})

	It("should get expected flow logs going from Staged EOT deny to Staged EOT pass", func() {
		// Describe the connectivity that we now expect.
		// For ep1_1 -> ep2_1 we use the service cluster IP to test service info in the flow log
		cc = &connectivity.Checker{}
		cc.ExpectSome(ep1_1, ep2_1)
		// Do 3 rounds of connectivity checking.
		cc.CheckConnectivity()
		cc.CheckConnectivity()
		cc.CheckConnectivity()

		flowlogs.WaitForConntrackScan(bpfEnabled)

		// TODO (dimitrin): This is expected to fail once
		// https://tigera.atlassian.net/browse/EV-5659 has been merged. At which point the staged
		// policy EOT expected action should be changed from DPI and DPE to PPI and PPE,
		// respectively.
		// Configured tier pass.
		confugureTier2Pass()

		// Do 3 rounds of connectivity checking.
		cc.CheckConnectivity()
		cc.CheckConnectivity()
		cc.CheckConnectivity()

		flowlogs.WaitForConntrackScan(bpfEnabled)

		// Delete conntrack state so that we don't keep seeing 0-metric copies of the logs.  This will allow the flows
		// to expire quickly.
		for ii := range tc.Felixes {
			tc.Felixes[ii].Exec("conntrack", "-F")
		}

		flowTester := flowlogs.NewFlowTester(flowlogs.FlowTesterOptions{
			ExpectLabels:           true,
			ExpectEnforcedPolicies: true,
			ExpectPendingPolicies:  true,
			MatchLabels:            false,
			MatchEnforcedPolicies:  true,
			MatchPendingPolicies:   true,
			Includes:               []flowlogs.IncludeFilter{flowlogs.IncludeByDestPort(wepPort)},
		})

		ep1_1_Meta := endpoint.Metadata{
			Type:           "wep",
			Namespace:      "default",
			Name:           flowlog.FieldNotIncluded,
			AggregatedName: ep1_1.Name,
		}
		ep2_1_Meta := endpoint.Metadata{
			Type:           "wep",
			Namespace:      "default",
			Name:           flowlog.FieldNotIncluded,
			AggregatedName: ep2_1.Name,
		}

		aggrTuple := tuple.Make(flowlog.EmptyIP, flowlog.EmptyIP, 6, flowlogs.SourcePortIsNotIncluded, wepPort)

		Eventually(func() error {
			// Felix 0.
			if err := flowTester.PopulateFromFlowLogs(tc.Felixes[0]); err != nil {
				return fmt.Errorf("Unable to populate flow tester from flow logs: %v", err)
			}

			flowTester.CheckFlow(
				flowlog.FlowLog{
					FlowMeta: flowlog.FlowMeta{
						Tuple:      aggrTuple,
						SrcMeta:    ep1_1_Meta,
						DstMeta:    ep2_1_Meta,
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
						"1|tier2|default/tier2.staged:tier2.np2-1|deny|-1": {},
					},
				},
			)
			flowTester.CheckFlow(
				flowlog.FlowLog{
					FlowMeta: flowlog.FlowMeta{
						Tuple:      aggrTuple,
						SrcMeta:    ep1_1_Meta,
						DstMeta:    ep2_1_Meta,
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
						"1|tier2|default/tier2.staged:tier2.np2-1|pass|-1": {},
						"2|__PROFILE__|__PROFILE__.kns.default|allow|0":    {},
					},
				},
			)

			if err := flowTester.Finish(); err != nil {
				return fmt.Errorf("Flows incorrect on Felix[0]:\n%v", err)
			}

			// Felix 1.
			if err := flowTester.PopulateFromFlowLogs(tc.Felixes[1]); err != nil {
				return fmt.Errorf("Unable to populate flow tester from flow logs: %v", err)
			}

			flowTester.CheckFlow(
				flowlog.FlowLog{
					FlowMeta: flowlog.FlowMeta{
						Tuple:      aggrTuple,
						SrcMeta:    ep1_1_Meta,
						DstService: flowlog.EmptyService,
						DstMeta:    ep2_1_Meta,
						Action:     "allow",
						Reporter:   "dst",
					},
					FlowEnforcedPolicySet: flowlog.FlowPolicySet{
						"0|tier1|default/tier1.np1-1|pass|0":            {},
						"1|__PROFILE__|__PROFILE__.kns.default|allow|0": {},
					},
					FlowPendingPolicySet: flowlog.FlowPolicySet{
						"0|tier1|default/tier1.np1-1|pass|0":               {},
						"1|tier2|default/tier2.staged:tier2.np2-1|deny|-1": {},
					},
				},
			)
			flowTester.CheckFlow(
				flowlog.FlowLog{
					FlowMeta: flowlog.FlowMeta{
						Tuple:      aggrTuple,
						SrcMeta:    ep1_1_Meta,
						DstService: flowlog.EmptyService,
						DstMeta:    ep2_1_Meta,
						Action:     "allow",
						Reporter:   "dst",
					},
					FlowEnforcedPolicySet: flowlog.FlowPolicySet{
						"0|tier1|default/tier1.np1-1|pass|0":            {},
						"1|__PROFILE__|__PROFILE__.kns.default|allow|0": {},
					},
					FlowPendingPolicySet: flowlog.FlowPolicySet{
						"0|tier1|default/tier1.np1-1|pass|0":               {},
						"1|tier2|default/tier2.staged:tier2.np2-1|pass|-1": {},
						"2|__PROFILE__|__PROFILE__.kns.default|allow|0":    {},
					},
				},
			)

			if err := flowTester.Finish(); err != nil {
				return fmt.Errorf("Flows incorrect on Felix[1]:\n%v", err)
			}

			return nil
		}, "60s", "1s").ShouldNot(HaveOccurred())
	})

	It("should get expected flow logs going from Staged Allow to Staged Drop", func() {
		// Configure the staged allow.
		configureStagedAllow()

		// Describe the connectivity that we now expect.
		// For ep1_1 -> ep2_1 we use the service cluster IP to test service info in the flow log
		cc = &connectivity.Checker{}
		cc.ExpectSome(ep1_1, ep2_1)
		// Do 3 rounds of connectivity checking.
		cc.CheckConnectivity()
		cc.CheckConnectivity()
		cc.CheckConnectivity()

		flowlogs.WaitForConntrackScan(bpfEnabled)

		// Configure staged drop.
		configureStagedDrop()

		// Do 3 rounds of connectivity checking.
		cc.CheckConnectivity()
		cc.CheckConnectivity()
		cc.CheckConnectivity()

		flowlogs.WaitForConntrackScan(bpfEnabled)

		// Delete conntrack state so that we don't keep seeing 0-metric copies of the logs.  This will allow the flows
		// to expire quickly.
		for ii := range tc.Felixes {
			tc.Felixes[ii].Exec("conntrack", "-F")
		}

		flowTester := flowlogs.NewFlowTester(flowlogs.FlowTesterOptions{
			ExpectLabels:           true,
			ExpectPendingPolicies:  true,
			ExpectEnforcedPolicies: true,
			MatchLabels:            false,
			MatchPendingPolicies:   false,
			MatchEnforcedPolicies:  false,
			Includes:               []flowlogs.IncludeFilter{flowlogs.IncludeByDestPort(wepPort)},
		})

		ep1_1_Meta := endpoint.Metadata{
			Type:           "wep",
			Namespace:      "default",
			Name:           flowlog.FieldNotIncluded,
			AggregatedName: ep1_1.Name,
		}
		ep2_1_Meta := endpoint.Metadata{
			Type:           "wep",
			Namespace:      "default",
			Name:           flowlog.FieldNotIncluded,
			AggregatedName: ep2_1.Name,
		}

		aggrTuple := tuple.Make(flowlog.EmptyIP, flowlog.EmptyIP, 6, flowlogs.SourcePortIsNotIncluded, wepPort)

		Eventually(func() error {
			// Felix 0.
			if err := flowTester.PopulateFromFlowLogs(tc.Felixes[0]); err != nil {
				return fmt.Errorf("Unable to populate flow tester from flow logs: %v", err)
			}

			flowTester.CheckFlow(
				flowlog.FlowLog{
					FlowMeta: flowlog.FlowMeta{
						Tuple:      aggrTuple,
						SrcMeta:    ep1_1_Meta,
						DstMeta:    ep2_1_Meta,
						DstService: flowlog.EmptyService,
						Action:     "allow",
						Reporter:   "src",
					},
					FlowEnforcedPolicySet: flowlog.FlowPolicySet{
						"0|tier1|default/tier1.np1-1|pass|0":            {},
						"1|__PROFILE__|__PROFILE__.kns.default|allow|0": {},
					},
				},
			)

			if err := flowTester.Finish(); err != nil {
				return fmt.Errorf("Flows incorrect on Felix[0]:\n%v", err)
			}

			// Felix 1.
			if err := flowTester.PopulateFromFlowLogs(tc.Felixes[1]); err != nil {
				return fmt.Errorf("Unable to populate flow tester from flow logs: %v", err)
			}

			flowTester.CheckFlow(
				flowlog.FlowLog{
					FlowMeta: flowlog.FlowMeta{
						Tuple:      aggrTuple,
						SrcMeta:    ep1_1_Meta,
						DstService: flowlog.EmptyService,
						DstMeta:    ep2_1_Meta,
						Action:     "allow",
						Reporter:   "dst",
					},
					FlowEnforcedPolicySet: flowlog.FlowPolicySet{
						"0|tier1|default/tier1.np1-1|pass|0":            {},
						"1|__PROFILE__|__PROFILE__.kns.default|allow|0": {},
					},
				},
			)

			if err := flowTester.Finish(); err != nil {
				return fmt.Errorf("Flows incorrect on Felix[1]:\n%v", err)
			}

			return nil
		}, "30s", "3s").ShouldNot(HaveOccurred())
	})
})

// Felix1             Felix2
//
//	EP1-1 <-+-------> EP2-1
//
//	     ^           ^
//	     `-----------`-- Apply test policies (for ingress and egress)
//
//	Tier1 | Tier2  | Default | Profile
//	np1-1 | snp2-1 |         | (default A)
//
// np1-1 will pass ingress and egress
// snp2-1 will be modified within the flush log interval so that:
// AllPolicies
// - ingress and egress have no hits - so staged end of tier drop
// - ingress moved to a staged allow
// PendingPolicies
// - egress moved to a staged allow prior to the flush log interval
var _ = infrastructure.DatastoreDescribe("_BPF-SAFE_ goldmane flow log with staged policies with pending policy tests", []apiconfig.DatastoreType{apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
	const (
		wepPort  = 8055
		wep2Port = 8056
	)
	wepPortStr := fmt.Sprintf("%d", wepPort)

	var (
		infra        infrastructure.DatastoreInfra
		opts         infrastructure.TopologyOptions
		tc           infrastructure.TopologyContainers
		client       client.Interface
		ep1_1, ep2_1 *workload.Workload
		cc           *connectivity.Checker
		snp          *api.StagedNetworkPolicy
	)

	bpfEnabled := os.Getenv("FELIX_FV_ENABLE_BPF") == "true"

	BeforeEach(func() {
		infra = getInfra()
		opts = infrastructure.DefaultTopologyOptions()
		opts.IPIPMode = api.IPIPModeNever
		opts.FlowLogSource = infrastructure.FlowLogSourceLocalSocket

		opts.ExtraEnvVars["FELIX_FLOWLOGSFLUSHINTERVAL"] = "3"
		opts.ExtraEnvVars["FELIX_FLOWLOGSCOLLECTORDEBUGTRACE"] = "true"
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

		// Create tiers tier1 and tier2
		tier := api.NewTier()
		tier.Name = "tier1"
		tier.Spec.Order = &float1_0
		_, err := client.Tiers().Create(utils.Ctx, tier, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

		tier = api.NewTier()
		tier.Name = "tier2"
		tier.Spec.Order = &float2_0
		_, err = client.Tiers().Create(utils.Ctx, tier, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

		// np1-1  egress/ingress pass
		np := api.NewNetworkPolicy()
		np.Name = "tier1.np1-1"
		np.Namespace = "default"
		np.Spec.Order = &float1_0
		np.Spec.Tier = "tier1"
		np.Spec.Selector = "name in {'" + ep1_1.Name + "', '" + ep2_1.Name + "'}"
		np.Spec.Types = []api.PolicyType{api.PolicyTypeIngress, api.PolicyTypeEgress}
		np.Spec.Egress = []api.Rule{
			{Action: api.Pass},
		}
		np.Spec.Ingress = []api.Rule{
			{Action: api.Pass},
		}
		_, err = client.NetworkPolicies().Create(utils.Ctx, np, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

		// Configure staged policy with EOT drop.
		snp = api.NewStagedNetworkPolicy()
		snp.Name = "tier2.np2-1"
		snp.Namespace = "default"
		snp.Spec.Order = &float1_0
		snp.Spec.Tier = "tier2"
		np.Spec.Selector = "name in {'" + ep1_1.Name + "', '" + ep2_1.Name + "'}"
		snp.Spec.Types = []api.PolicyType{api.PolicyTypeIngress, api.PolicyTypeEgress}
		snp, err = client.StagedNetworkPolicies().Create(utils.Ctx, snp, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

		if !bpfEnabled {
			Eventually(getRuleFunc(tc.Felixes[0], "PPI0|np/default/tier1.np1-1"), "10s", "1s").ShouldNot(HaveOccurred())
			Eventually(getRuleFunc(tc.Felixes[0], "PPE0|np/default/tier1.np1-1"), "10s", "1s").ShouldNot(HaveOccurred())
			Eventually(getRuleFunc(tc.Felixes[1], "PPI0|np/default/tier1.np1-1"), "10s", "1s").ShouldNot(HaveOccurred())
			Eventually(getRuleFunc(tc.Felixes[1], "PPE0|np/default/tier1.np1-1"), "10s", "1s").ShouldNot(HaveOccurred())
			// When policies are programmed, make sure no staged policy is programmed. Staged policies must be skipped.
			Consistently(getRuleFunc(tc.Felixes[0], "staged"), "5s", "1s").Should(HaveOccurred())
			Consistently(getRuleFunc(tc.Felixes[1], "staged"), "5s", "1s").Should(HaveOccurred())
		} else {
			bpfWaitForNetworkPolicy(tc.Felixes[0], ep1_1.InterfaceName, "egress", "default", "tier1.np1-1")
			bpfWaitForNetworkPolicy(tc.Felixes[0], ep1_1.InterfaceName, "ingress", "default", "tier1.np1-1")
			bpfWaitForNetworkPolicy(tc.Felixes[1], ep2_1.InterfaceName, "egress", "default", "tier1.np1-1")
			bpfWaitForNetworkPolicy(tc.Felixes[1], ep2_1.InterfaceName, "ingress", "default", "tier1.np1-1")

			// When policies are programmed, make sure no staged policy is programmed. Staged policies must be skipped.
			Consistently(bpfDumpPolicy(tc.Felixes[0], ep1_1.InterfaceName, "ingress"), "5s", "1s").ShouldNot(ContainSubstring("staged"))
			Consistently(bpfDumpPolicy(tc.Felixes[0], ep1_1.InterfaceName, "egress"), "5s", "1s").ShouldNot(ContainSubstring("staged"))
			Consistently(bpfDumpPolicy(tc.Felixes[1], ep2_1.InterfaceName, "ingress"), "5s", "1s").ShouldNot(ContainSubstring("staged"))
			Consistently(bpfDumpPolicy(tc.Felixes[1], ep2_1.InterfaceName, "egress"), "5s", "1s").ShouldNot(ContainSubstring("staged"))
		}
	})

	configureStagedAllow := func() {
		// Update staged network policy to allow ingress and egress.
		// Use a multitude of rule specs to test that the flow logs are correctly selected.
		var err error
		protoTCP := numorstring.ProtocolFromString(numorstring.ProtocolTCP)
		protoUDP := numorstring.ProtocolFromString(numorstring.ProtocolUDP)
		snp.Spec.Egress = []api.Rule{
			{
				Action:   api.Allow,
				Protocol: &protoUDP,
				Source: api.EntityRule{
					Nets: []string{"10.65.0.0/32"},
				},
				Destination: api.EntityRule{
					Nets:  []string{"10.65.1.0/32"},
					Ports: []numorstring.Port{numorstring.SinglePort(wepPort)},
				},
			},
			{
				Action:   api.Allow,
				Protocol: &protoTCP,
				Source: api.EntityRule{
					Nets: []string{"10.65.0.0/32"},
				},
				Destination: api.EntityRule{
					Nets:     []string{"10.65.1.0/32"},
					NotPorts: []numorstring.Port{numorstring.SinglePort(wepPort)},
				},
			},
			{
				Action:   api.Allow,
				Protocol: &protoTCP,
				Source: api.EntityRule{
					Nets:              []string{"10.65.0.0/32"},
					Selector:          "name in {'" + ep1_1.Name + "'}",
					NamespaceSelector: "projectcalico.org/name == 'default'",
				},
				Destination: api.EntityRule{
					Nets:              []string{"10.65.1.0/32"},
					Ports:             []numorstring.Port{numorstring.SinglePort(wepPort)},
					Selector:          "name in {'" + ep2_1.Name + "'}",
					NamespaceSelector: "projectcalico.org/name == 'default'",
				},
			},
		}
		snp.Spec.Ingress = []api.Rule{
			{
				Action:   api.Allow,
				Protocol: &protoUDP,
				Source: api.EntityRule{
					Nets: []string{"10.65.0.0/32"},
				},
				Destination: api.EntityRule{
					Nets:  []string{"10.65.1.0/32"},
					Ports: []numorstring.Port{numorstring.SinglePort(wepPort)},
				},
			},
			{
				Action:   api.Allow,
				Protocol: &protoTCP,
				Source: api.EntityRule{
					NotNets: []string{"10.65.3.0/32"},
				},
				Destination: api.EntityRule{
					NotPorts:    []numorstring.Port{numorstring.SinglePort(wep2Port)},
					NotSelector: "name in {'" + ep1_1.Name + "'}",
				},
			},
			{
				Action:   api.Allow,
				Protocol: &protoTCP,
				Source: api.EntityRule{
					Nets: []string{"10.65.0.0/32"},
				},
				Destination: api.EntityRule{
					Nets:  []string{"10.65.1.0/32"},
					Ports: []numorstring.Port{numorstring.SinglePort(wepPort)},
				},
			},
		}
		snp, err = client.StagedNetworkPolicies().Update(utils.Ctx, snp, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

		if !bpfEnabled {
			// Wait for felix to see and program some expected nflog entries, and for the cluster IP to appear.
			Eventually(getRuleFunc(tc.Felixes[0], "PPI0|np/default/tier1.np1-1"), "10s", "1s").ShouldNot(HaveOccurred())
			Eventually(getRuleFunc(tc.Felixes[0], "PPE0|np/default/tier1.np1-1"), "10s", "1s").ShouldNot(HaveOccurred())
			Eventually(getRuleFunc(tc.Felixes[1], "PPI0|np/default/tier1.np1-1"), "10s", "1s").ShouldNot(HaveOccurred())
			Eventually(getRuleFunc(tc.Felixes[1], "PPE0|np/default/tier1.np1-1"), "10s", "1s").ShouldNot(HaveOccurred())
			// When policies are programmed, make sure no staged policy is programmed. Staged policies must be skipped.
			Consistently(getRuleFunc(tc.Felixes[0], "staged"), "5s", "1s").Should(HaveOccurred())
			Consistently(getRuleFunc(tc.Felixes[1], "staged"), "5s", "1s").Should(HaveOccurred())
		} else {
			bpfWaitForNetworkPolicy(tc.Felixes[0], ep1_1.InterfaceName, "egress", "default", "tier1.np1-1")
			bpfWaitForNetworkPolicy(tc.Felixes[0], ep1_1.InterfaceName, "ingress", "default", "tier1.np1-1")
			bpfWaitForNetworkPolicy(tc.Felixes[1], ep2_1.InterfaceName, "egress", "default", "tier1.np1-1")
			bpfWaitForNetworkPolicy(tc.Felixes[1], ep2_1.InterfaceName, "ingress", "default", "tier1.np1-1")

			// When policies are programmed, make sure no staged policy is programmed. Staged policies must be skipped.
			Consistently(bpfDumpPolicy(tc.Felixes[0], ep1_1.InterfaceName, "ingress"), "5s", "1s").ShouldNot(ContainSubstring("staged"))
			Consistently(bpfDumpPolicy(tc.Felixes[0], ep1_1.InterfaceName, "egress"), "5s", "1s").ShouldNot(ContainSubstring("staged"))
			Consistently(bpfDumpPolicy(tc.Felixes[1], ep2_1.InterfaceName, "ingress"), "5s", "1s").ShouldNot(ContainSubstring("staged"))
			Consistently(bpfDumpPolicy(tc.Felixes[1], ep2_1.InterfaceName, "egress"), "5s", "1s").ShouldNot(ContainSubstring("staged"))
		}

		time.Sleep(5 * time.Second)
	}

	configureStagedPass := func() {
		// Update staged network policy to allow ingress and egress.
		// Use a multitude of rule specs to test that the flow logs are correctly selected.
		var err error
		protoTCP := numorstring.ProtocolFromString(numorstring.ProtocolTCP)
		snp.Spec.Egress = []api.Rule{
			{
				Action:   api.Pass,
				Protocol: &protoTCP,
				Source: api.EntityRule{
					Nets: []string{"10.65.0.0/32"},
				},
				Destination: api.EntityRule{
					Nets:  []string{"10.65.1.0/32"},
					Ports: []numorstring.Port{numorstring.SinglePort(wepPort)},
				},
			},
		}
		snp.Spec.Ingress = []api.Rule{
			{
				Action:   api.Pass,
				Protocol: &protoTCP,
				Source: api.EntityRule{
					Nets: []string{"10.65.0.0/32"},
				},
				Destination: api.EntityRule{
					Nets:  []string{"10.65.1.0/32"},
					Ports: []numorstring.Port{numorstring.SinglePort(wepPort)},
				},
			},
		}
		snp, err = client.StagedNetworkPolicies().Update(utils.Ctx, snp, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

		if !bpfEnabled {
			// Wait for felix to see and program some expected nflog entries, and for the cluster IP to appear.
			Eventually(getRuleFunc(tc.Felixes[0], "PPI0|np/default/tier1.np1-1"), "10s", "1s").ShouldNot(HaveOccurred())
			Eventually(getRuleFunc(tc.Felixes[0], "PPE0|np/default/tier1.np1-1"), "10s", "1s").ShouldNot(HaveOccurred())
			Eventually(getRuleFunc(tc.Felixes[1], "PPI0|np/default/tier1.np1-1"), "10s", "1s").ShouldNot(HaveOccurred())
			Eventually(getRuleFunc(tc.Felixes[1], "PPE0|np/default/tier1.np1-1"), "10s", "1s").ShouldNot(HaveOccurred())
			// When policies are programmed, make sure no staged policy is programmed. Staged policies must be skipped.
			Consistently(getRuleFunc(tc.Felixes[0], "staged"), "5s", "1s").Should(HaveOccurred())
			Consistently(getRuleFunc(tc.Felixes[1], "staged"), "5s", "1s").Should(HaveOccurred())
		} else {
			bpfWaitForNetworkPolicy(tc.Felixes[0], ep1_1.InterfaceName, "egress", "default", "tier1.np1-1")
			bpfWaitForNetworkPolicy(tc.Felixes[0], ep1_1.InterfaceName, "ingress", "default", "tier1.np1-1")
			bpfWaitForNetworkPolicy(tc.Felixes[1], ep2_1.InterfaceName, "egress", "default", "tier1.np1-1")
			bpfWaitForNetworkPolicy(tc.Felixes[1], ep2_1.InterfaceName, "ingress", "default", "tier1.np1-1")
			// When policies are programmed, make sure no staged policy is programmed. Staged policies must be skipped.
			Consistently(bpfDumpPolicy(tc.Felixes[0], ep1_1.InterfaceName, "ingress"), "5s", "1s").ShouldNot(ContainSubstring("staged"))
			Consistently(bpfDumpPolicy(tc.Felixes[0], ep1_1.InterfaceName, "egress"), "5s", "1s").ShouldNot(ContainSubstring("staged"))
			Consistently(bpfDumpPolicy(tc.Felixes[1], ep2_1.InterfaceName, "ingress"), "5s", "1s").ShouldNot(ContainSubstring("staged"))
			Consistently(bpfDumpPolicy(tc.Felixes[1], ep2_1.InterfaceName, "egress"), "5s", "1s").ShouldNot(ContainSubstring("staged"))
		}

		time.Sleep(5 * time.Second)
	}

	It("get expected flow logs with pending policies", func() {
		// Describe the connectivity that we now expect.
		// For ep1_1 -> ep2_1 we use the service cluster IP to test service info in the flow log
		cc = &connectivity.Checker{}
		cc.ExpectSome(ep1_1, ep2_1)

		// Do 1 rounds of connectivity checking.
		cc.CheckConnectivity()

		flowlogs.WaitForConntrackScan(bpfEnabled)

		// Configured staged allow.
		configureStagedAllow()

		// Do 1 rounds of connectivity checking within the flush log interval.
		cc.CheckConnectivity()

		flowlogs.WaitForConntrackScan(bpfEnabled)

		// Delete conntrack state so that we don't keep seeing 0-metric copies of the logs.  This will allow the flows
		// to expire quickly.
		for ii := range tc.Felixes {
			tc.Felixes[ii].Exec("conntrack", "-F")
		}

		flowTester := flowlogs.NewFlowTester(flowlogs.FlowTesterOptions{
			ExpectLabels:           true,
			ExpectEnforcedPolicies: true,
			ExpectPendingPolicies:  true,
			MatchEnforcedPolicies:  true,
			MatchPendingPolicies:   true,
			Includes: []flowlogs.IncludeFilter{
				flowlogs.IncludeByDestPort(wepPort),
				flowlogs.IncludeByDestPort(wep2Port),
			},
		})

		ep1_1_Meta := endpoint.Metadata{
			Type:           "wep",
			Namespace:      "default",
			Name:           flowlog.FieldNotIncluded,
			AggregatedName: ep1_1.Name,
		}
		ep2_1_Meta := endpoint.Metadata{
			Type:           "wep",
			Namespace:      "default",
			Name:           flowlog.FieldNotIncluded,
			AggregatedName: ep2_1.Name,
		}

		aggrTuple := tuple.Make(flowlog.EmptyIP, flowlog.EmptyIP, 6, flowlogs.SourcePortIsNotIncluded, wepPort)

		Eventually(func() error {
			// Felix 0.
			if err := flowTester.PopulateFromFlowLogs(tc.Felixes[0]); err != nil {
				return fmt.Errorf("Unable to populate flow tester from flow logs: %v", err)
			}

			flowTester.CheckFlow(
				flowlog.FlowLog{
					FlowMeta: flowlog.FlowMeta{
						Tuple:      aggrTuple,
						SrcMeta:    ep1_1_Meta,
						DstMeta:    ep2_1_Meta,
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
						"1|tier2|default/tier2.staged:tier2.np2-1|deny|-1": {},
					},
				},
			)

			flowTester.CheckFlow(
				flowlog.FlowLog{
					FlowMeta: flowlog.FlowMeta{
						Tuple:      aggrTuple,
						SrcMeta:    ep1_1_Meta,
						DstMeta:    ep2_1_Meta,
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
						"1|tier2|default/tier2.staged:tier2.np2-1|allow|2": {},
					},
				},
			)

			if err := flowTester.Finish(); err != nil {
				return fmt.Errorf("Flows incorrect on Felix[0]:\n%v", err)
			}

			// Felix 1.
			if err := flowTester.PopulateFromFlowLogs(tc.Felixes[1]); err != nil {
				return fmt.Errorf("Unable to populate flow tester from flow logs: %v", err)
			}

			flowTester.CheckFlow(
				flowlog.FlowLog{
					FlowMeta: flowlog.FlowMeta{
						Tuple:      aggrTuple,
						SrcMeta:    ep1_1_Meta,
						DstMeta:    ep2_1_Meta,
						DstService: flowlog.EmptyService,
						Action:     "allow",
						Reporter:   "dst",
					},
					FlowEnforcedPolicySet: flowlog.FlowPolicySet{
						"0|tier1|default/tier1.np1-1|pass|0":            {},
						"1|__PROFILE__|__PROFILE__.kns.default|allow|0": {},
					},
					FlowPendingPolicySet: flowlog.FlowPolicySet{
						"0|tier1|default/tier1.np1-1|pass|0":               {},
						"1|tier2|default/tier2.staged:tier2.np2-1|deny|-1": {},
					},
				},
			)

			flowTester.CheckFlow(
				flowlog.FlowLog{
					FlowMeta: flowlog.FlowMeta{
						Tuple:      aggrTuple,
						SrcMeta:    ep1_1_Meta,
						DstMeta:    ep2_1_Meta,
						DstService: flowlog.EmptyService,
						Action:     "allow",
						Reporter:   "dst",
					},
					FlowEnforcedPolicySet: flowlog.FlowPolicySet{
						"0|tier1|default/tier1.np1-1|pass|0":            {},
						"1|__PROFILE__|__PROFILE__.kns.default|allow|0": {},
					},
					FlowPendingPolicySet: flowlog.FlowPolicySet{
						"0|tier1|default/tier1.np1-1|pass|0":               {},
						"1|tier2|default/tier2.staged:tier2.np2-1|allow|1": {},
					},
				},
			)

			if err := flowTester.Finish(); err != nil {
				return fmt.Errorf("Flows incorrect on Felix[1]:\n%v", err)
			}

			return nil
		}, "60s", "1s").ShouldNot(HaveOccurred())
	})

	It("get expected flow logs with pending policies for a pass", func() {
		// Describe the connectivity that we now expect.
		// For ep1_1 -> ep2_1 we use the service cluster IP to test service info in the flow log
		cc = &connectivity.Checker{}
		cc.ExpectSome(ep1_1, ep2_1)

		// Do 1 rounds of connectivity checking.
		cc.CheckConnectivity()

		flowlogs.WaitForConntrackScan(bpfEnabled)

		// Configured staged pass.
		configureStagedPass()

		// Do 1 rounds of connectivity checking within the flush log interval.
		cc.CheckConnectivity()

		flowlogs.WaitForConntrackScan(bpfEnabled)

		// Delete conntrack state so that we don't keep seeing 0-metric copies of the logs.  This will allow the flows
		// to expire quickly.
		for ii := range tc.Felixes {
			tc.Felixes[ii].Exec("conntrack", "-F")
		}

		flowTester := flowlogs.NewFlowTester(flowlogs.FlowTesterOptions{
			ExpectLabels:           true,
			ExpectEnforcedPolicies: true,
			ExpectPendingPolicies:  true,
			MatchEnforcedPolicies:  true,
			MatchPendingPolicies:   true,
			Includes: []flowlogs.IncludeFilter{
				flowlogs.IncludeByDestPort(wepPort),
				flowlogs.IncludeByDestPort(wep2Port),
			},
		})

		ep1_1_Meta := endpoint.Metadata{
			Type:           "wep",
			Namespace:      "default",
			Name:           flowlog.FieldNotIncluded,
			AggregatedName: ep1_1.Name,
		}
		ep2_1_Meta := endpoint.Metadata{
			Type:           "wep",
			Namespace:      "default",
			Name:           flowlog.FieldNotIncluded,
			AggregatedName: ep2_1.Name,
		}

		aggrTuple := tuple.Make(flowlog.EmptyIP, flowlog.EmptyIP, 6, flowlogs.SourcePortIsNotIncluded, wepPort)

		Eventually(func() error {
			// Felix 0.
			if err := flowTester.PopulateFromFlowLogs(tc.Felixes[0]); err != nil {
				return fmt.Errorf("Unable to populate flow tester from flow logs: %v", err)
			}

			flowTester.CheckFlow(
				flowlog.FlowLog{
					FlowMeta: flowlog.FlowMeta{
						Tuple:      aggrTuple,
						SrcMeta:    ep1_1_Meta,
						DstMeta:    ep2_1_Meta,
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
						"1|tier2|default/tier2.staged:tier2.np2-1|deny|-1": {},
					},
				},
			)
			flowTester.CheckFlow(
				flowlog.FlowLog{
					FlowMeta: flowlog.FlowMeta{
						Tuple:      aggrTuple,
						SrcMeta:    ep1_1_Meta,
						DstMeta:    ep2_1_Meta,
						DstService: flowlog.EmptyService,
						Action:     "allow",
						Reporter:   "src",
					},
					FlowEnforcedPolicySet: flowlog.FlowPolicySet{
						"0|tier1|default/tier1.np1-1|pass|0":            {},
						"1|__PROFILE__|__PROFILE__.kns.default|allow|0": {},
					},
					FlowPendingPolicySet: flowlog.FlowPolicySet{
						"0|tier1|default/tier1.np1-1|pass|0":              {},
						"1|tier2|default/tier2.staged:tier2.np2-1|pass|0": {},
						"2|__PROFILE__|__PROFILE__.kns.default|allow|0":   {},
					},
				},
			)

			if err := flowTester.Finish(); err != nil {
				return fmt.Errorf("Flows incorrect on Felix[0]:\n%v", err)
			}

			// Felix 1.
			if err := flowTester.PopulateFromFlowLogs(tc.Felixes[1]); err != nil {
				return fmt.Errorf("Unable to populate flow tester from flow logs: %v", err)
			}

			flowTester.CheckFlow(
				flowlog.FlowLog{
					FlowMeta: flowlog.FlowMeta{
						Tuple:      aggrTuple,
						SrcMeta:    ep1_1_Meta,
						DstMeta:    ep2_1_Meta,
						DstService: flowlog.EmptyService,
						Action:     "allow",
						Reporter:   "dst",
					},
					FlowEnforcedPolicySet: flowlog.FlowPolicySet{
						"0|tier1|default/tier1.np1-1|pass|0":            {},
						"1|__PROFILE__|__PROFILE__.kns.default|allow|0": {},
					},
					FlowPendingPolicySet: flowlog.FlowPolicySet{
						"0|tier1|default/tier1.np1-1|pass|0":               {},
						"1|tier2|default/tier2.staged:tier2.np2-1|deny|-1": {},
					},
				},
			)
			flowTester.CheckFlow(
				flowlog.FlowLog{
					FlowMeta: flowlog.FlowMeta{
						Tuple:      aggrTuple,
						SrcMeta:    ep1_1_Meta,
						DstService: flowlog.EmptyService,
						DstMeta:    ep2_1_Meta,
						Action:     "allow",
						Reporter:   "dst",
					},
					FlowEnforcedPolicySet: flowlog.FlowPolicySet{
						"0|tier1|default/tier1.np1-1|pass|0":            {},
						"1|__PROFILE__|__PROFILE__.kns.default|allow|0": {},
					},
					FlowPendingPolicySet: flowlog.FlowPolicySet{
						"0|tier1|default/tier1.np1-1|pass|0":              {},
						"1|tier2|default/tier2.staged:tier2.np2-1|pass|0": {},
						"2|__PROFILE__|__PROFILE__.kns.default|allow|0":   {},
					},
				},
			)

			if err := flowTester.Finish(); err != nil {
				return fmt.Errorf("Flows incorrect on Felix[1]:\n%v", err)
			}

			return nil
		}, "60s", "1s").ShouldNot(HaveOccurred())
	})

	AfterEach(func() {
		for _, felix := range tc.Felixes {
			if bpfEnabled {
				// FIXME
				felix.Exec("calico-bpf", "connect-time", "clean")
			}
		}
	})
})

func getRuleFunc(felix *infrastructure.Felix, rule string) func() error {
	cmd := []string{"iptables-save", "-t", "filter"}
	if NFTMode() {
		cmd = []string{"nft", "list", "ruleset"}
	}
	return func() error {
		if out, err := felix.ExecOutput(cmd...); err != nil {
			return err
		} else if strings.Count(out, rule) > 0 {
			return nil
		} else {
			return errors.New("Rule not programmed: \nRule: " + rule + "\n" + out)
		}
	}
}
