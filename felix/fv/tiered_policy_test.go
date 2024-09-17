//go:build fvtests
// +build fvtests

// Copyright (c) 2024 Tigera, Inc. All rights reserved.

package fv_test

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/projectcalico/calico/felix/fv/connectivity"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

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
var _ = infrastructure.DatastoreDescribe("connectivity tests with policy tiers _BPF-SAFE_", []apiconfig.DatastoreType{apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
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
	)
	clusterIP := "10.101.0.10"

	BeforeEach(func() {
		infra = getInfra()
		opts = infrastructure.DefaultTopologyOptions()
		opts.IPIPEnabled = false

		// Start felix instances.
		tc, client = infrastructure.StartNNodeTopology(2, opts, infra)

		// Install a default profile that allows all ingress and egress, in the absence of any Policy.
		infra.AddDefaultAllow()

		// Create workload on host 1.
		ep1_1 = workload.Run(tc.Felixes[0], "ep1-1", "default", "10.65.0.0", wepPortStr, "tcp")
		ep1_1.ConfigureInInfra(infra)

		ep2_1 = workload.Run(tc.Felixes[1], "ep2-1", "default", "10.65.1.0", wepPortStr, "tcp")
		ep2_1.ConfigureInInfra(infra)

		ep2_2 = workload.Run(tc.Felixes[1], "ep2-2", "default", "10.65.1.1", wepPortStr, "tcp")
		ep2_2.ConfigureInInfra(infra)

		ep2_3 = workload.Run(tc.Felixes[1], "ep2-3", "default", "10.65.1.2", wepPortStr, "tcp")
		ep2_3.ConfigureInInfra(infra)

		ep2_4 = workload.Run(tc.Felixes[1], "ep2-4", "default", "10.65.1.3", wepPortStr, "tcp")
		ep2_4.ConfigureInInfra(infra)

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

		// Create a service that maps to ep2_1. Rather than checking connectivity to the endpoint we'll go via
		// the service to test the destination service name handling.
		svcName := "test-service"
		k8sClient := infra.(*infrastructure.K8sDatastoreInfra).K8sClient
		tSvc := k8sService(svcName, clusterIP, ep2_1, svcPort, wepPort, 0, "tcp")
		tSvcNamespace := tSvc.ObjectMeta.Namespace
		_, err = k8sClient.CoreV1().Services(tSvcNamespace).Create(context.Background(), tSvc, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		// Wait for the endpoints to be updated and for the address to be ready.
		Expect(ep2_1.IP).NotTo(Equal(""))
		getEpsFunc := k8sGetEpsForServiceFunc(k8sClient, tSvc)
		epCorrectFn := func() error {
			eps := getEpsFunc()
			if len(eps) != 1 {
				return fmt.Errorf("Wrong number of endpoints: %#v", eps)
			}
			addrs := eps[0].Addresses
			if len(addrs) != 1 {
				return fmt.Errorf("Wrong number of addresses: %#v", eps[0])
			}
			if addrs[0].IP != ep2_1.IP {
				return fmt.Errorf("Unexpected IP: %s != %s", addrs[0].IP, ep2_1.IP)
			}
			ports := eps[0].Ports
			if len(ports) != 1 {
				return fmt.Errorf("Wrong number of ports: %#v", eps[0])
			}
			if ports[0].Port != int32(wepPort) {
				return fmt.Errorf("Wrong port %d != svcPort", ports[0].Port)
			}
			return nil
		}
		Eventually(epCorrectFn, "10s").ShouldNot(HaveOccurred())

		if os.Getenv("FELIX_FV_ENABLE_BPF") != "true" {
			// Wait for felix to see and program some expected nflog entries, and for the cluster IP to appear.
			rulesProgrammed := func() bool {
				var out0, out1 string
				var err error
				if NFTMode() {
					out0, err = tc.Felixes[0].ExecOutput("nft", "list", "table", "ip", "calico")
					Expect(err).NotTo(HaveOccurred())
					out1, err = tc.Felixes[1].ExecOutput("nft", "list", "table", "ip", "calico")
					Expect(err).NotTo(HaveOccurred())
				} else {
					out0, err = tc.Felixes[0].ExecOutput("iptables-save", "-t", "filter")
					Expect(err).NotTo(HaveOccurred())
					out1, err = tc.Felixes[1].ExecOutput("iptables-save", "-t", "filter")
					Expect(err).NotTo(HaveOccurred())
				}
				return strings.Count(out0, "default.ep1-1-allow-all") > 0 &&
					strings.Count(out1, "default.ep1-1-allow-all") == 0
			}
			Eventually(rulesProgrammed, "10s", "1s").Should(BeTrue(),
				"Expected iptables rules to appear on the correct felix instances")

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

	It("should test connectivity between workloads with tier with Pass default action", func() {
		By("checking the initial connectivity")
		cc := createBaseConnectivityChecker()
		cc.ExpectNone(ep1_1, ep2_4) // denied by end of tier1 deny
		cc.ExpectNone(ep2_4, ep1_1) // denied by end of tier1 deny

		// Do 3 rounds of connectivity checking.
		cc.CheckConnectivity()

		By("changing the tier's default action to Pass")
		tier, err := client.Tiers().Get(utils.Ctx, "tier1", options.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		tier.Spec.DefaultAction = &actionPass
		_, err = client.Tiers().Update(utils.Ctx, tier, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

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

		cc = createBaseConnectivityChecker()
		cc.ExpectNone(ep1_1, ep2_4) // denied by end of tier1 deny
		cc.ExpectNone(ep2_4, ep1_1) // denied by end of tier1 deny

		cc.CheckConnectivity()
	})

	AfterEach(func() {
		if CurrentGinkgoTestDescription().Failed {
			for _, felix := range tc.Felixes {
				felix.Exec("iptables-save", "-c")
				felix.Exec("ipset", "list")
				felix.Exec("ip", "r")
				felix.Exec("ip", "a")
			}
		}

		ep1_1.Stop()
		ep2_1.Stop()
		ep2_2.Stop()
		ep2_3.Stop()
		ep2_4.Stop()
		tc.Stop()

		if CurrentGinkgoTestDescription().Failed {
			infra.DumpErrorData()
		}
		infra.Stop()
	})
})
