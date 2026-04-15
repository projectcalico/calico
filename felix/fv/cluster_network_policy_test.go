// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	clusternetpol "sigs.k8s.io/network-policy-api/apis/v1alpha2"
	netpolicyclient "sigs.k8s.io/network-policy-api/pkg/client/clientset/versioned/typed/apis/v1alpha2"

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

// Test topology:
//
// Felix1             Felix2
//  w[0]  <-+-------> w[1]
//          \-------> w[2]
//
//       ^           ^-- Apply test policies here (ingress and egress)
//       `-------------- Default-allow profile permits all traffic
//
// Connectivity test phases:
//   1. AdminTier deny-all ingress                                      → denied
//   2. AdminTier priority: allow (pri 50) overrides deny (pri 100)     → allowed; delete allow → denied
//   3. BaselineTier deny-all egress                                    → denied
//   4. AdminTier pass + GNP deny in default tier                       → denied; delete GNP → allowed
//   5. AdminTier allow overrides GNP deny in default tier              → allowed
//   6. GNP deny in kube-admin tier (order 0.5) vs KCNP allow (pri 100)→ denied; delete GNP → allowed
//   7. AdminTier pass + K8s NetworkPolicy implicit deny in default tier→ denied
//
// Flow log test:
//   Setup: KCNP pass in admin tier, NP allow for w[1], GNP deny for w[2], GNP allow-all for w[0]
//   w[0]→w[1] dst: allow  enforced: [kcnp pass, np allow]
//   w[0]→w[2] dst: deny   enforced: [kcnp pass, gnp deny]
//   w[0]→w[1] src: allow  enforced: [gnp allow-all]
//   w[0]→w[2] src: allow  enforced: [gnp allow-all]

var _ = infrastructure.DatastoreDescribe(
	"cluster network policy conversion _BPF-SAFE_",
	[]apiconfig.DatastoreType{apiconfig.Kubernetes},
	func(getInfra infrastructure.InfraFactory) {
		const wepPort = 8055
		wepPortStr := fmt.Sprintf("%d", wepPort)

		var (
			infra        infrastructure.DatastoreInfra
			opts         infrastructure.TopologyOptions
			tc           infrastructure.TopologyContainers
			calicoClient client.Interface
			cnpClient    *netpolicyclient.PolicyV1alpha2Client
			w            [3]*workload.Workload
			cc           *connectivity.Checker
		)

		testSetup := func() {
			tc, calicoClient = infrastructure.StartNNodeTopology(2, opts, infra)
			infra.AddDefaultAllow()

			infrastructure.AssignIP("w0", "10.65.0.0", tc.Felixes[0].Hostname, calicoClient)
			w[0] = workload.Run(tc.Felixes[0], "w0", "default", "10.65.0.0", wepPortStr, "tcp")
			w[0].ConfigureInInfra(infra)

			infrastructure.AssignIP("w1", "10.65.1.0", tc.Felixes[1].Hostname, calicoClient)
			w[1] = workload.Run(tc.Felixes[1], "w1", "default", "10.65.1.0", wepPortStr, "tcp")
			w[1].ConfigureInInfra(infra)

			infrastructure.AssignIP("w2", "10.65.1.1", tc.Felixes[1].Hostname, calicoClient)
			w[2] = workload.Run(tc.Felixes[1], "w2", "default", "10.65.1.1", wepPortStr, "tcp")
			w[2].ConfigureInInfra(infra)

			ensureRoutesProgrammed(tc.Felixes)
			if BPFMode() {
				ensureAllNodesBPFProgramsAttached(tc.Felixes)
			}

			k8sInfra := infra.(*infrastructure.K8sDatastoreInfra)
			var err error
			cnpClient, err = netpolicyclient.NewForConfig(&rest.Config{
				Transport: &http.Transport{
					Proxy: http.ProxyFromEnvironment,
					DialContext: (&net.Dialer{
						Timeout:   30 * time.Second,
						KeepAlive: 30 * time.Second,
					}).DialContext,
					TLSHandshakeTimeout: 10 * time.Second,
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true,
					},
				},
				Host: k8sInfra.Endpoint,
			})
			Expect(err).NotTo(HaveOccurred())
		}

		JustAfterEach(func() {
			// Clean up ClusterNetworkPolicies before tearing down infra,
			// since the K8s infra cleanup doesn't handle these CRDs.
			cnps, err := cnpClient.ClusterNetworkPolicies().List(
				context.Background(), metav1.ListOptions{},
			)
			if err == nil {
				for _, cnp := range cnps.Items {
					err := cnpClient.ClusterNetworkPolicies().Delete(
						context.Background(), cnp.Name, metav1.DeleteOptions{},
					)
					Expect(err).NotTo(HaveOccurred())
				}
			}

			for _, wl := range w {
				if wl != nil {
					wl.Stop()
				}
			}

			tc.Stop()
			infra.Stop()
		})

		// policyProgrammed checks whether a policy name appears in Felix[1]'s w[1] dataplane.
		policyProgrammed := func(policyName string) func() bool {
			return func() bool {
				if BPFMode() {
					out := bpfDumpPolicy(tc.Felixes[1], w[1].InterfaceName, "ingress")
					out += bpfDumpPolicy(tc.Felixes[1], w[1].InterfaceName, "egress")
					return strings.Contains(out, policyName)
				}
				if NFTMode() {
					out, err := tc.Felixes[1].ExecOutput("nft", "list", "ruleset")
					Expect(err).NotTo(HaveOccurred())
					return strings.Contains(out, policyName)
				}
				out, err := tc.Felixes[1].ExecOutput("iptables-save", "-t", "filter")
				Expect(err).NotTo(HaveOccurred())
				return strings.Contains(out, policyName)
			}
		}

		// policyProgrammedOn checks whether a policy name appears on a specific Felix/interface.
		policyProgrammedOn := func(felix *infrastructure.Felix, ifaceName, policyName string) func() bool {
			return func() bool {
				if BPFMode() {
					out := bpfDumpPolicy(felix, ifaceName, "ingress")
					out += bpfDumpPolicy(felix, ifaceName, "egress")
					return strings.Contains(out, policyName)
				}
				if NFTMode() {
					out, err := felix.ExecOutput("nft", "list", "ruleset")
					Expect(err).NotTo(HaveOccurred())
					return strings.Contains(out, policyName)
				}
				out, err := felix.ExecOutput("iptables-save", "-t", "filter")
				Expect(err).NotTo(HaveOccurred())
				return strings.Contains(out, policyName)
			}
		}

		// --- KCNP helpers ---

		createDenyAllIngressKCNP := func(name string, tier clusternetpol.Tier, priority int32) {
			cnp := &clusternetpol.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: name},
				Spec: clusternetpol.ClusterNetworkPolicySpec{
					Priority: priority,
					Tier:     tier,
					Subject: clusternetpol.ClusterNetworkPolicySubject{
						Namespaces: &metav1.LabelSelector{},
					},
					Ingress: []clusternetpol.ClusterNetworkPolicyIngressRule{{
						Name:   "deny-all-ingress",
						Action: clusternetpol.ClusterNetworkPolicyRuleActionDeny,
						From: []clusternetpol.ClusterNetworkPolicyIngressPeer{{
							Namespaces: &metav1.LabelSelector{},
						}},
					}},
				},
			}
			_, err := cnpClient.ClusterNetworkPolicies().Create(
				context.Background(), cnp, metav1.CreateOptions{},
			)
			Expect(err).NotTo(HaveOccurred())
		}

		createAllowTCPIngressKCNP := func(name string, tier clusternetpol.Tier, priority int32) {
			port := clusternetpol.Port{Number: wepPort}
			cnp := &clusternetpol.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: name},
				Spec: clusternetpol.ClusterNetworkPolicySpec{
					Priority: priority,
					Tier:     tier,
					Subject: clusternetpol.ClusterNetworkPolicySubject{
						Namespaces: &metav1.LabelSelector{},
					},
					Ingress: []clusternetpol.ClusterNetworkPolicyIngressRule{{
						Name:   "allow-tcp",
						Action: clusternetpol.ClusterNetworkPolicyRuleActionAccept,
						From: []clusternetpol.ClusterNetworkPolicyIngressPeer{{
							Namespaces: &metav1.LabelSelector{},
						}},
						Protocols: []clusternetpol.ClusterNetworkPolicyProtocol{{
							TCP: &clusternetpol.ClusterNetworkPolicyProtocolTCP{
								DestinationPort: &port,
							},
						}},
					}},
				},
			}
			_, err := cnpClient.ClusterNetworkPolicies().Create(
				context.Background(), cnp, metav1.CreateOptions{},
			)
			Expect(err).NotTo(HaveOccurred())
		}

		createPassIngressKCNP := func(name string, tier clusternetpol.Tier, priority int32) {
			cnp := &clusternetpol.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: name},
				Spec: clusternetpol.ClusterNetworkPolicySpec{
					Priority: priority,
					Tier:     tier,
					Subject: clusternetpol.ClusterNetworkPolicySubject{
						Namespaces: &metav1.LabelSelector{},
					},
					Ingress: []clusternetpol.ClusterNetworkPolicyIngressRule{{
						Name:   "pass-all-ingress",
						Action: clusternetpol.ClusterNetworkPolicyRuleActionPass,
						From: []clusternetpol.ClusterNetworkPolicyIngressPeer{{
							Namespaces: &metav1.LabelSelector{},
						}},
					}},
				},
			}
			_, err := cnpClient.ClusterNetworkPolicies().Create(
				context.Background(), cnp, metav1.CreateOptions{},
			)
			Expect(err).NotTo(HaveOccurred())
		}

		createDenyAllEgressKCNP := func(name string, tier clusternetpol.Tier, priority int32) {
			cnp := &clusternetpol.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: name},
				Spec: clusternetpol.ClusterNetworkPolicySpec{
					Priority: priority,
					Tier:     tier,
					Subject: clusternetpol.ClusterNetworkPolicySubject{
						Namespaces: &metav1.LabelSelector{},
					},
					Egress: []clusternetpol.ClusterNetworkPolicyEgressRule{{
						Name:   "deny-all-egress",
						Action: clusternetpol.ClusterNetworkPolicyRuleActionDeny,
						To: []clusternetpol.ClusterNetworkPolicyEgressPeer{{
							Namespaces: &metav1.LabelSelector{},
						}},
					}},
				},
			}
			_, err := cnpClient.ClusterNetworkPolicies().Create(
				context.Background(), cnp, metav1.CreateOptions{},
			)
			Expect(err).NotTo(HaveOccurred())
		}

		deleteCNP := func(name string) {
			err := cnpClient.ClusterNetworkPolicies().Delete(
				context.Background(), name, metav1.DeleteOptions{},
			)
			Expect(err).NotTo(HaveOccurred())
		}

		Context("connectivity and tier ordering", func() {
			JustBeforeEach(func() {
				infra = getInfra()
				opts = infrastructure.DefaultTopologyOptions()
				opts.IPIPMode = api.IPIPModeNever
				testSetup()
			})

			It("should enforce policy correctly across admin, baseline, and default tiers", func() {
				// ---- Phase 1: AdminTier deny-all ingress ----
				By("1. Creating an AdminTier KCNP that denies all ingress")
				createDenyAllIngressKCNP("kcnp-deny-ingress", clusternetpol.AdminTier, 100)
				Eventually(policyProgrammed("kcnp-deny-ingress"), "15s", "200ms").Should(BeTrue())

				cc = &connectivity.Checker{}
				cc.ExpectNone(w[0], w[1])
				cc.ExpectNone(w[0], w[2])
				cc.CheckConnectivity()

				// ---- Phase 2: AdminTier priority ordering ----
				By("2. Adding a higher-priority AdminTier KCNP allow to override the deny")
				createAllowTCPIngressKCNP("kcnp-allow-tcp", clusternetpol.AdminTier, 50)
				Eventually(policyProgrammed("kcnp-allow-tcp"), "15s", "200ms").Should(BeTrue())

				cc = &connectivity.Checker{}
				cc.ExpectSome(w[0], w[1])
				cc.ExpectSome(w[0], w[2])
				cc.CheckConnectivity()

				By("Deleting the allow KCNP so only the deny remains")
				deleteCNP("kcnp-allow-tcp")
				Eventually(policyProgrammed("kcnp-allow-tcp"), "15s", "200ms").Should(BeFalse())

				cc = &connectivity.Checker{}
				cc.ExpectNone(w[0], w[1])
				cc.ExpectNone(w[0], w[2])
				cc.CheckConnectivity()

				deleteCNP("kcnp-deny-ingress")
				Eventually(policyProgrammed("kcnp-deny-ingress"), "15s", "200ms").Should(BeFalse())

				// ---- Phase 3: BaselineTier deny-all egress ----
				By("3. Verifying connectivity is restored without policies")
				cc = &connectivity.Checker{}
				cc.ExpectSome(w[0], w[1])
				cc.ExpectSome(w[0], w[2])
				cc.CheckConnectivity()

				By("Creating a BaselineTier KCNP that denies all egress")
				createDenyAllEgressKCNP("kcnp-baseline-deny-egress", clusternetpol.BaselineTier, 100)
				Eventually(policyProgrammed("kcnp-baseline-deny-egress"), "15s", "200ms").Should(BeTrue())

				cc = &connectivity.Checker{}
				cc.ExpectNone(w[0], w[1])
				cc.ExpectNone(w[0], w[2])
				cc.CheckConnectivity()

				deleteCNP("kcnp-baseline-deny-egress")
				Eventually(policyProgrammed("kcnp-baseline-deny-egress"), "15s", "200ms").Should(BeFalse())

				// ---- Phase 4: KCNP pass in admin + GNP deny in default tier ----
				By("4. Creating KCNP pass in admin tier with GNP deny in default tier")
				createPassIngressKCNP("kcnp-pass-ingress", clusternetpol.AdminTier, 100)

				gnp := api.NewGlobalNetworkPolicy()
				gnp.Name = "default.gnp-deny-ingress"
				order := float64(1.0)
				gnp.Spec.Order = &order
				gnp.Spec.Tier = "default"
				gnp.Spec.Selector = "all()"
				gnp.Spec.Types = []api.PolicyType{api.PolicyTypeIngress}
				gnp.Spec.Ingress = []api.Rule{{Action: api.Deny}}
				_, err := calicoClient.GlobalNetworkPolicies().Create(utils.Ctx, gnp, utils.NoOptions)
				Expect(err).NotTo(HaveOccurred())

				Eventually(policyProgrammed("kcnp-pass-ingress"), "15s", "200ms").Should(BeTrue())
				Eventually(policyProgrammed("gnp-deny-ingress"), "15s", "200ms").Should(BeTrue())

				cc = &connectivity.Checker{}
				cc.ExpectNone(w[0], w[1])
				cc.ExpectNone(w[0], w[2])
				cc.CheckConnectivity()

				By("Deleting the GNP so traffic falls through to the default-allow profile")
				_, err = calicoClient.GlobalNetworkPolicies().Delete(
					utils.Ctx, "default.gnp-deny-ingress", options.DeleteOptions{},
				)
				Expect(err).NotTo(HaveOccurred())
				Eventually(policyProgrammed("gnp-deny-ingress"), "15s", "200ms").Should(BeFalse())

				cc = &connectivity.Checker{}
				cc.ExpectSome(w[0], w[1])
				cc.ExpectSome(w[0], w[2])
				cc.CheckConnectivity()

				deleteCNP("kcnp-pass-ingress")
				Eventually(policyProgrammed("kcnp-pass-ingress"), "15s", "200ms").Should(BeFalse())

				// ---- Phase 5: KCNP allow in admin overrides GNP deny in default ----
				By("5. Creating KCNP allow in admin tier to override GNP deny in default tier")
				gnp = api.NewGlobalNetworkPolicy()
				gnp.Name = "default.gnp-deny-ingress"
				gnp.Spec.Order = &order
				gnp.Spec.Tier = "default"
				gnp.Spec.Selector = "all()"
				gnp.Spec.Types = []api.PolicyType{api.PolicyTypeIngress}
				gnp.Spec.Ingress = []api.Rule{{Action: api.Deny}}
				_, err = calicoClient.GlobalNetworkPolicies().Create(utils.Ctx, gnp, utils.NoOptions)
				Expect(err).NotTo(HaveOccurred())

				createAllowTCPIngressKCNP("kcnp-allow-tcp", clusternetpol.AdminTier, 100)
				Eventually(policyProgrammed("kcnp-allow-tcp"), "15s", "200ms").Should(BeTrue())
				Eventually(policyProgrammed("gnp-deny-ingress"), "15s", "200ms").Should(BeTrue())

				cc = &connectivity.Checker{}
				cc.ExpectSome(w[0], w[1])
				cc.ExpectSome(w[0], w[2])
				cc.CheckConnectivity()

				deleteCNP("kcnp-allow-tcp")
				_, err = calicoClient.GlobalNetworkPolicies().Delete(
					utils.Ctx, "default.gnp-deny-ingress", options.DeleteOptions{},
				)
				Expect(err).NotTo(HaveOccurred())
				Eventually(policyProgrammed("kcnp-allow-tcp"), "15s", "200ms").Should(BeFalse())
				Eventually(policyProgrammed("gnp-deny-ingress"), "15s", "200ms").Should(BeFalse())

				// ---- Phase 6: GNP deny in kube-admin tier vs KCNP allow ----
				By("6. Creating a GNP deny in kube-admin tier alongside a KCNP allow")
				// Create KCNP first so the kube-admin tier exists.
				createAllowTCPIngressKCNP("kcnp-allow-tcp", clusternetpol.AdminTier, 100)
				Eventually(policyProgrammed("kcnp-allow-tcp"), "15s", "200ms").Should(BeTrue())

				gnpKubeAdmin := api.NewGlobalNetworkPolicy()
				gnpKubeAdmin.Name = "kube-admin.gnp-deny-ingress"
				kubeAdminOrder := float64(0.5)
				gnpKubeAdmin.Spec.Order = &kubeAdminOrder
				gnpKubeAdmin.Spec.Tier = "kube-admin"
				gnpKubeAdmin.Spec.Selector = "all()"
				gnpKubeAdmin.Spec.Types = []api.PolicyType{api.PolicyTypeIngress}
				gnpKubeAdmin.Spec.Ingress = []api.Rule{{Action: api.Deny}}
				_, err = calicoClient.GlobalNetworkPolicies().Create(utils.Ctx, gnpKubeAdmin, utils.NoOptions)
				Expect(err).NotTo(HaveOccurred())
				Eventually(policyProgrammed("kube-admin.gnp-deny-ingress"), "15s", "200ms").Should(BeTrue())

				// GNP at order 0.5 is evaluated before KCNP at order 100 in the same tier → deny wins.
				cc = &connectivity.Checker{}
				cc.ExpectNone(w[0], w[1])
				cc.ExpectNone(w[0], w[2])
				cc.CheckConnectivity()

				By("Deleting the GNP so KCNP allow takes effect")
				_, err = calicoClient.GlobalNetworkPolicies().Delete(
					utils.Ctx, "kube-admin.gnp-deny-ingress", options.DeleteOptions{},
				)
				Expect(err).NotTo(HaveOccurred())
				Eventually(policyProgrammed("kube-admin.gnp-deny-ingress"), "15s", "200ms").Should(BeFalse())

				cc = &connectivity.Checker{}
				cc.ExpectSome(w[0], w[1])
				cc.ExpectSome(w[0], w[2])
				cc.CheckConnectivity()

				deleteCNP("kcnp-allow-tcp")
				Eventually(policyProgrammed("kcnp-allow-tcp"), "15s", "200ms").Should(BeFalse())

				// ---- Phase 7: KCNP pass + K8s NetworkPolicy deny in default tier ----
				By("7. Creating KCNP pass in admin tier with K8s NetworkPolicy deny in default tier")
				createPassIngressKCNP("kcnp-pass-ingress", clusternetpol.AdminTier, 100)
				Eventually(policyProgrammed("kcnp-pass-ingress"), "15s", "200ms").Should(BeTrue())

				k8sClient := infra.(*infrastructure.K8sDatastoreInfra).K8sClient
				knp := &networkingv1.NetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "knp-deny-ingress",
						Namespace: "default",
					},
					Spec: networkingv1.NetworkPolicySpec{
						PodSelector: metav1.LabelSelector{},
						PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
						// No Ingress rules → implicit deny-all ingress.
					},
				}
				_, err = k8sClient.NetworkingV1().NetworkPolicies("default").Create(
					context.Background(), knp, metav1.CreateOptions{},
				)
				Expect(err).NotTo(HaveOccurred())
				Eventually(policyProgrammed("knp-deny-ingress"), "15s", "200ms").Should(BeTrue())

				cc = &connectivity.Checker{}
				cc.ExpectNone(w[0], w[1])
				cc.ExpectNone(w[0], w[2])
				cc.CheckConnectivity()
			})
		})

		Context("flow log generation with cross-tier policies", func() {
			JustBeforeEach(func() {
				infra = getInfra()
				opts = infrastructure.DefaultTopologyOptions()
				opts.IPIPMode = api.IPIPModeNever
				opts.FlowLogSource = infrastructure.FlowLogSourceLocalSocket

				opts.ExtraEnvVars["FELIX_FLOWLOGSCOLLECTORDEBUGTRACE"] = "true"
				opts.ExtraEnvVars["FELIX_FLOWLOGSFLUSHINTERVAL"] = "2"
				opts.ExtraEnvVars["FELIX_FLOWLOGSLOCALREPORTER"] = "Enabled"

				testSetup()
			})

			It("should generate correct flow logs for KCNP pass with GNP and NP in default tier", func() {
				// GNP: allow all traffic from/to w[0].
				gnpAllowSrc := api.NewGlobalNetworkPolicy()
				gnpAllowSrc.Name = "default.w0-allow-all"
				orderZero := float64(0.0)
				gnpAllowSrc.Spec.Order = &orderZero
				gnpAllowSrc.Spec.Tier = "default"
				gnpAllowSrc.Spec.Selector = w[0].NameSelector()
				gnpAllowSrc.Spec.Types = []api.PolicyType{api.PolicyTypeIngress, api.PolicyTypeEgress}
				gnpAllowSrc.Spec.Ingress = []api.Rule{{Action: api.Allow}}
				gnpAllowSrc.Spec.Egress = []api.Rule{{Action: api.Allow}}
				_, err := calicoClient.GlobalNetworkPolicies().Create(utils.Ctx, gnpAllowSrc, utils.NoOptions)
				Expect(err).NotTo(HaveOccurred())

				// KCNP: pass all ingress from admin tier to the next tier.
				createPassIngressKCNP("pass-ingress", clusternetpol.AdminTier, 100)

				// NP: allow ingress to w[1] in default tier.
				npAllowW1 := api.NewNetworkPolicy()
				npAllowW1.Name = "default.allow-w1"
				npAllowW1.Namespace = "default"
				orderOne := float64(1.0)
				npAllowW1.Spec.Order = &orderOne
				npAllowW1.Spec.Tier = "default"
				npAllowW1.Spec.Selector = w[1].NameSelector()
				npAllowW1.Spec.Types = []api.PolicyType{api.PolicyTypeIngress}
				npAllowW1.Spec.Ingress = []api.Rule{{Action: api.Allow}}
				_, err = calicoClient.NetworkPolicies().Create(utils.Ctx, npAllowW1, utils.NoOptions)
				Expect(err).NotTo(HaveOccurred())

				// GNP: deny ingress to w[2] in default tier.
				gnpDenyW2 := api.NewGlobalNetworkPolicy()
				gnpDenyW2.Name = "default.deny-w2"
				gnpDenyW2.Spec.Order = &orderOne
				gnpDenyW2.Spec.Tier = "default"
				gnpDenyW2.Spec.Selector = w[2].NameSelector()
				gnpDenyW2.Spec.Types = []api.PolicyType{api.PolicyTypeIngress}
				gnpDenyW2.Spec.Ingress = []api.Rule{{Action: api.Deny}}
				_, err = calicoClient.GlobalNetworkPolicies().Create(utils.Ctx, gnpDenyW2, utils.NoOptions)
				Expect(err).NotTo(HaveOccurred())

				Eventually(policyProgrammedOn(tc.Felixes[0], w[0].InterfaceName, "w0-allow-all"), "15s", "200ms").Should(BeTrue())
				Eventually(policyProgrammed("pass-ingress"), "15s", "200ms").Should(BeTrue())
				Eventually(policyProgrammedOn(tc.Felixes[1], w[1].InterfaceName, "allow-w1"), "15s", "200ms").Should(BeTrue())
				Eventually(policyProgrammedOn(tc.Felixes[1], w[2].InterfaceName, "deny-w2"), "15s", "200ms").Should(BeTrue())

				cc = &connectivity.Checker{}
				cc.ExpectSome(w[0], w[1]) // pass from admin, NP allow in default
				cc.ExpectNone(w[0], w[2]) // pass from admin, GNP deny in default
				cc.CheckConnectivity()

				// Flush conntrack so flows expire quickly.
				for i := range tc.Felixes {
					tc.Felixes[i].Exec("conntrack", "-F")
				}

				checkFlowLogs := func() error {
					aggrTuple := tuple.Make(flowlog.EmptyIP, flowlog.EmptyIP, 6, flowlogs.SourcePortIsNotIncluded, wepPort)

					w0Meta := endpoint.Metadata{
						Type:           "wep",
						Namespace:      "default",
						Name:           flowlog.FieldNotIncluded,
						AggregatedName: w[0].Name,
					}
					w1Meta := endpoint.Metadata{
						Type:           "wep",
						Namespace:      "default",
						Name:           flowlog.FieldNotIncluded,
						AggregatedName: w[1].Name,
					}
					w2Meta := endpoint.Metadata{
						Type:           "wep",
						Namespace:      "default",
						Name:           flowlog.FieldNotIncluded,
						AggregatedName: w[2].Name,
					}

					flowTester := flowlogs.NewFlowTester(flowlogs.FlowTesterOptions{
						ExpectLabels:           true,
						ExpectEnforcedPolicies: true,
						MatchEnforcedPolicies:  true,
						ExpectPendingPolicies:  true,
						MatchPendingPolicies:   true,
						Includes:               []flowlogs.IncludeFilter{flowlogs.IncludeByDestPort(wepPort)},
					})

					// ---- Source reporter on Felix[0] ----
					err := flowTester.PopulateFromFlowLogs(tc.Felixes[0])
					if err != nil {
						return fmt.Errorf("error populating flow logs from Felix[0]: %s", err)
					}

					// w[0] → w[1] src: egress allowed by GNP allow-all.
					flowTester.CheckFlow(
						flowlog.FlowLog{
							FlowMeta: flowlog.FlowMeta{
								Tuple:      aggrTuple,
								SrcMeta:    w0Meta,
								DstMeta:    w1Meta,
								DstService: flowlog.EmptyService,
								Action:     "allow",
								Reporter:   "src",
							},
							FlowEnforcedPolicySet: flowlog.FlowPolicySet{
								"0|default|gnp:default.w0-allow-all|allow|0": {},
							},
							FlowPendingPolicySet: flowlog.FlowPolicySet{
								"0|default|gnp:default.w0-allow-all|allow|0": {},
							},
						})

					// w[0] → w[2] src: egress allowed by GNP allow-all (destination denies).
					flowTester.CheckFlow(
						flowlog.FlowLog{
							FlowMeta: flowlog.FlowMeta{
								Tuple:      aggrTuple,
								SrcMeta:    w0Meta,
								DstMeta:    w2Meta,
								DstService: flowlog.EmptyService,
								Action:     "allow",
								Reporter:   "src",
							},
							FlowEnforcedPolicySet: flowlog.FlowPolicySet{
								"0|default|gnp:default.w0-allow-all|allow|0": {},
							},
							FlowPendingPolicySet: flowlog.FlowPolicySet{
								"0|default|gnp:default.w0-allow-all|allow|0": {},
							},
						})

					if err := flowTester.Finish(); err != nil {
						return fmt.Errorf("flows incorrect on Felix[0]:\n%v", err)
					}

					// ---- Destination reporter on Felix[1] ----
					err = flowTester.PopulateFromFlowLogs(tc.Felixes[1])
					if err != nil {
						return fmt.Errorf("error populating flow logs from Felix[1]: %s", err)
					}

					// w[0] → w[1] dst: KCNP pass in admin tier, then NP allow in default tier.
					flowTester.CheckFlow(
						flowlog.FlowLog{
							FlowMeta: flowlog.FlowMeta{
								Tuple:      aggrTuple,
								SrcMeta:    w0Meta,
								DstMeta:    w1Meta,
								DstService: flowlog.EmptyService,
								Action:     "allow",
								Reporter:   "dst",
							},
							FlowEnforcedPolicySet: flowlog.FlowPolicySet{
								"0|kube-admin|kcnp:pass-ingress|pass|0":         {},
								"1|default|np:default/default.allow-w1|allow|0": {},
							},
							FlowPendingPolicySet: flowlog.FlowPolicySet{
								"0|kube-admin|kcnp:pass-ingress|pass|0":         {},
								"1|default|np:default/default.allow-w1|allow|0": {},
							},
						})

					// w[0] → w[2] dst: KCNP pass in admin tier, then GNP deny in default tier.
					flowTester.CheckFlow(
						flowlog.FlowLog{
							FlowMeta: flowlog.FlowMeta{
								Tuple:      aggrTuple,
								SrcMeta:    w0Meta,
								DstMeta:    w2Meta,
								DstService: flowlog.EmptyService,
								Action:     "deny",
								Reporter:   "dst",
							},
							FlowEnforcedPolicySet: flowlog.FlowPolicySet{
								"0|kube-admin|kcnp:pass-ingress|pass|0": {},
								"1|default|gnp:default.deny-w2|deny|0":  {},
							},
							FlowPendingPolicySet: flowlog.FlowPolicySet{
								"0|kube-admin|kcnp:pass-ingress|pass|0": {},
								"1|default|gnp:default.deny-w2|deny|0":  {},
							},
						})

					if err := flowTester.Finish(); err != nil {
						return fmt.Errorf("flows incorrect on Felix[1]:\n%v", err)
					}

					return nil
				}

				Eventually(checkFlowLogs, "30s", "3s").ShouldNot(HaveOccurred())
			})
		})
	},
)
