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

var _ = infrastructure.DatastoreDescribe("cluster network policy conversion _BPF-SAFE_", []apiconfig.DatastoreType{apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
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

	JustBeforeEach(func() {
		infra = getInfra()
		opts = infrastructure.DefaultTopologyOptions()
		opts.IPIPMode = api.IPIPModeNever

		tc, calicoClient = infrastructure.StartNNodeTopology(2, opts, infra)
		infra.AddDefaultAllow()

		// Create workloads: w[0] on felix 0, w[1] and w[2] on felix 1.
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

		// Create the network-policy-api typed client using the k8s API endpoint.
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
	})

	JustAfterEach(func() {
		// Clean up ClusterNetworkPolicies before tearing down infra,
		// since the K8s infra cleanup doesn't handle these CRDs.
		cnps, err := cnpClient.ClusterNetworkPolicies().List(
			context.Background(), metav1.ListOptions{},
		)
		if err == nil {
			for _, cnp := range cnps.Items {
				_ = cnpClient.ClusterNetworkPolicies().Delete(
					context.Background(), cnp.Name, metav1.DeleteOptions{},
				)
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

	Context("with an AdminTier ClusterNetworkPolicy that denies ingress", func() {
		JustBeforeEach(func() {
			// Create a ClusterNetworkPolicy that denies ingress to all pods in
			// the "default" namespace.
			cnp := &clusternetpol.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "deny-ingress",
				},
				Spec: clusternetpol.ClusterNetworkPolicySpec{
					Priority: 100,
					Tier:     clusternetpol.AdminTier,
					Subject: clusternetpol.ClusterNetworkPolicySubject{
						Namespaces: &metav1.LabelSelector{},
					},
					Ingress: []clusternetpol.ClusterNetworkPolicyIngressRule{
						{
							Name:   "deny-all-ingress",
							Action: clusternetpol.ClusterNetworkPolicyRuleActionDeny,
							From: []clusternetpol.ClusterNetworkPolicyIngressPeer{
								{
									Namespaces: &metav1.LabelSelector{},
								},
							},
						},
					},
				},
			}
			_, err := cnpClient.ClusterNetworkPolicies().Create(
				context.Background(), cnp, metav1.CreateOptions{},
			)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should deny all ingress traffic to workloads", func() {
			Eventually(policyProgrammed("deny-ingress"), "15s", "200ms").Should(BeTrue())

			cc = &connectivity.Checker{}
			cc.ExpectNone(w[0], w[1])
			cc.ExpectNone(w[0], w[2])
			cc.CheckConnectivity()
		})

		It("should restore connectivity when the CNP is deleted", func() {
			Eventually(policyProgrammed("deny-ingress"), "15s", "200ms").Should(BeTrue())

			cc = &connectivity.Checker{}
			cc.ExpectNone(w[0], w[1])
			cc.CheckConnectivity()

			By("Deleting the ClusterNetworkPolicy")
			err := cnpClient.ClusterNetworkPolicies().Delete(
				context.Background(), "deny-ingress", metav1.DeleteOptions{},
			)
			Expect(err).NotTo(HaveOccurred())

			Eventually(policyProgrammed("deny-ingress"), "15s", "200ms").Should(BeFalse())

			cc = &connectivity.Checker{}
			cc.ExpectSome(w[0], w[1])
			cc.ExpectSome(w[0], w[2])
			cc.CheckConnectivity()
		})
	})

	Context("with CNP priority ordering: deny-all then allow-all", func() {
		JustBeforeEach(func() {
			// Create a deny-all CNP at lower priority (higher number = evaluated later).
			cnpDeny := &clusternetpol.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "deny-all-ingress",
				},
				Spec: clusternetpol.ClusterNetworkPolicySpec{
					Priority: 200,
					Tier:     clusternetpol.AdminTier,
					Subject: clusternetpol.ClusterNetworkPolicySubject{
						Namespaces: &metav1.LabelSelector{},
					},
					Ingress: []clusternetpol.ClusterNetworkPolicyIngressRule{
						{
							Name:   "deny-all",
							Action: clusternetpol.ClusterNetworkPolicyRuleActionDeny,
							From: []clusternetpol.ClusterNetworkPolicyIngressPeer{
								{
									Namespaces: &metav1.LabelSelector{},
								},
							},
						},
					},
				},
			}
			_, err := cnpClient.ClusterNetworkPolicies().Create(
				context.Background(), cnpDeny, metav1.CreateOptions{},
			)
			Expect(err).NotTo(HaveOccurred())

			// Create an allow-all CNP at higher priority (lower number = evaluated first).
			port := clusternetpol.Port{Number: wepPort}
			cnpAllow := &clusternetpol.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "allow-ingress-tcp",
				},
				Spec: clusternetpol.ClusterNetworkPolicySpec{
					Priority: 100,
					Tier:     clusternetpol.AdminTier,
					Subject: clusternetpol.ClusterNetworkPolicySubject{
						Namespaces: &metav1.LabelSelector{},
					},
					Ingress: []clusternetpol.ClusterNetworkPolicyIngressRule{
						{
							Name:   "allow-tcp",
							Action: clusternetpol.ClusterNetworkPolicyRuleActionAccept,
							From: []clusternetpol.ClusterNetworkPolicyIngressPeer{
								{
									Namespaces: &metav1.LabelSelector{},
								},
							},
							Protocols: []clusternetpol.ClusterNetworkPolicyProtocol{
								{
									TCP: &clusternetpol.ClusterNetworkPolicyProtocolTCP{
										DestinationPort: &port,
									},
								},
							},
						},
					},
				},
			}
			_, err = cnpClient.ClusterNetworkPolicies().Create(
				context.Background(), cnpAllow, metav1.CreateOptions{},
			)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should allow traffic when the higher-priority allow CNP matches", func() {
			Eventually(policyProgrammed("allow-ingress-tcp"), "15s", "200ms").Should(BeTrue())
			Eventually(policyProgrammed("deny-all-ingress"), "15s", "200ms").Should(BeTrue())

			cc = &connectivity.Checker{}
			cc.ExpectSome(w[0], w[1])
			cc.ExpectSome(w[0], w[2])
			cc.CheckConnectivity()
		})

		It("should deny traffic after deleting the allow CNP", func() {
			Eventually(policyProgrammed("allow-ingress-tcp"), "15s", "200ms").Should(BeTrue())
			Eventually(policyProgrammed("deny-all-ingress"), "15s", "200ms").Should(BeTrue())

			cc = &connectivity.Checker{}
			cc.ExpectSome(w[0], w[1])
			cc.CheckConnectivity()

			By("Deleting the allow CNP so only the deny remains")
			err := cnpClient.ClusterNetworkPolicies().Delete(
				context.Background(), "allow-ingress-tcp", metav1.DeleteOptions{},
			)
			Expect(err).NotTo(HaveOccurred())

			Eventually(policyProgrammed("allow-ingress-tcp"), "15s", "200ms").Should(BeFalse())

			cc = &connectivity.Checker{}
			cc.ExpectNone(w[0], w[1])
			cc.ExpectNone(w[0], w[2])
			cc.CheckConnectivity()
		})
	})

	Context("with a BaselineTier ClusterNetworkPolicy", func() {
		JustBeforeEach(func() {
			// Create a BaselineTier CNP that denies egress.
			cnp := &clusternetpol.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "baseline-deny-egress",
				},
				Spec: clusternetpol.ClusterNetworkPolicySpec{
					Priority: 100,
					Tier:     clusternetpol.BaselineTier,
					Subject: clusternetpol.ClusterNetworkPolicySubject{
						Namespaces: &metav1.LabelSelector{},
					},
					Egress: []clusternetpol.ClusterNetworkPolicyEgressRule{
						{
							Name:   "deny-all-egress",
							Action: clusternetpol.ClusterNetworkPolicyRuleActionDeny,
							To: []clusternetpol.ClusterNetworkPolicyEgressPeer{
								{
									Namespaces: &metav1.LabelSelector{},
								},
							},
						},
					},
				},
			}
			_, err := cnpClient.ClusterNetworkPolicies().Create(
				context.Background(), cnp, metav1.CreateOptions{},
			)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should deny egress traffic", func() {
			Eventually(policyProgrammed("baseline-deny-egress"), "15s", "200ms").Should(BeTrue())

			cc = &connectivity.Checker{}
			cc.ExpectNone(w[0], w[1])
			cc.ExpectNone(w[0], w[2])
			cc.CheckConnectivity()
		})
	})

	Context("with a KCNP pass rule and a GNP deny in the default tier", func() {
		JustBeforeEach(func() {
			// Create a KCNP in the kube-admin tier (order 1000) that passes
			// ingress traffic to the next tier.
			cnp := &clusternetpol.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "pass-ingress",
				},
				Spec: clusternetpol.ClusterNetworkPolicySpec{
					Priority: 100,
					Tier:     clusternetpol.AdminTier,
					Subject: clusternetpol.ClusterNetworkPolicySubject{
						Namespaces: &metav1.LabelSelector{},
					},
					Ingress: []clusternetpol.ClusterNetworkPolicyIngressRule{
						{
							Name:   "pass-all-ingress",
							Action: clusternetpol.ClusterNetworkPolicyRuleActionPass,
							From: []clusternetpol.ClusterNetworkPolicyIngressPeer{
								{
									Namespaces: &metav1.LabelSelector{},
								},
							},
						},
					},
				},
			}
			_, err := cnpClient.ClusterNetworkPolicies().Create(
				context.Background(), cnp, metav1.CreateOptions{},
			)
			Expect(err).NotTo(HaveOccurred())

			// Create a GNP in the default tier (evaluated after kube-admin) that
			// denies all ingress.
			gnp := api.NewGlobalNetworkPolicy()
			gnp.Name = "default.deny-all-ingress"
			order := float64(1.0)
			gnp.Spec.Order = &order
			gnp.Spec.Tier = "default"
			gnp.Spec.Selector = "all()"
			gnp.Spec.Types = []api.PolicyType{api.PolicyTypeIngress}
			gnp.Spec.Ingress = []api.Rule{{Action: api.Deny}}
			_, err = calicoClient.GlobalNetworkPolicies().Create(utils.Ctx, gnp, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should deny traffic via the GNP after the KCNP passes", func() {
			Eventually(policyProgrammed("pass-ingress"), "15s", "200ms").Should(BeTrue())
			Eventually(policyProgrammed("deny-all-ingress"), "15s", "200ms").Should(BeTrue())

			cc = &connectivity.Checker{}
			cc.ExpectNone(w[0], w[1])
			cc.ExpectNone(w[0], w[2])
			cc.CheckConnectivity()
		})

		It("should allow traffic once the GNP is removed", func() {
			Eventually(policyProgrammed("pass-ingress"), "15s", "200ms").Should(BeTrue())
			Eventually(policyProgrammed("deny-all-ingress"), "15s", "200ms").Should(BeTrue())

			cc = &connectivity.Checker{}
			cc.ExpectNone(w[0], w[1])
			cc.CheckConnectivity()

			By("Deleting the GNP so traffic falls through to the default-allow profile")
			_, err := calicoClient.GlobalNetworkPolicies().Delete(utils.Ctx, "default.deny-all-ingress", options.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())

			Eventually(policyProgrammed("deny-all-ingress"), "15s", "200ms").Should(BeFalse())

			cc = &connectivity.Checker{}
			cc.ExpectSome(w[0], w[1])
			cc.ExpectSome(w[0], w[2])
			cc.CheckConnectivity()
		})
	})

	Context("with a KCNP allow in kube-admin overriding a GNP deny in default tier", func() {
		JustBeforeEach(func() {
			// Create a GNP in the default tier that denies all ingress.
			gnp := api.NewGlobalNetworkPolicy()
			gnp.Name = "default.deny-all-ingress"
			order := float64(1.0)
			gnp.Spec.Order = &order
			gnp.Spec.Tier = "default"
			gnp.Spec.Selector = "all()"
			gnp.Spec.Types = []api.PolicyType{api.PolicyTypeIngress}
			gnp.Spec.Ingress = []api.Rule{{Action: api.Deny}}
			_, err := calicoClient.GlobalNetworkPolicies().Create(utils.Ctx, gnp, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())

			// Create a KCNP in kube-admin (evaluated before default) that allows
			// TCP traffic on wepPort. Because allow is terminal, the GNP deny
			// in the default tier is never reached.
			port := clusternetpol.Port{Number: wepPort}
			cnp := &clusternetpol.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "allow-ingress-tcp",
				},
				Spec: clusternetpol.ClusterNetworkPolicySpec{
					Priority: 100,
					Tier:     clusternetpol.AdminTier,
					Subject: clusternetpol.ClusterNetworkPolicySubject{
						Namespaces: &metav1.LabelSelector{},
					},
					Ingress: []clusternetpol.ClusterNetworkPolicyIngressRule{
						{
							Name:   "allow-tcp",
							Action: clusternetpol.ClusterNetworkPolicyRuleActionAccept,
							From: []clusternetpol.ClusterNetworkPolicyIngressPeer{
								{
									Namespaces: &metav1.LabelSelector{},
								},
							},
							Protocols: []clusternetpol.ClusterNetworkPolicyProtocol{
								{
									TCP: &clusternetpol.ClusterNetworkPolicyProtocolTCP{
										DestinationPort: &port,
									},
								},
							},
						},
					},
				},
			}
			_, err = cnpClient.ClusterNetworkPolicies().Create(
				context.Background(), cnp, metav1.CreateOptions{},
			)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should allow traffic because kube-admin allow takes precedence over default deny", func() {
			Eventually(policyProgrammed("allow-ingress-tcp"), "15s", "200ms").Should(BeTrue())
			Eventually(policyProgrammed("deny-all-ingress"), "15s", "200ms").Should(BeTrue())

			cc = &connectivity.Checker{}
			cc.ExpectSome(w[0], w[1])
			cc.ExpectSome(w[0], w[2])
			cc.CheckConnectivity()
		})
	})
})

var _ = infrastructure.DatastoreDescribe("pepper cluster network policy flow logs _BPF-SAFE_", []apiconfig.DatastoreType{apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
	const wepPort = 8055
	wepPortStr := fmt.Sprintf("%d", wepPort)

	var (
		infra        infrastructure.DatastoreInfra
		opts         infrastructure.TopologyOptions
		tc           infrastructure.TopologyContainers
		calicoClient client.Interface
		cnpClient    *netpolicyclient.PolicyV1alpha2Client
		w            [2]*workload.Workload
		cc           *connectivity.Checker
	)

	newCnpClient := func() *netpolicyclient.PolicyV1alpha2Client {
		k8sInfra := infra.(*infrastructure.K8sDatastoreInfra)
		c, err := netpolicyclient.NewForConfig(&rest.Config{
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
		return c
	}

	policyProgrammedOn := func(felix *infrastructure.Felix, ifaceName, policyName string) func() bool {
		return func() bool {
			if BPFMode() {
				out := bpfDumpPolicy(felix, ifaceName, "ingress")
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

	JustAfterEach(func() {
		if cnpClient != nil {
			cnps, err := cnpClient.ClusterNetworkPolicies().List(
				context.Background(), metav1.ListOptions{},
			)
			if err == nil {
				for _, cnp := range cnps.Items {
					_ = cnpClient.ClusterNetworkPolicies().Delete(
						context.Background(), cnp.Name, metav1.DeleteOptions{},
					)
				}
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

	Context("with AdminTier deny-all ingress CNP", func() {
		JustBeforeEach(func() {
			infra = getInfra()
			opts = infrastructure.DefaultTopologyOptions()
			opts.IPIPMode = api.IPIPModeNever
			opts.FlowLogSource = infrastructure.FlowLogSourceLocalSocket

			opts.ExtraEnvVars["FELIX_FLOWLOGSCOLLECTORDEBUGTRACE"] = "true"
			opts.ExtraEnvVars["FELIX_FLOWLOGSFLUSHINTERVAL"] = "2"
			opts.ExtraEnvVars["FELIX_FLOWLOGSLOCALREPORTER"] = "Enabled"

			tc, calicoClient = infrastructure.StartNNodeTopology(2, opts, infra)
			infra.AddDefaultAllow()

			infrastructure.AssignIP("w0", "10.65.0.0", tc.Felixes[0].Hostname, calicoClient)
			w[0] = workload.Run(tc.Felixes[0], "w0", "default", "10.65.0.0", wepPortStr, "tcp")
			w[0].ConfigureInInfra(infra)

			infrastructure.AssignIP("w1", "10.65.1.0", tc.Felixes[1].Hostname, calicoClient)
			w[1] = workload.Run(tc.Felixes[1], "w1", "default", "10.65.1.0", wepPortStr, "tcp")
			w[1].ConfigureInInfra(infra)

			ensureRoutesProgrammed(tc.Felixes)
			if BPFMode() {
				ensureAllNodesBPFProgramsAttached(tc.Felixes)
			}

			cnpClient = newCnpClient()

			cnp := &clusternetpol.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "deny-ingress",
				},
				Spec: clusternetpol.ClusterNetworkPolicySpec{
					Priority: 100,
					Tier:     clusternetpol.AdminTier,
					Subject: clusternetpol.ClusterNetworkPolicySubject{
						Namespaces: &metav1.LabelSelector{},
					},
					Ingress: []clusternetpol.ClusterNetworkPolicyIngressRule{
						{
							Name:   "deny-all-ingress",
							Action: clusternetpol.ClusterNetworkPolicyRuleActionDeny,
							From: []clusternetpol.ClusterNetworkPolicyIngressPeer{
								{
									Namespaces: &metav1.LabelSelector{},
								},
							},
						},
					},
				},
			}
			_, err := cnpClient.ClusterNetworkPolicies().Create(
				context.Background(), cnp, metav1.CreateOptions{},
			)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should generate deny flow logs with correct KCNP policy", func() {
			Eventually(policyProgrammedOn(tc.Felixes[1], w[1].InterfaceName, "deny-ingress"), "15s", "200ms").Should(BeTrue())

			cc = &connectivity.Checker{}
			cc.ExpectNone(w[0], w[1])
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

				flowTester := flowlogs.NewFlowTester(flowlogs.FlowTesterOptions{
					ExpectLabels:           true,
					ExpectEnforcedPolicies: true,
					MatchEnforcedPolicies:  true,
					ExpectPendingPolicies:  true,
					MatchPendingPolicies:   true,
					Includes:               []flowlogs.IncludeFilter{flowlogs.IncludeByDestPort(wepPort)},
				})

				err := flowTester.PopulateFromFlowLogs(tc.Felixes[1])
				if err != nil {
					return fmt.Errorf("error populating flow logs from Felix[1]: %s", err)
				}

				// Destination reporter on Felix[1] should see the deny from the KCNP.
				flowTester.CheckFlow(
					flowlog.FlowLog{
						FlowMeta: flowlog.FlowMeta{
							Tuple:      aggrTuple,
							SrcMeta:    w0Meta,
							DstMeta:    w1Meta,
							DstService: flowlog.EmptyService,
							Action:     "deny",
							Reporter:   "dst",
						},
						FlowEnforcedPolicySet: flowlog.FlowPolicySet{
							"0|kube-admin|kcnp:deny-ingress|deny|0": {},
						},
						FlowPendingPolicySet: flowlog.FlowPolicySet{
							"0|kube-admin|kcnp:deny-ingress|deny|0": {},
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

	Context("with AdminTier allow CNP overriding deny CNP", func() {
		JustBeforeEach(func() {
			infra = getInfra()
			opts = infrastructure.DefaultTopologyOptions()
			opts.IPIPMode = api.IPIPModeNever
			opts.FlowLogSource = infrastructure.FlowLogSourceLocalSocket

			opts.ExtraEnvVars["FELIX_FLOWLOGSCOLLECTORDEBUGTRACE"] = "true"
			opts.ExtraEnvVars["FELIX_FLOWLOGSFLUSHINTERVAL"] = "2"
			opts.ExtraEnvVars["FELIX_FLOWLOGSLOCALREPORTER"] = "Enabled"

			tc, calicoClient = infrastructure.StartNNodeTopology(2, opts, infra)
			infra.AddDefaultAllow()

			infrastructure.AssignIP("w0", "10.65.0.0", tc.Felixes[0].Hostname, calicoClient)
			w[0] = workload.Run(tc.Felixes[0], "w0", "default", "10.65.0.0", wepPortStr, "tcp")
			w[0].ConfigureInInfra(infra)

			infrastructure.AssignIP("w1", "10.65.1.0", tc.Felixes[1].Hostname, calicoClient)
			w[1] = workload.Run(tc.Felixes[1], "w1", "default", "10.65.1.0", wepPortStr, "tcp")
			w[1].ConfigureInInfra(infra)

			ensureRoutesProgrammed(tc.Felixes)
			if BPFMode() {
				ensureAllNodesBPFProgramsAttached(tc.Felixes)
			}

			cnpClient = newCnpClient()

			// Deny-all at lower priority (higher number = evaluated later).
			cnpDeny := &clusternetpol.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "deny-all-ingress",
				},
				Spec: clusternetpol.ClusterNetworkPolicySpec{
					Priority: 200,
					Tier:     clusternetpol.AdminTier,
					Subject: clusternetpol.ClusterNetworkPolicySubject{
						Namespaces: &metav1.LabelSelector{},
					},
					Ingress: []clusternetpol.ClusterNetworkPolicyIngressRule{
						{
							Name:   "deny-all",
							Action: clusternetpol.ClusterNetworkPolicyRuleActionDeny,
							From: []clusternetpol.ClusterNetworkPolicyIngressPeer{
								{
									Namespaces: &metav1.LabelSelector{},
								},
							},
						},
					},
				},
			}
			_, err := cnpClient.ClusterNetworkPolicies().Create(
				context.Background(), cnpDeny, metav1.CreateOptions{},
			)
			Expect(err).NotTo(HaveOccurred())

			// Allow TCP on wepPort at higher priority (lower number = evaluated first).
			port := clusternetpol.Port{Number: wepPort}
			cnpAllow := &clusternetpol.ClusterNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "allow-ingress-tcp",
				},
				Spec: clusternetpol.ClusterNetworkPolicySpec{
					Priority: 100,
					Tier:     clusternetpol.AdminTier,
					Subject: clusternetpol.ClusterNetworkPolicySubject{
						Namespaces: &metav1.LabelSelector{},
					},
					Ingress: []clusternetpol.ClusterNetworkPolicyIngressRule{
						{
							Name:   "allow-tcp",
							Action: clusternetpol.ClusterNetworkPolicyRuleActionAccept,
							From: []clusternetpol.ClusterNetworkPolicyIngressPeer{
								{
									Namespaces: &metav1.LabelSelector{},
								},
							},
							Protocols: []clusternetpol.ClusterNetworkPolicyProtocol{
								{
									TCP: &clusternetpol.ClusterNetworkPolicyProtocolTCP{
										DestinationPort: &port,
									},
								},
							},
						},
					},
				},
			}
			_, err = cnpClient.ClusterNetworkPolicies().Create(
				context.Background(), cnpAllow, metav1.CreateOptions{},
			)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should generate allow flow logs with higher-priority KCNP policy", func() {
			Eventually(policyProgrammedOn(tc.Felixes[1], w[1].InterfaceName, "allow-ingress-tcp"), "15s", "200ms").Should(BeTrue())
			Eventually(policyProgrammedOn(tc.Felixes[1], w[1].InterfaceName, "deny-all-ingress"), "15s", "200ms").Should(BeTrue())

			cc = &connectivity.Checker{}
			cc.ExpectSome(w[0], w[1])
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

				flowTester := flowlogs.NewFlowTester(flowlogs.FlowTesterOptions{
					ExpectLabels:           true,
					ExpectEnforcedPolicies: true,
					MatchEnforcedPolicies:  true,
					ExpectPendingPolicies:  true,
					MatchPendingPolicies:   true,
					Includes:               []flowlogs.IncludeFilter{flowlogs.IncludeByDestPort(wepPort)},
				})

				// Check destination reporter on Felix[1]: the allow CNP should be the
				// enforced policy since it has higher priority.
				err := flowTester.PopulateFromFlowLogs(tc.Felixes[1])
				if err != nil {
					return fmt.Errorf("error populating flow logs from Felix[1]: %s", err)
				}

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
							"0|kube-admin|kcnp:allow-ingress-tcp|allow|0": {},
						},
						FlowPendingPolicySet: flowlog.FlowPolicySet{
							"0|kube-admin|kcnp:allow-ingress-tcp|allow|0": {},
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
})
