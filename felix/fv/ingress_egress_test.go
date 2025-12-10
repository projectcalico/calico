// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.
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
	"strconv"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/fv/connectivity"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/utils"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
)

var _ = infrastructure.DatastoreDescribe("_INGRESS-EGRESS_ _BPF-SAFE_ with initialized Felix, etcd datastore, 3 workloads", []apiconfig.DatastoreType{apiconfig.EtcdV3}, func(getInfra infrastructure.InfraFactory) {
	var (
		tc     infrastructure.TopologyContainers
		client client.Interface
		infra  infrastructure.DatastoreInfra
		w      [3]*workload.Workload
		cc     *connectivity.Checker
	)

	BeforeEach(func() {
		infra = getInfra()
		opts := infrastructure.DefaultTopologyOptions()
		tc, client = infrastructure.StartSingleNodeTopology(opts, infra)
		infrastructure.CreateDefaultProfile(client, "default", map[string]string{"default": ""}, "default == ''")

		// Create three workloads, using that profile.
		for ii := range w {
			iiStr := strconv.Itoa(ii)
			w[ii] = workload.Run(tc.Felixes[0], "w"+iiStr, "default", "10.65.0.1"+iiStr, "8055", "tcp")
			w[ii].Configure(client)
		}

		cc = &connectivity.Checker{}
	})

	It("full connectivity to and from workload 0", func() {
		cc.ExpectSome(w[1], w[0])
		cc.ExpectSome(w[2], w[0])
		cc.ExpectSome(w[0], w[1])
		cc.ExpectSome(w[0], w[2])
		cc.CheckConnectivity()
	})

	Context("with ingress-only restriction for workload 0", func() {
		BeforeEach(func() {
			policy := api.NewNetworkPolicy()
			policy.Namespace = "fv"
			policy.Name = "policy-1"
			allowFromW1 := api.Rule{
				Action: api.Allow,
				Source: api.EntityRule{
					Selector: w[1].NameSelector(),
				},
			}
			policy.Spec.Ingress = []api.Rule{allowFromW1}
			policy.Spec.Selector = w[0].NameSelector()
			_, err := client.NetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())
		})

		It("only w1 can connect into w0, but egress from w0 is unrestricted", func() {
			cc.ExpectNone(w[2], w[0])
			cc.ExpectSome(w[1], w[0])
			cc.ExpectSome(w[0], w[1])
			cc.ExpectSome(w[0], w[2])
			cc.CheckConnectivity()
		})
	})

	Context("with egress-only restriction for workload 0", func() {
		BeforeEach(func() {
			policy := api.NewNetworkPolicy()
			policy.Namespace = "fv"
			policy.Name = "policy-1"
			allowToW1 := api.Rule{
				Action: api.Allow,
				Destination: api.EntityRule{
					Selector: w[1].NameSelector(),
				},
			}
			policy.Spec.Egress = []api.Rule{allowToW1}
			policy.Spec.Selector = w[0].NameSelector()
			_, err := client.NetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())
		})

		It("ingress to w0 is unrestricted, but w0 can only connect out to w1", func() {
			cc.ExpectNone(w[0], w[2])
			cc.ExpectSome(w[1], w[0])
			cc.ExpectSome(w[2], w[0])
			cc.ExpectSome(w[0], w[1])
			cc.CheckConnectivity()
		})
	})

	Context("with ingress rules and types [ingress,egress]", func() {
		BeforeEach(func() {
			policy := api.NewNetworkPolicy()
			policy.Namespace = "fv"
			policy.Name = "policy-1"
			allowFromW1 := api.Rule{
				Action: api.Allow,
				Source: api.EntityRule{
					Selector: w[1].NameSelector(),
				},
			}
			policy.Spec.Ingress = []api.Rule{allowFromW1}
			policy.Spec.Selector = w[0].NameSelector()
			policy.Spec.Types = []api.PolicyType{api.PolicyTypeIngress, api.PolicyTypeEgress}
			_, err := client.NetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())
		})

		It("only w1 can connect into w0, and all egress from w0 is denied", func() {
			cc.ExpectNone(w[2], w[0])
			cc.ExpectSome(w[1], w[0])
			cc.ExpectNone(w[0], w[1])
			cc.ExpectNone(w[0], w[2])
			cc.CheckConnectivity()
		})
	})

	Context("with an egress deny rule", func() {
		var policy *api.NetworkPolicy

		BeforeEach(func() {
			policy = api.NewNetworkPolicy()
			policy.Namespace = "fv"
			policy.Name = "policy-1"
			allowFromW1 := api.Rule{
				Action: api.Allow,
				Source: api.EntityRule{
					Selector: w[1].NameSelector(),
				},
			}
			policy.Spec.Ingress = []api.Rule{allowFromW1}
			policy.Spec.Egress = []api.Rule{{Action: api.Deny}}
			policy.Spec.Selector = w[0].NameSelector()
		})

		JustBeforeEach(func() {
			_, err := client.NetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())
		})

		Describe("and types [ingress] (i.e. disabling the egress rule)", func() {
			BeforeEach(func() {
				policy.Spec.Types = []api.PolicyType{api.PolicyTypeIngress}
			})

			It("only w1 can connect into w0, and all egress from w0 is allowed", func() {
				cc.ExpectNone(w[2], w[0])
				cc.ExpectSome(w[1], w[0])
				cc.ExpectSome(w[0], w[1])
				cc.ExpectSome(w[0], w[2])
				cc.CheckConnectivity()
			})
		})

		Describe("and types [ingress, egress]", func() {
			BeforeEach(func() {
				policy.Spec.Types = []api.PolicyType{api.PolicyTypeIngress, api.PolicyTypeEgress}
			})

			It("only w1 can connect into w0, and all egress from w0 is blocked", func() {
				cc.ExpectNone(w[2], w[0])
				cc.ExpectSome(w[1], w[0])
				cc.ExpectNone(w[0], w[1])
				cc.ExpectNone(w[0], w[2])
				cc.CheckConnectivity()
			})
		})
	})
})

var _ = infrastructure.DatastoreDescribe("_INGRESS-EGRESS_ (iptables-only) with initialized Felix, etcd datastore, 3 workloads", []apiconfig.DatastoreType{apiconfig.EtcdV3}, func(getInfra infrastructure.InfraFactory) {
	var (
		tc      infrastructure.TopologyContainers
		client  client.Interface
		infra   infrastructure.DatastoreInfra
		w       [3]*workload.Workload
		cc      *connectivity.Checker
		listCmd []string
	)

	BeforeEach(func() {
		infra = getInfra()
		opts := infrastructure.DefaultTopologyOptions()
		tc, client = infrastructure.StartSingleNodeTopology(opts, infra)
		infrastructure.CreateDefaultProfile(client, "default", map[string]string{"default": ""}, "default == ''")

		if NFTMode() {
			listCmd = []string{"nft", "list", "table", "calico"}
		} else {
			listCmd = []string{"iptables-save"}
		}

		// Create three workloads, using that profile.
		for ii := range w {
			iiStr := strconv.Itoa(ii)
			w[ii] = workload.Run(tc.Felixes[0], "w"+iiStr, "default", "10.65.0.1"+iiStr, "8055", "tcp")
			w[ii].Configure(client)
		}

		cc = &connectivity.Checker{}
	})

	Context("with an ingress policy with no rules", func() {
		BeforeEach(func() {
			policy := api.NewNetworkPolicy()
			policy.Namespace = "fv"
			policy.Name = "policy-1"
			policy.Spec.Ingress = []api.Rule{}
			policy.Spec.Selector = w[0].NameSelector()
			_, err := client.NetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())
		})

		It("no-one can connect to w0, but egress from w0 is unrestricted", func() {
			cc.ExpectNone(w[2], w[0])
			cc.ExpectNone(w[1], w[0])
			cc.ExpectSome(w[0], w[1])
			cc.ExpectSome(w[0], w[2])
			cc.CheckConnectivity()
		})

		It("should have the expected comment in the dataplane", func() {
			Eventually(func() string {
				out, _ := tc.Felixes[0].ExecOutput(listCmd...)
				return out
			}).Should(ContainSubstring("NetworkPolicy fv/policy-1 ingress"))
		})
	})

	Context("with egress-only restriction for workload 0", func() {
		BeforeEach(func() {
			policy := api.NewNetworkPolicy()
			policy.Namespace = "fv"
			policy.Name = "policy-1"
			allowToW1 := api.Rule{
				Action: api.Allow,
				Destination: api.EntityRule{
					Selector: w[1].NameSelector(),
				},
			}
			policy.Spec.Egress = []api.Rule{allowToW1}
			policy.Spec.Selector = w[0].NameSelector()
			_, err := client.NetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should have the expected comment in the dataplane", func() {
			Eventually(func() string {
				out, _ := tc.Felixes[0].ExecOutput(listCmd...)
				return out
			}).Should(ContainSubstring("NetworkPolicy fv/policy-1 egress"))
		})
	})
})

var _ = infrastructure.DatastoreDescribe("with Typha and Felix-Typha TLS", []apiconfig.DatastoreType{apiconfig.EtcdV3}, func(getInfra infrastructure.InfraFactory) {
	var (
		tc     infrastructure.TopologyContainers
		client client.Interface
		infra  infrastructure.DatastoreInfra
		w      [3]*workload.Workload
		cc     *connectivity.Checker
	)

	BeforeEach(func() {
		infra = getInfra()
		options := infrastructure.DefaultTopologyOptions()
		options.WithTypha = true
		options.WithFelixTyphaTLS = true
		tc, client = infrastructure.StartSingleNodeTopology(options, infra)
		infrastructure.CreateDefaultProfile(client, "default", map[string]string{"default": ""}, "default == ''")

		// Create three workloads, using that profile.
		for ii := range w {
			iiStr := strconv.Itoa(ii)
			w[ii] = workload.Run(tc.Felixes[0], "w"+iiStr, "default", "10.65.0.1"+iiStr, "8055", "tcp")
			w[ii].Configure(client)
		}

		cc = &connectivity.Checker{}
	})

	It("full connectivity to and from workload 0", func() {
		cc.ExpectSome(w[1], w[0])
		cc.ExpectSome(w[2], w[0])
		cc.ExpectSome(w[0], w[1])
		cc.ExpectSome(w[0], w[2])
		cc.CheckConnectivity()
	})

	Context("with ingress-only restriction for workload 0", func() {
		BeforeEach(func() {
			policy := api.NewNetworkPolicy()
			policy.Namespace = "fv"
			policy.Name = "policy-1"
			allowFromW1 := api.Rule{
				Action: api.Allow,
				Source: api.EntityRule{
					Selector: w[1].NameSelector(),
				},
			}
			policy.Spec.Ingress = []api.Rule{allowFromW1}
			policy.Spec.Selector = w[0].NameSelector()
			_, err := client.NetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())
		})

		It("only w1 can connect into w0, but egress from w0 is unrestricted", func() {
			cc.ExpectNone(w[2], w[0])
			cc.ExpectSome(w[1], w[0])
			cc.ExpectSome(w[0], w[1])
			cc.ExpectSome(w[0], w[2])
			cc.CheckConnectivity()
		})
	})
})
