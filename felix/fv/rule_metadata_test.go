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
	cryptorand "crypto/rand"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/fv/connectivity"
	"github.com/projectcalico/calico/felix/fv/containers"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/utils"
	"github.com/projectcalico/calico/felix/fv/workload"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
)

var _ = Describe("Rule Metadata tests", func() {
	var (
		tc     infrastructure.TopologyContainers
		client client.Interface
		infra  infrastructure.DatastoreInfra
		etcd   *containers.Container
		wl0    *workload.Workload
		wl1    *workload.Workload
	)

	BeforeEach(func() {
		tc, etcd, client, infra = infrastructure.StartSingleNodeEtcdTopology(infrastructure.DefaultTopologyOptions())

		wl0 = workload.Run(tc.Felixes[0], "test0", "default", "10.65.0.1", "80", "tcp")
		wl0.Configure(client)

		wl1 = workload.Run(tc.Felixes[0], "test1", "default", "10.65.0.2", "80", "tcp")
		wl1.Configure(client)
	})

	AfterEach(func() {
		if CurrentGinkgoTestDescription().Failed {
			for _, felix := range tc.Felixes {
				logNFTDiags(felix)
			}
		}
		wl0.Stop()
		wl1.Stop()
		tc.Stop()
		etcd.Stop()
		infra.Stop()
	})

	Context("With a GlobalNetworkPolicy with rule metadata", func() {
		var gnp *api.GlobalNetworkPolicy

		BeforeEach(func() {
			gnp = api.NewGlobalNetworkPolicy()
			gnp.Name = "rule-meta-test"
			gnp.Spec.Selector = "all()"
			gnp.Spec.Ingress = []api.Rule{{
				Action:   api.Allow,
				Metadata: &api.RuleMetadata{Annotations: map[string]string{"fvtest": "gnp"}},
			}}
			_, err := client.GlobalNetworkPolicies().Create(utils.Ctx, gnp, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should add comments to the dataplane", func() {
			if NFTMode() {
				Eventually(getNFTables(tc.Felixes[0])).Should(ContainSubstring("fvtest=gnp"))
			} else {
				Eventually(getIPTables(tc.Felixes[0].Name)).Should(ContainSubstring("-m comment --comment \"fvtest=gnp\""))
			}
		})
	})

	Context("With a Profile with rule metadata", func() {
		var p *api.Profile

		BeforeEach(func() {
			p = api.NewProfile()
			p.Name = "default"
			p.Spec.Ingress = []api.Rule{{
				Action:   api.Allow,
				Metadata: &api.RuleMetadata{Annotations: map[string]string{"fvtest": "profile"}},
			}}
			_, err := client.Profiles().Create(utils.Ctx, p, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should add comments to the dataplane", func() {
			if NFTMode() {
				Eventually(getNFTables(tc.Felixes[0])).Should(ContainSubstring("fvtest=profile"))
			} else {
				Eventually(getIPTables(tc.Felixes[0].Name)).Should(ContainSubstring("-m comment --comment \"fvtest=profile\""))
			}
		})
	})

	Context("With a NetworkPolicy with rule metadata", func() {
		var np *api.NetworkPolicy

		BeforeEach(func() {
			np = api.NewNetworkPolicy()
			np.Name = "rule-meta-test"
			np.Namespace = "fv"
			np.Spec.Selector = "all()"
			np.Spec.Ingress = []api.Rule{{
				Action:   api.Allow,
				Metadata: &api.RuleMetadata{Annotations: map[string]string{"fvtest": "networkpolicy"}},
			}}
			_, err := client.NetworkPolicies().Create(utils.Ctx, np, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should add comments to iptables", func() {
			if NFTMode() {
				Eventually(getNFTables(tc.Felixes[0])).Should(ContainSubstring("fvtest=networkpolicy"))
			} else {
				Eventually(getIPTables(tc.Felixes[0].Name)).Should(ContainSubstring("-m comment --comment \"fvtest=networkpolicy\""))
			}
		})
	})

	Context("With a Profile with rule metadata including newlines and unicode", func() {
		var p *api.Profile

		BeforeEach(func() {
			// build some random bytes to try to break annotation processing
			rv := make([]byte, 200)
			_, err := cryptorand.Read(rv)
			Expect(err).ToNot(HaveOccurred())
			// the profile should allow the workloads to communicate
			p = api.NewProfile()
			p.Name = "default"
			p.Spec.Egress = []api.Rule{{
				Action:   api.Allow,
				Metadata: &api.RuleMetadata{Annotations: map[string]string{"foo": "hello\nworld"}},
			}}
			p.Spec.Ingress = []api.Rule{{
				Action: api.Allow,
				Metadata: &api.RuleMetadata{Annotations: map[string]string{
					"hometown": "Småland",
					"random":   string(rv),
				}},
			}}
			_, err = client.Profiles().Create(utils.Ctx, p, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should add comments to iptables", func() {
			// Felix replaces anything other than "safe" shell characters with _
			if NFTMode() {
				Eventually(getNFTables(tc.Felixes[0])).Should(ContainSubstring("foo=hello_world"))
				Eventually(getNFTables(tc.Felixes[0])).Should(ContainSubstring("hometown=Sm_land"))
				Eventually(getNFTables(tc.Felixes[0])).Should(ContainSubstring("random="))
			} else {
				Eventually(getIPTables(tc.Felixes[0].Name)).Should(ContainSubstring("-m comment --comment \"foo=hello_world\""))
				Eventually(getIPTables(tc.Felixes[0].Name)).Should(ContainSubstring("-m comment --comment \"hometown=Sm_land\""))
				Eventually(getIPTables(tc.Felixes[0].Name)).Should(ContainSubstring("-m comment --comment \"random="))
			}
		})

		// This test case verifies that "interesting" annotations like newlines and unicode don't break
		// Felix's iptables handling code, which parses the output of iptables-save
		It("should allow connectivity between workloads", func() {
			cc := &connectivity.Checker{
				ReverseDirection: false,
				Protocol:         "tcp",
			}
			cc.ExpectSome(wl0, wl1.Port(80))
			cc.CheckConnectivity()
		})
	})
})

func getIPTables(name string) func() string {
	return func() string {
		cmd := utils.Command("docker", "exec", name, "iptables-save", "-c")
		out, err := cmd.Output()
		Expect(err).ToNot(HaveOccurred())
		return string(out)
	}
}

func getNFTables(f *infrastructure.Felix) func() string {
	return func() string {
		out, err := f.ExecOutput("nft", "list", "table", "ip", "calico")
		Expect(err).ToNot(HaveOccurred())
		return string(out)
	}
}
