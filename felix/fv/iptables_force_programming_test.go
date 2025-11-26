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
	"fmt"

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

var _ = infrastructure.DatastoreDescribe("iptables force-programming tests", []apiconfig.DatastoreType{apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
	var (
		tc     infrastructure.TopologyContainers
		infra  infrastructure.DatastoreInfra
		client client.Interface
		w      [3]*workload.Workload
		cc     *connectivity.Checker
	)

	BeforeEach(func() {
		if NFTMode() {
			Skip("This test is not yet supported in NFT mode")
		}

		infra = getInfra()
		opts := infrastructure.DefaultTopologyOptions()
		tc, client = infrastructure.StartNNodeTopology(1, opts, infra)
		for i := range w {
			w[i] = workload.Run(
				tc.Felixes[0],
				fmt.Sprintf("w%d", i),
				"default",
				fmt.Sprintf("10.65.0.%d", i+2),
				"8080",
				"tcp",
			)
			w[i].ConfigureInInfra(infra)
		}
		cc = &connectivity.Checker{}
		_ = cc
	})

	It("should program an AssumeNeededOnEveryNode policy even with no users", func() {
		pol := api.NewGlobalNetworkPolicy()
		pol.Name = "policy-1"
		pol.Spec.Ingress = []api.Rule{
			{
				Action: "Allow",
				Source: api.EntityRule{
					Selector: "has(allow-as-source)",
				},
				Destination: api.EntityRule{
					Selector: "has(allow-as-dest)",
				},
			},
		}
		pol.Spec.Egress = []api.Rule{
			{
				Action: "Allow",
			},
		}
		pol.Spec.Selector = "!all()"
		pol.Spec.PerformanceHints = []api.PolicyPerformanceHint{
			api.PerfHintAssumeNeededOnEveryNode,
		}
		pol, err := client.GlobalNetworkPolicies().Create(utils.Ctx, pol, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

		Eventually(func() map[string][]string {
			return tc.Felixes[0].IPTablesChains("filter")
		}, "10s", "100ms").Should(And(
			HaveKey("cali-pi-gnp/policy-1"),
			HaveKey("cali-po-gnp/policy-1"),
		))
	})

	AfterEach(func() {
		if CurrentGinkgoTestDescription().Failed {
			for _, felix := range tc.Felixes {
				if NFTMode() {
					logNFTDiags(felix)
				} else {
					_ = felix.ExecMayFail("iptables-save", "-c")
					_ = felix.ExecMayFail("ipset", "list")
				}
			}
		}
		tc.Stop()
		if CurrentGinkgoTestDescription().Failed {
			infra.DumpErrorData()
		}
		infra.Stop()
	})
})
