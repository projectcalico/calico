// Copyright (c) 2023 Tigera, Inc. All rights reserved.
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
	"strings"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/fv/connectivity"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

var _ = infrastructure.DatastoreDescribe("policy grouping tests", []apiconfig.DatastoreType{apiconfig.Kubernetes, apiconfig.EtcdV3}, func(getInfra infrastructure.InfraFactory) {
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

		// Add a default-allow policy so that we know that our deny rule is
		// effective.
		pol := v3.NewGlobalNetworkPolicy()
		pol.Name = "pol-default-allow"
		// Need a selector that matches all endpoints but is different to the
		// ones used in the test.
		pol.Spec.Selector = "!has(unknown)"
		pol.Spec.Order = floatPtr(200)
		pol.Spec.Ingress = []v3.Rule{
			{
				Action: v3.Allow,
			},
		}
		pol.Spec.Egress = []v3.Rule{
			{
				Action: v3.Allow,
			},
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		pol, err := client.GlobalNetworkPolicies().Create(ctx, pol, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())
	})

	createPolicies := func(selectors []string, actions []v3.Action) {
		for i, sel := range selectors {
			pol := v3.NewGlobalNetworkPolicy()
			pol.Name = fmt.Sprintf("pol-%d", i)
			pol.Spec.Selector = sel
			pol.Spec.Order = floatPtr(100.0 + float64(i))
			pol.Spec.Ingress = []v3.Rule{
				{
					Action: actions[i],
					Source: v3.EntityRule{
						Selector: w[i].NameSelector(),
					},
				},
			}
			pol.Spec.Egress = []v3.Rule{
				{
					Action: actions[i],
					Destination: v3.EntityRule{
						Selector: w[i].NameSelector(),
					},
				},
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			_, _ = client.GlobalNetworkPolicies().Delete(ctx, pol.Name, options.DeleteOptions{})
			pol, err := client.GlobalNetworkPolicies().Create(ctx, pol, options.SetOptions{})
			cancel()
			Expect(err).NotTo(HaveOccurred())
		}
	}

	It("should implement policy semantics correctly independent of grouping", func() {
		// Two selectors that are functionally equivalent here (they match all
		// endpoints) but they will trigger different policy groupings.
		const selA = "all()"
		const selB = "has(name)"

		for _, testCase := range []struct {
			Selectors        []string
			ExpectGroupChain bool
		}{
			// One big group.
			{[]string{selA, selA, selA}, true},
			// Group with two policies, one inlined.
			{[]string{selA, selA, selB}, true},
			// Inlined group followed by group with two.
			{[]string{selA, selB, selB}, true},
			// Three inlined groups due to alternating selector.
			{[]string{selA, selB, selA}, false},
		} {
			// For each pattern of selectors (which should give a different
			// policy grouping), move the deny rule between the three policies
			// so that we know that all three policies are active and working.
			for epToDeny := range w {
				By(fmt.Sprintf("Grouping policies on selectors %v and denying traffic to/from WEP %d", testCase.Selectors, epToDeny))
				actions := []v3.Action{v3.Allow, v3.Allow, v3.Allow}
				actions[epToDeny] = v3.Deny
				createPolicies(testCase.Selectors, actions)
				for fromEPIdx := range w {
					toEPIdx := (fromEPIdx + 1) % len(w)
					expectation := connectivity.Some
					if fromEPIdx == epToDeny || toEPIdx == epToDeny {
						expectation = connectivity.None
					}
					cc.Expect(expectation, w[fromEPIdx], w[toEPIdx])
				}
				cc.CheckConnectivity()
				cc.ResetExpectations()

				iptablesChains := tc.Felixes[0].IPTablesChains("filter")
				numInboundGroups := 0
				numOutboundGroups := 0
				for chainName := range iptablesChains {
					if strings.HasPrefix(chainName, rules.PolicyGroupInboundPrefix) {
						numInboundGroups++
					} else if strings.HasPrefix(chainName, rules.PolicyGroupOutboundPrefix) {
						numOutboundGroups++
					}
				}
				if testCase.ExpectGroupChain {
					Expect(numOutboundGroups).To(Equal(1),
						"expected exactly one outbound group chain")
					Expect(numInboundGroups).To(Equal(1),
						"expected exactly one inbound group chain")
				} else {
					Expect(numOutboundGroups).To(Equal(0),
						"expected no outbound group chains (failed cleanup of previous scenario?)")
					Expect(numInboundGroups).To(Equal(0),
						"expected no inbound group chains (failed cleanup of previous scenario?)")
				}
			}
		}
	})
})

func floatPtr(f float64) *float64 {
	return &f
}
