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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

var _ = infrastructure.DatastoreDescribe("_BPF-SAFE_ policy performance hints tests", []apiconfig.DatastoreType{apiconfig.Kubernetes, apiconfig.EtcdV3}, func(getInfra infrastructure.InfraFactory) {
	var (
		tc     infrastructure.TopologyContainers
		infra  infrastructure.DatastoreInfra
		client client.Interface
		w      *workload.Workload
	)

	BeforeEach(func() {
		infra = getInfra()
		opts := infrastructure.DefaultTopologyOptions()
		tc, client = infrastructure.StartNNodeTopology(1, opts, infra)
		w = workload.Run(
			tc.Felixes[0],
			"w",
			"default",
			"10.65.0.1",
			"8080",
			"tcp",
		)
		w.WorkloadEndpoint.Labels["foo"] = "bar"
		w.ConfigureInInfra(infra)
	})

	It("should program IP sets for policies with AssumeNeededOnEveryNode", func() {
		// Create a policy with the flag set.
		pol := v3.NewGlobalNetworkPolicy()
		pol.Name = "test"
		pol.Spec.Selector = "!all()" // Don't match anything.
		pol.Spec.Ingress = []v3.Rule{
			{
				Action: "Allow",
				Source: v3.EntityRule{
					Selector: "foo == 'bar'",
				},
			},
		}
		pol.Spec.PerformanceHints = []v3.PolicyPerformanceHint{v3.PerfHintAssumeNeededOnEveryNode}
		pol, err := client.GlobalNetworkPolicies().Create(context.TODO(), pol, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		var ipsetListCommand []string
		if BPFMode() {
			ipsetListCommand = []string{"calico-bpf", "ipsets", "dump"}
		} else if NFTMode() {
			// There is no nftables command to list all sets, so list the whole table.
			ipsetListCommand = []string{"nft", "list", "table", "calico"}
		} else {
			ipsetListCommand = []string{"ipset", "list"}
		}

		// That should result in programming the IP set the implements the
		// "foo == 'bar'" selector.  The iptables rules won't get created
		// because the iptables driver squashes them if they're not referenced.
		Eventually(tc.Felixes[0].ExecOutputFn(ipsetListCommand...), "10s").Should(
			ContainSubstring("10.65.0.1"),
			"Expected felix to create an IP set containing the workload's IP",
		)

		// Cross-check that the PerformanceHints field is the only thing
		// that's making the IP set get created.
		pol.Spec.PerformanceHints = nil
		pol, err = client.GlobalNetworkPolicies().Update(context.TODO(), pol, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())
		Eventually(tc.Felixes[0].ExecOutputFn(ipsetListCommand...), "10s").ShouldNot(
			ContainSubstring("10.65.0.1"),
			"Expected IP set to be cleaned up when policy no longer has AssumeNeededOnEveryNode",
		)
	})
})
