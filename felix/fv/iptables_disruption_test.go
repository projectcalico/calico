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
	"fmt"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/fv/connectivity"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
)

var _ = infrastructure.DatastoreDescribe("iptables disruption tests", []apiconfig.DatastoreType{apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
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
		opts.ExtraEnvVars["FELIX_IptablesRefreshInterval"] = "15"
		tc, client = infrastructure.StartNNodeTopology(1, opts, infra)
		_ = client
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

	It("should restore a deleted iptables insert rule", func() {
		var iptablesRule string
		findRule := func() string {
			for _, rule := range tc.Felixes[0].IPTablesChains("nat")["POSTROUTING"] {
				if strings.Contains(rule, "cali-POSTROUTING") {
					iptablesRule = rule
					return rule
				}
			}
			return ""
		}
		Eventually(findRule, "10s", "100ms").Should(Not(BeEmpty()))

		// Delete the rule
		parts := strings.Split(iptablesRule, " ")
		for i, part := range parts {
			parts[i] = strings.Trim(part, `"`)
		}
		parts = append([]string{"iptables", "-t", "nat", "-D"}, parts[1:]...)
		tc.Felixes[0].Exec(parts...)
		Expect(findRule()).To(BeEmpty())

		Eventually(findRule, "20s", "100ms").Should(Not(BeEmpty()))
	})
})
