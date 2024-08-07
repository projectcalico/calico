// Copyright (c) 2024 Tigera, Inc. All rights reserved.
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

//go:build fvtests

package fv_test

import (
	"fmt"
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/fv/connectivity"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
)

var _ = infrastructure.DatastoreDescribe("_BPF-SAFE_ routing table tests", []apiconfig.DatastoreType{apiconfig.EtcdV3, apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
	var (
		infra  infrastructure.DatastoreInfra
		tc     infrastructure.TopologyContainers
		client client.Interface
		_      = client
		w      [3][2]*workload.Workload
		cc     *connectivity.Checker
		_      = cc
	)

	BeforeEach(func() {
		w = [3][2]*workload.Workload{}
		infra = getInfra()

		topologyOptions := infrastructure.DefaultTopologyOptions()
		topologyOptions.VXLANMode = api.VXLANModeAlways
		topologyOptions.IPIPEnabled = false
		topologyOptions.EnableIPv6 = false
		topologyOptions.ExtraEnvVars["FELIX_ROUTESOURCE"] = "WorkloadIPs"
		topologyOptions.FelixDebugFilenameRegex = "route_table.go|vxlan_fdb"

		tc, client = infrastructure.StartNNodeTopology(3, topologyOptions, infra)
		cc = &connectivity.Checker{}
	})

	AfterEach(func() {
		if CurrentGinkgoTestDescription().Failed {
			for _, felix := range tc.Felixes {
				felix.Exec("ip", "r")
			}
		}

		for _, wls := range w {
			for _, wl := range wls {
				wl.Stop()
			}
		}
		tc.Stop()

		if CurrentGinkgoTestDescription().Failed {
			infra.DumpErrorData()
		}
		infra.Stop()
	})

	Describe("with locally conflicting IPs", func() {
		BeforeEach(func() {
			// Start two local workloads with the same IP >:)
			for i := 0; i < 2; i++ {
				w[0][i] = workload.Run(tc.Felixes[0], fmt.Sprintf("w%d", i), "default", "10.65.0.2", "8088", "tcp")
				w[0][i].ConfigureInInfra(infra)
			}
		})

		waitForInitialRouteProgramming := func() (winner, loser int) {
			// Winner is non-deterministic.
			Eventually(tc.Felixes[0].ExecOutputFn("ip", "r", "get", "10.65.0.2"), "10s").Should(Or(
				ContainSubstring(w[0][0].InterfaceName),
				ContainSubstring(w[0][1].InterfaceName),
			))
			out, err := tc.Felixes[0].ExecOutput("ip", "r", "get", "10.65.0.2")
			Expect(err).NotTo(HaveOccurred())
			if strings.Contains(out, w[0][0].InterfaceName) {
				winner = 0
				loser = 1
			} else {
				winner = 1
				loser = 0
			}
			return
		}

		It("should resolve when winning endpoint is removed", func() {
			// Winner is non-deterministic.
			winner, loser := waitForInitialRouteProgramming()
			w[0][winner].RemoveFromInfra(infra)
			Eventually(tc.Felixes[0].ExecOutputFn("ip", "r", "get", "10.65.0.2"), "10s").Should(
				ContainSubstring(w[0][loser].InterfaceName),
			)
		})

		It("should resolve when losing endpoint is removed", func() {
			// Winner is non-deterministic.
			winner, loser := waitForInitialRouteProgramming()
			w[0][loser].RemoveFromInfra(infra)
			Consistently(tc.Felixes[0].ExecOutputFn("ip", "r", "get", "10.65.0.2"), "5s").Should(
				ContainSubstring(w[0][winner].InterfaceName),
			)
		})
	})

	Describe("with local/remote conflicting IPs", func() {
		BeforeEach(func() {
			// One local, one remote workload with same IP >:)
			for i := 0; i < 2; i++ {
				w[i][0] = workload.Run(tc.Felixes[i], fmt.Sprintf("w%d", i), "default", "10.65.0.2", "8088", "tcp")
				w[i][0].ConfigureInInfra(infra)
			}

			// VXLAN route gets suppressed by the calc graph so local workload route will "win".
			Eventually(tc.Felixes[0].ExecOutputFn("ip", "r", "get", "10.65.0.2"), "10s").Should(
				ContainSubstring(w[0][0].InterfaceName))
			Consistently(tc.Felixes[0].ExecOutputFn("ip", "r", "get", "10.65.0.2"), "5s").Should(
				ContainSubstring(w[0][0].InterfaceName),
			)
		})

		It("should resolve when winning endpoint is removed", func() {
			w[0][0].RemoveFromInfra(infra)
			// Winner was remote so we now expect the local route to show up.
			Eventually(tc.Felixes[0].ExecOutputFn("ip", "r", "get", "10.65.0.2"), "10s").Should(
				ContainSubstring("vxlan.calico"),
			)
		})

		It("should resolve when losing endpoint is removed", func() {
			w[1][0].RemoveFromInfra(infra)
			Consistently(tc.Felixes[0].ExecOutputFn("ip", "r", "get", "10.65.0.2"), "5s").Should(
				ContainSubstring(w[0][0].InterfaceName),
			)
		})
	})
})
