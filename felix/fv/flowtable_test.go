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
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/dataplane/linux/dataplanedefs"
	"github.com/projectcalico/calico/felix/fv/connectivity"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
)

var _ = infrastructure.DatastoreDescribe("nftables flowtable offload", []apiconfig.DatastoreType{apiconfig.EtcdV3, apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
	var (
		infra infrastructure.DatastoreInfra
		tc    infrastructure.TopologyContainers
		w     [2]*workload.Workload
		cc    *connectivity.Checker
	)

	BeforeEach(func() {
		if !NFTMode() {
			Skip("Flowtable offload is an nftables-only feature.")
		}

		infra = getInfra()
		opts := infrastructure.DefaultTopologyOptions()
		// Enable flowtable offload at Felix startup rather than via a mid-test config
		// update, which would trigger a reprogram that races the connectivity checks.
		opts.ExtraEnvVars["FELIX_NFTABLESFLOWTABLEOFFLOAD"] = "Enabled"
		tc, _ = infrastructure.StartSingleNodeTopology(opts, infra)

		// Allow all traffic in the absence of any policy; without this the etcd datastore
		// has no default profile and Felix falls back to a default-drop.
		infra.AddDefaultAllow()

		for i := range w {
			w[i] = workload.Run(tc.Felixes[0], fmt.Sprintf("w%d", i), "default", fmt.Sprintf("10.65.0.%d", i+2), "8055", "tcp")
			w[i].ConfigureInInfra(infra)
		}
		cc = &connectivity.Checker{}
	})

	AfterEach(func() {
		if CurrentSpecReport().Failed() {
			logNFTDiags(tc.Felixes[0])
		}
		for i := range w {
			if w[i] != nil {
				w[i].Stop()
			}
		}
		tc.Stop()
		infra.Stop()
	})

	It("programs the flowtable over the workload interfaces", func() {
		Eventually(func() string {
			out, _ := tc.Felixes[0].ExecOutput("nft", "list", "table", "ip", "calico")
			return out
		}, "20s", "1s").Should(And(
			ContainSubstring(fmt.Sprintf("flowtable %s", dataplanedefs.FlowtableName)),
			ContainSubstring(w[0].InterfaceName),
			ContainSubstring(w[1].InterfaceName),
		))
	})

	It("preserves connectivity with offload enabled", func() {
		cc.ExpectSome(w[0], w[1])
		cc.ExpectSome(w[1], w[0])
		cc.CheckConnectivity()
	})

	It("drops a deleted workload's interface without wedging the table", func() {
		// Remove one workload; its veth disappears with it. Felix must filter the stale
		// device out of the flowtable rather than leaving a dangling reference that
		// wedges reprogramming (the regression this spec guards against).
		deletedInterfaceName := w[1].InterfaceName
		w[1].RemoveFromInfra(infra)
		w[1].Stop()
		w[1] = nil

		Eventually(func() string {
			out, _ := tc.Felixes[0].ExecOutput("nft", "list", "table", "ip", "calico")
			return out
		}, "20s", "1s").ShouldNot(ContainSubstring(deletedInterfaceName))

		// Remaining workload still reachable from the host, proving the table is healthy.
		cc.ExpectSome(tc.Felixes[0], w[0].Port(8055))
		cc.CheckConnectivity()
	})
})
