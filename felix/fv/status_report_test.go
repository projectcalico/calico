// Copyright (c) 2024-2025 Tigera, Inc. All rights reserved.
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
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/fv/connectivity"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
)

var _ = infrastructure.DatastoreDescribe("_BPF-SAFE_ openstack status-reporting", []apiconfig.DatastoreType{apiconfig.EtcdV3}, func(getInfra infrastructure.InfraFactory) {
	var (
		infra  infrastructure.DatastoreInfra
		tc     infrastructure.TopologyContainers
		client client.Interface
		_      = client
		w      *workload.Workload
		cc     *connectivity.Checker
		_      = cc
	)

	BeforeEach(func() {
		infra = getInfra()

		topologyOptions := infrastructure.DefaultTopologyOptions()
		topologyOptions.VXLANMode = api.VXLANModeAlways
		topologyOptions.VXLANStrategy = infrastructure.NewDefaultTunnelStrategy(topologyOptions.IPPoolCIDR, topologyOptions.IPv6PoolCIDR)
		topologyOptions.IPIPMode = api.IPIPModeNever
		topologyOptions.EnableIPv6 = false
		topologyOptions.ExtraEnvVars["FELIX_ENDPOINTREPORTINGENABLED"] = "true"
		topologyOptions.ExtraEnvVars["FELIX_OPENSTACKREGION"] = "r0"
		topologyOptions.FelixDebugFilenameRegex = "status_reporter.go"

		tc, client = infrastructure.StartNNodeTopology(1, topologyOptions, infra)

		w = workload.Run(tc.Felixes[0], "wl", "default", "10.65.0.2", "8088", "tcp")
		w.ConfigureInInfra(infra)
	})

	AfterEach(func() {
		w.Stop()
		tc.Stop()
		if CurrentGinkgoTestDescription().Failed {
			infra.DumpErrorData()
		}
		infra.Stop()
	})

	Describe("With status-reporting writing to etcd", func() {
		getStatus := func() string {
			wlListOpts := model.WorkloadEndpointStatusListOptions{
				Hostname: tc.Felixes[0].Hostname,
			}

			By(fmt.Sprintf("listing workload endpoint statuses {%+v}", wlListOpts))

			c := infra.GetCalicoClient()
			backendClient := c.(interface{ Backend() bapi.Client }).Backend()
			statuses, err := backendClient.List(context.Background(), wlListOpts, "")
			Expect(err).NotTo(HaveOccurred(), "Couldn't list workload endpoint statuses")

			if len(statuses.KVPairs) != 1 {
				return ""
			}

			wepStatusKey, ok := statuses.KVPairs[0].Key.(model.WorkloadEndpointStatusKey)
			Expect(ok).To(BeTrue(), "Unexpected key type when listing workload endpoint statuses")
			Expect(wepStatusKey.Hostname).To(Equal(tc.Felixes[0].Hostname))
			Expect(wepStatusKey.OrchestratorID).To(Equal("felixfv"))
			Expect(wepStatusKey.EndpointID).To(Equal(w.Name))
			wepStatusValue, ok := statuses.KVPairs[0].Value.(*model.WorkloadEndpointStatus)
			Expect(ok).To(BeTrue())

			return wepStatusValue.Status
		}

		It("should write endpoint to etcd", func() {
			Eventually(getStatus, "10s").Should(Equal("up"))
		})
	})
})
