// +build fvtests

// Copyright (c) 2017-2018 Tigera, Inc. All rights reserved.
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
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/felix/fv/infrastructure"
	"github.com/projectcalico/felix/fv/metrics"
	"github.com/projectcalico/felix/fv/utils"
	"github.com/projectcalico/felix/fv/workload"
	"github.com/projectcalico/libcalico-go/lib/apiconfig"
	api "github.com/projectcalico/libcalico-go/lib/apis/v3"
	client "github.com/projectcalico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/libcalico-go/lib/numorstring"
)

func MetricsPortReachable(felix *infrastructure.Felix) bool {
	// Delete existing conntrack state for the metrics port.
	felix.Exec("conntrack", "-L")
	felix.Exec("conntrack", "-L", "-p", "tcp", "--dport", metrics.PortString())
	felix.ExecMayFail("conntrack", "-D", "-p", "tcp", "--orig-port-dst", metrics.PortString())

	// Now try to get a metric.
	m, err := metrics.GetFelixMetric(felix.IP, "felix_active_local_endpoints")
	if err != nil {
		log.WithError(err).Info("Metrics port not reachable")
		return false
	}
	log.WithField("felix_active_local_endpoints", m).Info("Metrics port reachable")
	return true
}

// Here we test reachability to a port number running on a Calico host itself, specifically Felix's
// metrics port 9091, and how that is affected by policy, host endpoint and workload endpoint
// configuration.
//
// - When there is no policy or endpoint configuration, the port should be reachable.
//
// - When there is a local workload endpoint, the port should be reachable.  (Existence of workload
//   endpoints should make no difference to reachability to ports on the host itself.)
//
// - When a host endpoint is configured for the host's interface (eth0), but not yet any policy, the
//   port should be unreachable.
//
//   - When pre-DNAT policy is then configured, to allow ingress to that port, it should be
//     reachable again.

var _ = infrastructure.DatastoreDescribe("with initialized Felix", []apiconfig.DatastoreType{apiconfig.EtcdV3, apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
	var (
		infra                infrastructure.DatastoreInfra
		felix                *infrastructure.Felix
		client               client.Interface
		metricsPortReachable func() bool
	)

	BeforeEach(func() {
		var err error
		infra = getInfra()

		felix, client = infrastructure.StartSingleNodeTopology(infrastructure.DefaultTopologyOptions(), infra)

		metricsPortReachable = func() bool {
			return MetricsPortReachable(felix)
		}
	})

	AfterEach(func() {

		if CurrentGinkgoTestDescription().Failed {
			infra.DumpErrorData()
			felix.Exec("iptables-save", "-c")
			felix.Exec("ip", "r")
			felix.Exec("ip", "a")
		}
		felix.Stop()
		infra.Stop()
	})

	It("with no endpoints or policy, port should be reachable", func() {
		Eventually(metricsPortReachable, "10s", "1s").Should(BeTrue())
	})

	It("with a local workload, port should be reachable", func() {
		w := workload.Run(felix, "w", "default", "10.65.0.2", "8055", "tcp")
		w.ConfigureInDatastore(infra)
		Eventually(metricsPortReachable, "10s", "1s").Should(BeTrue(), "Not reachable with workload running")
		w.Stop()
		Eventually(metricsPortReachable, "10s", "1s").Should(BeTrue(), "With workload stopped, not reachable")
	})

	Context("with host endpoint defined", func() {

		BeforeEach(func() {
			err := infra.AddAllowToDatastore("host-endpoint=='true'")
			Expect(err).NotTo(HaveOccurred())
			hostEp := api.NewHostEndpoint()
			hostEp.Name = "host-endpoint-1"
			hostEp.Labels = map[string]string{"host-endpoint": "true"}
			hostEp.Spec.Node = felix.Hostname
			hostEp.Spec.InterfaceName = "eth0"
			_, err = client.HostEndpoints().Create(utils.Ctx, hostEp, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())
		})

		It("port should not be reachable", func() {
			Eventually(metricsPortReachable, "10s", "1s").Should(BeFalse())
		})

		Context("with pre-DNAT policy defined", func() {

			BeforeEach(func() {
				// Ensure the HostEndpoint has taken effect and is blocking traffic
				Eventually(metricsPortReachable, "10s", "1s").Should(BeFalse())
				policy := api.NewGlobalNetworkPolicy()
				policy.Name = "pre-dnat-policy-1"
				policy.Spec.PreDNAT = true
				policy.Spec.ApplyOnForward = true
				protocol := numorstring.ProtocolFromString("tcp")
				allowMetricsPortRule := api.Rule{
					Action:   api.Allow,
					Protocol: &protocol,
					Destination: api.EntityRule{
						Ports: []numorstring.Port{numorstring.SinglePort(uint16(metrics.Port))},
					},
				}
				policy.Spec.Ingress = []api.Rule{allowMetricsPortRule}
				policy.Spec.Selector = "host-endpoint=='true'"
				_, err := client.GlobalNetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
				Expect(err).NotTo(HaveOccurred())
			})

			It("port should be reachable", func() {
				Eventually(metricsPortReachable, "10s", "1s").Should(BeTrue())
			})
		})
	})
})
