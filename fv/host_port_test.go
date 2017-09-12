// +build fvtests

// Copyright (c) 2017 Tigera, Inc. All rights reserved.
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
	"github.com/projectcalico/felix/fv/containers"
	"github.com/projectcalico/felix/fv/metrics"
	"github.com/projectcalico/felix/fv/utils"
	"github.com/projectcalico/felix/fv/workload"
	"github.com/projectcalico/libcalico-go/lib/api"
	"github.com/projectcalico/libcalico-go/lib/client"
	"github.com/projectcalico/libcalico-go/lib/numorstring"
	log "github.com/sirupsen/logrus"
)

func RunEtcd() *containers.Container {
	return containers.Run("etcd-fv",
		"quay.io/coreos/etcd",
		"etcd",
		"--advertise-client-urls", "http://127.0.0.1:2379",
		"--listen-client-urls", "http://0.0.0.0:2379")
}

func RunFelix(etcdIP string) *containers.Container {
	return containers.Run("felix-fv",
		"--privileged",
		"-e", "CALICO_DATASTORE_TYPE=etcdv2",
		"-e", "FELIX_DATASTORETYPE=etcdv2",
		"-e", "FELIX_ETCDENDPOINTS=http://"+etcdIP+":2379",
		"-e", "FELIX_PROMETHEUSMETRICSENABLED=true",
		"-e", "FELIX_USAGEREPORTINGENABLED=false",
		"-e", "FELIX_IPV6SUPPORT=false",
		"calico/felix:latest")
}

func GetEtcdClient(etcdIP string) *client.Client {
	client, err := client.New(api.CalicoAPIConfig{
		Spec: api.CalicoAPIConfigSpec{
			DatastoreType: api.EtcdV2,
			EtcdConfig: api.EtcdConfig{
				EtcdEndpoints: "http://" + etcdIP + ":2379",
			},
		},
	})
	Expect(err).NotTo(HaveOccurred())
	return client
}

func MetricsPortReachable(felixName, felixIP string) bool {
	// Delete existing conntrack state for the metrics port.
	utils.Run("docker", "exec", felixName,
		"conntrack", "-L")
	utils.Run("docker", "exec", felixName,
		"conntrack", "-L", "-p", "tcp", "--dport", metrics.PortString())
	utils.RunMayFail("docker", "exec", felixName,
		"conntrack", "-D", "-p", "tcp", "--orig-port-dst", metrics.PortString())

	// Now try to get a metric.
	m, err := metrics.GetFelixMetric(felixIP, "felix_active_local_endpoints")
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

var _ = Context("with initialized Felix and etcd datastore", func() {

	var (
		etcd                 *containers.Container
		felix                *containers.Container
		client               *client.Client
		metricsPortReachable func() bool
	)

	BeforeEach(func() {

		etcd = RunEtcd()

		felix = RunFelix(etcd.IP)

		client = GetEtcdClient(etcd.IP)
		err := client.EnsureInitialized()
		Expect(err).NotTo(HaveOccurred())

		felixNode := api.NewNode()
		felixNode.Metadata.Name = felix.Hostname
		_, err = client.Nodes().Create(felixNode)
		Expect(err).NotTo(HaveOccurred())

		metricsPortReachable = func() bool {
			return MetricsPortReachable(felix.Name, felix.IP)
		}
	})

	AfterEach(func() {

		if CurrentGinkgoTestDescription().Failed {
			utils.Run("docker", "logs", felix.Name)
			utils.Run("docker", "exec", felix.Name, "iptables-save", "-c")
		}
		felix.Stop()

		if CurrentGinkgoTestDescription().Failed {
			utils.Run("docker", "exec", etcd.Name, "etcdctl", "ls", "--recursive", "/")
		}
		etcd.Stop()
	})

	It("with no endpoints or policy, port should be reachable", func() {
		Eventually(metricsPortReachable, "10s", "1s").Should(BeTrue())
	})

	It("with a local workload, port should be reachable", func() {
		w := workload.Run(felix, "cali12345", "10.65.0.2", "8055")
		w.Configure(client)
		Eventually(metricsPortReachable, "10s", "1s").Should(BeTrue())
		w.Stop()
		Eventually(metricsPortReachable, "10s", "1s").Should(BeTrue())
	})

	Context("with host endpoint defined", func() {

		BeforeEach(func() {
			hostEp := api.NewHostEndpoint()
			hostEp.Metadata.Name = "host-endpoint-1"
			hostEp.Metadata.Node = felix.Hostname
			hostEp.Metadata.Labels = map[string]string{"host-endpoint": "true"}
			hostEp.Spec.InterfaceName = "eth0"
			_, err := client.HostEndpoints().Create(hostEp)
			Expect(err).NotTo(HaveOccurred())
		})

		It("port should not be reachable", func() {
			Eventually(metricsPortReachable, "10s", "1s").Should(BeFalse())
		})

		Context("with pre-DNAT policy defined", func() {

			BeforeEach(func() {
				policy := api.NewPolicy()
				policy.Metadata.Name = "pre-dnat-policy-1"
				policy.Spec.PreDNAT = true
				protocol := numorstring.ProtocolFromString("tcp")
				allowMetricsPortRule := api.Rule{
					Action:   "allow",
					Protocol: &protocol,
					Destination: api.EntityRule{
						Ports: []numorstring.Port{numorstring.SinglePort(uint16(metrics.Port))},
					},
				}
				policy.Spec.IngressRules = []api.Rule{allowMetricsPortRule}
				policy.Spec.Selector = "host-endpoint=='true'"
				_, err := client.Policies().Create(policy)
				Expect(err).NotTo(HaveOccurred())
			})

			It("port should be reachable", func() {
				Eventually(metricsPortReachable, "10s", "1s").Should(BeTrue())
			})
		})
	})
})
