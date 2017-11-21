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
	"strconv"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/felix/fv/containers"
	"github.com/projectcalico/felix/fv/utils"
	"github.com/projectcalico/felix/fv/workload"
	api "github.com/projectcalico/libcalico-go/lib/apis/v3"
	client "github.com/projectcalico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/libcalico-go/lib/numorstring"
)

// Setup for planned further FV tests:
//
//     | +-----------+ +-----------+ |  | +-----------+ +-----------+ |
//     | | service A | | service B | |  | | service C | | service D | |
//     | | 10.65.0.2 | | 10.65.0.3 | |  | | 10.65.0.4 | | 10.65.0.5 | |
//     | | port 9002 | | port 9003 | |  | | port 9004 | | port 9005 | |
//     | | np 109002 | | port 9003 | |  | | port 9004 | | port 9005 | |
//     | +-----------+ +-----------+ |  | +-----------+ +-----------+ |
//     +-----------------------------+  +-----------------------------+

var _ = Context("with initialized Felix, etcd datastore, 2 workloads", func() {

	var (
		etcd   *containers.Container
		felix  *containers.Container
		client client.Interface
		w      [2]*workload.Workload
	)

	BeforeEach(func() {
		felix, etcd, client = containers.StartSingleNodeEtcdTopology()

		// Install a default profile that allows all ingress and egress, in the absence of any Policy.
		defaultProfile := api.NewProfile()
		defaultProfile.Name = "default"
		defaultProfile.Spec.LabelsToApply = map[string]string{"default": ""}
		defaultProfile.Spec.Egress = []api.Rule{{Action: api.Allow}}
		defaultProfile.Spec.Ingress = []api.Rule{{Action: api.Allow}}
		_, err := client.Profiles().Create(utils.Ctx, defaultProfile, utils.NoOptions)
		Expect(err).NotTo(HaveOccurred())

		// Create workloads, using that profile.
		for ii := range w {
			iiStr := strconv.Itoa(ii)
			w[ii] = workload.Run(felix, "w"+iiStr, "cali1"+iiStr, "10.65.0.1"+iiStr, "8055", "tcp")
			w[ii].Configure(client)
		}

		// We will use the etcd container to model an external client trying to connect into
		// workloads on a host.  Create a route in the etcd container for the workload CIDR.
		etcd.Exec("ip", "r", "add", "10.65.0.0/24", "via", felix.IP)
	})

	AfterEach(func() {

		if CurrentGinkgoTestDescription().Failed {
			felix.Exec("iptables-save", "-c")
			felix.Exec("ip", "r")
		}

		for ii := range w {
			w[ii].Stop()
		}
		felix.Stop()

		if CurrentGinkgoTestDescription().Failed {
			etcd.Exec("etcdctl", "ls", "--recursive", "/")
		}
		etcd.Stop()
	})

	Context("with node port DNATs", func() {

		BeforeEach(func() {
			felix.Exec(
				"iptables", "-t", "nat",
				"-A", "PREROUTING",
				"-p", "tcp",
				"-d", "10.65.0.10", "--dport", "32010",
				"-j", "DNAT", "--to", "10.65.0.10:8055",
			)
			felix.Exec(
				"iptables", "-t", "nat",
				"-A", "PREROUTING",
				"-p", "tcp",
				"-d", "10.65.0.11", "--dport", "32011",
				"-j", "DNAT", "--to", "10.65.0.11:8055",
			)
		})

		It("everyone can connect to node ports", func() {
			cc := &workload.ConnectivityChecker{}
			cc.ExpectSome(w[0], w[1], 32011)
			cc.ExpectSome(w[1], w[0], 32010)
			cc.ExpectSome(etcd, w[1], 32011)
			cc.ExpectSome(etcd, w[0], 32010)
			Eventually(cc.ActualConnectivity, "10s", "100ms").Should(Equal(cc.ExpectedConnectivity()))
		})

		Context("with pre-DNAT policy to prevent access from outside", func() {

			BeforeEach(func() {
				policy := api.NewGlobalNetworkPolicy()
				policy.Name = "deny-ingress"
				order := float64(20)
				policy.Spec.Order = &order
				policy.Spec.PreDNAT = true
				policy.Spec.ApplyOnForward = true
				policy.Spec.Ingress = []api.Rule{{Action: api.Deny}}
				policy.Spec.Selector = "has(host-endpoint)"
				_, err := client.GlobalNetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
				Expect(err).NotTo(HaveOccurred())

				hostEp := api.NewHostEndpoint()
				hostEp.Name = "felix-eth0"
				hostEp.Spec.Node = felix.Hostname
				hostEp.Labels = map[string]string{"host-endpoint": "true"}
				hostEp.Spec.InterfaceName = "eth0"
				_, err = client.HostEndpoints().Create(utils.Ctx, hostEp, utils.NoOptions)
				Expect(err).NotTo(HaveOccurred())
			})

			It("etcd cannot connect", func() {
				cc := &workload.ConnectivityChecker{}
				cc.ExpectSome(w[0], w[1], 32011)
				cc.ExpectSome(w[1], w[0], 32010)
				cc.ExpectNone(etcd, w[1], 32011)
				cc.ExpectNone(etcd, w[0], 32010)
				Eventually(cc.ActualConnectivity, "10s", "100ms").Should(Equal(cc.ExpectedConnectivity()))
			})

			Context("with pre-DNAT policy to open pinhole to 32010", func() {

				BeforeEach(func() {
					policy := api.NewGlobalNetworkPolicy()
					policy.Name = "allow-ingress-32010"
					order := float64(10)
					policy.Spec.Order = &order
					policy.Spec.PreDNAT = true
					policy.Spec.ApplyOnForward = true
					protocol := numorstring.ProtocolFromString("tcp")
					ports := numorstring.SinglePort(32010)
					policy.Spec.Ingress = []api.Rule{{
						Action:   api.Allow,
						Protocol: &protocol,
						Destination: api.EntityRule{Ports: []numorstring.Port{
							ports,
						}},
					}}
					policy.Spec.Selector = "has(host-endpoint)"
					_, err := client.GlobalNetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
					Expect(err).NotTo(HaveOccurred())
				})

				It("etcd can connect to 32010 but not 32011", func() {
					cc := &workload.ConnectivityChecker{}
					cc.ExpectSome(w[0], w[1], 32011)
					cc.ExpectSome(w[1], w[0], 32010)
					cc.ExpectNone(etcd, w[1], 32011)
					cc.ExpectSome(etcd, w[0], 32010)
					Eventually(cc.ActualConnectivity, "10s", "100ms").Should(Equal(cc.ExpectedConnectivity()))
				})
			})

			Context("with pre-DNAT policy to open pinhole to 8055", func() {

				BeforeEach(func() {
					policy := api.NewGlobalNetworkPolicy()
					policy.Name = "allow-ingress-8055"
					order := float64(10)
					policy.Spec.Order = &order
					policy.Spec.PreDNAT = true
					policy.Spec.ApplyOnForward = true
					protocol := numorstring.ProtocolFromString("tcp")
					ports := numorstring.SinglePort(8055)
					policy.Spec.Ingress = []api.Rule{{
						Action:   api.Allow,
						Protocol: &protocol,
						Destination: api.EntityRule{Ports: []numorstring.Port{
							ports,
						}},
					}}
					policy.Spec.Selector = "has(host-endpoint)"
					_, err := client.GlobalNetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
					Expect(err).NotTo(HaveOccurred())
				})

				It("etcd cannot connect", func() {
					cc := &workload.ConnectivityChecker{}
					cc.ExpectSome(w[0], w[1], 32011)
					cc.ExpectSome(w[1], w[0], 32010)
					cc.ExpectNone(etcd, w[1], 32011)
					cc.ExpectNone(etcd, w[0], 32010)
					Eventually(cc.ActualConnectivity, "10s", "100ms").Should(Equal(cc.ExpectedConnectivity()))
				})
			})
		})
	})
})
