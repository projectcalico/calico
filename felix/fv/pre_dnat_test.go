// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.
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
	"strconv"
	"time"

	"github.com/projectcalico/calico/felix/fv/connectivity"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"

	"github.com/projectcalico/calico/felix/fv/containers"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/utils"
	"github.com/projectcalico/calico/felix/fv/workload"
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

var _ = infrastructure.DatastoreDescribe("pre-dnat with initialized Felix, 2 workloads", []apiconfig.DatastoreType{apiconfig.EtcdV3, apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {

	var (
		infra          infrastructure.DatastoreInfra
		felix          *infrastructure.Felix
		client         client.Interface
		w              [2]*workload.Workload
		externalClient *containers.Container
	)

	BeforeEach(func() {
		infra = getInfra()

		options := infrastructure.DefaultTopologyOptions()
		// For variety, run this test with IPv6 disabled.
		options.EnableIPv6 = false
		felix, client = infrastructure.StartSingleNodeTopology(options, infra)

		// Install a default profile that allows all ingress and egress, in the absence of any Policy.
		infra.AddDefaultAllow()

		// Create workloads, using that profile.
		for ii := range w {
			iiStr := strconv.Itoa(ii)
			w[ii] = workload.Run(felix, "w"+iiStr, "default", "10.65.0.1"+iiStr, "8055", "tcp")
			w[ii].ConfigureInInfra(infra)
		}

		// We will use this container to model an external client trying to connect into
		// workloads on a host.  Create a route in the container for the workload CIDR.
		externalClient = infrastructure.RunExtClient("ext-client")
		externalClient.Exec("ip", "r", "add", "10.65.0.0/24", "via", felix.IP)
	})

	AfterEach(func() {

		if CurrentGinkgoTestDescription().Failed {
			infra.DumpErrorData()
			felix.Exec("iptables-save", "-c")
			felix.Exec("ip", "r")
			felix.Exec("ip", "a")
		}

		for ii := range w {
			w[ii].Stop()
		}
		felix.Stop()

		infra.Stop()
		externalClient.Stop()
	})

	Context("with node port DNATs", func() {

		BeforeEach(func() {
			felix.Exec(
				"iptables", "-t", "nat",
				"-w", "10", // Retry this for 10 seconds, e.g. if something else is holding the lock
				"-W", "100000", // How often to probe the lock in microsecs.
				"-A", "PREROUTING",
				"-p", "tcp",
				"-d", "10.65.0.10", "--dport", "32010",
				"-j", "DNAT", "--to", "10.65.0.10:8055",
			)
			felix.Exec(
				"iptables", "-t", "nat",
				"-w", "10", // Retry this for 10 seconds, e.g. if something else is holding the lock
				"-W", "100000", // How often to probe the lock in microsecs.
				"-A", "PREROUTING",
				"-p", "tcp",
				"-d", "10.65.0.11", "--dport", "32011",
				"-j", "DNAT", "--to", "10.65.0.11:8055",
			)
		})

		It("everyone can connect to node ports", func() {
			cc := &connectivity.Checker{}
			cc.ExpectSome(w[0], w[1], 32011)
			cc.ExpectSome(w[1], w[0], 32010)
			cc.ExpectSome(externalClient, w[1], 32011)
			cc.ExpectSome(externalClient, w[0], 32010)
			cc.CheckConnectivityWithTimeout(30 * time.Second)
		})

		Context("with pre-DNAT policy denying all ingress", func() {

			BeforeEach(func() {
				// Make sure our host endpoints won't cut felix off from the datastore.
				err := infra.AddAllowToDatastore("has(host-endpoint)")
				Expect(err).NotTo(HaveOccurred())

				policy := api.NewGlobalNetworkPolicy()
				policy.Name = "deny-ingress"
				order := float64(20)
				policy.Spec.Order = &order
				policy.Spec.PreDNAT = true
				policy.Spec.ApplyOnForward = true
				policy.Spec.Ingress = []api.Rule{{Action: api.Deny}}
				policy.Spec.Selector = "has(host-endpoint)"
				_, err = client.GlobalNetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
				Expect(err).NotTo(HaveOccurred())
			})

			Context("with host endpoint applying policy to eth0", func() {

				BeforeEach(func() {
					hostEp := api.NewHostEndpoint()
					hostEp.Name = "felix-eth0"
					hostEp.Spec.Node = felix.Hostname
					hostEp.Labels = map[string]string{"host-endpoint": "true"}
					hostEp.Spec.InterfaceName = "eth0"
					_, err := client.HostEndpoints().Create(utils.Ctx, hostEp, utils.NoOptions)
					Expect(err).NotTo(HaveOccurred())
				})

				It("external client cannot connect", func() {
					cc := &connectivity.Checker{}
					cc.ExpectSome(w[0], w[1], 32011)
					cc.ExpectSome(w[1], w[0], 32010)
					cc.ExpectNone(externalClient, w[1], 32011)
					cc.ExpectNone(externalClient, w[0], 32010)
					cc.CheckConnectivityWithTimeout(30 * time.Second)
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

					It("external client can connect to 32010 but not 32011", func() {
						cc := &connectivity.Checker{}
						cc.ExpectSome(w[0], w[1], 32011)
						cc.ExpectSome(w[1], w[0], 32010)
						cc.ExpectNone(externalClient, w[1], 32011)
						cc.ExpectSome(externalClient, w[0], 32010)
						cc.CheckConnectivity()
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

					It("external client cannot connect", func() {
						cc := &connectivity.Checker{}
						cc.ExpectSome(w[0], w[1], 32011)
						cc.ExpectSome(w[1], w[0], 32010)
						cc.ExpectNone(externalClient, w[1], 32011)
						cc.ExpectNone(externalClient, w[0], 32010)
						cc.CheckConnectivity()
					})
				})
			})

			Context("with all-interfaces host endpoint", func() {

				BeforeEach(func() {
					hostEp := api.NewHostEndpoint()
					hostEp.Name = "felix-all"
					hostEp.Spec.Node = felix.Hostname
					hostEp.Labels = map[string]string{"host-endpoint": "true"}
					hostEp.Spec.InterfaceName = "*"
					_, err := client.HostEndpoints().Create(utils.Ctx, hostEp, utils.NoOptions)
					Expect(err).NotTo(HaveOccurred())
				})

				It("no one can connect via NodePorts", func() {
					cc := &connectivity.Checker{}
					cc.ExpectNone(w[0], w[1], 32011)
					cc.ExpectNone(w[1], w[0], 32010)
					cc.ExpectNone(externalClient, w[1], 32011)
					cc.ExpectNone(externalClient, w[0], 32010)
					cc.CheckConnectivityWithTimeout(30 * time.Second)
				})

				Context("with pre-DNAT policy to open pinhole via 32010", func() {

					BeforeEach(func() {
						policy := api.NewGlobalNetworkPolicy()
						policy.Name = "allow-via-32010"
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

					It("clients can connect to 32010 but not 32011", func() {
						cc := &connectivity.Checker{}
						cc.ExpectNone(w[0], w[1], 32011)
						cc.ExpectSome(w[1], w[0], 32010)
						cc.ExpectNone(externalClient, w[1], 32011)
						cc.ExpectSome(externalClient, w[0], 32010)
						cc.CheckConnectivity()
					})

					Context("with workload egress policy to deny 32010 flow", func() {

						BeforeEach(func() {
							policy := api.NewNetworkPolicy()
							policy.Name = "deny-to-32010"
							policy.Namespace = "default"
							order := float64(10)
							policy.Spec.Order = &order
							policy.Spec.Egress = []api.Rule{{
								Action:      api.Deny,
								Destination: api.EntityRule{Selector: "name=='" + w[0].Name + "'"}},
							}
							policy.Spec.Selector = "name=='" + w[1].Name + "'"
							_, err := client.NetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
							Expect(err).NotTo(HaveOccurred())
						})

						It("only external client can connect to 32010; no one to 32011", func() {
							cc := &connectivity.Checker{}
							cc.ExpectNone(w[0], w[1], 32011)
							cc.ExpectNone(w[1], w[0], 32010)
							cc.ExpectNone(externalClient, w[1], 32011)
							cc.ExpectSome(externalClient, w[0], 32010)
							cc.CheckConnectivity()
						})
					})
				})
			})
		})
	})
})
