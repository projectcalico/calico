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
	"github.com/projectcalico/felix/fv/workload"
	"github.com/projectcalico/libcalico-go/lib/api"
	"github.com/projectcalico/libcalico-go/lib/client"
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
		client *client.Client
		w      [2]*workload.Workload
	)

	BeforeEach(func() {

		etcd = RunEtcd()

		client = GetEtcdClient(etcd.IP)
		err := client.EnsureInitialized()
		Expect(err).NotTo(HaveOccurred())

		felix = RunFelix(etcd.IP)

		felixNode := api.NewNode()
		felixNode.Metadata.Name = felix.Hostname
		_, err = client.Nodes().Create(felixNode)
		Expect(err).NotTo(HaveOccurred())

		// Install a default profile that allows all ingress and egress, in the absence of any Policy.
		defaultProfile := api.NewProfile()
		defaultProfile.Metadata.Name = "default"
		defaultProfile.Metadata.Tags = []string{"default"}
		defaultProfile.Spec.EgressRules = []api.Rule{{Action: "allow"}}
		defaultProfile.Spec.IngressRules = []api.Rule{{Action: "allow"}}
		_, err = client.Profiles().Create(defaultProfile)
		Expect(err).NotTo(HaveOccurred())

		// Create workloads, using that profile.
		for ii := range w {
			iiStr := strconv.Itoa(ii)
			w[ii] = workload.Run(felix, "w"+iiStr, "cali1"+iiStr, "10.65.0.1"+iiStr, "8055")
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
			Expect(w[0]).To(HaveConnectivityTo(w[1], 32011))
			Expect(w[1]).To(HaveConnectivityTo(w[0], 32010))
			Expect(etcd).To(HaveConnectivityTo(w[1], 32011))
			Expect(etcd).To(HaveConnectivityTo(w[0], 32010))
		})

		Context("with pre-DNAT policy to prevent access from outside", func() {

			BeforeEach(func() {
				policy := api.NewPolicy()
				policy.Metadata.Name = "deny-ingress"
				order := float64(20)
				policy.Spec.Order = &order
				policy.Spec.PreDNAT = true
				policy.Spec.IngressRules = []api.Rule{{Action: "deny"}}
				policy.Spec.Selector = "has(host-endpoint)"
				_, err := client.Policies().Create(policy)
				Expect(err).NotTo(HaveOccurred())

				hostEp := api.NewHostEndpoint()
				hostEp.Metadata.Name = "felix-eth0"
				hostEp.Metadata.Node = felix.Hostname
				hostEp.Metadata.Labels = map[string]string{"host-endpoint": "true"}
				hostEp.Spec.InterfaceName = "eth0"
				_, err = client.HostEndpoints().Create(hostEp)
				Expect(err).NotTo(HaveOccurred())
			})

			It("etcd cannot connect", func() {
				Expect(w[0]).To(HaveConnectivityTo(w[1], 32011))
				Expect(w[1]).To(HaveConnectivityTo(w[0], 32010))
				Expect(etcd).NotTo(HaveConnectivityTo(w[1], 32011))
				Expect(etcd).NotTo(HaveConnectivityTo(w[0], 32010))
			})

			Context("with pre-DNAT policy to open pinhole to 32010", func() {

				BeforeEach(func() {
					policy := api.NewPolicy()
					policy.Metadata.Name = "allow-ingress-32010"
					order := float64(10)
					policy.Spec.Order = &order
					policy.Spec.PreDNAT = true
					protocol := numorstring.ProtocolFromString("tcp")
					ports, _ := numorstring.PortFromRange(1, 65535)   // pass
					ports, _ = numorstring.PortFromRange(1, 10000)    // pass
					ports, _ = numorstring.PortFromRange(8000, 8055)  // pass
					ports, _ = numorstring.PortFromRange(8056, 10000) // fail
					ports = numorstring.SinglePort(8055)
					policy.Spec.IngressRules = []api.Rule{{
						Action:   "allow",
						Protocol: &protocol,
						Destination: api.EntityRule{Ports: []numorstring.Port{
							ports,
						}},
					}}
					policy.Spec.Selector = "has(host-endpoint)"
					_, err := client.Policies().Create(policy)
					Expect(err).NotTo(HaveOccurred())
				})

				// Pending because currently fails - investigation needed.
				PIt("etcd can connect to 32010 but not 32011", func() {
					Expect(w[0]).To(HaveConnectivityTo(w[1], 32011))
					Expect(w[1]).To(HaveConnectivityTo(w[0], 32010))
					//Expect(etcd).NotTo(HaveConnectivityTo(w[1], 32011))
					var success bool
					var err error
					success, err = HaveConnectivityTo(w[0], 32010).Match(etcd)
					success, err = HaveConnectivityTo(w[0], 32010).Match(etcd)
					success, err = HaveConnectivityTo(w[0], 32010).Match(etcd)
					success, err = HaveConnectivityTo(w[0], 32010).Match(etcd)
					success, err = HaveConnectivityTo(w[0], 32010).Match(etcd)
					success, err = HaveConnectivityTo(w[0], 32010).Match(etcd)
					success, err = HaveConnectivityTo(w[0], 32010).Match(etcd)
					success, err = HaveConnectivityTo(w[0], 32010).Match(etcd)
					success, err = HaveConnectivityTo(w[0], 32010).Match(etcd)
					success, err = HaveConnectivityTo(w[0], 32010).Match(etcd)
					Expect(success).To(BeTrue())
					Expect(err).NotTo(HaveOccurred())
					Expect(etcd).NotTo(HaveConnectivityTo(w[0], 32010))
				})
			})
		})
	})
})
