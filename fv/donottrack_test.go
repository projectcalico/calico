// +build fvtests

// Copyright (c) 2018 Tigera, Inc. All rights reserved.
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
	"time"

	"github.com/projectcalico/libcalico-go/lib/net"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/projectcalico/felix/fv/utils"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/felix/fv/containers"
	"github.com/projectcalico/felix/fv/workload"
	"github.com/projectcalico/libcalico-go/lib/api"
	"github.com/projectcalico/libcalico-go/lib/client"
)

var _ = Context("do-not-track policy tests; with 2 nodes", func() {

	var (
		etcd        *containers.Container
		felixes     []*containers.Container
		hostW       [2]*workload.Workload
		client      *client.Client
		cc          *workload.ConnectivityChecker
		dumpedDiags bool
	)

	BeforeEach(func() {
		dumpedDiags = false

		etcd = containers.RunEtcd()

		client = utils.GetEtcdClient(etcd.IP)
		Eventually(client.EnsureInitialized, "10s", "1s").ShouldNot(HaveOccurred())

		cc = &workload.ConnectivityChecker{}

		// Start a host networked workload on each host for connectivity checks.
		for ii := 0; ii < 2; ii++ {
			felix := containers.RunFelix(etcd.IP)

			felixNode := api.NewNode()
			felixNode.Metadata.Name = felix.Hostname
			_, err := client.Nodes().Create(felixNode)
			Expect(err).NotTo(HaveOccurred())
			felixes = append(felixes, felix)

			// We tell each workload to open:
			// - its normal (uninteresting) port, 8055
			// - port 2379, which is both an inbound and an outbound failsafe port
			// - port 22, which is an inbound failsafe port.
			// This allows us to test the interaction between do-not-track policy and failsafe
			// ports.
			const portsToOpen = "8055,2379,22"
			hostW[ii] = workload.Run(
				felix,
				fmt.Sprintf("host%d", ii),
				"", // No interface name means "run in the host's namespace"
				felixes[ii].IP,
				portsToOpen,
			)
		}
	})

	// Utility function to dump diags if the test failed.  Should be called in the inner-most
	// AfterEach() to dump diags before the test is torn down.  Only the first call for a given
	// test has any effect.
	dumpDiags := func() {
		if !CurrentGinkgoTestDescription().Failed || dumpedDiags {
			return
		}
		for ii := range felixes {
			iptSave, err := felixes[ii].ExecOutput("iptables-save", "-c")
			if err == nil {
				log.WithField("felix", ii).Info("iptables-save:\n" + iptSave)
			}
			ipR, err := felixes[ii].ExecOutput("ip", "r")
			if err == nil {
				log.WithField("felix", ii).Info("ip route:\n" + ipR)
			}
		}
		etcd.Exec("etcdctl", "ls", "--recursive", "/")

	}

	AfterEach(func() {
		dumpDiags()
		for _, f := range felixes {
			f.Stop()
		}
		etcd.Stop()
	})

	expectFullConnectivity := func() {
		cc.ResetExpectations()
		cc.ExpectSome(felixes[0], hostW[1].Port(8055))
		cc.ExpectSome(felixes[1], hostW[0].Port(8055))
		cc.ExpectSome(felixes[0], hostW[1].Port(2379))
		cc.ExpectSome(felixes[1], hostW[0].Port(2379))
		cc.ExpectSome(felixes[0], hostW[1].Port(22))
		cc.ExpectSome(felixes[1], hostW[0].Port(22))
		cc.ExpectSome(etcd, hostW[1].Port(22))
		cc.ExpectSome(etcd, hostW[0].Port(22))
		cc.CheckConnectivityOffset(1)
	}

	It("before adding policy, should have connectivity between hosts", func() {
		expectFullConnectivity()
	})

	Context("after adding host endpoints", func() {
		var (
			ctx    context.Context
			cancel context.CancelFunc
		)

		BeforeEach(func() {
			ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)

			for _, f := range felixes {
				hep := api.NewHostEndpoint()
				hep.Metadata.Name = "eth0-" + f.Name
				hep.Metadata.Labels = map[string]string{
					"name": hep.Metadata.Name,
				}
				hep.Metadata.Node = f.Hostname
				hep.Spec.ExpectedIPs = []net.IP{net.MustParseIP(f.IP)}
				_, err := client.HostEndpoints().Create(hep)
				Expect(err).NotTo(HaveOccurred())
			}
		})

		AfterEach(func() {
			dumpDiags()
			cancel()
		})

		It("should implement untracked policy correctly", func() {
			// This test covers both normal connectivity and failsafe connectivity.  We combine the
			// tests because we rely on the changes of normal connectivity at each step to make sure
			// that the policy has actually flowed through to the dataplane.

			By("having only failsafe connectivity to start with")
			cc.ExpectNone(felixes[0], hostW[1].Port(8055))
			cc.ExpectNone(felixes[1], hostW[0].Port(8055))
			// 2379 is outbound only.
			cc.ExpectNone(felixes[0], hostW[1].Port(2379))
			cc.ExpectNone(felixes[1], hostW[0].Port(2379))
			// Port 22 is inbound-only so it'll be blocked by the (lack of) egress policy.
			cc.ExpectNone(felixes[0], hostW[1].Port(22))
			cc.ExpectNone(felixes[1], hostW[0].Port(22))
			// But etcd should still be able to access it...
			cc.ExpectSome(etcd, hostW[1].Port(22))
			cc.ExpectSome(etcd, hostW[0].Port(22))
			cc.CheckConnectivity()

			host0Selector := fmt.Sprintf("name == 'eth0-%s'", felixes[0].Name)
			host1Selector := fmt.Sprintf("name == 'eth0-%s'", felixes[1].Name)

			By("Having connectivity after installing bidirectional policies")
			host0Pol := api.NewPolicy()
			host0Pol.Metadata.Name = "host-0-pol"
			host0Pol.Spec.Selector = host0Selector
			host0Pol.Spec.DoNotTrack = true
			host0Pol.Spec.IngressRules = []api.Rule{
				{
					Action: "allow",
					Source: api.EntityRule{
						Selector: host1Selector,
					},
				},
			}
			host0Pol.Spec.EgressRules = []api.Rule{
				{
					Action: "allow",
					Destination: api.EntityRule{
						Selector: host1Selector,
					},
				},
			}
			host0Pol, err := client.Policies().Create(host0Pol)
			Expect(err).NotTo(HaveOccurred())

			host1Pol := api.NewPolicy()
			host1Pol.Metadata.Name = "host-1-pol"
			host1Pol.Spec.Selector = host1Selector
			host1Pol.Spec.DoNotTrack = true
			host1Pol.Spec.IngressRules = []api.Rule{
				{
					Action: "allow",
					Source: api.EntityRule{
						Selector: host0Selector,
					},
				},
			}
			host1Pol.Spec.EgressRules = []api.Rule{
				{
					Action: "allow",
					Destination: api.EntityRule{
						Selector: host0Selector,
					},
				},
			}
			host1Pol, err = client.Policies().Create(host1Pol)
			Expect(err).NotTo(HaveOccurred())

			expectFullConnectivity()

			By("Having only failsafe connectivity after replacing host-0's egress rules with deny")
			// Since there's no conntrack, removing rules in one direction is enough to prevent
			// connectivity in either direction.
			host0Pol.Spec.EgressRules = []api.Rule{
				{
					Action: "deny",
					Destination: api.EntityRule{
						Selector: host0Selector,
					},
				},
			}
			host0Pol, err = client.Policies().Update(host0Pol)
			Expect(err).NotTo(HaveOccurred())

			cc.ResetExpectations()
			cc.ExpectNone(felixes[0], hostW[1].Port(8055))
			cc.ExpectNone(felixes[1], hostW[0].Port(8055))
			cc.ExpectSome(felixes[0], hostW[1].Port(2379)) // Allowed by host[0]'s egress failsafe + host[1]'s ingress
			cc.ExpectNone(felixes[1], hostW[0].Port(2379))
			cc.ExpectNone(felixes[0], hostW[1].Port(22)) // Now blocked (lack of egress).
			cc.ExpectSome(felixes[1], hostW[0].Port(22)) // Still open due to failsafe.
			cc.ExpectSome(etcd, hostW[1].Port(22))       // allowed by failsafe
			cc.ExpectSome(etcd, hostW[0].Port(22))       // allowed by failsafe
			cc.CheckConnectivity()

			By("Having full connectivity after putting them back")
			host0Pol.Spec.EgressRules = []api.Rule{
				{
					Action: "allow",
					Destination: api.EntityRule{
						Selector: host1Selector,
					},
				},
			}
			host0Pol, err = client.Policies().Update(host0Pol)
			Expect(err).NotTo(HaveOccurred())

			expectFullConnectivity()

			By("Having only failsafe connectivity after replacing host-0's ingress rules with deny")
			host0Pol.Spec.IngressRules = []api.Rule{
				{
					Action: "deny",
					Destination: api.EntityRule{
						Selector: host0Selector,
					},
				},
			}
			host0Pol, err = client.Policies().Update(host0Pol)
			Expect(err).NotTo(HaveOccurred())

			cc.ResetExpectations()
			cc.ExpectNone(felixes[0], hostW[1].Port(8055))
			cc.ExpectNone(felixes[1], hostW[0].Port(8055))
			cc.ExpectSome(felixes[0], hostW[1].Port(2379)) // allowed by host[0]'s egress failsafe + host[1]'s ingress
			cc.ExpectNone(felixes[1], hostW[0].Port(2379))
			cc.ExpectNone(felixes[0], hostW[1].Port(22)) // Response traffic blocked by policy
			cc.ExpectSome(felixes[1], hostW[0].Port(22)) // allowed by failsafe
			cc.ExpectSome(etcd, hostW[1].Port(22))       // allowed by failsafe
			cc.ExpectSome(etcd, hostW[0].Port(22))       // allowed by failsafe
			cc.CheckConnectivity()
		})
	})
})
