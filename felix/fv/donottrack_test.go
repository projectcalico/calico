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
	"context"
	"fmt"
	"time"

	"github.com/projectcalico/calico/felix/fv/connectivity"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"

	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/fv/containers"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

var _ = infrastructure.DatastoreDescribe("_BPF-SAFE_ do-not-track policy tests; with 2 nodes", []apiconfig.DatastoreType{apiconfig.EtcdV3, apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {

	var (
		infra          infrastructure.DatastoreInfra
		felixes        []*infrastructure.Felix
		hostW          [2]*workload.Workload
		client         client.Interface
		cc             *connectivity.Checker
		dumpedDiags    bool
		externalClient *containers.Container
	)

	BeforeEach(func() {
		var err error
		infra = getInfra()

		dumpedDiags = false
		options := infrastructure.DefaultTopologyOptions()
		felixes, client = infrastructure.StartNNodeTopology(2, options, infra)
		cc = &connectivity.Checker{}

		// Start a host networked workload on each host for connectivity checks.
		for ii := range felixes {
			// We tell each workload to open:
			// - its normal (uninteresting) port, 8055
			// - port 2379, which is both an inbound and an outbound failsafe port
			// - port 22, which is an inbound failsafe port.
			// This allows us to test the interaction between do-not-track policy and failsafe
			// ports.
			const portsToOpen = "8055,2379,22"
			hostW[ii] = workload.Run(
				felixes[ii],
				fmt.Sprintf("host%d", ii),
				"default",
				felixes[ii].IP, // Same IP as felix means "run in the host's namespace"
				portsToOpen,
				"tcp")
		}

		// We will use this container to model an external client trying to connect into
		// workloads on a host.  Create a route in the container for the workload CIDR.
		externalClient = infrastructure.RunExtClient("ext-client")
		err = infra.AddDefaultDeny()
		Expect(err).To(BeNil())
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
		infra.DumpErrorData()

	}

	AfterEach(func() {
		dumpDiags()
		for _, f := range felixes {
			f.Stop()
		}
		infra.Stop()
		externalClient.Stop()
	})

	expectFullConnectivity := func() {
		cc.ResetExpectations()
		cc.ExpectSome(felixes[0], hostW[1].Port(8055))
		cc.ExpectSome(felixes[1], hostW[0].Port(8055))
		cc.ExpectSome(felixes[0], hostW[1].Port(2379))
		cc.ExpectSome(felixes[1], hostW[0].Port(2379))
		cc.ExpectSome(felixes[0], hostW[1].Port(22))
		cc.ExpectSome(felixes[1], hostW[0].Port(22))
		cc.ExpectSome(externalClient, hostW[1].Port(22))
		cc.ExpectSome(externalClient, hostW[0].Port(22))
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
			// Make sure our new host endpoints don't cut felix off from the datastore.
			err := infra.AddAllowToDatastore("host-endpoint=='true'")
			Expect(err).NotTo(HaveOccurred())

			ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)

			for _, f := range felixes {
				hep := api.NewHostEndpoint()
				hep.Name = "eth0-" + f.Name
				hep.Labels = map[string]string{
					"name":          hep.Name,
					"host-endpoint": "true",
				}
				hep.Spec.Node = f.Hostname
				hep.Spec.ExpectedIPs = []string{f.IP}
				_, err := client.HostEndpoints().Create(ctx, hep, options.SetOptions{})
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
			cc.ExpectSome(felixes[0], hostW[1].Port(2379))
			cc.ExpectSome(felixes[1], hostW[0].Port(2379))
			// Port 22 is inbound-only so it'll be blocked by the (lack of egress policy).
			cc.ExpectNone(felixes[0], hostW[1].Port(22))
			cc.ExpectNone(felixes[1], hostW[0].Port(22))
			// But external client should still be able to access it...
			cc.ExpectSome(externalClient, hostW[1].Port(22))
			cc.ExpectSome(externalClient, hostW[0].Port(22))
			cc.CheckConnectivity()

			host0Selector := fmt.Sprintf("name == 'eth0-%s'", felixes[0].Name)
			host1Selector := fmt.Sprintf("name == 'eth0-%s'", felixes[1].Name)

			By("Having connectivity after installing bidirectional policies")
			host0Pol := api.NewGlobalNetworkPolicy()
			host0Pol.Name = "host-0-pol"
			host0Pol.Spec.Selector = host0Selector
			host0Pol.Spec.DoNotTrack = true
			host0Pol.Spec.ApplyOnForward = true
			host0Pol.Spec.Ingress = []api.Rule{
				{
					Action: api.Allow,
					Source: api.EntityRule{
						Selector: host1Selector,
					},
				},
			}
			host0Pol.Spec.Egress = []api.Rule{
				{
					Action: api.Allow,
					Destination: api.EntityRule{
						Selector: host1Selector,
					},
				},
			}
			host0Pol, err := client.GlobalNetworkPolicies().Create(ctx, host0Pol, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())

			host1Pol := api.NewGlobalNetworkPolicy()
			host1Pol.Name = "host-1-pol"
			host1Pol.Spec.Selector = host1Selector
			host1Pol.Spec.DoNotTrack = true
			host1Pol.Spec.ApplyOnForward = true
			host1Pol.Spec.Ingress = []api.Rule{
				{
					Action: api.Allow,
					Source: api.EntityRule{
						Selector: host0Selector,
					},
				},
			}
			host1Pol.Spec.Egress = []api.Rule{
				{
					Action: api.Allow,
					Destination: api.EntityRule{
						Selector: host0Selector,
					},
				},
			}
			host1Pol, err = client.GlobalNetworkPolicies().Create(ctx, host1Pol, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())

			expectFullConnectivity()

			By("Having only failsafe connectivity after replacing host-0's egress rules with Deny")
			// Since there's no conntrack, removing rules in one direction is enough to prevent
			// connectivity in either direction.
			host0Pol.Spec.Egress = []api.Rule{
				{
					Action: api.Deny,
					Destination: api.EntityRule{
						Selector: host0Selector,
					},
				},
			}
			host0Pol, err = client.GlobalNetworkPolicies().Update(ctx, host0Pol, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())

			cc.ResetExpectations()
			cc.ExpectNone(felixes[0], hostW[1].Port(8055))
			cc.ExpectNone(felixes[1], hostW[0].Port(8055))
			cc.ExpectSome(felixes[0], hostW[1].Port(2379))
			cc.ExpectSome(felixes[1], hostW[0].Port(2379))
			cc.ExpectNone(felixes[0], hostW[1].Port(22))     // Now blocked (lack of egress).
			cc.ExpectSome(felixes[1], hostW[0].Port(22))     // Still open due to failsafe.
			cc.ExpectSome(externalClient, hostW[1].Port(22)) // Allowed by failsafe
			cc.ExpectSome(externalClient, hostW[0].Port(22)) // Allowed by failsafe
			cc.CheckConnectivity()

			By("Having full connectivity after putting them back")
			host0Pol.Spec.Egress = []api.Rule{
				{
					Action: api.Allow,
					Destination: api.EntityRule{
						Selector: host1Selector,
					},
				},
			}
			host0Pol, err = client.GlobalNetworkPolicies().Update(ctx, host0Pol, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())

			expectFullConnectivity()

			By("Having only failsafe connectivity after replacing host-0's ingress rules with Deny")
			host0Pol.Spec.Ingress = []api.Rule{
				{
					Action: api.Deny,
					Destination: api.EntityRule{
						Selector: host0Selector,
					},
				},
			}
			host0Pol, err = client.GlobalNetworkPolicies().Update(ctx, host0Pol, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())

			cc.ResetExpectations()
			cc.ExpectNone(felixes[0], hostW[1].Port(8055))
			cc.ExpectNone(felixes[1], hostW[0].Port(8055))
			cc.ExpectSome(felixes[0], hostW[1].Port(2379))
			cc.ExpectSome(felixes[1], hostW[0].Port(2379))
			cc.ExpectNone(felixes[0], hostW[1].Port(22))     // Response traffic blocked by policy
			cc.ExpectSome(felixes[1], hostW[0].Port(22))     // Allowed by failsafe
			cc.ExpectSome(externalClient, hostW[1].Port(22)) // Allowed by failsafe
			cc.ExpectSome(externalClient, hostW[0].Port(22)) // Allowed by failsafe
			cc.CheckConnectivity()
		})
	})
})
