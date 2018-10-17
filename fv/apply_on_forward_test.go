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
	"strings"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/felix/fv/infrastructure"
	"github.com/projectcalico/felix/fv/utils"
	"github.com/projectcalico/felix/fv/workload"
	"github.com/projectcalico/libcalico-go/lib/apiconfig"
	api "github.com/projectcalico/libcalico-go/lib/apis/v3"
	client "github.com/projectcalico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/libcalico-go/lib/options"
)

var _ = infrastructure.DatastoreDescribe("apply on forward tests; with 2 nodes", []apiconfig.DatastoreType{apiconfig.EtcdV3, apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {

	var (
		infra   infrastructure.DatastoreInfra
		felixes []*infrastructure.Felix
		client  client.Interface
		w       [2]*workload.Workload
		hostW   [2]*workload.Workload
		cc      *workload.ConnectivityChecker
	)

	BeforeEach(func() {
		infra = getInfra()

		options := infrastructure.DefaultTopologyOptions()
		options.IPIPEnabled = false
		felixes, client = infrastructure.StartNNodeTopology(2, options, infra)

		// Install a default profile that allows all ingress and egress, in the absence of any Policy.
		infra.AddDefaultAllow()

		// Create workloads, using that profile.  One on each "host".
		for ii := range w {
			wIP := fmt.Sprintf("10.65.%d.2", ii)
			wName := fmt.Sprintf("w%d", ii)
			w[ii] = workload.Run(felixes[ii], wName, "default", wIP, "8055", "tcp")
			w[ii].ConfigureInDatastore(infra)

			hostW[ii] = workload.Run(felixes[ii], fmt.Sprintf("host%d", ii), "", felixes[ii].IP, "8055", "tcp")
		}

		cc = &workload.ConnectivityChecker{}
	})

	AfterEach(func() {
		if CurrentGinkgoTestDescription().Failed {
			for _, felix := range felixes {
				felix.Exec("iptables-save", "-c")
				felix.Exec("ipset", "list")
				felix.Exec("ip", "r")
				felix.Exec("ip", "a")
			}
		}

		for _, wl := range w {
			wl.Stop()
		}
		for _, wl := range hostW {
			wl.Stop()
		}
		for _, felix := range felixes {
			felix.Stop()
		}

		if CurrentGinkgoTestDescription().Failed {
			infra.DumpErrorData()
		}
		infra.Stop()
	})

	It("should have workload to workload/host connectivity", func() {
		cc.ExpectSome(w[0], w[1])
		cc.ExpectSome(w[1], w[0])
		cc.ExpectSome(w[0], hostW[1])
		cc.ExpectSome(w[1], hostW[0])
		cc.CheckConnectivity()
	})

	// The following tests verify that a HostEndpoint does not block forwarded traffic
	// when there is no applyOnForward policy that applies to that HostEndpoint.  We
	// create a HostEndpoint for eth0 on two hosts (A and B) and then test two cases:
	//
	// 1. Workload on host A -> Workload on host B.  In this case, the traffic is
	// forwarded on both hosts.
	//
	// 2. Workload on host A -> Local process on host B.  In this case, the traffic is
	// forwarded on host A, but _not_ on host B.
	//
	// For case (2), in order to allow the traffic to be received on host B, we have
	// to configure an Allow policy that applies to the endpoint there.  But note that
	// this is _not_ an applyOnForward policy, so it is still the case that there is
	// no applyOnForward policy that applies to the HostEndpoints.
	//
	Context("with host endpoints defined", func() {
		var (
			ctx    context.Context
			cancel context.CancelFunc
		)

		BeforeEach(func() {
			// Add a default-allow policy for the following host endpoints.
			policy := api.NewGlobalNetworkPolicy()
			policy.Name = "default-allow"
			policy.Spec.Selector = "host-endpoint=='true'"
			policy.Spec.Egress = []api.Rule{{Action: api.Allow}}
			policy.Spec.Ingress = []api.Rule{{Action: api.Allow}}
			_, err := client.GlobalNetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())

			ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

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

				// Wait for felix to see and program that host endpoint.
				hostEndpointProgrammed := func() bool {
					out, err := f.ExecOutput("iptables-save", "-t", "filter")
					Expect(err).NotTo(HaveOccurred())
					return (strings.Count(out, "cali-thfw-eth0") > 0)
				}
				Eventually(hostEndpointProgrammed, "10s", "1s").Should(BeTrue(),
					"Expected HostEndpoint iptables rules to appear")
			}
		})

		It("should have workload to workload/host connectivity", func() {
			cc.ExpectSome(w[0], w[1])
			cc.ExpectSome(w[1], w[0])
			cc.ExpectSome(w[0], hostW[1])
			cc.ExpectSome(w[1], hostW[0])
			cc.CheckConnectivity()
		})
	})
})
