// Copyright (c) 2020 Tigera, Inc. All rights reserved.
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
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/fv/connectivity"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/workload"
)

var _ = Describe("Spoof tests", func() {
	var (
		infra   infrastructure.DatastoreInfra
		felixes []*infrastructure.Felix
		w       [3]*workload.Workload
		cc      *connectivity.Checker
	)

	teardownInfra := func() {
		if CurrentGinkgoTestDescription().Failed {
			for _, felix := range felixes {
				felix.Exec("iptables-save", "-c")
				felix.Exec("ip6tables-save", "-c")
				felix.Exec("ipset", "list")
				felix.Exec("ip", "r")
				felix.Exec("ip", "-6", "r")
				felix.Exec("ip", "a")
				felix.Exec("ip", "-6", "a")
			}
		}
		for _, wl := range w {
			wl.Stop()
		}
		for _, felix := range felixes {
			felix.Stop()
		}
		if CurrentGinkgoTestDescription().Failed {
			infra.DumpErrorData()
		}
		infra.Stop()
	}

	spoofTests := func() {
		It("should drop spoofed traffic", func() {
			cc = &connectivity.Checker{}
			// Setup a spoofed workload. Make w[0] spoof w[2] by making it
			// use w[2]'s IP to test connections.
			spoofed := &workload.SpoofedWorkload{
				Workload:        w[0],
				SpoofedSourceIP: w[2].IP,
			}
			// The spoofed connection should be dropped.
			cc.ExpectNone(spoofed, w[1])
			// But a connection from the real w[2] should succeed.
			cc.ExpectSome(w[2], w[1])
			// And a connection from w[0] without spoofing, vice versa,
			// should also succeed.
			cc.ExpectSome(w[0], w[1])
			cc.ExpectSome(w[1], w[0])
			cc.CheckConnectivity()
		})

		It("should allow workload's traffic if workload spoofs its own IP", func() {
			cc = &connectivity.Checker{}
			// Setup a "spoofed" workload. Make w[0] spoof itself.
			spoofed := &workload.SpoofedWorkload{
				Workload:        w[0],
				SpoofedSourceIP: w[0].IP,
			}
			// The spoofed connection should be allowed.
			cc.ExpectSome(spoofed, w[1])
			cc.ExpectSome(w[1], spoofed)
			cc.CheckConnectivity()
		})
	}

	Context("_BPF-SAFE_ IPv4", func() {
		BeforeEach(func() {
			var err error
			infra, err = infrastructure.GetEtcdDatastoreInfra()
			Expect(err).NotTo(HaveOccurred())
			opts := infrastructure.DefaultTopologyOptions()
			felixes, _ = infrastructure.StartNNodeTopology(3, opts, infra)
			// Install a default profile allowing all ingress and egress,
			// in the absence of policy.
			infra.AddDefaultAllow()

			// Create workloads using "default" profile.
			for ii := range w {
				wIP := fmt.Sprintf("10.65.%d.2", ii)
				wName := fmt.Sprintf("w%d", ii)
				w[ii] = workload.Run(felixes[ii], wName, "default", wIP, "8055", "tcp")
				w[ii].ConfigureInInfra(infra)
			}
		})

		AfterEach(func() {
			teardownInfra()
		})

		spoofTests()
	})

	Context("IPv6", func() {
		BeforeEach(func() {
			var err error
			infra, err = infrastructure.GetEtcdDatastoreInfra()
			Expect(err).NotTo(HaveOccurred())
			opts := infrastructure.DefaultTopologyOptions()

			// The IPv4 tests had each workload running on an individual
			// felix, but our current topology setup tooling doesn't yet
			// support that for IPv6. So for these tests, we'll run the
			// workloads on a single felix.
			felixes, _ = infrastructure.StartNNodeTopology(1, opts, infra)

			// Install a default profile allowing all ingress and egress,
			// in the absence of policy.
			infra.AddDefaultAllow()

			// Create workloads using "default" profile.
			for ii := range w {
				wIP := fmt.Sprintf("fdc6:3dbc:e983:cbc%x::1", ii)
				wName := fmt.Sprintf("w%d", ii)
				w[ii] = workload.Run(felixes[0], wName, "default", wIP, "8055", "tcp")
				w[ii].ConfigureInInfra(infra)
			}
		})

		AfterEach(func() {
			teardownInfra()
		})

		spoofTests()
	})
})
