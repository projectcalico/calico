// Copyright (c) 2022 Tigera, Inc. All rights reserved.
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

	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"

	"github.com/projectcalico/calico/felix/fv/connectivity"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/utils"
	"github.com/projectcalico/calico/felix/fv/workload"
)

var _ = infrastructure.DatastoreDescribe("_BPF-SAFE_ named host endpoints",
	[]apiconfig.DatastoreType{apiconfig.EtcdV3}, func(getInfra infrastructure.InfraFactory) {
		describeHostEndpointTests2(getInfra, false)
	})

// describeHostEndpointTests describes tests exercising host endpoints.
// If allInterfaces, then interfaceName: "*". Otherwise, interfaceName: "eth0".
func describeHostEndpointTests2(getInfra infrastructure.InfraFactory, allInterfaces bool) {
	var (
		infra   infrastructure.DatastoreInfra
		felixes []*infrastructure.Felix
		client  client.Interface
		w       [2]*workload.Workload
		hostW   [2]*workload.Workload
		cc      *connectivity.Checker // Numbered checkers are for raw IP tests of specific protocols.
	)

	BeforeEach(func() {
		infra = getInfra()
		options := infrastructure.DefaultTopologyOptions()
		options.IPIPEnabled = false
		options.WithTypha = true
		felixes, client = infrastructure.StartNNodeTopology(2, options, infra)

		// Create workloads, using that profile. One on each "host".
		for ii := range w {
			wIP := fmt.Sprintf("10.65.%d.2", ii)
			wName := fmt.Sprintf("w%d", ii)
			w[ii] = workload.Run(felixes[ii], wName, "default", wIP, "8055", "tcp")
			w[ii].ConfigureInInfra(infra)

			hostW[ii] = workload.Run(felixes[ii], fmt.Sprintf("host%d", ii), "", felixes[ii].IP, "8055", "tcp")
		}

		cc = &connectivity.Checker{}
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

	expectHostToHostTraffic := func() {
		cc.ExpectSome(felixes[0], hostW[1])
		cc.ExpectSome(felixes[1], hostW[0])
	}

	// With an etcd datastore - as still used for OpenStack - test that a host endpoint inherits
	// labels from the profiles in its definition, and that GNP based on an inherited label
	// works.
	Context("with config that relies on host endpoint inheriting profile labels", func() {
		BeforeEach(func() {
			// Configure Profile with a label that we want to be inherited.
			prof := api.NewProfile()
			prof.Name = "inheritable"
			prof.Spec.LabelsToApply = map[string]string{"inherited": "yay"}
			_, err := client.Profiles().Create(utils.Ctx, prof, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())

			// Configure HostEndpoint on felixes[0], that inherits from that profile.
			hep := api.NewHostEndpoint()
			hep.Name = "hep-" + felixes[0].Name
			hep.Labels = map[string]string{
				"name":          hep.Name,
				"hostname":      felixes[0].Hostname,
				"host-endpoint": "true",
			}
			hep.Spec.Profiles = []string{"inheritable"}
			hep.Spec.Node = felixes[0].Hostname
			hep.Spec.ExpectedIPs = []string{felixes[0].IP}
			if allInterfaces {
				hep.Spec.InterfaceName = "*"
			} else {
				hep.Spec.InterfaceName = "eth0"
			}
			_, err = client.HostEndpoints().Create(utils.Ctx, hep, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())

			// Configure GNP to allow to/from endpoints with the "inherited" label.
			policy := api.NewGlobalNetworkPolicy()
			policy.Name = "allow-inherited"
			policy.Spec.Ingress = []api.Rule{{Action: api.Allow}}
			policy.Spec.Egress = []api.Rule{{Action: api.Allow}}
			policy.Spec.Selector = "has(inherited)"
			_, err = client.GlobalNetworkPolicies().Create(utils.Ctx, policy, utils.NoOptions)
			Expect(err).NotTo(HaveOccurred())

		})

		It("should allow host to host traffic", func() {
			expectHostToHostTraffic()
			cc.CheckConnectivity()
		})
	})
}
