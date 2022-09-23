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

package fv_test

import (
	"fmt"
	"os"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/pkg/errors"
	"github.com/projectcalico/calico/felix/fv/connectivity"
	"github.com/projectcalico/calico/felix/fv/containers"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	"github.com/vishvananda/netlink"
)

var _ = infrastructure.DatastoreDescribe("_BPF-SAFE_ Felix bpf with NOTRACK feature", []apiconfig.DatastoreType{apiconfig.EtcdV3}, func(getInfra infrastructure.InfraFactory) {

	if os.Getenv("FELIX_FV_ENABLE_BPF") != "true" {
		// Non-BPF run.
		return
	}

	var (
		infra          infrastructure.DatastoreInfra
		felixes        []*infrastructure.Felix
		workloads      [2]*workload.Workload
		cc             *connectivity.Checker
		externalClient *containers.Container
	)

	BeforeEach(func() {
		infra = getInfra()

		opts := infrastructure.DefaultTopologyOptions()
		opts.ExtraEnvVars = map[string]string{
			"FELIX_BPFENABLED":              "true",
			"FELIX_BPFHostConntrackBypass":  "false",
			"FELIX_DEBUGDISABLELOGDROPPING": "true"}

		felixes, _ = infrastructure.StartNNodeTopology(2, opts, infra)
		infra.AddDefaultAllow()
		cc = &connectivity.Checker{}

		// Wait until the tunl0 device appears; it is created when felix inserts the ipip module
		// into the kernel.
		Eventually(func() error {
			links, err := netlink.LinkList()
			if err != nil {
				return err
			}
			for _, link := range links {
				if link.Attrs().Name == "tunl0" {
					return nil
				}
			}
			return errors.New("tunl0 wasn't auto-created")
		}).Should(BeNil())

		for i := range felixes {
			const portsToOpen = "80"
			workloads[i] = workload.Run(felixes[i],
				fmt.Sprintf("host%d-webserver", i),
				"default",
				fmt.Sprintf("10.65.%d.2", i),
				portsToOpen, "tcp")
			workloads[i].ConfigureInInfra(infra)
		}

		externalClient = infrastructure.RunExtClient("ext-client")
	})

	AfterEach(func() {
		if CurrentGinkgoTestDescription().Failed {
			infra.DumpErrorData()
		}

		for _, felix := range felixes {
			felix.Stop()
		}

		infra.Stop()
	})

	It("should allow 3rd party DNAT to workloads work", func() {
		expectNormalConnectivity := func() {
			cc.ResetExpectations()
			for i := range felixes {
				cc.ExpectSome(felixes[i], workloads[0].Port(80))
				cc.ExpectSome(felixes[i], workloads[1].Port(80))
				cc.ExpectNone(externalClient, workloads[i].Port(80))
				hostIP := connectivity.TargetIP(felixes[i].IP)
				cc.ExpectNone(externalClient, hostIP, 8080)
			}
			cc.ExpectSome(workloads[1], workloads[0].Port(80))
			cc.ExpectSome(workloads[0], workloads[1].Port(80))
			cc.CheckConnectivity()
		}

		By("checking initial connectivity", func() {
			expectNormalConnectivity()
		})

		By("installing 3rd party rules", func() {
			// Install a DNAT in first felix
			felix := felixes[0]

			felix.Exec(
				"iptables", "-t", "nat", "-A", "PREROUTING", "-p", "tcp", "-m", "tcp",
				"--dport", "8080", "-j", "DNAT", "--to-destination", "10.65.0.2:80")

			cc.ResetExpectations()
			for i := range felixes {
				cc.ExpectSome(felixes[i], workloads[0].Port(80))
				cc.ExpectSome(felixes[i], workloads[1].Port(80))
				cc.ExpectNone(externalClient, workloads[i].Port(80))
			}
			cc.ExpectSome(workloads[1], workloads[0].Port(80))
			cc.ExpectSome(workloads[0], workloads[1].Port(80))

			hostIP0 := connectivity.TargetIP(felixes[0].IP)
			cc.ExpectSome(felixes[1], hostIP0, 8080)
			cc.ExpectSome(externalClient, hostIP0, 8080)

			hostIP1 := connectivity.TargetIP(felixes[1].IP)
			cc.ExpectNone(felixes[1], hostIP1, 8080)
			cc.ExpectNone(externalClient, hostIP1, 8080)
			cc.CheckConnectivity()
		})

		By("removing 3rd party rules and check connectivity is back to normal again", func() {
			felixes[0].Exec(
				"iptables", "-t", "nat", "-D", "PREROUTING", "-p", "tcp", "-m", "tcp",
				"--dport", "8080", "-j", "DNAT", "--to-destination", "10.65.0.2:80")

			expectNormalConnectivity()
		})
	})
})
