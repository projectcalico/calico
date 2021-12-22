// Copyright (c) 2020 Tigera, Inc. All rights reserved.

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

	"github.com/projectcalico/calico/felix/fv/connectivity"
	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/felix/fv/workload"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
)

var _ = infrastructure.DatastoreDescribe("Base FORWARD behaviour", []apiconfig.DatastoreType{apiconfig.EtcdV3}, func(getInfra infrastructure.InfraFactory) {

	var (
		infra infrastructure.DatastoreInfra
		felix *infrastructure.Felix
		w     [2]*workload.Workload
		cc    *connectivity.Checker
	)

	BeforeEach(func() {
		infra = getInfra()
		opts := infrastructure.DefaultTopologyOptions()
		opts.ExtraEnvVars["FELIX_REMOVEEXTERNALROUTES"] = "false"
		opts.ExtraEnvVars["FELIX_INTERFACEPREFIX"] = "wibbly"
		felix, _ = infrastructure.StartSingleNodeTopology(opts, infra)

		// Create two non-Calico-managed namespaces, so we can test the root namespace's
		// forwarding ability in the absence of any Calico policy.
		for ii := range w {
			wIP := fmt.Sprintf("10.65.%d.2", ii)
			wName := fmt.Sprintf("w%d", ii)
			w[ii] = workload.Run(felix, wName, "default", wIP, "8055", "tcp")
		}

		// Manually add routing between them.  We need FELIX_REMOVEEXTERNALROUTES and
		// FELIX_INTERFACEPREFIX other than "cali" (above) so that these manual routes
		// aren't removed again by Felix.
		felix.Exec("ip", "route", "add", w[0].IP+"/32", "dev", w[0].InterfaceName)
		felix.Exec("ip", "route", "add", w[1].IP+"/32", "dev", w[1].InterfaceName)

		// Also manually set up proxy ARP.
		felix.Exec("sysctl", "-w", "net.ipv4.conf."+w[0].InterfaceName+".proxy_arp=1")
		felix.Exec("sysctl", "-w", "net.ipv4.conf."+w[1].InterfaceName+".proxy_arp=1")
		felix.Exec("sysctl", "-w", "net.ipv4.neigh."+w[0].InterfaceName+".proxy_delay=0")
		felix.Exec("sysctl", "-w", "net.ipv4.neigh."+w[1].InterfaceName+".proxy_delay=0")

		cc = &connectivity.Checker{}
	})

	AfterEach(func() {
		felix.Stop()
		if CurrentGinkgoTestDescription().Failed {
			infra.DumpErrorData()
			felix.Exec("iptables-save", "-c")
			felix.Exec("ipset", "list")
			felix.Exec("ip", "r")
			felix.Exec("ip", "a")
		}
		infra.Stop()
	})

	It("should not forward because of FORWARD DROP policy", func() {
		cc.ExpectNone(w[0], w[1])
		cc.ExpectNone(w[1], w[0])
		cc.CheckConnectivity()
	})

	Context("with FORWARD ACCEPT policy", func() {
		BeforeEach(func() {
			felix.Exec("iptables", "-P", "FORWARD", "ACCEPT")
		})

		It("should now forward", func() {
			cc.ExpectSome(w[0], w[1])
			cc.ExpectSome(w[1], w[0])
			cc.CheckConnectivity()
		})
	})
})
