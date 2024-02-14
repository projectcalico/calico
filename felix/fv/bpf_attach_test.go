// Copyright (c) 2021 Tigera, Inc. All rights reserved.
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
	"os"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
)

var _ = infrastructure.DatastoreDescribe("_BPF-SAFE_ Felix bpf reattach object", []apiconfig.DatastoreType{apiconfig.EtcdV3}, func(getInfra infrastructure.InfraFactory) {

	if os.Getenv("FELIX_FV_ENABLE_BPF") != "true" {
		// Non-BPF run.
		return
	}

	var (
		infra infrastructure.DatastoreInfra
		tc    infrastructure.TopologyContainers
		felix *infrastructure.Felix
	)

	BeforeEach(func() {
		infra = getInfra()
		// opts := infrastructure.DefaultTopologyOptions()
		opts := infrastructure.TopologyOptions{
			FelixLogSeverity: "debug",
			DelayFelixStart:  true,
			ExtraEnvVars: map[string]string{
				"FELIX_BPFENABLED":              "true",
				"FELIX_DEBUGDISABLELOGDROPPING": "true",
			},
			IPPoolCIDR:   infrastructure.DefaultIPPoolCIDR,
			IPv6PoolCIDR: infrastructure.DefaultIPv6PoolCIDR,
		}

		tc, _ = infrastructure.StartNNodeTopology(1, opts, infra)
		felix = tc.Felixes[0]

		err := infra.AddAllowToDatastore("host-endpoint=='true'")
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		if CurrentGinkgoTestDescription().Failed {
			infra.DumpErrorData()
		}

		tc.Stop()
		infra.Stop()
	})

	It("should clean up programs when BPFDataIfacePattern changes", func() {
		By("Starting Felix")
		felix.TriggerDelayedStart()

		By("Checking that eth0 has a program")

		Eventually(func() string {
			out, _ := felix.ExecOutput("bpftool", "-jp", "net")
			return out
		}, "15s", "1s").Should(ContainSubstring("eth0"))

		By("Changing env and restarting felix")

		felix.SetEnv(map[string]string{"FELIX_BPFDataIfacePattern": "eth1"})
		felix.Restart()

		By("Checking that eth0 does not have a program anymore")

		Eventually(func() string {
			out, _ := felix.ExecOutput("bpftool", "-jp", "net")
			return out
		}, "15s", "1s").ShouldNot(ContainSubstring("eth0"))
	})
})
