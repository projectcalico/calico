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
	"encoding/json"
	"os"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/bpf/ifstate"
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

	It("should attach programs to the bond interfaces", func() {
		By("Starting Felix")
		felix.TriggerDelayedStart()
		By("Check that dummy interfaces has a program")
		tc.Felixes[0].Exec("ip", "link", "add", "eth10", "type", "dummy")
		tc.Felixes[0].Exec("ip", "link", "add", "eth20", "type", "dummy")

		getBPFNet := func() []string {
			out, _ := felix.ExecOutput("bpftool", "-jp", "net")
			devs := []string{}
			var output []struct {
				Tc []struct {
					Devname string `json:"devname"`
				} `json:"tc"`
			}
			err := json.Unmarshal([]byte(out), &output)
			if err == nil {
				for _, tc := range output[0].Tc {
					devs = append(devs, tc.Devname)
				}
			}
			return devs
		}

		// Bring up the interfaces
		tc.Felixes[0].Exec("ifconfig", "eth10", "up")
		tc.Felixes[0].Exec("ifconfig", "eth20", "up")

		Eventually(getBPFNet, "15s", "1s").Should(ContainElements("eth10", "eth20"))
		ensureRightIFStateFlags(tc.Felixes[0], ifstate.FlgIPv4Ready, ifstate.FlgHEP, map[string]uint32{"eth10": ifstate.FlgIPv4Ready | ifstate.FlgHEP, "eth20": ifstate.FlgIPv4Ready | ifstate.FlgHEP})

		By("Creating a bond interface and eth10, eth20 to the bond")
		tc.Felixes[0].Exec("ip", "link", "add", "bond0", "type", "bond", "mode", "802.3ad")
		tc.Felixes[0].Exec("ifconfig", "eth10", "down")
		tc.Felixes[0].Exec("ifconfig", "eth20", "down")
		tc.Felixes[0].Exec("ip", "link", "set", "eth10", "master", "bond0")
		tc.Felixes[0].Exec("ip", "link", "set", "eth20", "master", "bond0")
		tc.Felixes[0].Exec("ifconfig", "bond0", "up")
		time.Sleep(0 * time.Second)
		Eventually(getBPFNet, "15s", "1s").Should(ContainElement("bond0"))
		Eventually(getBPFNet, "15s", "1s").ShouldNot(ContainElements("eth10", "eth20"))
		ensureRightIFStateFlags(tc.Felixes[0], ifstate.FlgIPv4Ready, ifstate.FlgHEP, map[string]uint32{"bond0": ifstate.FlgIPv4Ready | ifstate.FlgBond})

		By("Removing eth10 from bond")
		tc.Felixes[0].Exec("ip", "link", "set", "eth10", "nomaster")
		tc.Felixes[0].Exec("ifconfig", "eth10", "up")
		Eventually(getBPFNet, "15s", "1s").ShouldNot(ContainElement("eth20"))
		Eventually(getBPFNet, "15s", "1s").Should(ContainElements("bond0", "eth10"))
		ensureRightIFStateFlags(tc.Felixes[0], ifstate.FlgIPv4Ready, ifstate.FlgHEP, map[string]uint32{"bond0": ifstate.FlgIPv4Ready | ifstate.FlgBond, "eth10": ifstate.FlgIPv4Ready | ifstate.FlgHEP})

		By("Removing eth20 from bond")
		tc.Felixes[0].Exec("ip", "link", "set", "eth20", "nomaster")
		tc.Felixes[0].Exec("ifconfig", "eth20", "up")
		Eventually(getBPFNet, "15s", "1s").Should(ContainElements("bond0", "eth10", "eth20"))
		ensureRightIFStateFlags(tc.Felixes[0], ifstate.FlgIPv4Ready, ifstate.FlgHEP, map[string]uint32{"eth10": ifstate.FlgIPv4Ready | ifstate.FlgHEP, "eth20": ifstate.FlgIPv4Ready | ifstate.FlgHEP})

		By("Creating a bond interface which does match BPFDataIfacePattern")
		tc.Felixes[0].Exec("ip", "link", "add", "foo0", "type", "bond", "mode", "802.3ad")
		tc.Felixes[0].Exec("ifconfig", "eth10", "down")
		tc.Felixes[0].Exec("ifconfig", "eth20", "down")

		tc.Felixes[0].Exec("ip", "link", "set", "eth10", "master", "foo0")
		tc.Felixes[0].Exec("ip", "link", "set", "eth20", "master", "foo0")
		tc.Felixes[0].Exec("ifconfig", "foo0", "up")
		Eventually(getBPFNet, "15s", "1s").Should(ContainElements("eth10", "eth20"))

	})
})
