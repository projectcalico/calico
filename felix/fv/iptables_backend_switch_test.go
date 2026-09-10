// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
)

// Boot ordering can move a node between the two iptables backends. Felix sweeps the one it isn't
// programming.
var _ = infrastructure.DatastoreDescribe("_BPF-SAFE_ iptables backend switch cleanup", []apiconfig.DatastoreType{apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
	var (
		infra infrastructure.DatastoreInfra
		tc    infrastructure.TopologyContainers
	)

	// Not in a BeforeEach: the env var has to be set before Felix starts.
	startFelix := func(backend string) {
		infra = getInfra()
		options := infrastructure.DefaultTopologyOptions()
		options.ExtraEnvVars["FELIX_IptablesBackend"] = backend
		options.ExtraEnvVars["FELIX_IptablesRefreshInterval"] = "1"
		tc, _ = infrastructure.StartSingleNodeTopology(options, infra)
	}

	// Restarts so the startup sweep is the path under test.
	plant := func(restoreCmd string) {
		Expect(tc.Felixes[0].CopyFileIntoContainer("cali-iptables-dump.txt", "/iptables-dump.txt")).To(Succeed())
		Eventually(func() error {
			// Can fail if Felix is trying to do a concurrent update.  Just keep trying...
			return tc.Felixes[0].ExecMayFail(restoreCmd, "/iptables-dump.txt")
		}, "5s", "100ms").ShouldNot(HaveOccurred())
		tc.Felixes[0].Restart()
	}

	save := func(saveCmd string) func() string {
		return func() string {
			out, err := tc.Felixes[0].ExecOutput(saveCmd)
			Expect(err).NotTo(HaveOccurred())
			return out
		}
	}

	BeforeEach(func() {
		if NFTMode() {
			Skip("These tests cover Felix switching between the two iptables backends.")
		}
	})

	AfterEach(func() {
		if CurrentSpecReport().Failed() && len(tc.Felixes) > 0 {
			tc.Felixes[0].Exec("iptables-legacy-save")
			tc.Felixes[0].Exec("iptables-nft-save")
		}
		tc.Stop()
		if infra != nil {
			infra.Stop()
		}
	})

	Describe("switching from legacy iptables -> nft iptables", func() {
		BeforeEach(func() {
			startFelix("nft")
			plant("iptables-legacy-restore")
		})

		It("cleans up the legacy rules and keeps programming the nft ones", func() {
			Eventually(save("iptables-legacy-save"), "20s").ShouldNot(ContainSubstring("cali-"))

			// Felix's own rules are in the backend it's programming, and stay there.
			Expect(save("iptables-nft-save")()).To(ContainSubstring("cali-"))
			Consistently(save("iptables-nft-save"), "5s").Should(ContainSubstring("cali-"))

			// Cleanup never terminates, so rules that turn up while Felix runs go too.
			Eventually(func() error {
				return tc.Felixes[0].ExecMayFail("iptables-legacy-restore", "/iptables-dump.txt")
			}, "5s", "100ms").ShouldNot(HaveOccurred())
			Eventually(save("iptables-legacy-save"), "20s").ShouldNot(ContainSubstring("cali-"))
		})
	})

	Describe("switching from nft iptables -> legacy iptables", func() {
		BeforeEach(func() {
			startFelix("legacy")
			plant("iptables-nft-restore")
		})

		It("cleans up the nft rules and keeps programming the legacy ones", func() {
			Eventually(save("iptables-nft-save"), "20s").ShouldNot(ContainSubstring("cali-"))

			Expect(save("iptables-legacy-save")()).To(ContainSubstring("cali-"))
			Consistently(save("iptables-legacy-save"), "5s").Should(ContainSubstring("cali-"))

			Eventually(func() error {
				return tc.Felixes[0].ExecMayFail("iptables-nft-restore", "/iptables-dump.txt")
			}, "5s", "100ms").ShouldNot(HaveOccurred())
			Eventually(save("iptables-nft-save"), "20s").ShouldNot(ContainSubstring("cali-"))
		})
	})
})
