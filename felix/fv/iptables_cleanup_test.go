// Copyright (c) 2019-2026 Tigera, Inc. All rights reserved.
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
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/fv/infrastructure"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
)

var _ = infrastructure.DatastoreDescribe("_BPF-SAFE_ iptables cleanup tests", []apiconfig.DatastoreType{apiconfig.Kubernetes}, func(getInfra infrastructure.InfraFactory) {
	var (
		infra   infrastructure.DatastoreInfra
		tc      infrastructure.TopologyContainers
		options infrastructure.TopologyOptions
	)

	BeforeEach(func() {
		infra = getInfra()
		options = infrastructure.DefaultTopologyOptions()
		// Make sure Felix re-scans the dataplane frequently. Which of these applies depends on
		// the mode Felix is in; in nftables mode the iptables one is ignored.
		options.ExtraEnvVars["FELIX_IptablesRefreshInterval"] = "1"
		options.ExtraEnvVars["FELIX_NftablesRefreshInterval"] = "1"
	})

	// The topology starts here rather than in BeforeEach so that each test below can finish
	// configuring Felix (in particular which iptables backend it uses) first. Tests seed the
	// dataplane from their own JustBeforeEach, which runs after this one.
	JustBeforeEach(func() {
		tc, _ = infrastructure.StartSingleNodeTopology(options, infra)
	})

	Describe("with a range of rules in iptables", func() {
		BeforeEach(func() {
			if NFTMode() {
				Skip("This test is not yet supported in nftables mode")
			}
		})

		JustBeforeEach(func() {
			err := tc.Felixes[0].CopyFileIntoContainer("iptables-dump.txt", "/iptables-dump.txt")
			Expect(err).ToNot(HaveOccurred(), "Failed to copy iptables dump into felix container")
			Eventually(func() error {
				// Can fail if felix is trying to do a concurrent update.  Just keep trying...
				return tc.Felixes[0].ExecMayFail("iptables-restore", "/iptables-dump.txt")
			}, "5s", "100ms").ShouldNot(HaveOccurred())
		})

		const kubeChainsThatShouldBeCleanedUp = `KUBE-(SERVICES|EXTERNAL-SERVICES|NODEPORTS|FORWARD|SVC|SEP|FW|XLB)`
		const kubeChainsThatShouldNeverBeCleanedUp = `KUBE-(MARK-MASQ|MARK-DROP|KUBE-FIREWALL)`
		const caliChainsThatShouldBeCleanedUp = `cali-old-chain`

		dumpIptables := func() string {
			out, err := tc.Felixes[0].ExecOutput("iptables-save")
			Expect(err).NotTo(HaveOccurred())
			return out
		}

		if os.Getenv("FELIX_FV_ENABLE_BPF") == "true" {
			It("_BPF_ should clean up kube-proxy's rules", func() {
				Eventually(dumpIptables, "5s").ShouldNot(MatchRegexp(kubeChainsThatShouldBeCleanedUp))
				Consistently(dumpIptables, "2s").Should(MatchRegexp(kubeChainsThatShouldNeverBeCleanedUp))
			})
		} else {
			It("should leave kube-proxy rules alone", func() {
				Consistently(dumpIptables, "5s").Should(MatchRegexp(kubeChainsThatShouldBeCleanedUp))
			})
		}
		It("should clean up our rules", func() {
			Eventually(dumpIptables, "5s").ShouldNot(MatchRegexp(caliChainsThatShouldBeCleanedUp))
		})
	})

	// A Felix that was in iptables mode left its rules in one of two dataplanes, depending on the
	// backend it was using, and only that backend's tools can see them. We pin the backend and
	// name the binaries explicitly, so each case exercises the dataplane it means to rather than
	// whichever one the image's "iptables" alternative happens to point at.
	describeSwitchToNFTables := func(desc, backend string) {
		Describe(desc, func() {
			BeforeEach(func() {
				if !NFTMode() {
					Skip("This test is only relevant in nftables mode")
				}
				options.ExtraEnvVars["FELIX_IptablesBackend"] = backend
			})

			JustBeforeEach(func() {
				// Install some iptables rules that we expect to be cleaned up.
				err := tc.Felixes[0].CopyFileIntoContainer("cali-iptables-dump.txt", "/iptables-dump.txt")
				Expect(err).ToNot(HaveOccurred(), "Failed to copy iptables dump into felix container")
				Eventually(func() error {
					// Can fail if felix is trying to do a concurrent update.  Just keep trying...
					return tc.Felixes[0].ExecMayFail("iptables-"+backend+"-restore", "/iptables-dump.txt")
				}, "5s", "100ms").ShouldNot(HaveOccurred())
			})

			It("should clean up iptables rules when running in nftables mode", func() {
				// There should be no cali chains left in iptables after Felix has run.
				Eventually(func() string {
					out, err := tc.Felixes[0].ExecOutput("iptables-" + backend + "-save")
					Expect(err).NotTo(HaveOccurred())
					return out
				}, "10s").ShouldNot(ContainSubstring("cali-"))
			})
		})
	}

	describeSwitchToNFTables("switching from iptables -> nftables, nft backend", "nft")
	describeSwitchToNFTables("switching from iptables -> nftables, legacy backend", "legacy")

	Describe("switching from nftables -> iptables", func() {
		BeforeEach(func() {
			if NFTMode() {
				Skip("This test is only relevant in iptables mode")
			}
		})

		JustBeforeEach(func() {
			// Install some nftables rules that we expect to be cleaned up.
			err := tc.Felixes[0].CopyFileIntoContainer("cali-nftables-dump.txt", "/nftables-dump.txt")
			Expect(err).ToNot(HaveOccurred(), "Failed to copy iptables dump into felix container")
			Eventually(func() error {
				return tc.Felixes[0].ExecMayFail("nft", "-f", "/nftables-dump.txt")
			}, "5s", "100ms").ShouldNot(HaveOccurred())
		})

		It("should clean up nftables rules when running in iptables mode", func() {
			// The stale "table ip calico" should be cleaned up. The "table arp calico-arp"
			// is legitimately created by Felix for ARP suppression regardless of dataplane mode.
			Eventually(func() string {
				out, err := tc.Felixes[0].ExecOutput("nft", "list", "tables")
				Expect(err).NotTo(HaveOccurred())
				return out
			}, "5s").ShouldNot(ContainSubstring("table ip calico"))
		})
	})
})
