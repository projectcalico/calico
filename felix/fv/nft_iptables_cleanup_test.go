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

// Reproduction of #13263: native nft rules written into the shared filter/mangle/nat tables by
// other tools made those tables unreadable to iptables-nft-save, which Felix was using to clean up
// after a previous iptables-nft Felix, so Felix panic-looped.
//
// foreign-nft-dump.txt is the ruleset from the issue; cali-iptables-dump.txt is the state a
// previous iptables-nft Felix would have left underneath it.
var _ = infrastructure.DatastoreDescribe("_BPF-SAFE_ nftables cleanup of iptables rules, with foreign nft rules present", []apiconfig.DatastoreType{apiconfig.EtcdV3}, func(getInfra infrastructure.InfraFactory) {
	var (
		infra infrastructure.DatastoreInfra
		tc    infrastructure.TopologyContainers
	)

	felixReady := func() int {
		return healthStatus(tc.Felixes[0].IP, "9099", "readiness")
	}

	nftTable := func(table string) string {
		out, err := tc.Felixes[0].ExecOutput("nft", "list", "table", "ip", table)
		Expect(err).NotTo(HaveOccurred())
		return out
	}

	BeforeEach(func() {
		if !NFTMode() {
			Skip("This cleanup only runs in nftables mode.")
		}

		infra = getInfra()
		opts := infrastructure.DefaultTopologyOptions()
		tc, _ = infrastructure.StartSingleNodeTopology(opts, infra)
		infra.AddDefaultAllow()

		Eventually(felixReady, "10s", "200ms").Should(BeGood())

		for _, f := range []struct{ src, dst string }{
			{"cali-iptables-dump.txt", "/iptables-dump.txt"},
			{"foreign-nft-dump.txt", "/foreign-nft-dump.txt"},
		} {
			Expect(tc.Felixes[0].CopyFileIntoContainer(f.src, f.dst)).To(Succeed())
		}

		// Leftovers from a previous Felix first: iptables-nft-restore can't touch the tables once
		// the foreign rules are in.
		Eventually(func() error {
			return tc.Felixes[0].ExecMayFail("iptables-nft-restore", "--noflush", "/iptables-dump.txt")
		}, "5s", "100ms").ShouldNot(HaveOccurred())
		Expect(tc.Felixes[0].ExecMayFail("nft", "-f", "/foreign-nft-dump.txt")).To(Succeed())
	})

	AfterEach(func() {
		if CurrentSpecReport().Failed() && len(tc.Felixes) > 0 {
			logNFTDiags(tc.Felixes[0])
			tc.Felixes[0].Exec("iptables-nft-save")
		}
		tc.Stop()
		if infra != nil {
			infra.Stop()
		}
	})

	It("cleans up the iptables rules and leaves the foreign ones alone", func() {
		// Confirm we've reproduced the conditions for the bug: iptables-nft reports the unreadable
		// table on stdout and exits 0, so otherwise this would pass on a readable ruleset.
		out, err := tc.Felixes[0].ExecOutput("iptables-nft-save", "-t", "filter")
		Expect(err).NotTo(HaveOccurred())
		Expect(out).To(ContainSubstring("is incompatible, use 'nft' tool"),
			"foreign ruleset did not make the filter table unreadable to iptables-nft")

		// Restart so the cleanup pass runs at startup: the path that used to panic-loop.
		tc.Felixes[0].Restart()
		Eventually(felixReady, "20s", "200ms").Should(BeGood())
		Consistently(felixReady, "10s", "500ms").Should(BeGood())

		// Felix programs its own table, and our old iptables rules go from the shared ones.
		Eventually(func() string { return nftTable("calico") }, "10s", "500ms").Should(ContainSubstring("cali-"))
		Eventually(func() string { return nftTable("filter") }, "20s", "500ms").ShouldNot(ContainSubstring("cali-"))

		// Everyone else's rules survive, including their own mark rules.
		Expect(nftTable("filter")).To(And(
			ContainSubstring("chain ts-input"),
			ContainSubstring("chain ts-forward"),
			ContainSubstring("chain nixos-fw"),
			ContainSubstring("jump ts-input"),
		))
		Expect(nftTable("mangle")).To(And(
			ContainSubstring("chain nixos-fw-rpfilter"),
			ContainSubstring("ct mark set meta mark & 0x0000ff00"),
		))
		Expect(nftTable("nat")).To(And(
			ContainSubstring("chain ts-postrouting"),
			ContainSubstring("chain CNI-HOSTPORT-MASQ"),
			ContainSubstring("masquerade"),
		))
	})
})
