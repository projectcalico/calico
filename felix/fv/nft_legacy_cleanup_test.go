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

// This test reproduces calico #13263: in nftables mode, a foreign tool (Tailscale,
// kube-proxy, a host firewall) writing native nft rules into the standard filter/nat
// tables used to wedge Felix. The legacy iptables cleanup pass ran iptables-nft-save on
// those tables every apply cycle, and iptables-nft-save aborts with "table is
// incompatible" on any table holding rules it didn't author (e.g. a named-set reference).
// Felix retried, panicked, and restart-looped.
//
// The ruleset below mimics Tailscale: base chains jumping to ts-* chains, plus a named-set
// reference (`ip saddr @ts-hosts`) that iptables-nft-save cannot represent. Felix must stay
// healthy and keep programming its own `ip calico` table, and must leave the foreign chains
// alone.
var _ = infrastructure.DatastoreDescribe("_BPF-SAFE_ nftables legacy cleanup with foreign nft rules", []apiconfig.DatastoreType{apiconfig.EtcdV3}, func(getInfra infrastructure.InfraFactory) {
	var (
		infra infrastructure.DatastoreInfra
		tc    infrastructure.TopologyContainers
	)

	// A Tailscale-like ruleset in the shared filter/nat tables. The named-set reference is
	// what makes iptables-nft-save report the table incompatible.
	foreignRuleset := []byte(`
add table ip filter
add chain ip filter INPUT { type filter hook input priority 0; policy accept; }
add chain ip filter FORWARD { type filter hook forward priority 0; policy accept; }
add chain ip filter ts-input
add chain ip filter ts-forward
add set ip filter ts-hosts { type ipv4_addr; }
add rule ip filter INPUT counter jump ts-input
add rule ip filter FORWARD counter jump ts-forward
add rule ip filter ts-input iifname "tailscale0" accept
add rule ip filter ts-input ip saddr @ts-hosts accept
add rule ip filter ts-forward iifname "tailscale0" accept
add table ip nat
add chain ip nat POSTROUTING { type nat hook postrouting priority 100; policy accept; }
add chain ip nat ts-postrouting
add rule ip nat POSTROUTING counter jump ts-postrouting
add rule ip nat ts-postrouting meta mark and 0x00040000 == 0x00040000 masquerade
`)

	felixReady := func() int {
		return healthStatus(tc.Felixes[0].IP, "9099", "readiness")
	}

	BeforeEach(func() {
		if !NFTMode() {
			Skip("Legacy iptables cleanup only runs in nftables mode.")
		}

		infra = getInfra()
		opts := infrastructure.DefaultTopologyOptions()
		tc, _ = infrastructure.StartSingleNodeTopology(opts, infra)
		infra.AddDefaultAllow()

		// Wait for the initial programming to settle before disturbing the shared tables.
		Eventually(felixReady, "10s", "200ms").Should(BeGood())
	})

	AfterEach(func() {
		if CurrentSpecReport().Failed() {
			logNFTDiags(tc.Felixes[0])
			tc.Felixes[0].Exec("iptables-nft-save")
		}
		tc.Stop()
		infra.Stop()
	})

	It("stays healthy and keeps programming its table", func() {
		// Inject the foreign rules, then restart Felix so the cleanup pass reads the now
		// "incompatible" tables during startup - the exact path that used to panic-loop.
		tc.Felixes[0].ExecWithInput(foreignRuleset, "nft", "-f", "-")
		tc.Felixes[0].Restart()

		// Felix comes back and stays ready despite the foreign nft rules.
		Eventually(felixReady, "20s", "200ms").Should(BeGood())
		Consistently(felixReady, "10s", "500ms").Should(BeGood())

		// It is still programming its own table.
		Eventually(func() string {
			out, _ := tc.Felixes[0].ExecOutput("nft", "list", "table", "ip", "calico")
			return out
		}, "10s", "500ms").Should(ContainSubstring("cali-"))

		// The foreign chains are left untouched.
		out, err := tc.Felixes[0].ExecOutput("nft", "list", "table", "ip", "filter")
		Expect(err).NotTo(HaveOccurred())
		Expect(out).To(And(
			ContainSubstring("chain ts-input"),
			ContainSubstring("chain ts-forward"),
		))
	})
})
