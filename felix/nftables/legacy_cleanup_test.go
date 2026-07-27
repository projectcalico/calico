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

package nftables_test

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"sigs.k8s.io/knftables"

	"github.com/projectcalico/calico/felix/nftables"
	"github.com/projectcalico/calico/felix/rules"
)

var _ = Describe("Legacy iptables cleanup via the nft view", func() {
	var fakes map[string]*fakeNFT

	newDataplane := func(fam knftables.Family, name string, _ ...knftables.Option) (knftables.Interface, error) {
		key := string(fam) + "/" + name
		if f, ok := fakes[key]; ok {
			return f, nil
		}
		f := NewFake(fam, name)
		fakes[key] = f
		return f, nil
	}

	// seed builds the given table with a base chain that holds one of our jump rules plus a
	// foreign jump, our own chain, a historic-prefix chain, and a foreign chain that must survive.
	seed := func(table, baseChain string, hook knftables.BaseChainHook) {
		f, err := newDataplane(knftables.IPv4Family, table)
		Expect(err).NotTo(HaveOccurred())
		tx := f.NewTransaction()
		tx.Add(&knftables.Table{})
		tx.Add(&knftables.Chain{
			Name:     baseChain,
			Type:     ptr(knftables.FilterType),
			Hook:     ptr(hook),
			Priority: ptr(knftables.FilterPriority),
		})
		tx.Add(&knftables.Chain{Name: "KUBE-FIREWALL"})
		tx.Add(&knftables.Chain{Name: "cali-" + baseChain})
		tx.Add(&knftables.Chain{Name: "califw-abcd1234"})
		tx.Add(&knftables.Rule{Chain: baseChain, Rule: "jump cali-" + baseChain, Comment: ptr("cali:hashCali")})
		tx.Add(&knftables.Rule{Chain: baseChain, Rule: "jump KUBE-FIREWALL"})
		tx.Add(&knftables.Rule{Chain: "cali-" + baseChain, Rule: "accept", Comment: ptr("cali:hashAccept")})
		tx.Add(&knftables.Rule{Chain: "KUBE-FIREWALL", Rule: "drop"})
		Expect(f.Run(context.Background(), tx)).NotTo(HaveOccurred())
	}

	BeforeEach(func() {
		fakes = map[string]*fakeNFT{}
	})

	newCleanup := func() *nftables.LegacyIPTablesCleanup {
		return nftables.NewLegacyIPTablesCleanup(4, rules.RuleHashPrefix, rules.AllHistoricChainNamePrefixes,
			nftables.TableOptions{NewDataplane: newDataplane})
	}

	It("removes our chains and jumps while leaving foreign rules untouched", func() {
		seed("filter", "INPUT", knftables.InputHook)
		seed("nat", "POSTROUTING", knftables.PostroutingHook)

		newCleanup().CleanUp()

		for _, table := range []string{"filter", "nat"} {
			dump := fakes["ip/"+table].Fake().Dump()

			// Our chains and the jump into them are gone (no trace of "cali" left).
			Expect(dump).NotTo(ContainSubstring("cali"), "table %s still has one of our chains/rules", table)

			// The foreign chain and the base chain that jumps to it both survive.
			Expect(dump).To(ContainSubstring("chain ip "+table+" KUBE-FIREWALL"), "table %s dropped the foreign chain", table)
			Expect(dump).To(ContainSubstring("jump KUBE-FIREWALL"), "table %s dropped the foreign jump", table)
		}
	})

	It("is a no-op when a table was never written to", func() {
		Expect(func() {
			newCleanup().CleanUp()
		}).NotTo(Panic())
	})

	It("stops reading the dataplane once a pass comes back clean", func() {
		seed("filter", "INPUT", knftables.InputHook)
		c := newCleanup()

		// First pass deletes our state, the second confirms it stuck. With no refresh interval
		// configured there's nothing to bring us back after that.
		c.CleanUp()
		Expect(c.CleanUp()).To(BeZero())

		seed("mangle", "PREROUTING", knftables.PreroutingHook)
		Expect(c.CleanUp()).To(BeZero())
		Expect(fakes["ip/mangle"].Fake().Dump()).To(ContainSubstring("cali"))
	})
})
