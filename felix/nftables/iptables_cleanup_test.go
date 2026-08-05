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

package nftables

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"sigs.k8s.io/knftables"

	"github.com/projectcalico/calico/felix/rules/rulesdefs"
)

// The testdata files are real netlink reads of the #13263 ruleset (Tailscale, NixOS firewall, CNI
// port mapping, kubelet) over the state a previous iptables-mode Felix would have left, captured
// from felix/fv/cali-iptables-dump.txt plus felix/fv/foreign-nft-dump.txt.
func loadTestdata(table string) *iptablesTableState {
	raw, err := os.ReadFile("testdata/iptables_nft_" + table + "_state.json")
	Expect(err).NotTo(HaveOccurred())
	var state iptablesTableState
	Expect(json.Unmarshal(raw, &state)).To(Succeed())
	return &state
}

// stubDataplane fails to delete one chain, the way nftables does when something still jumps to it.
type stubDataplane struct {
	knftables.Interface

	stuckChain string
}

func (s *stubDataplane) Run(ctx context.Context, tx *knftables.Transaction) error {
	if s.stuckChain != "" && strings.Contains(tx.String(), "delete chain ip filter "+s.stuckChain+"\n") {
		return errors.New("Device or resource busy")
	}
	return s.Interface.Run(ctx, tx)
}

var _ = Describe("iptables cleanup, sweeping a table", func() {
	var (
		ctx      context.Context
		fake     *knftables.Fake
		stub     *stubDataplane
		cleanup  *IPTablesCleanup
		state    *iptablesTableState
		listing  func(string) []string
		ruleText func(string) []string
	)

	BeforeEach(func() {
		ctx = context.Background()
		fake = knftables.NewFake(knftables.IPv4Family, "filter")
		stub = &stubDataplane{Interface: fake}
		cleanup = NewIPTablesCleanup(4, rulesdefs.AllHistoricChainNamePrefixes, TableOptions{
			NewDataplane: func(knftables.Family, string, ...knftables.Option) (knftables.Interface, error) {
				return stub, nil
			},
		})

		// A previous Felix's state: its own chains, jumps into them from INPUT, and a neighbour's
		// rule that has to survive.
		tx := fake.NewTransaction()
		tx.Add(&knftables.Table{})
		tx.Add(&knftables.Chain{Name: "INPUT", Type: knftables.PtrTo(knftables.FilterType), Hook: knftables.PtrTo(knftables.InputHook), Priority: knftables.PtrTo(knftables.FilterPriority)})
		tx.Add(&knftables.Chain{Name: "cali-INPUT"})
		tx.Add(&knftables.Chain{Name: "cali-from-wl"})
		tx.Add(&knftables.Chain{Name: "ts-input"})
		tx.Add(&knftables.Rule{Chain: "INPUT", Rule: "jump cali-INPUT", Comment: knftables.PtrTo(rulesdefs.RuleHashPrefix + "abcdef")})
		tx.Add(&knftables.Rule{Chain: "INPUT", Rule: "jump ts-input"})
		tx.Add(&knftables.Rule{Chain: "cali-INPUT", Rule: "jump cali-from-wl"})
		Expect(fake.Run(ctx, tx)).To(Succeed())

		// Read the handles back so the state matches what a netlink read would have returned.
		inputRules, err := fake.ListRules(ctx, "INPUT")
		Expect(err).NotTo(HaveOccurred())
		state = &iptablesTableState{
			Chains: []iptablesChain{
				{Name: "INPUT", Base: true},
				{Name: "cali-INPUT"},
				{Name: "cali-from-wl"},
				{Name: "ts-input"},
			},
		}
		for _, r := range inputRules {
			rule := iptablesRule{Chain: "INPUT", Handle: uint64(*r.Handle)}
			if r.Comment != nil {
				rule.Comment = *r.Comment
			}
			state.Rules = append(state.Rules, rule)
		}

		listing = func(objectType string) []string {
			out, err := fake.List(ctx, objectType)
			Expect(err).NotTo(HaveOccurred())
			return out
		}
		ruleText = func(chain string) []string {
			rules, err := fake.ListRules(ctx, chain)
			Expect(err).NotTo(HaveOccurred())
			var out []string
			for _, r := range rules {
				out = append(out, r.Rule)
			}
			return out
		}
	})

	It("removes our chains and our jumps, and nothing else", func() {
		Expect(cleanup.sweepTable("filter", state)).To(Succeed())

		Expect(listing("chains")).To(ConsistOf("INPUT", "ts-input"))
		Expect(ruleText("INPUT")).To(ConsistOf("jump ts-input"))
	})

	It("does nothing to a table with none of our state in it", func() {
		Expect(cleanup.sweepTable("filter", &iptablesTableState{
			Chains: []iptablesChain{{Name: "ts-input"}},
		})).To(Succeed())

		Expect(listing("chains")).To(ContainElements("cali-INPUT", "cali-from-wl"))
	})

	// nftables won't delete a chain something still jumps to, and one of those used to take the
	// whole table's cleanup with it.
	It("empties the chains it can't delete and deletes the rest", func() {
		stub.stuckChain = "cali-from-wl"
		Expect(cleanup.sweepTable("filter", state)).To(Succeed())

		Expect(listing("chains")).To(ConsistOf("INPUT", "ts-input", "cali-from-wl"))
		Expect(ruleText("cali-from-wl")).To(BeEmpty())
		Expect(ruleText("INPUT")).To(ConsistOf("jump ts-input"))
	})
})

var _ = Describe("iptables cleanup, identifying our own state", func() {
	var cleanup *IPTablesCleanup

	BeforeEach(func() {
		cleanup = NewIPTablesCleanup(4, rulesdefs.AllHistoricChainNamePrefixes, TableOptions{})
	})

	Describe("filter table", func() {
		var state *iptablesTableState

		BeforeEach(func() {
			state = loadTestdata("filter")
		})

		It("loads the real capture", func() {
			Expect(state.Chains).To(HaveLen(22))
			Expect(state.Rules).NotTo(BeEmpty())
		})

		It("claims every chain of ours and none of anyone else's", func() {
			ourChains, _ := cleanup.ourState(state)
			Expect(ourChains).To(HaveLen(11))
			Expect(ourChains).To(ContainElement("cali-FORWARD"))
			Expect(ourChains).NotTo(ContainElement("ts-input"))
			Expect(ourChains).NotTo(ContainElement("nixos-fw"))
			Expect(ourChains).NotTo(ContainElement("FORWARD"))
		})

		// 17 and 18 are the accept-mark rules, which used to need the mark mask and the MARK
		// target judgement call. Both carry a hash.
		It("claims our rules in the base chains by their hash", func() {
			_, handles := cleanup.ourState(state)
			Expect(handles).To(Equal(map[string][]uint64{
				"INPUT":   {15},
				"FORWARD": {16, 17, 18},
				"OUTPUT":  {19},
			}))
		})

		It("leaves the neighbours' rules alone", func() {
			_, handles := cleanup.ourState(state)

			// 374/375/376 jump to ts-input, KUBE-FIREWALL and nixos-fw; 378/379 likewise.
			Expect(handles["INPUT"]).NotTo(ContainElements(uint64(374), uint64(375), uint64(376)))
			Expect(handles["OUTPUT"]).NotTo(ContainElement(uint64(378)))
			Expect(handles["FORWARD"]).NotTo(ContainElement(uint64(379)))
			Expect(handles).NotTo(HaveKey("ts-input"))
			Expect(handles).NotTo(HaveKey("ts-forward"))
			Expect(handles).NotTo(HaveKey("nixos-fw"))
		})
	})

	Describe("nat table", func() {
		var state *iptablesTableState

		BeforeEach(func() {
			state = loadTestdata("nat")
		})

		It("claims our chains and our jumps, and nothing else", func() {
			ourChains, handles := cleanup.ourState(state)
			Expect(ourChains).To(HaveLen(6))
			Expect(handles).To(Equal(map[string][]uint64{
				"PREROUTING":  {11},
				"OUTPUT":      {12},
				"POSTROUTING": {13},
			}))
		})

		It("ignores the neighbours' mark rules", func() {
			_, handles := cleanup.ourState(state)
			Expect(handles).NotTo(HaveKey("CNI-HOSTPORT-SETMARK"))
			Expect(handles).NotTo(HaveKey("CNI-HOSTPORT-MASQ"))
			Expect(handles).NotTo(HaveKey("ts-postrouting"))
		})
	})

	// Tailscale matches 0x40000/0xff0000, inside Felix's default mask, so the old mark matching
	// claimed it as ours.
	It("ignores another tool's rules whatever mark bits they touch", func() {
		state := &iptablesTableState{
			Chains: []iptablesChain{{Name: "ts-forward"}},
			Rules: []iptablesRule{
				{Chain: "ts-forward", Handle: 9, Comment: "tailscale internal"},
				{Chain: "ts-forward", Handle: 10},
			},
		}
		_, handles := cleanup.ourState(state)
		Expect(handles).To(BeEmpty())
	})

	It("claims a rule that jumps into one of our chains even without a hash", func() {
		state := &iptablesTableState{
			Chains: []iptablesChain{{Name: "INPUT"}},
			Rules:  []iptablesRule{{Chain: "INPUT", Handle: 30, JumpTarget: "cali-INPUT"}},
		}
		_, handles := cleanup.ourState(state)
		Expect(handles).To(HaveKeyWithValue("INPUT", []uint64{30}))
	})

	It("does not claim a rule on the strength of a comment that isn't a hash", func() {
		state := &iptablesTableState{
			Chains: []iptablesChain{{Name: "INPUT"}},
			Rules: []iptablesRule{
				{Chain: "INPUT", Handle: 31, Comment: "calico-ish but not ours"},
				{Chain: "INPUT", Handle: 32, Comment: "cali-INPUT"},
			},
		}
		_, handles := cleanup.ourState(state)
		Expect(handles).To(BeEmpty(), "the hash prefix is cali: with the colon")
	})

	// The netlink read only fetches rules from base chains, so anything we claim in a chain we're
	// not deleting has to live in one. Guards the two halves against drifting apart.
	It("claims rules only in base chains", func() {
		for _, table := range []string{"filter", "nat", "mangle", "raw"} {
			state := loadTestdata(table)
			isBase := map[string]bool{}
			for _, ch := range state.Chains {
				isBase[ch.Name] = ch.Base
			}

			_, handles := cleanup.ourState(state)
			Expect(handles).NotTo(BeEmpty(), "%s capture should hold rules of ours", table)
			for chain := range handles {
				Expect(isBase[chain]).To(BeTrue(), "%s: claimed a rule in non-base chain %s", table, chain)
			}
		}
	})
})

var _ = Describe("iptables cleanup, scheduling its passes", func() {
	var (
		read     [][]string
		readErr  error
		contents *iptablesTableState
		now      time.Time
		cleanup  *IPTablesCleanup
	)

	// Stands in for the netlink read. Of our four tables only "filter" exists on this host.
	readTables := func(family knftables.Family, tables []string, onStillAlive func()) (map[string]*iptablesTableState, error) {
		read = append(read, tables)
		onStillAlive()
		if readErr != nil {
			return nil, readErr
		}
		return map[string]*iptablesTableState{"filter": contents}, nil
	}

	BeforeEach(func() {
		read, readErr = nil, nil
		now = time.Now()
		// A table with none of our state in it.
		contents = &iptablesTableState{
			Chains: []iptablesChain{{Name: "ts-input", Base: true}},
			Rules:  []iptablesRule{{Chain: "ts-input", Handle: 3}},
		}
		cleanup = NewIPTablesCleanup(4, rulesdefs.AllHistoricChainNamePrefixes, TableOptions{
			RefreshInterval: time.Minute,
			NowOverride:     func() time.Time { return now },
		})
		cleanup.readTables = readTables
	})

	It("asks for every table on every pass", func() {
		Expect(cleanup.CleanUp()).To(Equal(time.Minute))
		Expect(read).To(ConsistOf(ConsistOf("filter", "nat", "mangle", "raw")))

		// A clean table doesn't retire: something else can write to it at any point.
		now = now.Add(time.Minute)
		Expect(cleanup.CleanUp()).To(Equal(time.Minute))
		Expect(read).To(HaveLen(2))
	})

	It("waits out the refresh interval between passes", func() {
		cleanup.CleanUp()

		now = now.Add(20 * time.Second)
		Expect(cleanup.CleanUp()).To(Equal(40 * time.Second))
		Expect(read).To(HaveLen(1), "should not have read the dataplane again")
	})

	It("reschedules when the read fails", func() {
		readErr = errors.New("netlink blew up")
		Expect(cleanup.CleanUp()).To(Equal(time.Minute))
	})
})
