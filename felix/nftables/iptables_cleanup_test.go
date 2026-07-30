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
	"encoding/json"
	"errors"
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"sigs.k8s.io/knftables"
)

// Copy of rules.AllHistoricChainNamePrefixes; felix/rules imports this package, so importing it
// back would be a cycle.
var ourPrefixes = []string{
	"cali-", "califw-", "calitw-", "califh-", "calith-", "calipi-", "calipo-", "felix-",
}

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

var _ = Describe("iptables cleanup, identifying our own state", func() {
	var cleanup *IPTablesCleanup

	BeforeEach(func() {
		cleanup = NewIPTablesCleanup(4, ourPrefixes, TableOptions{})
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
})

var _ = Describe("iptables cleanup, deciding when it's finished", func() {
	var (
		read     [][]string
		readErr  error
		contents *iptablesTableState
		cleanup  *IPTablesCleanup
	)

	// Stands in for the netlink read. Of our four tables only "filter" exists on this host.
	readTables := func(family knftables.Family, tables []string) (map[string]*iptablesTableState, error) {
		read = append(read, tables)
		if readErr != nil {
			return nil, readErr
		}
		return map[string]*iptablesTableState{"filter": contents}, nil
	}

	tablesRead := func() []string {
		var all []string
		for _, pass := range read {
			all = append(all, pass...)
		}
		return all
	}

	BeforeEach(func() {
		read, readErr = nil, nil
		// A table with none of our state in it.
		contents = &iptablesTableState{
			Chains: []iptablesChain{{Name: "ts-input"}},
			Rules:  []iptablesRule{{Chain: "ts-input", Handle: 3}},
		}
		cleanup = NewIPTablesCleanup(4, ourPrefixes, TableOptions{})
		cleanup.readTables = readTables
	})

	It("asks for every table it hasn't cleared yet", func() {
		cleanup.CleanUp()
		Expect(tablesRead()).To(ConsistOf("filter", "nat", "mangle", "raw"))
	})

	It("finishes after one pass when there is nothing of ours anywhere", func() {
		Expect(cleanup.CleanUp()).To(BeZero())
		Expect(cleanup.Done()).To(BeTrue())

		read = nil
		Expect(cleanup.CleanUp()).To(BeZero())
		Expect(read).To(BeEmpty())
	})

	It("retries the whole pass if the read fails", func() {
		readErr = errors.New("netlink blew up")
		cleanup = NewIPTablesCleanup(4, ourPrefixes, TableOptions{RefreshInterval: time.Second})
		cleanup.readTables = readTables

		Expect(cleanup.CleanUp()).To(Equal(time.Second))
		Expect(cleanup.Done()).To(BeFalse())
	})

	It("keeps a table that errored, and drops it once the read succeeds", func() {
		readErr = errors.New("netlink blew up")
		cleanup.CleanUp()
		Expect(cleanup.Done()).To(BeFalse())

		readErr = nil
		read = nil
		cleanup.CleanUp()
		Expect(tablesRead()).To(ConsistOf("filter", "nat", "mangle", "raw"))
		Expect(cleanup.Done()).To(BeTrue())
	})
})
