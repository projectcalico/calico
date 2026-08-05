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

//go:build linux

package nftables

import (
	"errors"

	"github.com/google/nftables"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// fakeNftReader stands in for the netlink client, failing the rule dump for one chain.
type fakeNftReader struct {
	tables  []*nftables.Table
	chains  []*nftables.Chain
	failFor string

	rulesRead []string
}

func (f *fakeNftReader) ListTablesOfFamily(nftables.TableFamily) ([]*nftables.Table, error) {
	return f.tables, nil
}

func (f *fakeNftReader) ListChainsOfTableFamily(nftables.TableFamily) ([]*nftables.Chain, error) {
	return f.chains, nil
}

func (f *fakeNftReader) GetRules(table *nftables.Table, chain *nftables.Chain) ([]*nftables.Rule, error) {
	f.rulesRead = append(f.rulesRead, table.Name+"/"+chain.Name)
	if chain.Name == f.failFor {
		return nil, errors.New("netlink dump failed")
	}
	return []*nftables.Rule{{Handle: 7}}, nil
}

var _ = Describe("iptables cleanup, reading the tables over netlink", func() {
	var (
		reader *fakeNftReader
		hook   = nftables.ChainHookInput
		alive  int
	)

	BeforeEach(func() {
		alive = 0
		filter := &nftables.Table{Name: "filter"}
		nat := &nftables.Table{Name: "nat"}
		reader = &fakeNftReader{
			tables: []*nftables.Table{filter, nat, {Name: "calico"}},
			chains: []*nftables.Chain{
				{Name: "INPUT", Table: filter, Hooknum: hook},
				{Name: "cali-INPUT", Table: filter},
				{Name: "POSTROUTING", Table: nat, Hooknum: hook},
			},
		}
	})

	read := func() (map[string]*iptablesTableState, error) {
		return readTablesFrom(reader, nftables.TableFamilyIPv4, iptablesTables, func() { alive++ })
	}

	It("reads rules from the base chains only", func() {
		states, err := read()
		Expect(err).NotTo(HaveOccurred())

		Expect(states).To(HaveKey("filter"))
		Expect(states).To(HaveKey("nat"))
		Expect(states).NotTo(HaveKey("calico"), "table we were not asked for")
		Expect(reader.rulesRead).To(ConsistOf("filter/INPUT", "nat/POSTROUTING"))
		Expect(states["filter"].Chains).To(HaveLen(2))
	})

	It("reports still-alive once per base chain", func() {
		_, err := read()
		Expect(err).NotTo(HaveOccurred())
		Expect(alive).To(Equal(2))
	})

	// One bad dump used to abort the pass, leaving every table unswept until the next refresh.
	It("drops only the table whose rules it can't read", func() {
		reader.failFor = "INPUT"

		states, err := read()
		Expect(err).NotTo(HaveOccurred())
		Expect(states).NotTo(HaveKey("filter"))
		Expect(states).To(HaveKey("nat"))
		Expect(states["nat"].Rules).To(HaveLen(1))
	})
})
