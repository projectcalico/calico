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
	"bytes"
	"errors"
	"io"
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/iptables/cmdshim"
)

// ourPrefixes mirrors rules.AllHistoricChainNamePrefixes, which we cannot import here: felix/rules
// imports this package, so an internal test importing it back would be a cycle.
var ourPrefixes = []string{"cali", "felix-"}

// testdata/iptables_nft_filter_table.json is real `nft --json list table ip filter` output,
// captured from a container after restoring felix/fv/cali-iptables-dump.txt with
// iptables-nft-restore and then adding foreign rules on top of it (including a `ct label` match,
// which is what stops iptables from being able to read the table at all).
//
// Testing against the real encoding matters here, because the parts of it we depend on are not
// what you would guess: iptables writes its rule comments as an extension blob that nft renders
// as an `xt` expression with no payload, so the `cali:` rule hashes are not visible in this view
// and we have to recognise our own rules structurally instead.
var _ = Describe("Legacy iptables cleanup, identifying our own state", func() {
	const markMask = 0xffff0000

	var (
		chains  []nftChain
		parsedRules  []nftRule
		cleanup *LegacyIPTablesCleanup
	)

	BeforeEach(func() {
		raw, err := os.ReadFile("testdata/iptables_nft_filter_table.json")
		Expect(err).NotTo(HaveOccurred())
		chains, parsedRules, err = parseNFTTable(raw)
		Expect(err).NotTo(HaveOccurred())

		cleanup = NewLegacyIPTablesCleanup(4, ourPrefixes, markMask, TableOptions{})
	})

	It("parses the real nft output", func() {
		Expect(chains).To(HaveLen(15), "11 of ours plus INPUT, FORWARD, OUTPUT and ts-input")
		Expect(parsedRules).NotTo(BeEmpty())
	})

	It("claims every chain of ours and none of the other tool's", func() {
		ourChains, _ := cleanup.ourState(chains, parsedRules)
		Expect(ourChains).To(HaveLen(11))
		Expect(ourChains).To(ContainElement("cali-FORWARD"))
		Expect(ourChains).NotTo(ContainElement("ts-input"))
		Expect(ourChains).NotTo(ContainElement("FORWARD"))
	})

	It("claims our rules in the base chains, by all three signals", func() {
		_, handles := cleanup.ourState(chains, parsedRules)

		// 15 and 19 are jumps into our chains. 16 is the jump into cali-FORWARD; 17 matches on
		// our accept mark; 18 is an opaque MARK target in a chain we had hooked, which we take
		// because leaving it would set our accept mark on every forwarded packet.
		Expect(handles).To(Equal(map[string][]int{
			"INPUT":   {15},
			"FORWARD": {16, 17, 18},
			"OUTPUT":  {19},
		}))
	})

	It("leaves the other tool's rules alone", func() {
		_, handles := cleanup.ourState(chains, parsedRules)

		// Handle 43 is the other tool's jump to its own chain, 42 its ct label match. Neither is
		// ours, and we must not touch its chain at all.
		Expect(handles["INPUT"]).NotTo(ContainElement(43))
		Expect(handles).NotTo(HaveKey("ts-input"))
	})

	It("does not claim a MARK rule in a chain it never hooked", func() {
		// Same opaque MARK target, but in a base chain with no jump of ours in it, so we have no
		// reason to believe it's ours.
		raw := []byte(`{"nftables":[
			{"chain":{"family":"ip","table":"filter","name":"INPUT"}},
			{"rule":{"family":"ip","table":"filter","chain":"INPUT","handle":7,
			  "expr":[{"xt":{"type":"target","name":"MARK"}}]}}
		]}`)
		chains, parsedRules, err := parseNFTTable(raw)
		Expect(err).NotTo(HaveOccurred())

		ourChains, handles := cleanup.ourState(chains, parsedRules)
		Expect(ourChains).To(BeEmpty())
		Expect(handles).To(BeEmpty())
	})

	It("ignores a mark match that falls outside our mask", func() {
		raw := []byte(`{"nftables":[
			{"chain":{"family":"ip","table":"filter","name":"INPUT"}},
			{"rule":{"family":"ip","table":"filter","chain":"INPUT","handle":8,
			  "expr":[{"match":{"op":"==","left":{"&":[{"meta":{"key":"mark"}},255]},"right":255}}]}}
		]}`)
		chains, parsedRules, err := parseNFTTable(raw)
		Expect(err).NotTo(HaveOccurred())

		_, handles := cleanup.ourState(chains, parsedRules)
		Expect(handles).To(BeEmpty(), "0xff is outside Felix's mark mask, so that rule isn't ours")
	})
})

var _ = Describe("Legacy iptables cleanup, deciding when it's finished", func() {
	var (
		listed  []string
		cmds    [][]string
		output  []byte
		listErr error
		cleanup *LegacyIPTablesCleanup
	)

	// newCmd stands in for the nft binary: only "filter" exists, and the other tables report
	// what nft says about a table that was never created.
	newCmd := func(name string, args ...string) cmdshim.CmdIface {
		cmds = append(cmds, append([]string{name}, args...))
		table := args[len(args)-1]
		listed = append(listed, table)
		if table != "filter" {
			return &fakeCmd{err: errors.New("exit status 1"), output: []byte("Error: No such file or directory")}
		}
		return &fakeCmd{err: listErr, output: output}
	}

	BeforeEach(func() {
		listed, cmds, listErr = nil, nil, nil
		// A table with none of our state in it, only the other tool's.
		output = []byte(`{"nftables":[
			{"chain":{"family":"ip","table":"filter","name":"ts-input"}},
			{"rule":{"family":"ip","table":"filter","chain":"ts-input","handle":3,"expr":[{"accept":null}]}}
		]}`)
		cleanup = NewLegacyIPTablesCleanup(4, ourPrefixes, 0xffff0000,
			TableOptions{NewCmdOverride: newCmd})
	})

	It("reads only the tables it needs, one at a time", func() {
		cleanup.CleanUp()
		Expect(listed).To(ConsistOf("filter", "nat", "mangle", "raw"))
		for _, cmd := range cmds {
			Expect(cmd[0]).To(Equal("nft"))
			Expect(cmd).To(ContainElement("--json"))
			// Listing the whole ruleset can crash older nft binaries, see #11750.
			Expect(cmd).NotTo(ContainElement("ruleset"))
		}
	})

	It("finishes after one pass when there is nothing of ours anywhere", func() {
		Expect(cleanup.CleanUp()).To(BeZero())
		Expect(cleanup.Done()).To(BeTrue())

		// And it stops touching the dataplane from then on.
		listed = nil
		Expect(cleanup.CleanUp()).To(BeZero())
		Expect(listed).To(BeEmpty())
	})

	It("keeps a table that errored, and drops it once the read succeeds", func() {
		listErr = errors.New("nft blew up")
		cleanup.CleanUp()
		Expect(cleanup.Done()).To(BeFalse())
		Expect(listed).To(ContainElement("filter"))

		listErr = nil
		listed = nil
		cleanup.CleanUp()
		Expect(listed).To(ConsistOf("filter"), "the absent tables were already finished")
		Expect(cleanup.Done()).To(BeTrue())
	})

	It("treats unparseable output as a failure rather than as a clean table", func() {
		output = []byte("this is not json")
		cleanup.CleanUp()
		Expect(cleanup.Done()).To(BeFalse())
	})
})

// fakeCmd is a cmdshim.CmdIface standing in for the nft binary, returning canned output.
type fakeCmd struct {
	output []byte
	err    error
}

func (c *fakeCmd) SetStdin(io.Reader)      {}
func (c *fakeCmd) SetStdout(io.Writer)     {}
func (c *fakeCmd) SetStderr(io.Writer)     {}
func (c *fakeCmd) Run() error              { return c.err }
func (c *fakeCmd) Start() error            { return c.err }
func (c *fakeCmd) Kill() error             { return nil }
func (c *fakeCmd) Wait() error             { return c.err }
func (c *fakeCmd) Output() ([]byte, error) { return c.output, c.err }
func (c *fakeCmd) String() string          { return "fakeCmd" }

func (c *fakeCmd) StdoutPipe() (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(c.output)), c.err
}
