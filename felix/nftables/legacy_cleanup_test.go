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
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/iptables/cmdshim"
)

// Copy of rules.AllHistoricChainNamePrefixes; felix/rules imports this package, so importing it
// back would be a cycle.
var ourPrefixes = []string{
	"cali-", "califw-", "calitw-", "califh-", "calith-", "calipi-", "calipo-", "felix-",
}

// The testdata files are real `nft --json list table ip <table>` output, captured from the ruleset
// attached to #13263 (Tailscale, NixOS firewall, CNI port mapping, kubelet) with the state a
// previous iptables-mode Felix would have left underneath it. Testing against the real encoding
// matters: iptables writes its rule comments as an opaque `xt` blob, so our rule hashes are
// invisible in this view and we have to recognise our own rules structurally.
func loadTestdata(table string) ([]nftChain, []nftRule) {
	raw, err := os.ReadFile("testdata/iptables_nft_" + table + "_table.json")
	Expect(err).NotTo(HaveOccurred())
	chains, rules, err := parseNFTTable(raw)
	Expect(err).NotTo(HaveOccurred())
	return chains, rules
}

var _ = Describe("Legacy iptables cleanup, identifying our own state", func() {
	const markMask = 0xffff0000

	var cleanup *LegacyIPTablesCleanup

	BeforeEach(func() {
		cleanup = NewLegacyIPTablesCleanup(4, ourPrefixes, markMask, TableOptions{})
	})

	Describe("filter table", func() {
		var chains []nftChain
		var rules []nftRule

		BeforeEach(func() {
			chains, rules = loadTestdata("filter")
		})

		It("parses the real nft output", func() {
			Expect(chains).To(HaveLen(22))
			Expect(rules).NotTo(BeEmpty())
		})

		It("claims every chain of ours and none of anyone else's", func() {
			ourChains, _ := cleanup.ourState(chains, rules)
			Expect(ourChains).To(HaveLen(11))
			Expect(ourChains).To(ContainElement("cali-FORWARD"))
			Expect(ourChains).NotTo(ContainElement("ts-input"))
			Expect(ourChains).NotTo(ContainElement("nixos-fw"))
			Expect(ourChains).NotTo(ContainElement("FORWARD"))
		})

		It("claims our rules in the base chains, by all three signals", func() {
			_, handles := cleanup.ourState(chains, rules)

			// 15/16/19 are jumps into our chains, 17 matches our accept mark, 18 is an opaque MARK
			// target in a chain we had hooked.
			Expect(handles).To(Equal(map[string][]int{
				"INPUT":   {15},
				"FORWARD": {16, 17, 18},
				"OUTPUT":  {19},
			}))
		})

		It("leaves the neighbours' rules alone", func() {
			_, handles := cleanup.ourState(chains, rules)

			// 83/84/85 jump to ts-input, KUBE-FIREWALL and nixos-fw; 87/88 likewise.
			Expect(handles["INPUT"]).NotTo(ContainElements(83, 84, 85))
			Expect(handles["OUTPUT"]).NotTo(ContainElement(87))
			Expect(handles["FORWARD"]).NotTo(ContainElement(88))
			Expect(handles).NotTo(HaveKey("ts-input"))
			Expect(handles).NotTo(HaveKey("ts-forward"))
			Expect(handles).NotTo(HaveKey("nixos-fw"))
		})
	})

	Describe("nat table", func() {
		var chains []nftChain
		var rules []nftRule

		BeforeEach(func() {
			chains, rules = loadTestdata("nat")
		})

		It("claims our chains and our jumps, and nothing else", func() {
			ourChains, handles := cleanup.ourState(chains, rules)
			Expect(ourChains).To(HaveLen(6))
			Expect(handles).To(Equal(map[string][]int{
				"PREROUTING":  {11},
				"OUTPUT":      {12},
				"POSTROUTING": {13},
			}))
		})

		It("ignores the neighbours' mark rules", func() {
			// CNI uses 0x2000 and Tailscale 0x400; both fall outside Felix's mask.
			_, handles := cleanup.ourState(chains, rules)
			Expect(handles).NotTo(HaveKey("CNI-HOSTPORT-SETMARK"))
			Expect(handles).NotTo(HaveKey("CNI-HOSTPORT-MASQ"))
			Expect(handles).NotTo(HaveKey("ts-postrouting"))
		})
	})

	It("does not claim a MARK rule in a chain it never hooked", func() {
		raw := []byte(`{"nftables":[
			{"chain":{"family":"ip","table":"filter","name":"INPUT"}},
			{"rule":{"family":"ip","table":"filter","chain":"INPUT","handle":7,
			  "expr":[{"xt":{"type":"target","name":"MARK"}}]}}
		]}`)
		chains, rules, err := parseNFTTable(raw)
		Expect(err).NotTo(HaveOccurred())

		ourChains, handles := cleanup.ourState(chains, rules)
		Expect(ourChains).To(BeEmpty())
		Expect(handles).To(BeEmpty())
	})

	It("ignores a mark match that falls outside our mask", func() {
		raw := []byte(`{"nftables":[
			{"chain":{"family":"ip","table":"filter","name":"INPUT"}},
			{"rule":{"family":"ip","table":"filter","chain":"INPUT","handle":8,
			  "expr":[{"xt":{"type":"match","name":"comment"}},
			          {"match":{"op":"==","left":{"&":[{"meta":{"key":"mark"}},255]},"right":255}}]}}
		]}`)
		chains, rules, err := parseNFTTable(raw)
		Expect(err).NotTo(HaveOccurred())

		_, handles := cleanup.ourState(chains, rules)
		Expect(handles).To(BeEmpty())
	})

	It("ignores mark rules that iptables didn't write", func() {
		// Native nft rules using mark bits inside our mask: ours all carry a comment match, and
		// nothing written natively carries any xt expression.
		raw := []byte(`{"nftables":[
			{"chain":{"family":"ip","table":"filter","name":"INPUT"}},
			{"rule":{"family":"ip","table":"filter","chain":"INPUT","handle":9,
			  "expr":[{"match":{"op":"==","left":{"&":[{"meta":{"key":"mark"}},65536]},"right":65536}},
			          {"accept":null}]}},
			{"rule":{"family":"ip","table":"filter","chain":"INPUT","handle":10,
			  "expr":[{"mangle":{"key":{"meta":{"key":"mark"}},"value":65536}}]}}
		]}`)
		chains, rules, err := parseNFTTable(raw)
		Expect(err).NotTo(HaveOccurred())

		_, handles := cleanup.ourState(chains, rules)
		Expect(handles).To(BeEmpty())
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

	// Stands in for the nft binary. Of our four tables only "filter" exists on this host.
	newCmd := func(name string, args ...string) cmdshim.CmdIface {
		cmds = append(cmds, append([]string{name}, args...))
		if args[2] == "tables" {
			return &fakeCmd{output: []byte(`{"nftables":[
				{"table":{"family":"ip","name":"filter","handle":1}},
				{"table":{"family":"ip","name":"kube-proxy","handle":2}}
			]}`)}
		}
		listed = append(listed, args[len(args)-1])
		return &fakeCmd{err: listErr, output: output}
	}

	BeforeEach(func() {
		listed, cmds, listErr = nil, nil, nil
		// A table with none of our state in it.
		output = []byte(`{"nftables":[
			{"chain":{"family":"ip","table":"filter","name":"ts-input"}},
			{"rule":{"family":"ip","table":"filter","chain":"ts-input","handle":3,"expr":[{"accept":null}]}}
		]}`)
		cleanup = NewLegacyIPTablesCleanup(4, ourPrefixes, 0xffff0000,
			TableOptions{NewCmdOverride: newCmd})
	})

	It("only reads the tables that exist", func() {
		cleanup.CleanUp()
		Expect(listed).To(ConsistOf("filter"))
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
		Expect(listed).To(ConsistOf("filter"))
		Expect(cleanup.Done()).To(BeTrue())
	})

	It("retries the whole pass if it can't even list the tables", func() {
		cleanup = NewLegacyIPTablesCleanup(4, ourPrefixes, 0xffff0000, TableOptions{
			RefreshInterval: time.Second,
			NewCmdOverride: func(name string, args ...string) cmdshim.CmdIface {
				return &fakeCmd{err: errors.New("exit status 1")}
			},
		})
		Expect(cleanup.CleanUp()).To(Equal(time.Second))
		Expect(cleanup.Done()).To(BeFalse())
	})

	It("treats unparseable output as a failure rather than as a clean table", func() {
		output = []byte("this is not json")
		cleanup.CleanUp()
		Expect(cleanup.Done()).To(BeFalse())
	})
})

// fakeCmd stands in for the nft binary, returning canned output.
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
