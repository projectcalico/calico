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
	"fmt"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"sigs.k8s.io/knftables"

	"github.com/projectcalico/calico/felix/iptables/cmdshim"
	"github.com/projectcalico/calico/felix/logutils"
)

// legacyIPTablesTables are the standard tables a previous iptables-mode Felix would have
// written into. In nftables mode we sweep our chains and rules back out of them.
var legacyIPTablesTables = []string{"filter", "nat", "mangle", "raw"}

// LegacyIPTablesCleanup removes what a previous iptables-mode Felix left in the standard
// filter/nat/mangle/raw tables of one IP family, for a Felix that was using the nft backend of
// iptables. (A Felix on the legacy backend wrote to xtables instead, which is a different
// dataplane that nft cannot see; that cleanup goes through iptables-legacy.)
//
// We read these tables with nft rather than iptables-nft-save, because iptables-nft-save
// refuses to read a table holding anything iptables can't express - which is what made Felix
// crash-loop next to Tailscale (#13263). nft has no such trouble, so we can still clean up a
// table another tool has "poisoned".
//
// The catch is that nft can't see the rule comments iptables wrote: iptables stores them as an
// extension blob that nft renders as an opaque `xt` expression with no payload. So we identify
// our own state structurally instead - see ourRules.
type LegacyIPTablesCleanup struct {
	ipVersion uint8
	family    knftables.Family

	// chainPrefixes are the chain name prefixes Felix has used over the years, and markMask is
	// the mark bitmask Felix owns. Together they're enough to recognise our own state without
	// the rule comments.
	chainPrefixes []string
	markMask      uint32

	newDataplane NewNftablesDataplaneFn
	newCmd       cmdshim.CmdFactory

	// pending holds the tables we have yet to see a clean pass on. A table drops out once it
	// comes back with none of our state in it, so cleanup finishes instead of reading the
	// dataplane forever. Leftovers can only be written by a previous Felix process, so a table
	// that is clean once stays clean.
	pending map[string]bool

	refreshInterval time.Duration
	lastSweep       time.Time
	timeNow         func() time.Time
	onStillAlive    func()
	opReporter      logutils.OpRecorder
}

// NewLegacyIPTablesCleanup returns a cleanup pass over the shared nftables tables for the given
// IP version. markMask should be Felix's iptables mark mask.
func NewLegacyIPTablesCleanup(
	ipVersion uint8,
	chainPrefixes []string,
	markMask uint32,
	options TableOptions,
) *LegacyIPTablesCleanup {
	family := knftables.IPv4Family
	if ipVersion == 6 {
		family = knftables.IPv6Family
	}

	newDataplane := options.NewDataplane
	if newDataplane == nil {
		// Same convention as NewTable: production leaves this nil and gets the real knftables
		// client, tests inject a fake.
		newDataplane = knftables.New
	}

	newCmd := options.NewCmdOverride
	if newCmd == nil {
		newCmd = cmdshim.NewRealCmd
	}

	timeNow := options.NowOverride
	if timeNow == nil {
		timeNow = time.Now
	}

	onStillAlive := options.OnStillAlive
	if onStillAlive == nil {
		onStillAlive = func() {}
	}

	pending := map[string]bool{}
	for _, t := range legacyIPTablesTables {
		pending[t] = true
	}

	return &LegacyIPTablesCleanup{
		ipVersion:       ipVersion,
		family:          family,
		chainPrefixes:   chainPrefixes,
		markMask:        markMask,
		newDataplane:    newDataplane,
		newCmd:          newCmd,
		pending:         pending,
		refreshInterval: options.RefreshInterval,
		timeNow:         timeNow,
		onStillAlive:    onStillAlive,
		opReporter:      options.OpRecorder,
	}
}

func (c *LegacyIPTablesCleanup) Name() string {
	return "legacy-iptables"
}

func (c *LegacyIPTablesCleanup) IPVersion() uint8 {
	return c.ipVersion
}

// Done reports whether every table has come back clean, so there is nothing left to do.
func (c *LegacyIPTablesCleanup) Done() bool {
	return len(c.pending) == 0
}

// CleanUp makes one pass over the tables we haven't yet seen clean, rate limited to one pass per
// refresh interval. A table that errors out keeps its place in the queue and is retried.
func (c *LegacyIPTablesCleanup) CleanUp() (rescheduleAfter time.Duration) {
	if c.Done() {
		return 0
	}

	now := c.timeNow()
	if sinceLast := now.Sub(c.lastSweep); !c.lastSweep.IsZero() && sinceLast < c.refreshInterval {
		return c.refreshInterval - sinceLast
	}
	c.lastSweep = now

	for table := range c.pending {
		c.onStillAlive()

		clean, err := c.sweepTable(table)
		if err != nil {
			logrus.WithError(err).WithFields(logrus.Fields{
				"family": c.family,
				"table":  table,
			}).Warn("Failed to clean up rules left by a previous iptables-mode Felix; will retry")
			continue
		}
		if clean {
			delete(c.pending, table)
		}
	}

	if c.Done() {
		logrus.WithField("family", c.family).Debug("No legacy iptables state left to clean up")
		return 0
	}
	return c.refreshInterval
}

// sweepTable removes our state from one table, reporting whether the table came back without any.
func (c *LegacyIPTablesCleanup) sweepTable(table string) (bool, error) {
	raw, absent, err := c.listTable(table)
	if err != nil {
		return false, err
	}
	if absent {
		// No such table, so no previous Felix ever wrote here.
		return true, nil
	}

	chains, rules, err := parseNFTTable(raw)
	if err != nil {
		return false, fmt.Errorf("parse nft output for %s: %w", table, err)
	}

	ourChains, ourRuleHandles := c.ourState(chains, rules)
	if len(ourChains) == 0 && len(ourRuleHandles) == 0 {
		return true, nil
	}

	nft, err := c.newDataplane(c.family, table)
	if err != nil {
		return false, fmt.Errorf("create nft client: %w", err)
	}
	tx := nft.NewTransaction()

	// Delete our rules out of chains belonging to others first, so that our own chains stop
	// being referenced and become deletable. Rules inside our own chains go with the chain.
	for chain, handles := range ourRuleHandles {
		for _, h := range handles {
			handle := h
			tx.Delete(&knftables.Rule{Chain: chain, Handle: &handle})
		}
	}
	// Flush every one of our chains before deleting any of them. Our chains jump to each other,
	// and nft applies a transaction in order, so deleting as we go would hit a chain that a later
	// one still references ("Device or resource busy") and lose the whole transaction.
	for _, name := range ourChains {
		tx.Flush(&knftables.Chain{Name: name})
	}
	for _, name := range ourChains {
		tx.Delete(&knftables.Chain{Name: name})
	}

	if c.opReporter != nil {
		c.opReporter.RecordOperation(fmt.Sprintf("cleanup-legacy-%s-v%d", table, c.ipVersion))
	}
	if err := nft.Run(context.Background(), tx); err != nil {
		return false, fmt.Errorf("apply cleanup transaction: %w", err)
	}

	logrus.WithFields(logrus.Fields{
		"family": c.family,
		"table":  table,
		"chains": len(ourChains),
	}).Info("Cleaned up rules left behind by a previous iptables-mode Felix")

	// Read the table again on the next pass to confirm the deletes stuck.
	return false, nil
}

// ourState picks out the chains and rules that a previous iptables-mode Felix wrote.
//
// Chains are easy: we have always prefixed them. Rules in chains belonging to others (the base
// chains) take three signals, because the comment holding our rule hash is invisible here:
//
//   - a jump or goto into one of our chains
//   - a match on mark bits inside the mask Felix owns, which nothing else on the host uses
//   - an opaque MARK target, but only in a base chain where we found one of our own jumps.
//     iptables renders no payload for its own targets, so this last one is a judgement call:
//     Felix writes its mark rules alongside its jump, and leaving a stray rule that sets our
//     accept mark on every packet is worse than the small chance of removing a MARK rule that
//     belonged to someone else who was also using the chain we had hooked.
func (c *LegacyIPTablesCleanup) ourState(chains []nftChain, rules []nftRule) ([]string, map[string][]int) {
	ourChains := []string{}
	isOurChain := map[string]bool{}
	for _, ch := range chains {
		if hasAnyPrefix(ch.Name, c.chainPrefixes) {
			ourChains = append(ourChains, ch.Name)
			isOurChain[ch.Name] = true
		}
	}

	// First pass: the unambiguous signals, which also tell us which foreign chains we had
	// hooked into.
	handles := map[string][]int{}
	hookedChains := map[string]bool{}
	var undecided []nftRule
	for _, r := range rules {
		if isOurChain[r.Chain] || r.Handle == nil {
			continue
		}
		switch {
		case hasAnyPrefix(r.jumpTarget(), c.chainPrefixes):
			hookedChains[r.Chain] = true
			handles[r.Chain] = append(handles[r.Chain], *r.Handle)
		case r.matchesMarkWithin(c.markMask):
			handles[r.Chain] = append(handles[r.Chain], *r.Handle)
		case r.hasXTTarget("MARK"):
			undecided = append(undecided, r)
		}
	}

	// Second pass: opaque MARK targets, in chains we know we had hooked.
	for _, r := range undecided {
		if hookedChains[r.Chain] {
			handles[r.Chain] = append(handles[r.Chain], *r.Handle)
		} else {
			logrus.WithFields(logrus.Fields{
				"chain":  r.Chain,
				"handle": *r.Handle,
			}).Debug("Leaving MARK rule alone: no Calico jump in this chain, so it isn't ours")
		}
	}

	return ourChains, handles
}

// listTable returns the raw `nft --json` output for one table, reporting separately when the
// table doesn't exist.
func (c *LegacyIPTablesCleanup) listTable(table string) (raw []byte, absent bool, err error) {
	cmd := c.newCmd("nft", "--json", "list", "table", string(c.family), table)
	out, err := cmd.Output()
	if err != nil {
		// nft says this on a table that was never created, which is the common case.
		if strings.Contains(err.Error(), "No such file or directory") ||
			strings.Contains(string(out), "No such file or directory") {
			return nil, true, nil
		}
		return nil, false, fmt.Errorf("list table %s: %w", table, err)
	}
	return out, false, nil
}

// nftChain and nftRule are the parts of nft's JSON output we care about.
type nftChain struct {
	Name string `json:"name"`
}

type nftRule struct {
	Chain  string                       `json:"chain"`
	Handle *int                         `json:"handle"`
	Expr   []map[string]json.RawMessage `json:"expr"`
}

func parseNFTTable(raw []byte) ([]nftChain, []nftRule, error) {
	var doc struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, nil, err
	}

	var chains []nftChain
	var rules []nftRule
	for _, obj := range doc.Nftables {
		if v, ok := obj["chain"]; ok {
			var ch nftChain
			if err := json.Unmarshal(v, &ch); err != nil {
				return nil, nil, err
			}
			chains = append(chains, ch)
		}
		if v, ok := obj["rule"]; ok {
			var r nftRule
			if err := json.Unmarshal(v, &r); err != nil {
				return nil, nil, err
			}
			rules = append(rules, r)
		}
	}
	return chains, rules, nil
}

// jumpTarget returns the chain this rule jumps or gotos to, or "".
func (r nftRule) jumpTarget() string {
	for _, e := range r.Expr {
		for _, key := range []string{"jump", "goto"} {
			v, ok := e[key]
			if !ok {
				continue
			}
			var verdict struct {
				Target string `json:"target"`
			}
			if err := json.Unmarshal(v, &verdict); err == nil {
				return verdict.Target
			}
		}
	}
	return ""
}

// matchesMarkWithin reports whether the rule tests packet mark bits, all of which fall inside
// the given mask. nft renders such a match as {"&": [{"meta": {"key": "mark"}}, <mask>]}.
func (r nftRule) matchesMarkWithin(mask uint32) bool {
	for _, e := range r.Expr {
		v, ok := e["match"]
		if !ok {
			continue
		}
		var m struct {
			Left struct {
				And []json.RawMessage `json:"&"`
			} `json:"left"`
		}
		if err := json.Unmarshal(v, &m); err != nil || len(m.Left.And) != 2 {
			continue
		}
		var meta struct {
			Meta struct {
				Key string `json:"key"`
			} `json:"meta"`
		}
		if err := json.Unmarshal(m.Left.And[0], &meta); err != nil || meta.Meta.Key != "mark" {
			continue
		}
		var ruleMask uint32
		if err := json.Unmarshal(m.Left.And[1], &ruleMask); err != nil {
			continue
		}
		if ruleMask != 0 && ruleMask&^mask == 0 {
			return true
		}
	}
	return false
}

// hasXTTarget reports whether the rule uses the named iptables target extension. nft can't
// decode the target's payload, so the name is all we get.
func (r nftRule) hasXTTarget(name string) bool {
	for _, e := range r.Expr {
		v, ok := e["xt"]
		if !ok {
			continue
		}
		var xt struct {
			Type string `json:"type"`
			Name string `json:"name"`
		}
		if err := json.Unmarshal(v, &xt); err == nil && xt.Type == "target" && xt.Name == name {
			return true
		}
	}
	return false
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}
