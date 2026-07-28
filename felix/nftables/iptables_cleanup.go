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
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"sigs.k8s.io/knftables"

	"github.com/projectcalico/calico/felix/iptables/cmdshim"
	"github.com/projectcalico/calico/felix/logutils"
)

var iptablesTables = []string{"filter", "nat", "mangle", "raw"}

// IPTablesCleanup removes what an iptables-mode Felix left in the standard filter/nat/mangle/raw
// tables of one IP family. Those are nftables tables too, since iptables-nft writes there.
//
// We read the tables with nft rather than iptables-nft-save, because iptables-nft-save refuses to
// read a table holding anything iptables can't express, which is what made Felix crash-loop next
// to Tailscale (#13263). The catch is that nft can't decode the comments holding our rule hashes,
// so we identify our own state structurally instead - see ourState.
type IPTablesCleanup struct {
	ipVersion uint8
	family    knftables.Family

	chainPrefixes []string
	markMask      uint32

	newDataplane NewNftablesDataplaneFn
	newCmd       cmdshim.CmdFactory

	// pending holds the tables we have yet to see a clean pass on, so cleanup finishes instead of
	// reading the dataplane forever.
	pending map[string]bool

	refreshInterval time.Duration
	lastSweep       time.Time
	timeNow         func() time.Time
	onStillAlive    func()
	opReporter      logutils.OpRecorder
}

// NewIPTablesCleanup returns a cleanup pass over the shared nftables tables for the given IP
// version. markMask should be the widest mark mask Felix reserves, since the rules were written by
// a Felix that may have been configured differently to this one.
func NewIPTablesCleanup(
	ipVersion uint8,
	chainPrefixes []string,
	markMask uint32,
	options TableOptions,
) *IPTablesCleanup {
	family := knftables.IPv4Family
	if ipVersion == 6 {
		family = knftables.IPv6Family
	}

	newDataplane := options.NewDataplane
	if newDataplane == nil {
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
	for _, t := range iptablesTables {
		pending[t] = true
	}

	return &IPTablesCleanup{
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

func (c *IPTablesCleanup) Name() string {
	return "iptables"
}

func (c *IPTablesCleanup) IPVersion() uint8 {
	return c.ipVersion
}

// Done reports whether every table has come back clean.
func (c *IPTablesCleanup) Done() bool {
	return len(c.pending) == 0
}

// CleanUp makes one pass over the tables we haven't yet seen clean, rate limited to one pass per
// refresh interval. A table that errors out is retried.
func (c *IPTablesCleanup) CleanUp() (rescheduleAfter time.Duration) {
	if c.Done() {
		return 0
	}

	now := c.timeNow()
	if sinceLast := now.Sub(c.lastSweep); !c.lastSweep.IsZero() && sinceLast < c.refreshInterval {
		return c.refreshInterval - sinceLast
	}
	c.lastSweep = now

	// Asking which tables exist up front saves us telling "no such table" apart from a real read
	// failure below.
	present, err := c.listTables()
	if err != nil {
		logrus.WithError(err).WithField("family", c.family).Warn(
			"Failed to list nftables tables; will retry iptables cleanup")
		return c.refreshInterval
	}

	for table := range c.pending {
		c.onStillAlive()

		if !present[table] {
			delete(c.pending, table)
			continue
		}

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
		logrus.WithField("family", c.family).Debug("No iptables state left to clean up")
		return 0
	}
	return c.refreshInterval
}

// sweepTable removes our state from one table, reporting whether the table came back without any.
func (c *IPTablesCleanup) sweepTable(table string) (bool, error) {
	raw, err := c.listTable(table)
	if err != nil {
		return false, err
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

	// Delete our rules from other people's chains first, so our own chains stop being referenced.
	for chain, handles := range ourRuleHandles {
		for _, h := range handles {
			handle := h
			tx.Delete(&knftables.Rule{Chain: chain, Handle: &handle})
		}
	}
	// Flush all of our chains before deleting any: they jump to each other, and deleting as we go
	// would hit a chain a later one still references, losing the whole transaction.
	for _, name := range ourChains {
		tx.Flush(&knftables.Chain{Name: name})
	}
	for _, name := range ourChains {
		tx.Delete(&knftables.Chain{Name: name})
	}

	if c.opReporter != nil {
		c.opReporter.RecordOperation(fmt.Sprintf("cleanup-iptables-%s-v%d", table, c.ipVersion))
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()
	if err := nft.Run(ctx, tx); err != nil {
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

// ourState picks out the chains and rules a previous iptables-mode Felix wrote. Chains are matched
// by prefix; rules in other people's chains take one of three signals, since our rule hashes are
// invisible here:
//
//   - a jump or goto into one of our chains
//   - a match on mark bits inside the mask Felix owns
//   - an opaque MARK target, but only in a chain where we found one of our own jumps. A judgement
//     call: leaving a rule that sets our accept mark on every packet is worse than the chance of
//     removing someone else's MARK rule from a chain we had hooked.
//
// The last two also require an iptables comment match, which all of our rules carry and no
// natively-programmed nft rule does.
func (c *IPTablesCleanup) ourState(chains []nftChain, rules []nftRule) ([]string, map[string][]int) {
	ourChains := []string{}
	isOurChain := map[string]bool{}
	for _, ch := range chains {
		if hasAnyPrefix(ch.Name, c.chainPrefixes) {
			ourChains = append(ourChains, ch.Name)
			isOurChain[ch.Name] = true
		}
	}

	// First pass: the unambiguous signals, which also tell us which chains we had hooked.
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
		case !r.hasXT("match", "comment"):
			// Not written by iptables at all, so not ours.
		case r.matchesMarkWithin(c.markMask):
			handles[r.Chain] = append(handles[r.Chain], *r.Handle)
		case r.hasXT("target", "MARK"):
			undecided = append(undecided, r)
		}
	}

	// Second pass: opaque MARK targets, in chains we had hooked.
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

// listTables returns the names of the tables that exist in our family.
func (c *IPTablesCleanup) listTables() (map[string]bool, error) {
	out, err := c.runNFT("--json", "list", "tables", string(c.family))
	if err != nil {
		return nil, err
	}

	var doc struct {
		Nftables []struct {
			Table *struct {
				Name string `json:"name"`
			} `json:"table"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		return nil, fmt.Errorf("parse nft table list: %w", err)
	}

	tables := map[string]bool{}
	for _, obj := range doc.Nftables {
		if obj.Table != nil {
			tables[obj.Table.Name] = true
		}
	}
	return tables, nil
}

// listTable returns the raw `nft --json` output for one table.
func (c *IPTablesCleanup) listTable(table string) ([]byte, error) {
	out, err := c.runNFT("--json", "list", "table", string(c.family), table)
	if err != nil {
		return nil, fmt.Errorf("list table %s: %w", table, err)
	}
	return out, nil
}

// runNFT runs one nft command, folding its stderr into the error: Output() keeps it out of
// err.Error(), and nft says everything useful there.
func (c *IPTablesCleanup) runNFT(args ...string) ([]byte, error) {
	out, err := c.newCmd("nft", args...).Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && len(exitErr.Stderr) > 0 {
			return nil, fmt.Errorf("%w: %s", err, strings.TrimSpace(string(exitErr.Stderr)))
		}
		return nil, err
	}
	return out, nil
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

// matchesMarkWithin reports whether the rule tests mark bits that all fall inside the given mask.
// nft renders such a match as {"&": [{"meta": {"key": "mark"}}, <mask>]}.
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

// hasXT reports whether the rule uses the named iptables extension, e.g. ("target", "MARK"). nft
// can't decode the payload, so type and name are all we get.
func (r nftRule) hasXT(xtType, name string) bool {
	for _, e := range r.Expr {
		v, ok := e["xt"]
		if !ok {
			continue
		}
		var xt struct {
			Type string `json:"type"`
			Name string `json:"name"`
		}
		if err := json.Unmarshal(v, &xt); err == nil && xt.Type == xtType && xt.Name == name {
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
