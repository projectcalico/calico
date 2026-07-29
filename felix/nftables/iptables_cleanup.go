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
	"fmt"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"sigs.k8s.io/knftables"

	"github.com/projectcalico/calico/felix/logutils"
)

var iptablesTables = []string{"filter", "nat", "mangle", "raw"}

// ruleHashPrefix mirrors rules.RuleHashPrefix; we can't import felix/rules, it imports us.
const ruleHashPrefix = "cali:"

// IPTablesCleanup removes what an iptables-mode Felix left in the standard filter/nat/mangle/raw
// tables of one IP family. Those are nftables tables too, since iptables-nft writes there.
//
// We read them over netlink, not with iptables-nft-save: that refuses to read a table holding
// anything iptables can't express, which crash-looped Felix next to Tailscale (#13263).
type IPTablesCleanup struct {
	ipVersion uint8
	family    knftables.Family

	// chainPrefixes are the prefixes Felix has used for its chain names.
	chainPrefixes []string

	newDataplane NewNftablesDataplaneFn

	// readTables reads back whichever of the given tables exist; tests inject a fake.
	readTables func(family knftables.Family, tables []string) (map[string]*iptablesTableState, error)

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
// version.
func NewIPTablesCleanup(
	ipVersion uint8,
	chainPrefixes []string,
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
		newDataplane:    newDataplane,
		readTables:      readTablesViaNetlink,
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

	wanted := make([]string, 0, len(c.pending))
	for table := range c.pending {
		wanted = append(wanted, table)
	}
	states, err := c.readTables(c.family, wanted)
	if err != nil {
		logrus.WithError(err).WithField("family", c.family).Warn("Failed to read nftables tables; will retry iptables cleanup")
		return c.refreshInterval
	}

	for table := range c.pending {
		c.onStillAlive()

		state, ok := states[table]
		if !ok {
			// No such table, so no previous Felix ever wrote here.
			delete(c.pending, table)
			continue
		}

		clean, err := c.sweepTable(table, state)
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

// sweepTable removes our state from one table, reporting whether the table held none of it.
func (c *IPTablesCleanup) sweepTable(table string, state *iptablesTableState) (bool, error) {
	ourChains, ourRuleHandles := c.ourState(state)
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
			handle := int(h)
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

// ourState picks out the chains and rules a previous iptables-mode Felix wrote: chains by name,
// rules by the hash comment the iptables Table puts on every rule it manages.
func (c *IPTablesCleanup) ourState(state *iptablesTableState) ([]string, map[string][]uint64) {
	ourChains := []string{}
	isOurChain := map[string]bool{}
	for _, ch := range state.Chains {
		if hasAnyPrefix(ch.Name, c.chainPrefixes) {
			ourChains = append(ourChains, ch.Name)
			isOurChain[ch.Name] = true
		}
	}

	handles := map[string][]uint64{}
	for _, r := range state.Rules {
		if isOurChain[r.Chain] {
			// Goes when the chain does.
			continue
		}
		if strings.HasPrefix(r.Comment, ruleHashPrefix) || hasAnyPrefix(r.JumpTarget, c.chainPrefixes) {
			handles[r.Chain] = append(handles[r.Chain], r.Handle)
		}
	}
	return ourChains, handles
}

// iptablesTableState is one table as we read it back. Exported fields so tests can load captured
// state from testdata.
type iptablesTableState struct {
	Chains []iptablesChain `json:"chains"`
	Rules  []iptablesRule  `json:"rules"`
}

type iptablesChain struct {
	Name string `json:"name"`
}

type iptablesRule struct {
	Chain  string `json:"chain"`
	Handle uint64 `json:"handle"`

	// Comment holds the rule hash for our rules.
	Comment string `json:"comment,omitempty"`

	// JumpTarget is the chain this rule jumps or gotos to, or "".
	JumpTarget string `json:"jumpTarget,omitempty"`
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}
