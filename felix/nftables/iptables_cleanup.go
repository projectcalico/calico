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

	"github.com/projectcalico/calico/felix/rules/rulesdefs"
	"github.com/projectcalico/calico/lib/logrusr"
)

// defaultSweepInterval paces the sweep when the refresh interval is disabled; it walks every chain
// in the family, so it can't run on every dataplane apply.
const defaultSweepInterval = 180 * time.Second

// IPTablesNFTCleanup removes what an iptables-nft Felix left in the nftables copies of the shared
// tables for one IP family.
//
// We read them over netlink rather than with iptables-nft-save, which refuses to read a table
// holding anything iptables can't express and so crash-looped Felix next to Tailscale (#13263).
type IPTablesNFTCleanup struct {
	ipVersion uint8
	family    knftables.Family

	// chainPrefixes are the prefixes Felix has used for its chain names.
	chainPrefixes []string

	newDataplane NewNftablesDataplaneFn

	// readTables reads back whichever of the given tables exist; tests inject a fake.
	readTables func(family knftables.Family, tables []string, onStillAlive func()) (map[string]*iptablesTableState, error)

	refreshInterval time.Duration
	lastSweep       time.Time
	timeNow         func() time.Time
	onStillAlive    func()
	opReporter      logrusr.OpRecorder
}

// NewIPTablesNFTCleanup returns a cleanup pass over the nftables copies of the shared tables.
func NewIPTablesNFTCleanup(
	ipVersion uint8,
	chainPrefixes []string,
	options TableOptions,
) *IPTablesNFTCleanup {
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

	refreshInterval := options.RefreshInterval
	if refreshInterval <= 0 {
		refreshInterval = defaultSweepInterval
	}

	return &IPTablesNFTCleanup{
		ipVersion:       ipVersion,
		family:          family,
		chainPrefixes:   chainPrefixes,
		newDataplane:    newDataplane,
		readTables:      readTablesViaNetlink,
		refreshInterval: refreshInterval,
		timeNow:         timeNow,
		onStillAlive:    onStillAlive,
		opReporter:      options.OpRecorder,
	}
}

func (c *IPTablesNFTCleanup) Name() string {
	return "iptables-nft"
}

func (c *IPTablesNFTCleanup) IPVersion() uint8 {
	return c.ipVersion
}

// CleanUp makes one pass over the tables, rate limited to one pass per refresh interval.
func (c *IPTablesNFTCleanup) CleanUp() (rescheduleAfter time.Duration) {
	now := c.timeNow()
	if sinceLast := now.Sub(c.lastSweep); !c.lastSweep.IsZero() && sinceLast < c.refreshInterval {
		return c.refreshInterval - sinceLast
	}
	c.lastSweep = now

	states, err := c.readTables(c.family, rulesdefs.SharedTables, c.onStillAlive)
	if err != nil {
		logrus.WithError(err).WithField("family", c.family).Warn("Failed to read the shared tables; will retry the iptables-nft cleanup")
		return c.refreshInterval
	}

	for _, table := range rulesdefs.SharedTables {
		c.onStillAlive()

		state, ok := states[table]
		if !ok {
			// The table doesn't exist, so no iptables-nft Felix ever wrote there.
			logrus.WithFields(logrus.Fields{"family": c.family, "table": table}).Debug("Shared table not present")
			continue
		}

		if err := c.sweepTable(table, state); err != nil {
			logrus.WithError(err).WithFields(logrus.Fields{
				"family": c.family,
				"table":  table,
			}).Warn("Failed to clean up rules left by a previous iptables-nft Felix; will retry")
		}
	}

	return c.refreshInterval
}

// sweepTable removes our state from one table.
func (c *IPTablesNFTCleanup) sweepTable(table string, state *iptablesTableState) error {
	ourChains, ourRuleHandles := c.ourState(state)
	if len(ourChains) == 0 && len(ourRuleHandles) == 0 {
		return nil
	}

	nft, err := c.newDataplane(c.family, table)
	if err != nil {
		return fmt.Errorf("create nft client: %w", err)
	}

	if c.opReporter != nil {
		c.opReporter.RecordOperation(fmt.Sprintf("cleanup-iptables-nft-%s-v%d", table, c.ipVersion))
	}

	// Rules first, then empty our chains. Nothing of ours affects traffic after this, even if the
	// deletes below can't go through.
	tx := nft.NewTransaction()
	for chain, handles := range ourRuleHandles {
		for _, h := range handles {
			handle := int(h)
			tx.Delete(&knftables.Rule{Chain: chain, Handle: &handle})
		}
	}
	for _, name := range ourChains {
		tx.Flush(&knftables.Chain{Name: name})
	}
	if err := c.runTransaction(nft, tx); err != nil {
		return fmt.Errorf("remove rules: %w", err)
	}

	if len(ourChains) > 0 {
		c.deleteChains(nft, table, ourChains)
	}

	logrus.WithFields(logrus.Fields{
		"family": c.family,
		"table":  table,
		"chains": len(ourChains),
	}).Info("Cleaned up rules left behind by a previous iptables-nft Felix")

	return nil
}

// deleteChains removes our chains, falling back to one transaction each. nftables refuses to delete
// a chain something still jumps to, and one of those would otherwise take the whole batch with it.
func (c *IPTablesNFTCleanup) deleteChains(nft knftables.Interface, table string, chains []string) {
	tx := nft.NewTransaction()
	for _, name := range chains {
		tx.Delete(&knftables.Chain{Name: name})
	}
	if err := c.runTransaction(nft, tx); err == nil {
		return
	}

	var referenced []string
	for _, name := range chains {
		tx := nft.NewTransaction()
		tx.Delete(&knftables.Chain{Name: name})
		if err := c.runTransaction(nft, tx); err != nil {
			referenced = append(referenced, name)
		}
	}
	if len(referenced) > 0 {
		logrus.WithFields(logrus.Fields{
			"family": c.family,
			"table":  table,
			"chains": referenced,
		}).Warn("Left empty chains behind; something outside the base chains still jumps to them")
	}
}

func (c *IPTablesNFTCleanup) runTransaction(nft knftables.Interface, tx *knftables.Transaction) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()
	return nft.Run(ctx, tx)
}

// ourState picks out the chains and rules a previous iptables-nft Felix wrote: chains by name,
// rules by the hash comment iptables puts on every rule Felix manages.
func (c *IPTablesNFTCleanup) ourState(state *iptablesTableState) ([]string, map[string][]uint64) {
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
		if strings.HasPrefix(r.Comment, rulesdefs.RuleHashPrefix) || hasAnyPrefix(r.JumpTarget, c.chainPrefixes) {
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

	// Base is set for a chain attached to a netfilter hook. Felix only ever inserted rules into
	// those, so they're the only chains we need to read rules from.
	Base bool `json:"base,omitempty"`
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
