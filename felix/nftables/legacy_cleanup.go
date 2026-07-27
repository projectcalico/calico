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

	"github.com/projectcalico/calico/felix/generictables"
	"github.com/projectcalico/calico/felix/logutils"
)

// legacyIPTablesTables are the standard tables that a previous iptables-mode Felix would
// have written into. In nftables mode we sweep our chains back out of them.
var legacyIPTablesTables = []string{"filter", "nat", "mangle", "raw"}

var _ generictables.CleanupTable = (*LegacyIPTablesCleanup)(nil)

// LegacyIPTablesCleanup removes chains and inserted rules left behind by a previous
// iptables-mode Felix from the standard filter/nat/mangle/raw tables of one IP family.
//
// Unlike the tables an NftablesTable owns, these are shared with anything else on the host
// that uses nftables, so we remove only the chains and rules we recognise as our own and
// leave the rest alone.
//
// We also read through knftables rather than iptables-nft-save. The latter aborts with an
// "incompatible" error on any table that also holds native nft rules (Tailscale, kube-proxy, a
// host firewall), which is what made nftables-mode Felix loop forever on cleanup (#13263).
type LegacyIPTablesCleanup struct {
	ipVersion uint8
	family    knftables.Family

	hashPrefix    string
	chainPrefixes []string

	newDataplane    NewNftablesDataplaneFn
	refreshInterval time.Duration

	// done is set once there's nothing left to do: a clean pass, with no refresh interval
	// configured to bring us back.
	done bool

	timeNow      func() time.Time
	lastSweep    time.Time
	onStillAlive func()
	opReporter   logutils.OpRecorder
}

// NewLegacyIPTablesCleanup returns a CleanupTable that sweeps leftover iptables-mode rules out
// of the shared nftables tables for the given IP version.
func NewLegacyIPTablesCleanup(
	ipVersion uint8,
	hashPrefix string,
	chainPrefixes []string,
	options TableOptions,
) *LegacyIPTablesCleanup {
	family := knftables.IPv4Family
	if ipVersion == 6 {
		family = knftables.IPv6Family
	}

	newDataplane := options.NewDataplane
	if newDataplane == nil {
		// Same convention as NewTable: production callers leave this nil and get the real
		// knftables client, tests inject a fake.
		newDataplane = knftables.New
	}

	timeNow := time.Now
	if options.NowOverride != nil {
		timeNow = options.NowOverride
	}

	onStillAlive := options.OnStillAlive
	if onStillAlive == nil {
		onStillAlive = func() {}
	}

	return &LegacyIPTablesCleanup{
		ipVersion:       ipVersion,
		family:          family,
		hashPrefix:      hashPrefix,
		chainPrefixes:   chainPrefixes,
		newDataplane:    newDataplane,
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

// CleanUp sweeps each of the tables, rate limited to one pass per refresh interval. A table
// that errors out gets another attempt on the next pass, so a transient failure (or a host with
// no nft binary) costs us nothing beyond a log line.
func (c *LegacyIPTablesCleanup) CleanUp() (rescheduleAfter time.Duration) {
	if c.done {
		return 0
	}

	now := c.timeNow()
	if sinceLast := now.Sub(c.lastSweep); !c.lastSweep.IsZero() && c.refreshInterval > 0 && sinceLast < c.refreshInterval {
		// Swept recently, nothing to do until the refresh interval is up.
		return c.refreshInterval - sinceLast
	}
	c.lastSweep = now

	allClean := true
	for _, table := range legacyIPTablesTables {
		c.onStillAlive()

		clean, err := c.sweepTable(table)
		if err != nil {
			logrus.WithError(err).WithFields(logrus.Fields{
				"family": c.family,
				"table":  table,
			}).Warn("Failed to clean up legacy iptables rules; will retry")
		}
		if !clean {
			allClean = false
		}
	}

	if allClean && c.refreshInterval <= 0 {
		// Nothing of ours is left and nothing will bring us back, so stop reading the dataplane.
		c.done = true
		return 0
	}
	return c.refreshInterval
}

// sweepTable removes our state from one table, reporting whether the table came back free of it.
func (c *LegacyIPTablesCleanup) sweepTable(table string) (bool, error) {
	nft, err := c.newDataplane(c.family, table)
	if err != nil {
		return false, fmt.Errorf("create nft client: %w", err)
	}

	ctx := context.Background()

	chainNames, err := nft.List(ctx, objectTypeChain)
	if knftables.IsNotFound(err) {
		// A missing table means a prior Felix never wrote here.
		return true, nil
	} else if err != nil {
		return false, fmt.Errorf("list chains: %w", err)
	}

	ourChains := map[string]bool{}
	for _, name := range chainNames {
		if hasAnyPrefix(name, c.chainPrefixes) {
			ourChains[name] = true
		}
	}

	rules, err := nft.ListRules(ctx, "")
	if err != nil {
		return false, fmt.Errorf("list rules: %w", err)
	}

	tx := nft.NewTransaction()

	// Delete our inserted jumps from foreign chains (base chains like INPUT/FORWARD) first, so
	// the chains they target become unreferenced and deletable. Rules living inside our own
	// chains are skipped here - the flush below clears those.
	for _, r := range rules {
		if ourChains[r.Chain] {
			continue
		}
		if r.Comment != nil && strings.HasPrefix(*r.Comment, c.hashPrefix) {
			tx.Delete(&knftables.Rule{Chain: r.Chain, Handle: r.Handle})
		}
	}

	for name := range ourChains {
		tx.Flush(&knftables.Chain{Name: name})
		tx.Delete(&knftables.Chain{Name: name})
	}

	if tx.NumOperations() == 0 {
		return true, nil
	}

	if c.opReporter != nil {
		c.opReporter.RecordOperation(fmt.Sprintf("cleanup-legacy-%s-v%d", table, c.ipVersion))
	}
	if err := nft.Run(ctx, tx); err != nil {
		return false, fmt.Errorf("apply cleanup transaction: %w", err)
	}

	logrus.WithFields(logrus.Fields{
		"family": c.family,
		"table":  table,
		"chains": len(ourChains),
	}).Info("Cleaned up legacy iptables rules via the nftables view")

	// Re-read on the next pass to confirm the deletes stuck.
	return false, nil
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}
