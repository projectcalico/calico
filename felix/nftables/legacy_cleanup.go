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

	"github.com/sirupsen/logrus"
	"sigs.k8s.io/knftables"
)

// legacyIPTablesTables are the standard tables that a previous iptables-mode Felix would
// have written into. In nftables mode we sweep our chains back out of them.
var legacyIPTablesTables = []string{"filter", "nat", "mangle", "raw"}

// CleanUpLegacyIPTables removes chains and inserted rules left behind by a previous
// iptables-mode Felix from the standard filter/nat/mangle/raw tables of the given family.
//
// We read through knftables rather than iptables-nft-save. The latter aborts with an
// "incompatible" error on any table that also holds native nft rules (Tailscale,
// kube-proxy, a host firewall), which is what made nftables-mode Felix loop forever on
// cleanup (calico #13263). The native nft view reads those shared tables fine, and we only
// touch chains and rules we recognise as our own.
//
// Best-effort: a table that was never written to, or a host with no nft binary, is a no-op.
// Anything left behind gets swept on the next restart, so we log and move on rather than
// failing startup.
func CleanUpLegacyIPTables(newDataplane NewNftablesDataplaneFn, ipVersion uint8, hashPrefix string, chainPrefixes []string) {
	// NewDataplane is optional in the same way as for nftables.NewTable: the production callers
	// leave it nil and get the real knftables client; tests inject a fake.
	if newDataplane == nil {
		newDataplane = knftables.New
	}

	family := knftables.IPv4Family
	if ipVersion == 6 {
		family = knftables.IPv6Family
	}

	for _, table := range legacyIPTablesTables {
		if err := cleanUpLegacyTable(newDataplane, family, table, hashPrefix, chainPrefixes); err != nil {
			logrus.WithError(err).WithFields(logrus.Fields{
				"family": family,
				"table":  table,
			}).Warn("Failed to clean up legacy iptables rules; will retry on next restart")
		}
	}
}

func cleanUpLegacyTable(newDataplane NewNftablesDataplaneFn, family knftables.Family, table, hashPrefix string, chainPrefixes []string) error {
	nft, err := newDataplane(family, table)
	if err != nil {
		return fmt.Errorf("create nft client: %w", err)
	}

	ctx := context.Background()

	// A missing table means a prior Felix never wrote here - nothing to do.
	chainNames, err := nft.List(ctx, objectTypeChain)
	if knftables.IsNotFound(err) {
		return nil
	} else if err != nil {
		return fmt.Errorf("list chains: %w", err)
	}

	ourChains := map[string]bool{}
	for _, name := range chainNames {
		if hasAnyPrefix(name, chainPrefixes) {
			ourChains[name] = true
		}
	}
	if len(ourChains) == 0 {
		return nil
	}

	rules, err := nft.ListRules(ctx, "")
	if err != nil {
		return fmt.Errorf("list rules: %w", err)
	}

	tx := nft.NewTransaction()

	// Delete our inserted jumps from foreign chains (base chains like INPUT/FORWARD) first, so
	// the chains they target become unreferenced and deletable. Rules living inside our own
	// chains are skipped here - the flush below clears those.
	for _, r := range rules {
		if ourChains[r.Chain] {
			continue
		}
		if r.Comment != nil && strings.HasPrefix(*r.Comment, hashPrefix) {
			tx.Delete(&knftables.Rule{Chain: r.Chain, Handle: r.Handle})
		}
	}

	for name := range ourChains {
		tx.Flush(&knftables.Chain{Name: name})
		tx.Delete(&knftables.Chain{Name: name})
	}

	if tx.NumOperations() == 0 {
		return nil
	}
	if err := nft.Run(ctx, tx); err != nil {
		return fmt.Errorf("apply cleanup transaction: %w", err)
	}

	logrus.WithFields(logrus.Fields{
		"family": family,
		"table":  table,
		"chains": len(ourChains),
	}).Info("Cleaned up legacy iptables rules via the nftables view")
	return nil
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}
