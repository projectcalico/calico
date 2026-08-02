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
	"fmt"
	"slices"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/google/nftables/xt"
	"github.com/sirupsen/logrus"
	"sigs.k8s.io/knftables"
)

// readTablesViaNetlink reads back whichever of the named tables exist; a table missing from the
// result doesn't exist.
//
// Netlink rather than the nft binary because of the rule comment: the kernel hands back iptables'
// comment payload, which is how iptables-nft-save recovers it, but every nft renderer drops it.
func readTablesViaNetlink(family knftables.Family, tables []string) (map[string]*iptablesTableState, error) {
	netlinkFamily := nftables.TableFamilyIPv4
	if family == knftables.IPv6Family {
		netlinkFamily = nftables.TableFamilyIPv6
	}

	// One socket for the whole pass; the default is one per call, and we make a call per chain.
	conn, err := nftables.New(nftables.AsLasting())
	if err != nil {
		return nil, fmt.Errorf("open netlink connection: %w", err)
	}
	defer func() {
		if err := conn.CloseLasting(); err != nil {
			logrus.WithError(err).Debug("Failed to close nftables netlink connection")
		}
	}()

	present, err := conn.ListTablesOfFamily(netlinkFamily)
	if err != nil {
		return nil, fmt.Errorf("list tables: %w", err)
	}
	wanted := map[string]*nftables.Table{}
	for _, t := range present {
		if slices.Contains(tables, t.Name) {
			wanted[t.Name] = t
		}
	}
	if len(wanted) == 0 {
		return nil, nil
	}

	chains, err := conn.ListChainsOfTableFamily(netlinkFamily)
	if err != nil {
		return nil, fmt.Errorf("list chains: %w", err)
	}

	states := map[string]*iptablesTableState{}
	for name := range wanted {
		states[name] = &iptablesTableState{}
	}
	for _, chain := range chains {
		if chain.Table == nil {
			continue
		}
		table, ok := wanted[chain.Table.Name]
		if !ok {
			continue
		}
		state := states[chain.Table.Name]
		state.Chains = append(state.Chains, iptablesChain{Name: chain.Name})

		rules, err := conn.GetRules(table, chain)
		if err != nil {
			return nil, fmt.Errorf("list rules in chain %s: %w", chain.Name, err)
		}
		for _, rule := range rules {
			state.Rules = append(state.Rules, iptablesRule{
				Chain:      chain.Name,
				Handle:     rule.Handle,
				Comment:    ruleComment(rule),
				JumpTarget: ruleJumpTarget(rule),
			})
		}
	}
	return states, nil
}

// ruleComment returns the rule's first iptables comment, or "". Our rules put the hash first.
func ruleComment(rule *nftables.Rule) string {
	for _, e := range rule.Exprs {
		match, ok := e.(*expr.Match)
		if !ok || match.Name != "comment" {
			continue
		}

		comment, ok := match.Info.(*xt.Comment)
		if !ok {
			continue
		}
		return string(*comment)
	}
	return ""
}

// ruleJumpTarget returns the chain this rule jumps or gotos to, or "".
func ruleJumpTarget(rule *nftables.Rule) string {
	for _, e := range rule.Exprs {
		if verdict, ok := e.(*expr.Verdict); ok && verdict.Chain != "" {
			return verdict.Chain
		}
	}
	return ""
}
