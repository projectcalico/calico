// Copyright (c) 2024 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package nftables

import (
	"fmt"
	"strings"
	"time"

	"github.com/projectcalico/calico/felix/generictables"
	"github.com/sirupsen/logrus"
)

func NewTableLayer(name string, table generictables.Table) generictables.Table {
	if _, ok := table.(MapsDataplane); !ok {
		logrus.Panicf("Table %s does not implement MapsDataplane", name)
	}

	return &tableLayer{
		name: name,
		impl: table,
		maps: table.(MapsDataplane),
	}
}

var (
	_ generictables.Table = &tableLayer{}
	_ MapsDataplane       = &tableLayer{}
)

type tableLayer struct {
	// name is the name of the table, used to namespace operations performed on the underlying table.
	name string

	// impl is the underlying table implementation to use.
	impl generictables.Table
	maps MapsDataplane
}

// namespaceName return a namespaced name for the given chain. Since we use a single nftables Table to
// manage chains from several logical tables, we need to namespace the chain names as well as jump / goto
// statements to avoid conflicts.
func (t *tableLayer) namespaceName(name string) string {
	if strings.HasPrefix(name, t.name) {
		return name
	}
	return fmt.Sprintf("%s-%s", t.name, name)
}

func (t *tableLayer) namespaceRules(rules []generictables.Rule) []generictables.Rule {
	newRules := make([]generictables.Rule, len(rules))
	for i, r := range rules {
		newRule := r
		if n, ok := r.Action.(namespaceable); ok {
			newRule.Action = n.Namespace(t.name)
		}
		if n, ok := r.Match.(NFTMatchCriteria); ok {
			newRule.Match = n.SetLayer(t.name)
		}
		newRules[i] = newRule
	}
	return newRules
}

func (t *tableLayer) namespaceMapMember(m []string) []string {
	// TODO: We only use "goto" in map members right now. If we add other actions, we'll need to namespace them.
	// This is a very brittle implementation that assumes that the map member is a single string that starts with "goto ".
	if len(m) != 1 {
		logrus.Panicf("Unexpected map member: %s", m)
	}
	if !strings.HasPrefix(m[0], "goto ") {
		logrus.Panicf("Unexpected map member: %s", m)
	}
	return []string{fmt.Sprintf("goto %s", t.namespaceName(m[0][5:]))}
}

func (t *tableLayer) Name() string {
	return t.name
}

func (t *tableLayer) IPVersion() uint8 {
	return t.impl.IPVersion()
}

func (t *tableLayer) InsertOrAppendRules(chainName string, rules []generictables.Rule) {
	chainName = t.namespaceName(chainName)
	rules = t.namespaceRules(rules)
	t.impl.InsertOrAppendRules(chainName, rules)
}

func (t *tableLayer) AppendRules(chainName string, rules []generictables.Rule) {
	chainName = t.namespaceName(chainName)
	rules = t.namespaceRules(rules)
	t.impl.AppendRules(chainName, rules)
}

func (t *tableLayer) UpdateChain(chain *generictables.Chain) {
	c := *chain
	c.Name = t.namespaceName(chain.Name)
	c.Rules = t.namespaceRules(chain.Rules)
	t.impl.UpdateChain(&c)
}

func (t *tableLayer) UpdateChains(chains []*generictables.Chain) {
	for _, c := range chains {
		t.UpdateChain(c)
	}
}

func (t *tableLayer) RemoveChains(chains []*generictables.Chain) {
	for _, c := range chains {
		t.RemoveChainByName(c.Name)
	}
}

func (t *tableLayer) RemoveChainByName(name string) {
	name = t.namespaceName(name)
	t.impl.RemoveChainByName(name)
}

func (t *tableLayer) InvalidateDataplaneCache(reason string) {
	t.impl.InvalidateDataplaneCache(reason)
}

func (t *tableLayer) Apply() time.Duration {
	return t.impl.Apply()
}

func (t *tableLayer) InsertRulesNow(chainName string, rules []generictables.Rule) error {
	chainName = t.namespaceName(chainName)
	rules = t.namespaceRules(rules)
	return t.impl.InsertRulesNow(chainName, rules)
}

func (t *tableLayer) CheckRulesPresent(chain string, rules []generictables.Rule) []generictables.Rule {
	chain = t.namespaceName(chain)
	rules = t.namespaceRules(rules)
	return t.impl.CheckRulesPresent(chain, rules)
}

func (t *tableLayer) AddOrReplaceMap(meta MapMetadata, members map[string][]string) {
	// Namespace the map name.
	meta.Name = t.namespaceName(meta.Name)

	// For each member, namespace any rules.
	for k, v := range members {
		members[k] = t.namespaceMapMember(v)
	}

	// Call the underlying implementation.
	t.maps.AddOrReplaceMap(meta, members)
}

func (t *tableLayer) RemoveMap(id string) {
	t.maps.RemoveMap(t.namespaceName(id))
}

func (t *tableLayer) MapUpdates() *MapUpdates {
	return t.maps.MapUpdates()
}

func (t *tableLayer) FinishMapUpdates(updates *MapUpdates) {
	t.maps.FinishMapUpdates(updates)
}

func (t *tableLayer) LoadDataplaneState() error {
	return t.maps.LoadDataplaneState()
}
