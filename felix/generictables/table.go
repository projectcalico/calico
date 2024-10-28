// Copyright (c) 2016-2024 Tigera, Inc. All rights reserved.
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

package generictables

import (
	"time"
)

// TableSet is a collection of one or more logical tables.
type TableSet interface {
	WithTable(name string) Table
}

// Table is a logical table of chains and rules.
type Table interface {
	Name() string
	IPVersion() uint8
	InsertOrAppendRules(chainName string, rules []Rule)
	AppendRules(chainName string, rules []Rule)
	UpdateChain(chain *Chain)
	UpdateChains([]*Chain)
	RemoveChains([]*Chain)
	RemoveChainByName(name string)
	InvalidateDataplaneCache(reason string)
	Apply() time.Duration
	InsertRulesNow(chainName string, rules []Rule) error
	CheckRulesPresent(chain string, rules []Rule) []Rule
}

var _ Table = &NoopTable{}

// NoopTable fulfils the Table interface but does nothing.
type NoopTable struct{}

func NewNoopTable() *NoopTable {
	return new(NoopTable)
}

func (t *NoopTable) Name() string                                        { return "" }
func (t *NoopTable) IPVersion() uint8                                    { return 0 }
func (t *NoopTable) InsertOrAppendRules(chainName string, rules []Rule)  {}
func (t *NoopTable) AppendRules(chainName string, rules []Rule)          {}
func (t *NoopTable) UpdateChain(chain *Chain)                            {}
func (t *NoopTable) UpdateChains([]*Chain)                               {}
func (t *NoopTable) RemoveChains([]*Chain)                               {}
func (t *NoopTable) RemoveChainByName(name string)                       {}
func (t *NoopTable) InvalidateDataplaneCache(reason string)              {}
func (t *NoopTable) Apply() time.Duration                                { return 0 }
func (n *NoopTable) InsertRulesNow(chainName string, rules []Rule) error { return nil }
func (n *NoopTable) CheckRulesPresent(chain string, rules []Rule) []Rule { return nil }
