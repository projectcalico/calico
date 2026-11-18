// Copyright (c) 2017 Tigera, Inc. All rights reserved.
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

// Package dptest holds test doubles shared by the Linux dataplane's manager
// tests.
package dptest

import (
	"fmt"
	"strings"

	"github.com/google/go-cmp/cmp"
	"github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/generictables"
)

type MockTable struct {
	Table          string
	CurrentChains  map[string]*generictables.Chain
	expectedChains map[string]*generictables.Chain
	UpdateCalled   bool
}

func NewMockTable(table string) *MockTable {
	return &MockTable{
		Table:          table,
		CurrentChains:  map[string]*generictables.Chain{},
		expectedChains: map[string]*generictables.Chain{},
	}
}

func logChains(message string, chains []*generictables.Chain) {
	if chains == nil {
		log.Debug(message, " with nil chains")
	} else {
		log.WithField("chains", chains).Debug(message)
		for _, chain := range chains {
			log.WithField("chain", *chain).Debug("")
		}
	}
}

func (t *MockTable) UpdateChain(chain *generictables.Chain) {
	t.UpdateChains([]*generictables.Chain{chain})
}

func (t *MockTable) UpdateChains(chains []*generictables.Chain) {
	t.UpdateCalled = true
	logChains("UpdateChains", chains)
	for _, chain := range chains {
		t.CurrentChains[chain.Name] = chain
	}
}

func (t *MockTable) RemoveChains(chains []*generictables.Chain) {
	logChains("RemoveChains", chains)
	for _, chain := range chains {
		t.RemoveChainByName(chain.Name)
		delete(t.CurrentChains, chain.Name)
	}
}

func (t *MockTable) RemoveChainByName(name string) {
	delete(t.CurrentChains, name)
}

func (t *MockTable) CheckChains(expecteds [][]*generictables.Chain) {
	t.expectedChains = map[string]*generictables.Chain{}
	for _, expected := range expecteds {
		for _, chain := range expected {
			t.expectedChains[chain.Name] = chain
		}
	}
	t.checkChainsSameAsBefore()
}

func (t *MockTable) checkChainsSameAsBefore() {
	// Build a failure message in case of unexpected chains.
	var msg strings.Builder
	msg.WriteString("Unexpected chain:\n\n %+v\n\n Expected chains:\n\n")
	for _, chain := range t.expectedChains {
		log.WithField("chain", *chain).Debug("")
		fmt.Fprintf(&msg, " %+v\n", *chain)
	}

	// Check each current chain is as expected.
	for _, chain := range t.CurrentChains {
		expected, ok := t.expectedChains[chain.Name]
		gomega.ExpectWithOffset(2, ok).To(gomega.BeTrue(), fmt.Sprintf(msg.String(), *chain))
		gomega.ExpectWithOffset(2, *chain).To(gomega.Equal(*expected), cmp.Diff(expected, chain))
	}

	// Ensure no expected chains are missing.
	for _, chain := range t.expectedChains {
		_, ok := t.CurrentChains[chain.Name]
		gomega.ExpectWithOffset(2, ok).To(gomega.BeTrue(), "Missing expected chain: %v", chain)
	}

	// Assert the whole map is as expected.
	gomega.ExpectWithOffset(2, t.CurrentChains).To(gomega.Equal(t.expectedChains), t.Table+" chains incorrect")
}
