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

package intdataplane

import (
	"fmt"

	"github.com/google/go-cmp/cmp"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/generictables"
)

type mockTable struct {
	Table          string
	currentChains  map[string]*generictables.Chain
	expectedChains map[string]*generictables.Chain
	UpdateCalled   bool
}

func newMockTable(table string) *mockTable {
	return &mockTable{
		Table:          table,
		currentChains:  map[string]*generictables.Chain{},
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

func (t *mockTable) UpdateChain(chain *generictables.Chain) {
	t.UpdateChains([]*generictables.Chain{chain})
}

func (t *mockTable) UpdateChains(chains []*generictables.Chain) {
	t.UpdateCalled = true
	logChains("UpdateChains", chains)
	for _, chain := range chains {
		t.currentChains[chain.Name] = chain
	}
}

func (t *mockTable) RemoveChains(chains []*generictables.Chain) {
	logChains("RemoveChains", chains)
	for _, chain := range chains {
		t.RemoveChainByName(chain.Name)
		delete(t.currentChains, chain.Name)
	}
}

func (t *mockTable) RemoveChainByName(name string) {
	delete(t.currentChains, name)
}

func (t *mockTable) checkChains(expecteds [][]*generictables.Chain) {
	t.expectedChains = map[string]*generictables.Chain{}
	for _, expected := range expecteds {
		for _, chain := range expected {
			t.expectedChains[chain.Name] = chain
		}
	}
	t.checkChainsSameAsBefore()
}

func (t *mockTable) checkChainsSameAsBefore() {
	// Build a failure message in case of unexpected chains.
	msg := "Unexpected chain:\n\n %+v\n\n Expected chains:\n\n"
	for _, chain := range t.expectedChains {
		log.WithField("chain", *chain).Debug("")
		msg += fmt.Sprintf(" %+v\n", *chain)
	}

	// Check each current chain is as expected.
	for _, chain := range t.currentChains {
		expected, ok := t.expectedChains[chain.Name]
		ExpectWithOffset(2, ok).To(BeTrue(), fmt.Sprintf(msg, *chain))
		ExpectWithOffset(2, *chain).To(Equal(*expected), cmp.Diff(expected, chain))
	}

	// Ensure no expected chains are missing.
	for _, chain := range t.expectedChains {
		_, ok := t.currentChains[chain.Name]
		ExpectWithOffset(2, ok).To(BeTrue(), "Missing expected chain: %v", chain)
	}

	// Assert the whole map is as expected.
	ExpectWithOffset(2, t.currentChains).To(Equal(t.expectedChains), t.Table+" chains incorrect")
}
