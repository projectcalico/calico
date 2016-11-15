// Copyright (c) 2016 Tigera, Inc. All rights reserved.
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

package iptables

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/fasaxc/go/src/os/exec"
	"github.com/projectcalico/felix/go/felix/set"
)

// Table represents a single one of the iptables tables i.e. "raw", "nat", "filter", etc.
type Table struct {
	Name string

	// chainToInsertedFragments maps from chain name to a list of iptables fragments that should
	// be inserted into that chain.  Used for hooking top-level chains.
	chainToInsertedFragments map[string][]string
	dirtyInserts             set.Set
	// chainToRemovedFragments maps from chain name to a list of iptables fragments that should
	// be removed from that chain.  Used for unhooking top-level chains.  We need to track
	// removals forever in case another process reinstates an old rule by mistake.  Hence,
	// only suitable for a static set of top-level rules.
	chainToRemovedFragments  map[string][]string
	dirtyRemoves             set.Set
	// chainToRuleFragments contains the desired state of our iptables chains, indexed by
	// chain name.  The values are slices of iptables fragments, such as
	// "--match foo --jump DROP" (i.e. omitting the action and chain name, which are calculated
	// as needed).
	chainToRuleFragments     map[string][]string
	dirtyChains              set.Set

	inSyncWithDataPlane      bool
	// chainToDataplaneHashes contains the rule hashes that we think are in the dataplane.
	// it is updated when we write to the dataplane but it can also be read back and compared
	// to what we calculate from chainToContents.
	chainToDataplaneHashes   map[string][]string

	logCxt                   *log.Entry

	restoreCmd               string
	saveCmd                  string
	iptablesCmd              string
}

func NewTable(name string, ipVersion uint8) {
	table := &Table{
		Name: name,
		chainToInsertedFragments: map[string][]string{},
		dirtyInserts:             set.New(),
		chainToRemovedFragments:  map[string][]string{},
		dirtyRemoves:             set.New(),
		chainToRuleFragments:          map[string][]string{},
		dirtyChains:              set.New(),
		logCxt: log.WithFields(log.Fields{
			"ipVersion": ipVersion,
			"table":     name,
		}),
	}

	if ipVersion == 4 {
		table.restoreCmd = "iptables-restore"
		table.saveCmd = "iptables-save"
		table.iptablesCmd = "iptables"
	} else {
		table.restoreCmd = "ip6tables-restore"
		table.saveCmd = "ip6tables-save"
		table.iptablesCmd = "ip6tables"
	}
}

func (t *Table) UpdateChain(name string, ruleFragments []string) {
	t.chainToRuleFragments[name] = ruleFragments
	t.dirtyChains.Add(name)
}

func (t *Table) RemoveChain(name string) {
	delete(t.chainToRuleFragments, name)
	t.dirtyChains.Add(name)
}

func (t *Table) loadDataplaneState() {
	// TODO(smc) Run iptables-save for our table.
	// TODO(smc) Parse out the rule hashes
	// TODO(smc) Scan for inconsistencies and mark chains as dirty as appropriate.
}

func (t *Table) Flush() {
	// Retry until we succeed.  There are several reasons that updating iptables may fail:
	// - a concurrent write may invalidate iptables-restore's compare-and-swap
	// - another process may have clobbered some of our state, resulting in inconsistencies
	//   in what we try to program.
	success := false
	for !success {
		if !t.inSyncWithDataPlane {
			// We have reason to believe that our picture of the dataplane is out of
			// sync.  Refresh it.  This may mark more chains as dirty.
			t.logCxt.Info("Out-of-sync with iptables, loading current state")
			t.loadDataplaneState()
		}

		if err := t.flushUpdates(); err != nil {
			log.WithError(err).Warn("Failed to program iptables, will retry")
			continue
		}
	}
}

func (t *Table) flushUpdates() error {
	var inputBuf bytes.Buffer
	// iptables-restore input starts with a line indicating the table name.
	inputBuf.WriteString(fmt.Sprintf("*%s\n", t.Name))

	// Make a pass over the dirty chains and generate a forward reference for any that need to
	// be created.
	t.dirtyChains.Iter(func(item interface{}) error {
		chainName := item.(string)
		flushChain := false
		if _, ok := t.chainToRuleFragments[chainName]; !ok {
			flushChain = true
		} else if _, ok := t.chainToDataplaneHashes[chainName]; !ok {
			flushChain = true
		}
		if flushChain {
			inputBuf.WriteString(fmt.Sprintf(":%s - -\n", chainName))
		}
		return nil
	})

	// Make a second pass over the dirty chains.  This time, we write out the rule changes.
	newHashes := map[string][]string{}
	t.dirtyChains.Iter(func(item interface{}) error {
		chainName := item.(string)
		if rulesFrags, ok := t.chainToRuleFragments[chainName]; !ok {
			// Chain deletion
			inputBuf.WriteString(fmt.Sprintf("--delete-chain %s\n", chainName))
			newHashes[chainName] = nil
		} else {
			// Chain update or creation.  Scan the chain against its previous hashes
			// and replace/append/delete as appropriate.
			previousHashes := t.chainToDataplaneHashes[chainName]
			currentHashes := RuleHashes(chainName, rulesFrags)
			newHashes[chainName] = currentHashes
			for i := 0; i < len(previousHashes) || i < len(currentHashes); i++ {
				var line string
				if i < len(previousHashes) && i < len(currentHashes) {
					if previousHashes[i] != currentHashes[i] {
						// Hash doesn't match, replace the rule.
						ruleNum := i + 1 // 1-indexed.
						comment := commentFrag(currentHashes[i])
						line = fmt.Sprintf("-R %s %s %v %s\n", chainName, comment, ruleNum, rulesFrags[i])
					}
				} else if i < len(previousHashes) {
					// previousHashes was longer, remove the old rules from the end.
					ruleNum := len(currentHashes) // 1-indexed
					line = fmt.Sprintf("-D %s %v\n", chainName, ruleNum)
				} else {
					// currentHashes was longer.  Append.
					comment := commentFrag(currentHashes[i])
					line = fmt.Sprintf("-A %s %s %s\n", chainName, comment, rulesFrags[i])
				}
				inputBuf.WriteString(line)
			}
		}
		return nil
	})

	// iptables-restore input ends with a COMMIT.
	inputBuf.WriteString("COMMIT\n")

	if log.GetLevel() >= log.DebugLevel {
		log.WithField("iptablesInput", inputBuf.String()).Debug("Writing to iptables")
	}

	// Actually execute iptables-restore.
	cmd := exec.Command(t.restoreCmd, "--noflush", "--verbose")
	cmd.Stdin = &inputBuf
	err := cmd.Run()
	if err != nil {
		t.inSyncWithDataPlane = false
		return err
	}
	// Clear the dirty set.
	t.dirtyChains = set.New()

	// Store off the updates.
	for chainName, hashes := range newHashes {
		if hashes == nil {
			delete(t.chainToDataplaneHashes, chainName)
		} else {
			t.chainToDataplaneHashes[chainName] = hashes
		}
	}
	return nil
}

func commentFrag(hash string) string {
	return fmt.Sprintf(`-m comment --comment "felix-hash:%s"`, hash)
}

// RuleHashes hashes the rules of a given chain, generating a hash for each rule.
// The hash depends on the name of the chain, the rule itself and the rules that precede it.
// A secure hash is used so hash collisions should be negligible.
func RuleHashes(chainName string, ruleFragments []string) []string {
	hashes := make([]string, len(ruleFragments))
	// First hash the chain name so that identical rules in different chains will get different
	// hashes.
	s := sha256.New224()
	s.Write([]byte(chainName))
	hash := s.Sum(nil)
	for ii, frag := range ruleFragments {
		// Each hash chains in the previous hash, so that its position in the chain and
		// the rules before it affect its hash.
		s.Reset()
		s.Write(hash)
		s.Write([]byte(frag))
		hash = s.Sum(hash[0:0])
		// Encode the hash using a compact character set.  We use the URL-safe base64
		// variant because it uses '-' and '_', which are more shell-friendly.
		hashes[ii] = base64.RawURLEncoding.EncodeToString(hash)
		if log.GetLevel() >= log.DebugLevel {
			log.WithFields(log.Fields{
				"ruleFragment": frag,
				"position":     ii,
				"chain":        chainName,
			}).Debug("Hashed rule")
		}
	}
	return hashes
}
