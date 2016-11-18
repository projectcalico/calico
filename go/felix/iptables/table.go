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
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/projectcalico/felix/go/felix/set"
	"os/exec"
	"reflect"
	"regexp"
	"strings"
)

const (
	MaxChainNameLength = 28
)

var (
	chainCreateRegexp = regexp.MustCompile(`^:(\S+)`)
	appendRegexp      = regexp.MustCompile(`^-A (\S+)`)
)

// Table represents a single one of the iptables tables i.e. "raw", "nat", "filter", etc.
type Table struct {
	Name string

	// TODO(smc) Implement rule insertions to hook root chains.
	// chainToInsertedFragments maps from chain name to a list of iptables fragments that should
	// be inserted into that chain.  Used for hooking top-level chains.
	chainToInsertedFragments map[string][]string
	dirtyInserts             set.Set
	// chainToRemovedFragments maps from chain name to a list of iptables fragments that should
	// be removed from that chain.  Used for unhooking top-level chains.  We need to track
	// removals forever in case another process reinstates an old rule by mistake.  Hence,
	// only suitable for a static set of top-level rules.
	chainToRemovedFragments map[string][]string
	dirtyRemoves            set.Set
	// chainToRuleFragments contains the desired state of our iptables chains, indexed by
	// chain name.  The values are slices of iptables fragments, such as
	// "--match foo --jump DROP" (i.e. omitting the action and chain name, which are calculated
	// as needed).
	chainNameToChain map[string]*Chain
	dirtyChains      set.Set

	inSyncWithDataPlane bool

	// chainToDataplaneHashes contains the rule hashes that we think are in the dataplane.
	// it is updated when we write to the dataplane but it can also be read back and compared
	// to what we calculate from chainToContents.
	chainToDataplaneHashes map[string][]string

	// hashCommentPrefix holds the prefix that we prepend to our rule-tracking hashes.
	hashCommentPrefix string
	// hashCommentRegexp matches the rule-tracking comment, capturing the rule hash.
	hashCommentRegexp *regexp.Regexp
	// ourChainsRegexp matches the names of chains that are "ours", i.e. start with one of our
	// prefixes.
	ourChainsRegexp *regexp.Regexp

	restoreCmd  string
	saveCmd     string
	iptablesCmd string

	logCxt *log.Entry
}

func NewTable(name string, ipVersion uint8, chainPrefixes []string, hashPrefix string) *Table {
	hashCommentRegexp := regexp.MustCompile(`--comment "?` + hashPrefix + `([a-zA-Z0-9_-]+)"?`)
	ourChainsPattern := "^(" + strings.Join(chainPrefixes, "|") + ")"
	ourChainsRegexp := regexp.MustCompile(ourChainsPattern)
	table := &Table{
		Name: name,
		chainToInsertedFragments: map[string][]string{},
		dirtyInserts:             set.New(),
		chainToRemovedFragments:  map[string][]string{},
		dirtyRemoves:             set.New(),
		chainNameToChain:         map[string]*Chain{},
		dirtyChains:              set.New(),
		chainToDataplaneHashes:   map[string][]string{},
		logCxt: log.WithFields(log.Fields{
			"ipVersion": ipVersion,
			"table":     name,
		}),
		hashCommentPrefix: hashPrefix,
		hashCommentRegexp: hashCommentRegexp,
		ourChainsRegexp:   ourChainsRegexp,
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
	return table
}

func (t *Table) UpdateChains(chains []*Chain) {
	for _, chain := range chains {
		t.UpdateChain(chain)
	}
}

func (t *Table) UpdateChain(chain *Chain) {
	t.logCxt.WithField("chainName", chain.Name).Info("Queueing update of chain.")
	t.chainNameToChain[chain.Name] = chain
	t.dirtyChains.Add(chain.Name)
}

func (t *Table) RemoveChainByName(name string) {
	t.logCxt.WithField("chainName", name).Info("Queing deletion of chain.")
	delete(t.chainNameToChain, name)
	t.dirtyChains.Add(name)
}

func (t *Table) RemoveChains(chains []*Chain) {
	for _, chain := range chains {
		t.RemoveChainByName(chain.Name)
	}
}

func (t *Table) loadDataplaneState() {
	// Load the hashes from the dataplane.
	dataplaneHashes := t.getHashesFromDataplane()

	// Check that the rules we think we've programmed are still there and mark any inconsistent
	// chains for refresh.
	t.logCxt.Info("Scanning for out-of-sync iptables chains")
	for chainName, expectedHashes := range t.chainToDataplaneHashes {
		logCxt := t.logCxt.WithField("chainName", chainName)
		if t.dirtyChains.Contains(chainName) {
			// Already an update pending for this chain.
			logCxt.Debug("Skipping known-dirty chain")
			continue
		}
		if !reflect.DeepEqual(dataplaneHashes[chainName], expectedHashes) {
			logCxt.Warn("Detected out-of-sync iptables chain, marking for resync")
			t.dirtyChains.Add("chainName")
		}
	}

	// Now scan for chains that shouldn't be there and mark for deletion.
	t.logCxt.Info("Scanning for unexpected iptables chains")
	for chainName := range dataplaneHashes {
		logCxt := t.logCxt.WithField("chainName", chainName)
		if t.dirtyChains.Contains(chainName) {
			// Already an update pending for this chain.
			logCxt.Debug("Skipping known-dirty chain")
			continue
		}
		if !t.ourChainsRegexp.MatchString(chainName) {
			// Skip non-felix chain
			logCxt.Debug("Skipping non-calico chain")
			continue
		}
		if _, ok := t.chainToDataplaneHashes[chainName]; ok {
			// Chain expected, we'll have checked its contents above.
			logCxt.Debug("Skipping expected chain")
			continue
		}
		// Chain exists in dataplane but not in memory, mark as dirty so we'll clean it up.
		logCxt.Info("Found unexpected chain, marking for cleanup")
		t.dirtyChains.Add(chainName)
	}

	t.logCxt.Info("Done scanning, in sync with dataplane")
	t.chainToDataplaneHashes = dataplaneHashes
}

// getHashesFromDataplane loads the current state of our table and parses out the hashes that we
// add to rules.  It returns a map with an entry for each chain in the table.  Each entry is a slice
// containing the hashes for the rules in that table.  Rules with no hashes are represented by
// an empty string.
func (t *Table) getHashesFromDataplane() map[string][]string {
	cmd := exec.Command(t.saveCmd, "-t", t.Name)
	output, err := cmd.Output()
	if err != nil {
		log.WithError(err).Panic("iptables save failed")
	}
	buf := bytes.NewBuffer(output)
	newHashes := map[string][]string{}
	for {
		// Read the next line of the output.
		line, err := buf.ReadString('\n')
		if err != nil { // EOF
			break
		}

		// Look for lines of the form ":chain-name - [0:0]", which are forward declarations
		// for (possibly empty) chains.
		logCxt := log.WithField("line", line)
		logCxt.Debug("Parsing line")
		captures := chainCreateRegexp.FindStringSubmatch(line)
		if captures != nil {
			// Chain forward-reference, make sure the chain exists.
			chainName := captures[1]
			logCxt.WithField("chainName", chainName).Debug("Found forward-reference")
			newHashes[chainName] = []string{}
			continue
		}

		// Look for append lines, such as "-A chain-name -m foo --foo bar"; these are the
		// actual rules.
		captures = appendRegexp.FindStringSubmatch(line)
		if captures == nil {
			// Skip any non-append lines.
			logCxt.Debug("Not an append, skipping")
			continue
		}
		chainName := captures[1]

		// Look for one of our hashes on the rule.  We record a zero hash for unknown rules
		// so that they get cleaned up.
		hash := ""
		captures = t.hashCommentRegexp.FindStringSubmatch(line)
		if captures != nil {
			hash = captures[1]
			logCxt.WithField("hash", hash).Debug("Found felix hash")
		}
		newHashes[chainName] = append(newHashes[chainName], hash)
	}
	log.WithField("newHashes", newHashes).Debug("Read hashes from dataplane")
	return newHashes
}

func (t *Table) Apply() {
	// Retry until we succeed.  There are several reasons that updating iptables may fail:
	// - a concurrent write may invalidate iptables-restore's compare-and-swap
	// - another process may have clobbered some of our state, resulting in inconsistencies
	//   in what we try to program.
	for {
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
		break
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
		chainNeedsToBeFlushed := false
		if _, ok := t.chainNameToChain[chainName]; !ok {
			// About to delete this chain, flush it first to sever dependencies.
			chainNeedsToBeFlushed = true
		} else if _, ok := t.chainToDataplaneHashes[chainName]; !ok {
			// Chain doesn't exist in dataplane, mark it for creation.
			chainNeedsToBeFlushed = true
		}
		if chainNeedsToBeFlushed {
			inputBuf.WriteString(fmt.Sprintf(":%s - -\n", chainName))
		}
		return nil
	})

	// Make a second pass over the dirty chains.  This time, we write out the rule changes.
	newHashes := map[string][]string{}
	t.dirtyChains.Iter(func(item interface{}) error {
		chainName := item.(string)
		if chain, ok := t.chainNameToChain[chainName]; !ok {
			// Chain deletion
			// TODO(smc) Might need to do deletions in a second pass because can fail if someone else is referencing our chain.
			inputBuf.WriteString(fmt.Sprintf("--delete-chain %s\n", chainName))
			newHashes[chainName] = nil
		} else {
			// Chain update or creation.  Scan the chain against its previous hashes
			// and replace/append/delete as appropriate.
			previousHashes := t.chainToDataplaneHashes[chainName]
			currentHashes := chain.RuleHashes()
			newHashes[chainName] = currentHashes
			for i := 0; i < len(previousHashes) || i < len(currentHashes); i++ {
				var line string
				if i < len(previousHashes) && i < len(currentHashes) {
					if previousHashes[i] != currentHashes[i] {
						// Hash doesn't match, replace the rule.
						ruleNum := i + 1 // 1-indexed.
						comment := t.commentFrag(currentHashes[i])
						line = fmt.Sprintf("-R %s %d %s %s %s\n", chainName, ruleNum, comment,
							chain.Rules[i].MatchCriteria, chain.Rules[i].Action.ToFragment())
					}
				} else if i < len(previousHashes) {
					// previousHashes was longer, remove the old rules from the end.
					ruleNum := len(currentHashes) + 1 // 1-indexed
					line = fmt.Sprintf("-D %s %d\n", chainName, ruleNum)
				} else {
					// currentHashes was longer.  Append.
					comment := t.commentFrag(currentHashes[i])
					line = fmt.Sprintf("-A %s %s %s %s\n", chainName, comment,
						chain.Rules[i].MatchCriteria, chain.Rules[i].Action.ToFragment())
				}
				inputBuf.WriteString(line)
			}
		}
		return nil
	})

	// iptables-restore input ends with a COMMIT.
	inputBuf.WriteString("COMMIT\n")

	// Actually execute iptables-restore.
	if log.GetLevel() >= log.DebugLevel {
		log.WithField("iptablesInput", inputBuf.String()).Debug("Writing to iptables")
	}
	var outputBuf, errBuf bytes.Buffer
	cmd := exec.Command(t.restoreCmd, "--noflush", "--verbose")
	cmd.Stdin = &inputBuf
	cmd.Stdout = &outputBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	if err != nil {
		log.WithFields(log.Fields{
			"output":      outputBuf.String(),
			"errorOutput": errBuf.String(),
			"error":       err,
		}).Warn("Failed to execute iptable restore command")
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

func (t *Table) commentFrag(hash string) string {
	return fmt.Sprintf(`-m comment --comment "%s%s"`, t.hashCommentPrefix, hash)
}
