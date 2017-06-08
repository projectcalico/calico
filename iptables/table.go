// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.
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
	"os/exec"
	"reflect"
	"regexp"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/projectcalico/felix/set"
)

const (
	MaxChainNameLength = 28
)

var (
	// List of all the top-level kernel-created chains by iptables table.
	tableToKernelChains = map[string][]string{
		"filter": []string{"INPUT", "FORWARD", "OUTPUT"},
		"nat":    []string{"PREROUTING", "INPUT", "OUTPUT", "POSTROUTING"},
		"mangle": []string{"PREROUTING", "INPUT", "FORWARD", "OUTPUT", "POSTROUTING"},
		"raw":    []string{"PREROUTING", "OUTPUT"},
	}

	// chainCreateRegexp matches iptables-save output lines for chain forward reference lines.
	// It captures the name of the chain.
	chainCreateRegexp = regexp.MustCompile(`^:(\S+)`)
	// appendRegexp matches an iptables-save output line for an append operation.
	appendRegexp = regexp.MustCompile(`^-A (\S+)`)

	// Prometheus metrics.
	countNumRestoreCalls = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "felix_iptables_restore_calls",
		Help: "Number of iptables-restore calls.",
	})
	countNumRestoreErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "felix_iptables_restore_errors",
		Help: "Number of iptables-restore errors.",
	})
	countNumSaveCalls = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "felix_iptables_save_calls",
		Help: "Number of iptables-save calls.",
	})
	countNumSaveErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "felix_iptables_save_errors",
		Help: "Number of iptables-save errors.",
	})
	gaugeNumChains = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "felix_iptables_chains",
		Help: "Number of active iptables chains.",
	}, []string{"ip_version", "table"})
	gaugeNumRules = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "felix_iptables_rules",
		Help: "Number of active iptables rules.",
	}, []string{"ip_version", "table"})
	countNumLinesExecuted = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "felix_iptables_lines_executed",
		Help: "Number of iptables rule updates executed.",
	}, []string{"ip_version", "table"})
)

func init() {
	prometheus.MustRegister(countNumRestoreCalls)
	prometheus.MustRegister(countNumRestoreErrors)
	prometheus.MustRegister(countNumSaveCalls)
	prometheus.MustRegister(countNumSaveErrors)
	prometheus.MustRegister(gaugeNumChains)
	prometheus.MustRegister(gaugeNumRules)
	prometheus.MustRegister(countNumLinesExecuted)
}

// Table represents a single one of the iptables tables i.e. "raw", "nat", "filter", etc.  It
// caches the desired state of that table, then attempts to bring it into sync when Apply() is
// called.
//
// API Model
//
// Table supports two classes of operation:  "rule insertions" and "full chain updates".
//
// As the name suggests, rule insertions allow for inserting one or more rules into a pre-existing
// chain.  Rule insertions are intended to be used to hook kernel chains (such as "FORWARD") in
// order to direct them to a Felix-owned chain.  It is important to minimise the use of rule
// insertions because the top-level chains are shared resources, which can be modified by other
// applications.  In addition, rule insertions are harder to clean up after an upgrade to a new
// version of Felix (because we need a way to recognise our rules in a crowded chain).
//
// Full chain updates replace the entire contents of a Felix-owned chain with a new set of rules.
// Limiting the operation to "replace whole chain" in this way significantly simplifies the API.
// Although the API operates on full chains, the dataplane write logic tries to avoid rewriting
// a whole chain if only part of it has changed (this was not the case in Felix 1.4).  This
// prevents iptables counters from being reset unnecessarily.
//
// In either case, the actual dataplane updates are deferred until the next call to Apply() so
// chain updates and insertions may occur in any order as long as they are consistent (i.e. there
// are no references to non-existent chains) by the time Apply() is called.
//
// Design
//
// We had several goals in designing the iptables machinery in 2.0.0:
//
// (1) High performance. Felix needs to handle high churn of endpoints and rules.
//
// (2) Ability to restore rules, even if other applications accidentally break them: we found that
// other applications sometimes misuse iptables-save and iptables-restore to do a read, modify,
// write cycle. That behaviour is not safe under concurrent modification.
//
// (3) Avoid rewriting rules that haven't changed so that we don't reset iptables counters.
//
// (4) Avoid parsing iptables commands (for example, the output from iptables/iptables-save).
// This is very hard to do robustly because iptables rules do not necessarily round-trip through
// the kernel in the same form.  In addition, the format could easily change due to changes or
// fixes in the iptables/iptables-save command.
//
// (5) Support for graceful restart.  I.e. deferring potentially incorrect updates until we're
// in-sync with the datastore.  For example, if we have 100 endpoints on a host, after a restart
// we don't want to write a "dispatch" chain when we learn about the first endpoint (possibly
// replacing an existing one that had all 100 endpoints in place and causing traffic to glitch);
// instead, we want to defer until we've seen all 100 and then do the write.
//
// (6) Improved handling of rule inserts vs Felix 1.4.x.  Previous versions of Felix sometimes
// inserted special-case rules that were not marked as Calico rules in any sensible way making
// cleanup of those rules after an upgrade difficult.
//
// Implementation
//
// For high performance (goal 1), we use iptables-restore to do bulk updates to iptables.  This is
// much faster than individual iptables calls.
//
// To allow us to restore rules after they are clobbered by another process (goal 2), we cache
// them at this layer.  This means that we don't need a mechanism to ask the other layers of Felix
// to do a resync.  Note: Table doesn't start a thread of its own so it relies on the main event
// loop to trigger any dataplane resync polls.
//
// There is tension between goals 3 and 4.  In order to avoid full rewrites (goal 3), we need to
// know what rules are in place, but we also don't want to parse them to find out (goal 4)!  As
// a compromise, we deterministically calculate an ID for each rule and store it in an iptables
// comment.  Then, when we want to know what rules are in place, we _do_ parse the output from
// iptables-save, but only to read back the rule IDs.  That limits the amount of parsing we need
// to do and keeps it manageable/robust.
//
// To support graceful restart (goal 5), we defer updates to the dataplane until Apply() is called,
// then we do an atomic update using iptables-restore.  As long as the first Apply() call is
// after we're in sync, the dataplane won't be touched until the right time.  Felix 1.4.x had a
// more complex mechanism to support partial updates during the graceful restart period but
// Felix 2.0.0 resyncs so quickly that the added complexity is not justified.
//
// To make it easier to manage rule insertions (goal 6), we add rule IDs to those too.  With
// rule IDs in place, we can easily distinguish Calico rules from non-Calico rules without needing
// to know exactly which rules to expect.  To deal with cleanup after upgrade from older versions
// that did not write rule IDs, we support special-case regexes to detect our old rules.
//
// Thread safety
//
// Table doesn't do any internal synchronization, its methods should only be called from one
// thread.  To avoid conflicts in the dataplane itself, there should only be one instance of
// Table for each iptable table in an application.
type Table struct {
	Name      string
	IPVersion uint8

	// chainToInsertedRules maps from chain name to a list of rules to be inserted at the start
	// of that chain.  Rules are written with rule hash comments.  The Table cleans up inserted
	// rules with unknown hashes.
	chainToInsertedRules map[string][]Rule
	dirtyInserts         set.Set

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
	// oldInsertRegexp matches inserted rules from old pre rule-hash versions of felix.
	oldInsertRegexp *regexp.Regexp

	iptablesRestoreCmd string
	iptablesSaveCmd    string

	// insertMode is either "insert" or "append"; whether we insert our rules or append them
	// to top-level chains.
	insertMode string

	// Record when we did our most recent reads and writes of the table.  We use these to
	// calculate the next time we should force a refresh.
	lastReadTime      time.Time
	lastWriteTime     time.Time
	postWriteInterval time.Duration
	refreshInterval   time.Duration

	logCxt *log.Entry

	gaugeNumChains        prometheus.Gauge
	gaugeNumRules         prometheus.Gauge
	countNumLinesExecuted prometheus.Counter

	// Factory for making commands, used by UTs to shim exec.Command().
	newCmd cmdFactory
	// Shims for time.XXX functions:
	timeSleep func(d time.Duration)
	timeNow   func() time.Time
}

type TableOptions struct {
	HistoricChainPrefixes    []string
	ExtraCleanupRegexPattern string
	InsertMode               string
	RefreshInterval          time.Duration

	// NewCmdOverride for tests, if non-nil, factory to use instead of the real exec.Command()
	NewCmdOverride cmdFactory
	// SleepOverride for tests, if non-nil, replacement for time.Sleep()
	SleepOverride func(d time.Duration)
	// NowOverride for tests, if non-nil, replacement for time.Now()
	NowOverride func() time.Time
}

func NewTable(
	name string,
	ipVersion uint8,
	hashPrefix string,
	options TableOptions,
) *Table {
	// Calculate the regex used to match the hash comment.  The comment looks like this:
	// --comment "cali:abcd1234_-".
	hashCommentRegexp := regexp.MustCompile(`--comment "?` + hashPrefix + `([a-zA-Z0-9_-]+)"?`)
	ourChainsPattern := "^(" + strings.Join(options.HistoricChainPrefixes, "|") + ")"
	ourChainsRegexp := regexp.MustCompile(ourChainsPattern)

	oldInsertRegexpParts := []string{}
	for _, prefix := range options.HistoricChainPrefixes {
		part := fmt.Sprintf("(?:-j|--jump) %s", prefix)
		oldInsertRegexpParts = append(oldInsertRegexpParts, part)
	}
	if options.ExtraCleanupRegexPattern != "" {
		oldInsertRegexpParts = append(oldInsertRegexpParts,
			options.ExtraCleanupRegexPattern)
	}
	oldInsertPattern := strings.Join(oldInsertRegexpParts, "|")
	oldInsertRegexp := regexp.MustCompile(oldInsertPattern)

	// Pre-populate the insert table with empty lists for each kernel chain.  Ensures that we
	// clean up any chains that we hooked on a previous run.
	inserts := map[string][]Rule{}
	dirtyInserts := set.New()
	for _, kernelChain := range tableToKernelChains[name] {
		inserts[kernelChain] = []Rule{}
		dirtyInserts.Add(kernelChain)
	}

	var insertMode string
	switch options.InsertMode {
	case "", "insert":
		insertMode = "insert"
	case "append":
		insertMode = "append"
	default:
		log.WithField("insertMode", options.InsertMode).Panic("Unknown insert mode")
	}

	// Allow override of exec.Command() and time.Sleep() for test purposes.
	newCmd := newRealCmd
	if options.NewCmdOverride != nil {
		newCmd = options.NewCmdOverride
	}
	sleep := time.Sleep
	if options.SleepOverride != nil {
		sleep = options.SleepOverride
	}
	now := time.Now
	if options.NowOverride != nil {
		now = options.NowOverride
	}

	table := &Table{
		Name:                   name,
		IPVersion:              ipVersion,
		chainToInsertedRules:   inserts,
		dirtyInserts:           dirtyInserts,
		chainNameToChain:       map[string]*Chain{},
		dirtyChains:            set.New(),
		chainToDataplaneHashes: map[string][]string{},
		logCxt: log.WithFields(log.Fields{
			"ipVersion": ipVersion,
			"table":     name,
		}),
		hashCommentPrefix: hashPrefix,
		hashCommentRegexp: hashCommentRegexp,
		ourChainsRegexp:   ourChainsRegexp,
		oldInsertRegexp:   oldInsertRegexp,
		insertMode:        insertMode,

		// Initialise the write tracking as if we'd just done a write, this will trigger
		// us to recheck the dataplane at exponentially increasing intervals at startup.
		// Note: if we didn't do this, the calculation logic would need to be modified
		// to cope with zero values for these fields.
		lastWriteTime:     now(),
		postWriteInterval: 50 * time.Millisecond,

		refreshInterval: options.RefreshInterval,

		newCmd:    newCmd,
		timeSleep: sleep,
		timeNow:   now,

		gaugeNumChains:        gaugeNumChains.WithLabelValues(fmt.Sprintf("%d", ipVersion), name),
		gaugeNumRules:         gaugeNumRules.WithLabelValues(fmt.Sprintf("%d", ipVersion), name),
		countNumLinesExecuted: countNumLinesExecuted.WithLabelValues(fmt.Sprintf("%d", ipVersion), name),
	}

	if ipVersion == 4 {
		table.iptablesRestoreCmd = "iptables-restore"
		table.iptablesSaveCmd = "iptables-save"
	} else {
		table.iptablesRestoreCmd = "ip6tables-restore"
		table.iptablesSaveCmd = "ip6tables-save"
	}
	return table
}

func (t *Table) SetRuleInsertions(chainName string, rules []Rule) {
	t.logCxt.WithField("chainName", chainName).Debug("Updating rule insertions")
	oldRules := t.chainToInsertedRules[chainName]
	t.chainToInsertedRules[chainName] = rules
	numRulesDelta := len(rules) - len(oldRules)
	t.gaugeNumRules.Add(float64(numRulesDelta))
	t.dirtyInserts.Add(chainName)

	// Defensive: make sure we re-read the dataplane state before we make updates.  While the
	// code was originally designed not to need this, we found that other users of
	// iptables-restore can still clobber out updates so it's safest to re-read the state before
	// each write.
	t.InvalidateDataplaneCache("insertion")
}

func (t *Table) UpdateChains(chains []*Chain) {
	for _, chain := range chains {
		t.UpdateChain(chain)
	}
}

func (t *Table) UpdateChain(chain *Chain) {
	t.logCxt.WithField("chainName", chain.Name).Info("Queueing update of chain.")
	oldNumRules := 0
	if oldChain := t.chainNameToChain[chain.Name]; oldChain != nil {
		oldNumRules = len(oldChain.Rules)
	}
	t.chainNameToChain[chain.Name] = chain
	numRulesDelta := len(chain.Rules) - oldNumRules
	t.gaugeNumRules.Add(float64(numRulesDelta))
	t.dirtyChains.Add(chain.Name)

	// Defensive: make sure we re-read the dataplane state before we make updates.  While the
	// code was originally designed not to need this, we found that other users of
	// iptables-restore can still clobber out updates so it's safest to re-read the state before
	// each write.
	t.InvalidateDataplaneCache("chain update")
}

func (t *Table) RemoveChains(chains []*Chain) {
	for _, chain := range chains {
		t.RemoveChainByName(chain.Name)
	}
}

func (t *Table) RemoveChainByName(name string) {
	t.logCxt.WithField("chainName", name).Info("Queing deletion of chain.")
	if oldChain, known := t.chainNameToChain[name]; known {
		t.gaugeNumRules.Sub(float64(len(oldChain.Rules)))
		delete(t.chainNameToChain, name)
		t.dirtyChains.Add(name)
	}

	// Defensive: make sure we re-read the dataplane state before we make updates.  While the
	// code was originally designed not to need this, we found that other users of
	// iptables-restore can still clobber out updates so it's safest to re-read the state before
	// each write.
	t.InvalidateDataplaneCache("chain removal")
}

func (t *Table) loadDataplaneState() {
	// Load the hashes from the dataplane.
	t.logCxt.Info("Loading current iptables state and checking it is correct.")
	t.lastReadTime = t.timeNow()
	dataplaneHashes := t.getHashesFromDataplane()

	// Check that the rules we think we've programmed are still there and mark any inconsistent
	// chains for refresh.
	for chainName, expectedHashes := range t.chainToDataplaneHashes {
		logCxt := t.logCxt.WithField("chainName", chainName)
		if t.dirtyChains.Contains(chainName) || t.dirtyInserts.Contains(chainName) {
			// Already an update pending for this chain; no point in flagging it as
			// out-of-sync.
			logCxt.Debug("Skipping known-dirty chain")
			continue
		}
		dpHashes := dataplaneHashes[chainName]
		if !t.ourChainsRegexp.MatchString(chainName) {
			// Not one of our chains so it may be one that we're inserting rules into.
			insertedRules := t.chainToInsertedRules[chainName]
			if len(insertedRules) == 0 {
				// This chain shouldn't have any inserts, make sure that's the
				// case.  This case also covers the case where a chain was removed,
				// making dpHashes nil.
				dataplaneHasInserts := false
				for _, hash := range dpHashes {
					if hash != "" {
						dataplaneHasInserts = true
						break
					}
				}
				if dataplaneHasInserts {
					logCxt.WithField("actualRuleIDs", dpHashes).Warn(
						"Chain had unexpected inserts, marking for resync")
					t.dirtyInserts.Add(chainName)
				}
				continue
			}

			// Re-calculate the expected rule insertions based on the current length
			// of the chain (since other processes may have inserted/removed rules
			// from the chain, throwing off the numbers).
			expectedHashes, _ = t.expectedHashesForInsertChain(
				chainName,
				numEmptyStrings(dpHashes),
			)
			if !reflect.DeepEqual(dpHashes, expectedHashes) {
				logCxt.WithFields(log.Fields{
					"expectedRuleIDs": expectedHashes,
					"actualRuleIDs":   dpHashes,
				}).Warn("Detected out-of-sync inserts, marking for resync")
				t.dirtyInserts.Add(chainName)
			}
		} else {
			// One of our chains, should match exactly.
			if !reflect.DeepEqual(dpHashes, expectedHashes) {
				logCxt.Warn("Detected out-of-sync Calico chain, marking for resync")
				t.dirtyChains.Add(chainName)
			}
		}
	}

	// Now scan for chains that shouldn't be there and mark for deletion.
	t.logCxt.Debug("Scanning for unexpected iptables chains")
	for chainName, dataplaneHashes := range dataplaneHashes {
		logCxt := t.logCxt.WithField("chainName", chainName)
		if t.dirtyChains.Contains(chainName) || t.dirtyInserts.Contains(chainName) {
			// Already an update pending for this chain.
			logCxt.Debug("Skipping known-dirty chain")
			continue
		}
		if _, ok := t.chainToDataplaneHashes[chainName]; ok {
			// Chain expected, we'll have checked its contents above.
			logCxt.Debug("Skipping expected chain")
			continue
		}
		if !t.ourChainsRegexp.MatchString(chainName) {
			// Non-calico chain that is not tracked in chainToDataplaneHashes. We
			// haven't seen the chain before and we haven't been asked to insert
			// anything into it.  Check that it doesn't have an rule insertions in it
			// from a previous run of Felix.
			for _, hash := range dataplaneHashes {
				if hash != "" {
					logCxt.Info("Found unexpected insert, marking for cleanup")
					t.dirtyInserts.Add(chainName)
					break
				}
			}
			continue
		}
		// Chain exists in dataplane but not in memory, mark as dirty so we'll clean it up.
		logCxt.Info("Found unexpected chain, marking for cleanup")
		t.dirtyChains.Add(chainName)
	}

	t.logCxt.Debug("Finished loading iptables state")
	t.chainToDataplaneHashes = dataplaneHashes
	t.inSyncWithDataPlane = true
}

// expectedHashesForInsertChain calculates the expected hashes for a whole top-level chain
// given our inserts.  If we're in append mode, that consists of numNonCalicoRules empty strings
// followed by our hashes; in insert mode, the opposite way round.  To avoid recalculation, it
// returns the rule hashes as a second output.
func (t *Table) expectedHashesForInsertChain(
	chainName string,
	numNonCalicoRules int,
) (allHashes, ourHashes []string) {
	insertedRules := t.chainToInsertedRules[chainName]
	allHashes = make([]string, len(insertedRules)+numNonCalicoRules)
	ourHashes = calculateRuleInsertHashes(chainName, insertedRules)
	offset := 0
	if t.insertMode == "append" {
		log.Debug("In append mode, returning our hashes at end.")
		offset = numNonCalicoRules
	}
	for i, hash := range ourHashes {
		allHashes[i+offset] = hash
	}
	return
}

// getHashesFromDataplane loads the current state of our table and parses out the hashes that we
// add to rules.  It returns a map with an entry for each chain in the table.  Each entry is a slice
// containing the hashes for the rules in that table.  Rules with no hashes are represented by
// an empty string.
func (t *Table) getHashesFromDataplane() map[string][]string {
	retries := 3
	retryDelay := 100 * time.Millisecond
	// Retry a few times before we panic.  This deals with any transient errors and it prevents
	// us from spamming a panic into the log when we're being gracefully shut down by a SIGTERM.
	for {
		cmd := t.newCmd(t.iptablesSaveCmd, "-t", t.Name)
		countNumSaveCalls.Inc()
		output, err := cmd.Output()
		if err != nil {
			countNumSaveErrors.Inc()
			var stderr string
			if ee, ok := err.(*exec.ExitError); ok {
				stderr = string(ee.Stderr)
			}
			t.logCxt.WithError(err).WithField("stderr", stderr).Warnf("%s command failed", t.iptablesSaveCmd)
			if retries > 0 {
				retries--
				t.timeSleep(retryDelay)
				retryDelay *= 2
			} else {
				t.logCxt.Panicf("%s command failed after retries", t.iptablesSaveCmd)
			}
			continue
		}
		buf := bytes.NewBuffer(output)
		return t.getHashesFromBuffer(buf)
	}
}

// getHashesFromBuffer parses a buffer containing iptables-save output for this table, extracting
// our rule hashes.  Entries in the returned map are indexed by chain name.  For rules that we
// wrote, the hash is extracted from a comment that we added to the rule.  For rules written by
// previous versions of Felix, returns a dummy non-zero value.  For rules not written by Felix,
// returns a zero string.  Hence, the lengths of the returned values are the lengths of the chains
// whether written by Felix or not.
func (t *Table) getHashesFromBuffer(buf *bytes.Buffer) map[string][]string {
	newHashes := map[string][]string{}
	for {
		// Read the next line of the output.
		line, err := buf.ReadString('\n')
		if err != nil { // EOF
			break
		}

		// Look for lines of the form ":chain-name - [0:0]", which are forward declarations
		// for (possibly empty) chains.
		logCxt := t.logCxt.WithField("line", line)
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
		// so that they get cleaned up.  Note: we're implicitly capturing the first match
		// of the regex.  When writing the rules, we ensure that the hash is written as the
		// first comment.
		hash := ""
		captures = t.hashCommentRegexp.FindStringSubmatch(line)
		if captures != nil {
			hash = captures[1]
			logCxt.WithField("hash", hash).Debug("Found hash in rule")
		} else if t.oldInsertRegexp.FindString(line) != "" {
			logCxt.WithFields(log.Fields{
				"rule":      line,
				"chainName": chainName,
			}).Info("Found inserted rule from previous Felix version, marking for cleanup.")
			hash = "OLD INSERT RULE"
		}
		newHashes[chainName] = append(newHashes[chainName], hash)
	}
	t.logCxt.Debugf("Read hashes from dataplane: %#v", newHashes)
	return newHashes
}

func (t *Table) InvalidateDataplaneCache(reason string) {
	logCxt := t.logCxt.WithField("reason", reason)
	if !t.inSyncWithDataPlane {
		logCxt.Debug("Would invalidate dataplane cache but it was already invalid.")
		return
	}
	logCxt.Info("Invalidating dataplane cache")
	t.inSyncWithDataPlane = false
}

func (t *Table) Apply() (rescheduleAfter time.Duration) {
	now := t.timeNow()
	// We _think_ we're in sync, check if there are any reasons to think we might
	// not be in sync.
	lastReadToNow := now.Sub(t.lastReadTime)
	invalidated := false
	if t.refreshInterval > 0 && lastReadToNow > t.refreshInterval {
		// Too long since we've forced a refresh.
		t.InvalidateDataplaneCache("refresh timer")
		invalidated = true
	}
	// To workaround the possibility of another process clobbering our updates, we refresh the
	// dataplane after we do a write at exponentially increasing intervals.  We do a refresh
	// if the delta from the last write to now is twice the delta from the last read.
	for t.postWriteInterval != 0 &&
		t.postWriteInterval < time.Hour &&
		!now.Before(t.lastWriteTime.Add(t.postWriteInterval)) {

		t.postWriteInterval *= 2
		t.logCxt.WithField("newPostWriteInterval", t.postWriteInterval).Debug("Updating post-write interval")
		if !invalidated {
			t.InvalidateDataplaneCache("post update")
			invalidated = true
		}
	}

	// Retry until we succeed.  There are several reasons that updating iptables may fail:
	//
	// - A concurrent write may invalidate iptables-restore's compare-and-swap; this manifests
	//   as a failure on the COMMIT line.
	// - Another process may have clobbered some of our state, resulting in inconsistencies
	//   in what we try to program.  This could manifest in a number of ways depending on what
	//   the other process did.
	// - Random transient failure.
	//
	// It's also possible that we're bugged and trying to write bad data so we give up
	// eventually.
	retries := 10
	backoffTime := 1 * time.Millisecond
	failedAtLeastOnce := false
	for {
		if !t.inSyncWithDataPlane {
			// We have reason to believe that our picture of the dataplane is out of
			// sync.  Refresh it.  This may mark more chains as dirty.
			t.loadDataplaneState()
		}

		if err := t.applyUpdates(); err != nil {
			if retries > 0 {
				retries--
				t.logCxt.WithError(err).Warn("Failed to program iptables, will retry")
				t.timeSleep(backoffTime)
				backoffTime *= 2
				t.logCxt.WithError(err).Warn("Retrying...")
				failedAtLeastOnce = true
				continue
			} else {
				t.logCxt.WithError(err).Error("Failed to program iptables, loading diags before panic.")
				cmd := t.newCmd(t.iptablesSaveCmd, "-t", t.Name)
				output, err2 := cmd.Output()
				if err2 != nil {
					t.logCxt.WithError(err2).Error("Failed to load iptables state")
				} else {
					t.logCxt.WithField("iptablesState", string(output)).Error("Current state of iptables")
				}
				t.logCxt.WithError(err).Panic("Failed to program iptables, giving up after retries")
			}
		}
		if failedAtLeastOnce {
			t.logCxt.Warn("Succeeded after retry.")
		}
		break
	}

	t.gaugeNumChains.Set(float64(len(t.chainNameToChain)))

	// Check whether we need to be rescheduled and how soon.
	if t.refreshInterval > 0 {
		// Refresh interval is set, start with that.
		lastReadToNow = now.Sub(t.lastReadTime)
		rescheduleAfter = t.refreshInterval - lastReadToNow
	}
	if t.postWriteInterval < time.Hour {
		postWriteReched := t.lastWriteTime.Add(t.postWriteInterval).Sub(now)
		if postWriteReched <= 0 {
			rescheduleAfter = 1 * time.Millisecond
		} else if t.refreshInterval <= 0 || postWriteReched < rescheduleAfter {
			rescheduleAfter = postWriteReched
		}
	}

	return
}

func (t *Table) applyUpdates() error {
	var inputBuf bytes.Buffer
	// iptables-restore input starts with a line indicating the table name.
	tableNameLine := fmt.Sprintf("*%s\n", t.Name)
	inputBuf.WriteString(tableNameLine)

	// Make a pass over the dirty chains and generate a forward reference for any that need to
	// be created or flushed.
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
			t.countNumLinesExecuted.Inc()
		}
		return nil
	})

	// Make a second pass over the dirty chains.  This time, we write out the rule changes.
	newHashes := map[string][]string{}
	t.dirtyChains.Iter(func(item interface{}) error {
		chainName := item.(string)
		if chain, ok := t.chainNameToChain[chainName]; ok {
			// Chain update or creation.  Scan the chain against its previous hashes
			// and replace/append/delete as appropriate.
			previousHashes := t.chainToDataplaneHashes[chainName]
			currentHashes := chain.RuleHashes()
			newHashes[chainName] = currentHashes
			for i := 0; i < len(previousHashes) || i < len(currentHashes); i++ {
				var line string
				if i < len(previousHashes) && i < len(currentHashes) {
					if previousHashes[i] == currentHashes[i] {
						continue
					}
					// Hash doesn't match, replace the rule.
					ruleNum := i + 1 // 1-indexed.
					prefixFrag := t.commentFrag(currentHashes[i])
					line = chain.Rules[i].RenderReplace(chainName, ruleNum, prefixFrag)
				} else if i < len(previousHashes) {
					// previousHashes was longer, remove the old rules from the end.
					ruleNum := len(currentHashes) + 1 // 1-indexed
					line = deleteRule(chainName, ruleNum)
				} else {
					// currentHashes was longer.  Append.
					prefixFrag := t.commentFrag(currentHashes[i])
					line = chain.Rules[i].RenderAppend(chainName, prefixFrag)
				}
				inputBuf.WriteString(line)
				inputBuf.WriteString("\n")
				t.countNumLinesExecuted.Inc()
			}
		}
		return nil // Delay clearing the set until we've programmed iptables.
	})

	// Now calculate iptables updates for our inserted rules, which are used to hook top-level
	// chains.
	t.dirtyInserts.Iter(func(item interface{}) error {
		chainName := item.(string)
		previousHashes := t.chainToDataplaneHashes[chainName]

		// Calculate the hashes for our inserted rules.
		newChainHashes, newRuleHashes := t.expectedHashesForInsertChain(
			chainName, numEmptyStrings(previousHashes))

		if reflect.DeepEqual(newChainHashes, previousHashes) {
			// Chain is in sync, skip to next one.
			return nil
		}

		// For simplicity, if we've discovered that we're out-of-sync, remove all our
		// rules from this chain, then re-insert/re-append them below.
		//
		// Remove in reverse order so that we don't disturb the rule numbers of rules we're
		// about to remove.
		for i := len(previousHashes) - 1; i >= 0; i-- {
			if previousHashes[i] != "" {
				ruleNum := i + 1
				line := deleteRule(chainName, ruleNum)
				inputBuf.WriteString(line)
				inputBuf.WriteString("\n")
				t.countNumLinesExecuted.Inc()
			}
		}

		rules := t.chainToInsertedRules[chainName]
		if t.insertMode == "insert" {
			t.logCxt.Debug("Rendering insert rules.")
			// Since each insert is pushed onto the top of the chain, do the inserts in
			// reverse order so that they end up in the correct order in the final
			// state of the chain.
			for i := len(rules) - 1; i >= 0; i-- {
				prefixFrag := t.commentFrag(newRuleHashes[i])
				line := rules[i].RenderInsert(chainName, prefixFrag)
				inputBuf.WriteString(line)
				inputBuf.WriteString("\n")
				t.countNumLinesExecuted.Inc()
			}
		} else {
			t.logCxt.Debug("Rendering append rules.")
			for i := 0; i < len(rules); i++ {
				prefixFrag := t.commentFrag(newRuleHashes[i])
				line := rules[i].RenderAppend(chainName, prefixFrag)
				inputBuf.WriteString(line)
				inputBuf.WriteString("\n")
				t.countNumLinesExecuted.Inc()
			}
		}

		newHashes[chainName] = newChainHashes

		return nil // Delay clearing the set until we've programmed iptables.
	})

	// Do deletions at the end.  This ensures that we don't try to delete any chains that
	// are still referenced (because we'll have removed the references in the modify pass
	// above).  Note: if a chain is being deleted at the same time as a chain that it refers to
	// then we'll issue a create+flush instruction in the very first pass, which will sever the
	// references.
	t.dirtyChains.Iter(func(item interface{}) error {
		chainName := item.(string)
		if _, ok := t.chainNameToChain[chainName]; !ok {
			// Chain deletion
			inputBuf.WriteString(fmt.Sprintf("--delete-chain %s\n", chainName))
			t.countNumLinesExecuted.Inc()
			newHashes[chainName] = nil
		}
		return nil // Delay clearing the set until we've programmed iptables.
	})

	if inputBuf.Len() > len(tableNameLine) {
		// We've figured out that we need to make some changes, finish off the input then
		// execute iptables-restore.  iptables-restore input ends with a COMMIT.
		inputBuf.WriteString("COMMIT\n")

		// Annoying to have to copy the buffer here but reading from a buffer is
		// destructive so if we want to trace out the contents after a failure, we have to
		// take a copy.
		input := inputBuf.String()
		t.logCxt.WithField("iptablesInput", input).Debug("Writing to iptables")

		var outputBuf, errBuf bytes.Buffer
		cmd := t.newCmd(t.iptablesRestoreCmd, "--noflush", "--verbose")
		cmd.SetStdin(&inputBuf)
		cmd.SetStdout(&outputBuf)
		cmd.SetStderr(&errBuf)
		countNumRestoreCalls.Inc()
		err := cmd.Run()
		if err != nil {
			t.logCxt.WithFields(log.Fields{
				"output":      outputBuf.String(),
				"errorOutput": errBuf.String(),
				"error":       err,
				"input":       input,
			}).Warn("Failed to execute ip(6)tables-restore command")
			t.inSyncWithDataPlane = false
			countNumRestoreErrors.Inc()
			return err
		}
		t.lastWriteTime = t.timeNow()
		t.postWriteInterval = 50 * time.Millisecond
	}

	// Now we've successfully updated iptables, clear the dirty sets.  We do this even if we
	// found there was nothing to do above, since we may have found out that a dirty chain
	// was actually a no-op update.
	t.dirtyChains = set.New()
	t.dirtyInserts = set.New()

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

func deleteRule(chainName string, ruleNum int) string {
	return fmt.Sprintf("-D %s %d", chainName, ruleNum)
}

func calculateRuleInsertHashes(chainName string, rules []Rule) []string {
	chain := Chain{
		Name:  chainName,
		Rules: rules,
	}
	return (&chain).RuleHashes()
}

func numEmptyStrings(strs []string) int {
	count := 0
	for _, s := range strs {
		if s == "" {
			count++
		}
	}
	return count
}
