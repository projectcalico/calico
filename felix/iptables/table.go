// Copyright (c) 2016-2020 Tigera, Inc. All rights reserved.
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
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/set"

	"github.com/projectcalico/calico/felix/detector"
	"github.com/projectcalico/calico/felix/iptables/cmdshim"
	"github.com/projectcalico/calico/felix/logutils"
)

const (
	MaxChainNameLength   = 28
	minPostWriteInterval = 50 * time.Millisecond
)

var (
	// List of all the top-level kernel-created chains by iptables table.
	tableToKernelChains = map[string][]string{
		"filter": {"INPUT", "FORWARD", "OUTPUT"},
		"nat":    {"PREROUTING", "INPUT", "OUTPUT", "POSTROUTING"},
		"mangle": {"PREROUTING", "INPUT", "FORWARD", "OUTPUT", "POSTROUTING"},
		"raw":    {"PREROUTING", "OUTPUT"},
	}

	// chainCreateRegexp matches iptables-save output lines for chain forward reference lines.
	// It captures the name of the chain.
	chainCreateRegexp = regexp.MustCompile(`^:(\S+)`)
	// appendRegexp matches an iptables-save output line for an append operation.
	appendRegexp = regexp.MustCompile(`^-A (\S+)`)
	// nftErrorRegexp matches a particular error emitted if iptables-nft is run on a system that
	// uses nft features that iptables-nft doesn't understand.
	nftErrorRegexp = regexp.MustCompile(`^# Table .* is incompatible, use 'nft' tool.`)

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

	// featureDetector detects the features of the dataplane.
	featureDetector *detector.FeatureDetector

	// chainToInsertedRules maps from chain name to a list of rules to be inserted at the start
	// of that chain.  Rules are written with rule hash comments.  The Table cleans up inserted
	// rules with unknown hashes.
	chainToInsertedRules map[string][]Rule
	// chainToAppendRules maps from chain name to a list of rules to be appended at the end
	// of that chain.
	chainToAppendedRules map[string][]Rule
	dirtyInsertAppend    set.Set

	// chainToRuleFragments contains the desired state of our iptables chains, indexed by
	// chain name.  The values are slices of iptables fragments, such as
	// "--match foo --jump DROP" (i.e. omitting the action and chain name, which are calculated
	// as needed).
	chainNameToChain map[string]*Chain
	// chainRefCounts counts the number of chains that refer to a given chain.  Transitive
	// reachability isn't tracked but testing whether a chain is referenced does allow us to
	// avoid programming unreferenced leaf chains (for example, policies that aren't used in
	// this table).
	chainRefCounts map[string]int
	dirtyChains    set.Set

	inSyncWithDataPlane bool

	// chainToDataplaneHashes contains the rule hashes that we think are in the dataplane.
	// it is updated when we write to the dataplane but it can also be read back and compared
	// to what we calculate from chainToContents.
	chainToDataplaneHashes map[string][]string

	// chainToFullRules contains the full rules for any chains that we may be hooking into, mapped from chain name
	// to slices of rules in that chain.
	chainToFullRules map[string][]string

	// hashCommentPrefix holds the prefix that we prepend to our rule-tracking hashes.
	hashCommentPrefix string
	// hashCommentRegexp matches the rule-tracking comment, capturing the rule hash.
	hashCommentRegexp *regexp.Regexp
	// ourChainsRegexp matches the names of chains that are "ours", i.e. start with one of our
	// prefixes.
	ourChainsRegexp *regexp.Regexp
	// oldInsertRegexp matches inserted rules from old pre rule-hash versions of felix.
	oldInsertRegexp *regexp.Regexp

	// nftablesMode should be set to true if iptables is using the nftables backend.
	nftablesMode       bool
	iptablesRestoreCmd string
	iptablesSaveCmd    string

	// insertMode is either "insert" or "append"; whether we insert our rules or append them
	// to top-level chains.
	insertMode string

	// Record when we did our most recent reads and writes of the table.  We use these to
	// calculate the next time we should force a refresh.
	lastReadTime             time.Time
	lastWriteTime            time.Time
	initialPostWriteInterval time.Duration
	postWriteInterval        time.Duration
	refreshInterval          time.Duration

	// calicoXtablesLock, if enabled, our implementation of the xtables lock.
	calicoXtablesLock sync.Locker

	// lockTimeout is the timeout used for iptables-restore's native xtables lock implementation.
	lockTimeout time.Duration
	// lockTimeout is the lock probe interval used for iptables-restore's native xtables lock
	// implementation.
	lockProbeInterval time.Duration

	logCxt *log.Entry

	gaugeNumChains        prometheus.Gauge
	gaugeNumRules         prometheus.Gauge
	countNumLinesExecuted prometheus.Counter

	// Reusable buffer for writing to iptables.
	restoreInputBuffer RestoreInputBuilder

	// Factory for making commands, used by UTs to shim exec.Command().
	newCmd cmdshim.CmdFactory
	// Shims for time.XXX functions:
	timeSleep func(d time.Duration)
	timeNow   func() time.Time
	// lookPath is a shim for exec.LookPath.
	lookPath func(file string) (string, error)

	onStillAlive func()
	opReporter   logutils.OpRecorder
}

type TableOptions struct {
	HistoricChainPrefixes    []string
	ExtraCleanupRegexPattern string
	BackendMode              string
	InsertMode               string
	RefreshInterval          time.Duration
	PostWriteInterval        time.Duration

	// LockTimeout is the timeout to use for iptables-restore's native xtables lock.
	LockTimeout time.Duration
	// LockProbeInterval is the probe interval to use for iptables-restore's native xtables lock.
	LockProbeInterval time.Duration

	// NewCmdOverride for tests, if non-nil, factory to use instead of the real exec.Command()
	NewCmdOverride cmdshim.CmdFactory
	// SleepOverride for tests, if non-nil, replacement for time.Sleep()
	SleepOverride func(d time.Duration)
	// NowOverride for tests, if non-nil, replacement for time.Now()
	NowOverride func() time.Time
	// LookPathOverride for tests, if non-nil, replacement for exec.LookPath()
	LookPathOverride func(file string) (string, error)
	// Thunk to call periodically when doing a long-running operation.
	OnStillAlive func()
	// OpRecorder to tell when we do resyncs etc.
	OpRecorder logutils.OpRecorder
}

func NewTable(
	name string,
	ipVersion uint8,
	hashPrefix string,
	iptablesWriteLock sync.Locker,
	featuredetector *detector.FeatureDetector,
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
	log.WithField("pattern", oldInsertPattern).Info("Calculated old-insert detection regex.")
	oldInsertRegexp := regexp.MustCompile(oldInsertPattern)

	// Pre-populate the insert and append table with empty lists for each kernel chain.  Ensures that we
	// clean up any chains that we hooked on a previous run.
	inserts := map[string][]Rule{}
	appends := map[string][]Rule{}
	dirtyInsertAppend := set.New()
	refcounts := map[string]int{}
	for _, kernelChain := range tableToKernelChains[name] {
		inserts[kernelChain] = []Rule{}
		appends[kernelChain] = []Rule{}
		dirtyInsertAppend.Add(kernelChain)
		// Kernel chains are referred to by definition.
		refcounts[kernelChain] += 1
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

	if options.PostWriteInterval <= minPostWriteInterval {
		log.WithFields(log.Fields{
			"setValue": options.PostWriteInterval,
			"default":  minPostWriteInterval,
		}).Info("PostWriteInterval too small, defaulting.")
		options.PostWriteInterval = minPostWriteInterval
	}

	// Allow override of exec.Command() and time.Sleep() for test purposes.
	newCmd := cmdshim.NewRealCmd
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
	lookPath := exec.LookPath
	if options.LookPathOverride != nil {
		lookPath = options.LookPathOverride
	}

	table := &Table{
		Name:                   name,
		IPVersion:              ipVersion,
		featureDetector:        featuredetector,
		chainToInsertedRules:   inserts,
		chainToAppendedRules:   appends,
		dirtyInsertAppend:      dirtyInsertAppend,
		chainNameToChain:       map[string]*Chain{},
		chainRefCounts:         refcounts,
		dirtyChains:            set.New(),
		chainToDataplaneHashes: map[string][]string{},
		chainToFullRules:       map[string][]string{},
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
		lastWriteTime:            now(),
		initialPostWriteInterval: options.PostWriteInterval,
		postWriteInterval:        options.PostWriteInterval,

		refreshInterval: options.RefreshInterval,

		calicoXtablesLock: iptablesWriteLock,

		lockTimeout:       options.LockTimeout,
		lockProbeInterval: options.LockProbeInterval,

		newCmd:    newCmd,
		timeSleep: sleep,
		timeNow:   now,
		lookPath:  lookPath,

		gaugeNumChains:        gaugeNumChains.WithLabelValues(fmt.Sprintf("%d", ipVersion), name),
		gaugeNumRules:         gaugeNumRules.WithLabelValues(fmt.Sprintf("%d", ipVersion), name),
		countNumLinesExecuted: countNumLinesExecuted.WithLabelValues(fmt.Sprintf("%d", ipVersion), name),
		opReporter:            options.OpRecorder,
	}
	table.restoreInputBuffer.NumLinesWritten = table.countNumLinesExecuted

	if options.OnStillAlive != nil {
		table.onStillAlive = options.OnStillAlive
	} else {
		table.onStillAlive = func() {}
	}

	iptablesVariant := strings.ToLower(options.BackendMode)
	if iptablesVariant == "" {
		iptablesVariant = "legacy"
	}
	if iptablesVariant == "nft" {
		log.Info("Enabling iptables-in-nftables-mode workarounds.")
		table.nftablesMode = true
	}

	table.iptablesRestoreCmd = detector.FindBestBinary(table.lookPath, ipVersion, iptablesVariant, "restore")
	table.iptablesSaveCmd = detector.FindBestBinary(table.lookPath, ipVersion, iptablesVariant, "save")

	return table
}

// Insert or Append rules based on insert mode configuration.
func (t *Table) InsertOrAppendRules(chainName string, rules []Rule) {
	t.logCxt.WithField("chainName", chainName).Debug("Updating rule insertions")
	oldRules := t.chainToInsertedRules[chainName]
	t.chainToInsertedRules[chainName] = rules
	numRulesDelta := len(rules) - len(oldRules)
	t.gaugeNumRules.Add(float64(numRulesDelta))
	t.dirtyInsertAppend.Add(chainName)

	// Incref any newly-referenced chains, then decref the old ones.  By incrementing first we
	// avoid marking a still-referenced chain as dirty.
	t.increfReferredChains(rules)
	t.decrefReferredChains(oldRules)

	// Defensive: make sure we re-read the dataplane state before we make updates.  While the
	// code was originally designed not to need this, we found that other users of
	// iptables-restore can still clobber our updates so it's safest to re-read the state before
	// each write.
	t.InvalidateDataplaneCache("insertion")
}

// Append rules.
func (t *Table) AppendRules(chainName string, rules []Rule) {
	t.logCxt.WithField("chainName", chainName).Debug("Updating rule appends")
	oldRules := t.chainToAppendedRules[chainName]
	t.chainToAppendedRules[chainName] = rules
	numRulesDelta := len(rules) - len(oldRules)
	t.gaugeNumRules.Add(float64(numRulesDelta))
	t.dirtyInsertAppend.Add(chainName)

	// Incref any newly-referenced chains, then decref the old ones.  By incrementing first we
	// avoid marking a still-referenced chain as dirty.
	t.increfReferredChains(rules)
	t.decrefReferredChains(oldRules)

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

	// Incref any newly-referenced chains, then decref the old ones.  By incrementing first we
	// avoid marking a still-referenced chain as dirty.
	t.increfReferredChains(chain.Rules)
	if oldChain := t.chainNameToChain[chain.Name]; oldChain != nil {
		oldNumRules = len(oldChain.Rules)
		t.decrefReferredChains(oldChain.Rules)
	}
	t.chainNameToChain[chain.Name] = chain
	numRulesDelta := len(chain.Rules) - oldNumRules
	t.gaugeNumRules.Add(float64(numRulesDelta))
	if t.chainRefCounts[chain.Name] > 0 {
		t.dirtyChains.Add(chain.Name)
	}

	// Defensive: make sure we re-read the dataplane state before we make updates.  While the
	// code was originally designed not to need this, we found that other users of
	// iptables-restore can still clobber our updates so it's safest to re-read the state before
	// each write.
	t.InvalidateDataplaneCache("chain update")
}

func (t *Table) RemoveChains(chains []*Chain) {
	for _, chain := range chains {
		t.RemoveChainByName(chain.Name)
	}
}

func (t *Table) RemoveChainByName(name string) {
	t.logCxt.WithField("chainName", name).Info("Queuing deletion of chain.")
	if oldChain, known := t.chainNameToChain[name]; known {
		t.gaugeNumRules.Sub(float64(len(oldChain.Rules)))
		delete(t.chainNameToChain, name)
		if t.chainRefCounts[name] > 0 {
			t.dirtyChains.Add(name)
		}
		t.decrefReferredChains(oldChain.Rules)
	}

	// Defensive: make sure we re-read the dataplane state before we make updates.  While the
	// code was originally designed not to need this, we found that other users of
	// iptables-restore can still clobber out updates so it's safest to re-read the state before
	// each write.
	t.InvalidateDataplaneCache("chain removal")
}

// increfReferredChains finds all the chains that the given rules refer to  (i.e. have jumps/gotos to) and
// increments their refcount.
func (t *Table) increfReferredChains(rules []Rule) {
	for _, r := range rules {
		if ref, ok := r.Action.(Referrer); ok {
			t.increfChain(ref.ReferencedChain())
		}
	}
}

// decrefReferredChains finds all the chains that the given rules refer to (i.e. have jumps/gotos to) and
// decrements their refcount.
func (t *Table) decrefReferredChains(rules []Rule) {
	for _, r := range rules {
		if ref, ok := r.Action.(Referrer); ok {
			t.decrefChain(ref.ReferencedChain())
		}
	}
}

// increfChain increments the refcount of the given chain; if the refcount transitions from 0,
// marks the chain dirty so it will be programmed.
func (t *Table) increfChain(chainName string) {
	log.WithField("chainName", chainName).Debug("Incref chain")
	t.chainRefCounts[chainName] += 1
	if t.chainRefCounts[chainName] == 1 {
		log.WithField("chainName", chainName).Info("Chain became referenced, marking it for programming")
		t.dirtyChains.Add(chainName)
	}
}

// decrefChain decrements the refcount of the given chain; if the refcount transitions to 0,
// marks the chain dirty so it will be cleaned up.
func (t *Table) decrefChain(chainName string) {
	log.WithField("chainName", chainName).Debug("Decref chain")
	t.chainRefCounts[chainName] -= 1
	if t.chainRefCounts[chainName] == 0 {
		log.WithField("chainName", chainName).Info("Chain no longer referenced, marking it for removal")
		delete(t.chainRefCounts, chainName)
		t.dirtyChains.Add(chainName)
	}
}

func (t *Table) loadDataplaneState() {
	// Refresh the cache of feature data.
	t.featureDetector.RefreshFeatures()

	// Load the hashes from the dataplane.
	t.logCxt.Debug("Loading current iptables state and checking it is correct.")
	t.opReporter.RecordOperation(fmt.Sprintf("resync-%v-v%d", t.Name, t.IPVersion))

	t.lastReadTime = t.timeNow()
	dataplaneHashes, dataplaneRules := t.getHashesAndRulesFromDataplane()

	// Check that the rules we think we've programmed are still there and mark any inconsistent
	// chains for refresh.
	for chainName, expectedHashes := range t.chainToDataplaneHashes {
		logCxt := t.logCxt.WithField("chainName", chainName)
		if t.dirtyChains.Contains(chainName) || t.dirtyInsertAppend.Contains(chainName) {
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
					t.dirtyInsertAppend.Add(chainName)
				}
				continue
			}

			// Re-calculate the expected rule insertions based on the current length
			// of the chain (since other processes may have inserted/removed rules
			// from the chain, throwing off the numbers).
			expectedHashes, _, _ = t.expectedHashesForInsertAppendChain(
				chainName,
				numEmptyStrings(dpHashes),
			)
			if !reflect.DeepEqual(dpHashes, expectedHashes) {
				logCxt.WithFields(log.Fields{
					"expectedRuleIDs": expectedHashes,
					"actualRuleIDs":   dpHashes,
				}).Warn("Detected out-of-sync inserts, marking for resync")
				t.dirtyInsertAppend.Add(chainName)
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
		if t.dirtyChains.Contains(chainName) || t.dirtyInsertAppend.Contains(chainName) {
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
					t.dirtyInsertAppend.Add(chainName)
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
	t.chainToFullRules = dataplaneRules
	t.inSyncWithDataPlane = true
}

// expectedHashesForInsertAppendChain calculates the expected hashes for a whole top-level chain
// given our inserts and appends.
// Hashes for inserted rules are caculated first. If we're in append mode, that consists of numNonCalicoRules empty strings
// followed by our inserted hashes; in insert mode, the opposite way round. Hashes for appended rules are caculated and
// appended at the end.
// To avoid recalculation, it returns the inserted rule hashes as a second output and appended rule hashes
// a third output.
func (t *Table) expectedHashesForInsertAppendChain(
	chainName string,
	numNonCalicoRules int,
) (allHashes, ourInsertedHashes, ourAppendedHashes []string) {
	insertedRules := t.chainToInsertedRules[chainName]
	appendedRules := t.chainToAppendedRules[chainName]
	allHashes = make([]string, len(insertedRules)+len(appendedRules)+numNonCalicoRules)
	features := t.featureDetector.GetFeatures()
	if len(insertedRules) > 0 {
		ourInsertedHashes = calculateRuleHashes(chainName, insertedRules, features)
	}
	if len(appendedRules) > 0 {
		// Add *append* to chainName to produce a unique hash in case append chain/rules are same
		// as insert chain/rules above.
		ourAppendedHashes = calculateRuleHashes(chainName+"*appends*", appendedRules, features)
	}
	offset := 0
	if t.insertMode == "append" {
		log.Debug("In append mode, returning our hashes at end.")
		offset = numNonCalicoRules
	}
	for i, hash := range ourInsertedHashes {
		allHashes[i+offset] = hash
	}

	offset = len(insertedRules) + numNonCalicoRules
	for i, hash := range ourAppendedHashes {
		allHashes[i+offset] = hash
	}
	return
}

// getHashesAndRulesFromDataplane loads the current state of our table. It parses out the hashes that we
// add to rules and, for chains that we insert into, the full rules. The 'hashes' map contains an entry for each chain
// in the table. Each entry is a slice containing the hashes for the rules in that table. Rules with no hashes are
// represented by an empty string. The 'rules' map contains an entry for each non-Calico chain in the table that
// contains inserts. It is used to generate deletes using the full rule, rather than deletes by line number, to avoid
// race conditions on chains we don't fully control.
func (t *Table) getHashesAndRulesFromDataplane() (hashes map[string][]string, rules map[string][]string) {
	retries := 3
	retryDelay := 100 * time.Millisecond

	// Retry a few times before we panic.  This deals with any transient errors and it prevents
	// us from spamming a panic into the log when we're being gracefully shut down by a SIGTERM.
	for {
		t.onStillAlive()
		hashes, rules, err := t.attemptToGetHashesAndRulesFromDataplane()
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

		return hashes, rules
	}
}

// attemptToGetHashesAndRulesFromDataplane starts an iptables-save subprocess and feeds its output to
// readHashesAndRulesFrom() via a pipe.  It handles the various error cases.
func (t *Table) attemptToGetHashesAndRulesFromDataplane() (hashes map[string][]string, rules map[string][]string, err error) {
	cmd := t.newCmd(t.iptablesSaveCmd, "-t", t.Name)
	countNumSaveCalls.Inc()

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.WithError(err).Warnf("Failed to get stdout pipe for %s", t.iptablesSaveCmd)
		return
	}
	err = cmd.Start()
	if err != nil {
		// Failed even before we started, close the pipe.  (This would normally be done
		// by Wait().
		log.WithError(err).Warnf("Failed to start %s", t.iptablesSaveCmd)
		closeErr := stdout.Close()
		if closeErr != nil {
			log.WithError(closeErr).Warn("Error closing stdout after Start() failed.")
		}
		return
	}
	hashes, rules, err = t.readHashesAndRulesFrom(stdout)
	if err != nil {
		// In case readHashesAndRulesFrom() returned due to an error that didn't cause the
		// process to exit, kill it now.
		log.WithError(err).Warnf("Killing %s process after a failure", t.iptablesSaveCmd)
		killErr := cmd.Kill()
		if killErr != nil {
			// If we don't know what state the process is in, we can't Wait() on it.
			log.WithError(killErr).Panicf(
				"Failed to kill %s process after failure.", t.iptablesSaveCmd)
		}
	}
	waitErr := cmd.Wait()
	if waitErr != nil {
		log.WithError(waitErr).Warn("iptables save failed")
		if err == nil {
			err = waitErr
		}
	}
	return
}

// readHashesAndRulesFrom scans the given reader containing iptables-save output for this table, extracting
// our rule hashes and, for all chains we insert into, the full rules.  Entries in the returned map are indexed by
// chain name.  For rules that we wrote, the hash is extracted from a comment that we added to the rule.
// For rules written by previous versions of Felix, returns a dummy non-zero value.  For rules not written by Felix,
// returns a zero string.  Hence, the lengths of the returned values are the lengths of the chains
// whether written by Felix or not.
func (t *Table) readHashesAndRulesFrom(r io.ReadCloser) (hashes map[string][]string, rules map[string][]string, err error) {
	hashes = map[string][]string{}
	rules = map[string][]string{}
	scanner := bufio.NewScanner(r)

	// Keep track of whether the non-Calico chain has inserts. If the chain does not have inserts, we'll remove the
	// full rules for that chain.
	chainHasCalicoRule := set.New()

	// Figure out if debug logging is enabled so we can skip some WithFields() calls in the
	// tight loop below if the log wouldn't be emitted anyway.
	debug := log.GetLevel() >= log.DebugLevel

	for scanner.Scan() {
		// Read the next line of the output.
		line := scanner.Bytes()
		logCxt := t.logCxt
		if debug {
			// Avoid stringifying the line (and hence copying it) unless we're at debug
			// level.
			logCxt = logCxt.WithField("line", string(line))
			logCxt.Debug("Parsing line")
		}

		// Special-case, if iptables-nft can't handle a ruleset then it writes an error
		// but then returns an RC of 0.  Detect this case.
		if nftErrorRegexp.Match(line) {
			logCxt.Error("iptables-save failed because there are incompatible nft rules in the table.  " +
				"Remove the nft rules to continue.")
			return nil, nil, errors.New(
				"iptables-save failed because there are incompatible nft rules in the table")
		}

		// Look for lines of the form ":chain-name - [0:0]", which are forward declarations
		// for (possibly empty) chains.
		captures := chainCreateRegexp.FindSubmatch(line)
		if captures != nil {
			// Chain forward-reference, make sure the chain exists.
			chainName := string(captures[1])
			if debug {
				logCxt.WithField("chainName", chainName).Debug("Found forward-reference")
			}
			hashes[chainName] = []string{}
			continue
		}

		// Look for append lines, such as "-A chain-name -m foo --foo bar"; these are the
		// actual rules.
		captures = appendRegexp.FindSubmatch(line)
		if captures == nil {
			// Skip any non-append lines.
			logCxt.Debug("Not an append, skipping")
			continue
		}
		chainName := string(captures[1])

		// Look for one of our hashes on the rule.  We record a zero hash for unknown rules
		// so that they get cleaned up.  Note: we're implicitly capturing the first match
		// of the regex.  When writing the rules, we ensure that the hash is written as the
		// first comment.
		hash := ""
		captures = t.hashCommentRegexp.FindSubmatch(line)
		if captures != nil {
			hash = string(captures[1])
			if debug {
				logCxt.WithField("hash", hash).Debug("Found hash in rule")
			}
			chainHasCalicoRule.Add(chainName)
		} else if t.oldInsertRegexp.Find(line) != nil {
			logCxt.WithFields(log.Fields{
				"rule":      string(line),
				"chainName": chainName,
			}).Info("Found inserted rule from previous Felix version, marking for cleanup.")
			hash = "OLD INSERT RULE"
			chainHasCalicoRule.Add(chainName)
		}
		hashes[chainName] = append(hashes[chainName], hash)

		// Not our chain so cache the full rule in case we need to generate deletes later on.
		// After scanning the input, we prune any chains of full rules that do not contain inserts.
		if !t.ourChainsRegexp.MatchString(chainName) {
			// Only store the full rule for Calico rules. Otherwise, we just use the placeholder "-".
			fullRule := "-"
			if captures := t.hashCommentRegexp.FindSubmatch(line); captures != nil {
				fullRule = string(line)
			} else if t.oldInsertRegexp.Find(line) != nil {
				fullRule = string(line)
			}

			rules[chainName] = append(rules[chainName], fullRule)
		}
	}
	if scanner.Err() != nil {
		log.WithError(scanner.Err()).Error("Failed to read hashes from dataplane")
		return nil, nil, scanner.Err()
	}

	// Remove full rules for the non-Calico chain if it does not have inserts.
	for chainName := range rules {
		if !chainHasCalicoRule.Contains(chainName) {
			delete(rules, chainName)
		}
	}
	t.logCxt.Debugf("Read hashes from dataplane: %#v", hashes)
	t.logCxt.Debugf("Read rules from dataplane: %#v", rules)
	return hashes, rules, nil
}

func (t *Table) InvalidateDataplaneCache(reason string) {
	logCxt := t.logCxt.WithField("reason", reason)
	if !t.inSyncWithDataPlane {
		logCxt.Debug("Would invalidate dataplane cache but it was already invalid.")
		return
	}
	logCxt.Debug("Invalidating dataplane cache")
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
		t.onStillAlive()

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

	t.gaugeNumChains.Set(float64(len(t.chainRefCounts)))

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
	// If needed, detect the dataplane features.
	features := t.featureDetector.GetFeatures()

	// Build up the iptables-restore input in an in-memory buffer.  This allows us to log out the exact input after
	// a failure, which has proven to be a very useful diagnostic tool.
	buf := &t.restoreInputBuffer
	buf.Reset() // Defensive.

	// iptables-restore commands live in per-table transactions.
	buf.StartTransaction(t.Name)

	// Make a pass over the dirty chains and generate a forward reference for any that we're about to update.
	// Writing a forward reference ensures that the chain exists and that it is empty.
	t.dirtyChains.Iter(func(item interface{}) error {
		chainName := item.(string)
		chainNeedsToBeFlushed := false
		if t.nftablesMode {
			// iptables-nft-restore <v1.8.3 has a bug (https://bugzilla.netfilter.org/show_bug.cgi?id=1348)
			// where only the first replace command sets the rule index.  Work around that by refreshing the
			// whole chain using a flush.
			chain, _ := t.desiredStateOfChain(chainName)
			currentHashes := chain.RuleHashes(features)
			previousHashes := t.chainToDataplaneHashes[chainName]
			t.logCxt.WithFields(log.Fields{
				"previous": previousHashes,
				"current":  currentHashes,
			}).Debug("Comparing old to new hashes.")
			if len(previousHashes) > 0 && reflect.DeepEqual(currentHashes, previousHashes) {
				// Chain is already correct, skip it.
				log.Debug("Chain already correct")
				return set.RemoveItem
			}
			chainNeedsToBeFlushed = true
		} else if _, present := t.desiredStateOfChain(chainName); !present {
			// About to delete this chain, flush it first to sever dependencies.
			chainNeedsToBeFlushed = true
		} else if _, ok := t.chainToDataplaneHashes[chainName]; !ok {
			// Chain doesn't exist in dataplane, mark it for creation.
			chainNeedsToBeFlushed = true
		}
		if chainNeedsToBeFlushed {
			buf.WriteForwardReference(chainName)
		}
		return nil
	})

	// Make a second pass over the dirty chains.  This time, we write out the rule changes.
	newHashes := map[string][]string{}
	t.dirtyChains.Iter(func(item interface{}) error {
		chainName := item.(string)
		if chain, ok := t.desiredStateOfChain(chainName); ok {
			// Chain update or creation.  Scan the chain against its previous hashes
			// and replace/append/delete as appropriate.
			var previousHashes []string
			if t.nftablesMode {
				// Due to a bug in iptables nft mode, force a whole-chain rewrite.  (See above.)
				previousHashes = nil
			} else {
				// In iptables legacy mode, we compare the rules one by one and apply deltas rule by rule.
				previousHashes = t.chainToDataplaneHashes[chainName]
			}
			currentHashes := chain.RuleHashes(features)
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
					line = chain.Rules[i].RenderReplace(chainName, ruleNum, prefixFrag, features)
				} else if i < len(previousHashes) {
					// previousHashes was longer, remove the old rules from the end.
					ruleNum := len(currentHashes) + 1 // 1-indexed
					line = t.renderDeleteByIndexLine(chainName, ruleNum)
				} else {
					// currentHashes was longer.  Append.
					prefixFrag := t.commentFrag(currentHashes[i])
					line = chain.Rules[i].RenderAppend(chainName, prefixFrag, features)
				}
				buf.WriteLine(line)
			}
		}
		return nil // Delay clearing the set until we've programmed iptables.
	})

	// Make a copy of our full rules map and keep track of all changes made while processing dirtyInsertAppend.
	// When we've successfully updated iptables, we'll update our cache of chainToFullRules with this map.
	newChainToFullRules := map[string][]string{}
	for chain, rules := range t.chainToFullRules {
		newChainToFullRules[chain] = make([]string, len(rules))
		copy(newChainToFullRules[chain], rules)
	}

	// Now calculate iptables updates for our inserted and appended rules, which are used to hook top-level chains.
	var deleteRenderingErr error
	var line string
	t.dirtyInsertAppend.Iter(func(item interface{}) error {
		chainName := item.(string)
		previousHashes := t.chainToDataplaneHashes[chainName]
		newRules := newChainToFullRules[chainName]

		// Calculate the hashes for our inserted and appended rules.
		newChainHashes, newInsertedRuleHashes, newAppendedRuleHashes := t.expectedHashesForInsertAppendChain(
			chainName, numEmptyStrings(previousHashes))

		if reflect.DeepEqual(newChainHashes, previousHashes) {
			// Chain is in sync, skip to next one.
			return nil
		}

		// For simplicity, if we've discovered that we're out-of-sync, remove all our
		// rules from this chain, then re-insert/re-append them below.
		for i := 0; i < len(previousHashes); i++ {
			if previousHashes[i] != "" {
				line, deleteRenderingErr = t.renderDeleteByValueLine(chainName, i)
				if deleteRenderingErr != nil {
					return set.StopIteration
				}
				buf.WriteLine(line)
			}
		}

		// Go over our slice of "new" rules and create a copy of the slice with just the rules we didn't empty out.
		copyOfNewRules := []string{}
		for _, rule := range newRules {
			if rule != "" {
				copyOfNewRules = append(copyOfNewRules, rule)
			}
		}
		newRules = copyOfNewRules
		rules := t.chainToInsertedRules[chainName]
		insertRuleLines := make([]string, len(rules))

		// Add inserted rules if there is any
		if len(rules) > 0 {
			if t.insertMode == "insert" {
				t.logCxt.Debug("Rendering insert rules.")
				// Since each insert is pushed onto the top of the chain, do the inserts in
				// reverse order so that they end up in the correct order in the final
				// state of the chain.
				for i := len(rules) - 1; i >= 0; i-- {
					prefixFrag := t.commentFrag(newInsertedRuleHashes[i])
					line := rules[i].RenderInsert(chainName, prefixFrag, features)
					buf.WriteLine(line)
					insertRuleLines[i] = line
				}
				newRules = append(insertRuleLines, newRules...)
			} else {
				t.logCxt.Debug("Rendering append rules.")
				for i := 0; i < len(rules); i++ {
					prefixFrag := t.commentFrag(newInsertedRuleHashes[i])
					line := rules[i].RenderAppend(chainName, prefixFrag, features)
					buf.WriteLine(line)
					insertRuleLines[i] = line
				}
				newRules = append(newRules, insertRuleLines...)
			}
		}

		// Add appended rules if there is any
		rules = t.chainToAppendedRules[chainName]
		appendRuleLines := make([]string, len(rules))

		if len(rules) > 0 {
			t.logCxt.Debug("Rendering specific append rules.")
			for i := 0; i < len(rules); i++ {
				prefixFrag := t.commentFrag(newAppendedRuleHashes[i])
				line := rules[i].RenderAppend(chainName, prefixFrag, features)
				buf.WriteLine(line)
				appendRuleLines[i] = line
			}
			newRules = append(newRules, appendRuleLines...)
		}

		newHashes[chainName] = newChainHashes
		newChainToFullRules[chainName] = newRules

		return nil // Delay clearing the set until we've programmed iptables.
	})
	// If rendering a delete by line number reached an unexpected state, error out so applyUpdates() can be retried.
	if deleteRenderingErr != nil {
		return deleteRenderingErr
	}

	if t.nftablesMode {
		// The nftables version of iptables-restore requires that chains are unreferenced at the start of the
		// transaction before they can be deleted (i.e. it doesn't seem to update the reference calculation as
		// rules are deleted).  Close the current transaction and open a new one for the deletions in order to
		// refresh its state.  The buffer will discard a no-op transaction so we don't need to check.
		t.logCxt.Debug("In nftables mode, restarting transaction between updates and deletions.")
		buf.EndTransaction()
		buf.StartTransaction(t.Name)

		t.dirtyChains.Iter(func(item interface{}) error {
			chainName := item.(string)
			if _, ok := t.desiredStateOfChain(chainName); !ok {
				// Chain deletion
				buf.WriteForwardReference(chainName)
			}
			return nil // Delay clearing the set until we've programmed iptables.
		})
	}

	// Do deletions at the end.  This ensures that we don't try to delete any chains that
	// are still referenced (because we'll have removed the references in the modify pass
	// above).  Note: if a chain is being deleted at the same time as a chain that it refers to
	// then we'll issue a create+flush instruction in the very first pass, which will sever the
	// references.
	t.dirtyChains.Iter(func(item interface{}) error {
		chainName := item.(string)
		if _, ok := t.desiredStateOfChain(chainName); !ok {
			// Chain deletion
			buf.WriteLine(fmt.Sprintf("--delete-chain %s", chainName))
			newHashes[chainName] = nil
		}
		return nil // Delay clearing the set until we've programmed iptables.
	})

	buf.EndTransaction()

	if buf.Empty() {
		t.logCxt.Debug("Update ended up being no-op, skipping call to ip(6)tables-restore.")
	} else {
		// Get the contents of the buffer ready to send to iptables-restore.  Warning: for perf, this is directly
		// accessing the buffer's internal array; don't touch the buffer after this point.
		t.opReporter.RecordOperation(fmt.Sprintf("update-%v-v%d", t.Name, t.IPVersion))

		inputBytes := buf.GetBytesAndReset()

		if log.GetLevel() >= log.DebugLevel {
			// Only convert (potentially very large slice) to string at debug level.
			inputStr := string(inputBytes)
			t.logCxt.WithField("iptablesInput", inputStr).Debug("Writing to iptables")
		}

		var outputBuf, errBuf bytes.Buffer
		args := []string{"--noflush", "--verbose"}
		if features.RestoreSupportsLock {
			// Versions of iptables-restore that support the xtables lock also make it impossible to disable.  Make
			// sure that we configure it to retry and configure for a short retry interval (the default is to try to
			// acquire the lock only once).
			lockTimeout := t.lockTimeout.Seconds()
			if lockTimeout <= 0 {
				// Before iptables-restore added lock support, we were able to disable the lock completely, which
				// was indicated by a value <=0 (and was our default).  Newer versions of iptables-restore require the
				// lock so we override the default and set it to 10s.
				lockTimeout = 10
			}
			lockProbeMicros := t.lockProbeInterval.Nanoseconds() / 1000
			timeoutStr := fmt.Sprintf("%.0f", lockTimeout)
			intervalStr := fmt.Sprintf("%d", lockProbeMicros)
			args = append(args,
				"--wait", timeoutStr, // seconds
				"--wait-interval", intervalStr, // microseconds
			)
			log.WithFields(log.Fields{
				"timeoutSecs":         timeoutStr,
				"probeIntervalMicros": intervalStr,
			}).Debug("Using native iptables-restore xtables lock.")
		}
		cmd := t.newCmd(t.iptablesRestoreCmd, args...)
		cmd.SetStdin(bytes.NewReader(inputBytes))
		cmd.SetStdout(&outputBuf)
		cmd.SetStderr(&errBuf)
		countNumRestoreCalls.Inc()
		// Note: calicoXtablesLock will be a dummy lock if our xtables lock is disabled (i.e. if iptables-restore
		// supports the xtables lock itself, or if our implementation is disabled by config.
		t.calicoXtablesLock.Lock()
		err := cmd.Run()
		t.calicoXtablesLock.Unlock()
		if err != nil {
			// To log out the input, we must convert to string here since, after we return, the buffer can be re-used
			// (and the logger may convert to string on a background thread).
			inputStr := string(inputBytes)
			t.logCxt.WithFields(log.Fields{
				"output":      outputBuf.String(),
				"errorOutput": errBuf.String(),
				"error":       err,
				"input":       inputStr,
			}).Warn("Failed to execute ip(6)tables-restore command")
			t.inSyncWithDataPlane = false
			countNumRestoreErrors.Inc()
			return err
		}
		t.lastWriteTime = t.timeNow()
		t.postWriteInterval = t.initialPostWriteInterval
	}

	// Now we've successfully updated iptables, clear the dirty sets.  We do this even if we
	// found there was nothing to do above, since we may have found out that a dirty chain
	// was actually a no-op update.
	t.dirtyChains = set.New()
	t.dirtyInsertAppend = set.New()

	// Store off the updates.
	for chainName, hashes := range newHashes {
		if hashes == nil {
			delete(t.chainToDataplaneHashes, chainName)
		} else {
			t.chainToDataplaneHashes[chainName] = hashes
		}
	}
	t.chainToFullRules = newChainToFullRules

	return nil
}

// desiredStateOfChain returns the given chain, if and only if it exists in the cache and it is referenced by some
// other chain.  If the chain doesn't exist or it is not referenced, returns nil and false.
func (t *Table) desiredStateOfChain(chainName string) (chain *Chain, present bool) {
	if t.chainRefCounts[chainName] == 0 {
		return
	}
	chain, present = t.chainNameToChain[chainName]
	return
}

func (t *Table) commentFrag(hash string) string {
	return fmt.Sprintf(`-m comment --comment "%s%s"`, t.hashCommentPrefix, hash)
}

// renderDeleteByIndexLine produces a delete line by rule number. This function is used for cali chains.
func (t *Table) renderDeleteByIndexLine(chainName string, ruleNum int) string {
	return fmt.Sprintf("-D %s %d", chainName, ruleNum)
}

// renderDeleteByValueLine produces a delete line by the full rule at the given rule number. This function is
// used for non-Calico chains.
func (t *Table) renderDeleteByValueLine(chainName string, ruleNum int) (string, error) {
	// For non-cali chains, get the rule by number but delete using the full rule instead of rule number.
	rules, ok := t.chainToFullRules[chainName]
	if !ok || ruleNum >= len(rules) {
		return "", fmt.Errorf("Rendering delete for non-existent rule: Rule %d in %q", ruleNum, chainName)
	}

	rule := rules[ruleNum]

	// Make the append a delete.
	return strings.Replace(rule, "-A", "-D", 1), nil
}

func calculateRuleHashes(chainName string, rules []Rule, features *detector.Features) []string {
	chain := Chain{
		Name:  chainName,
		Rules: rules,
	}
	return (&chain).RuleHashes(features)
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
