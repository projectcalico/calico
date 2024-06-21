// Copyright (c) 2016-2024 Tigera, Inc. All rights reserved.
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
	"os/exec"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"

	"sigs.k8s.io/knftables"

	"github.com/projectcalico/calico/felix/dataplane/common"
	"github.com/projectcalico/calico/felix/environment"
	"github.com/projectcalico/calico/felix/generictables"
	"github.com/projectcalico/calico/felix/ipsets"
	"github.com/projectcalico/calico/felix/iptables/cmdshim"
	"github.com/projectcalico/calico/felix/logutils"
	logutilslc "github.com/projectcalico/calico/libcalico-go/lib/logutils"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

const (
	MaxChainNameLength = knftables.NameLengthMax
	defaultTimeout     = 30 * time.Second
)

var (
	// Define the top-level chains for each table.
	inputHook       = knftables.InputHook
	forwardHook     = knftables.ForwardHook
	outputHook      = knftables.OutputHook
	preroutingHook  = knftables.PreroutingHook
	postroutingHook = knftables.PostroutingHook

	natType    = knftables.NATType
	filterType = knftables.FilterType
	routeType  = knftables.RouteType

	// Each type of hook requires a specific filterPriority in order to be executed in the correct order.
	filterPriority = knftables.FilterPriority
	rawPriority    = knftables.RawPriority
	manglePriority = knftables.ManglePriority
	snatPriority   = knftables.SNATPriority
	dnatPriority   = knftables.DNATPriority

	// Calico uses a single nftables with a variety of hooks.
	// The top level base chains are laid out below.
	baseChains = map[string]knftables.Chain{
		// Filter hook.
		"filter-INPUT":   {Name: "filter-INPUT", Hook: &inputHook, Type: &filterType, Priority: &filterPriority},
		"filter-FORWARD": {Name: "filter-FORWARD", Hook: &forwardHook, Type: &filterType, Priority: &filterPriority},
		"filter-OUTPUT":  {Name: "filter-OUTPUT", Hook: &outputHook, Type: &filterType, Priority: &filterPriority},

		// NAT hooks.
		"nat-PREROUTING":  {Name: "nat-PREROUTING", Hook: &preroutingHook, Type: &natType, Priority: &dnatPriority},
		"nat-INPUT":       {Name: "nat-INPUT", Hook: &inputHook, Type: &natType, Priority: &dnatPriority},
		"nat-OUTPUT":      {Name: "nat-OUTPUT", Hook: &outputHook, Type: &natType, Priority: &snatPriority},
		"nat-POSTROUTING": {Name: "nat-POSTROUTING", Hook: &postroutingHook, Type: &natType, Priority: &snatPriority},

		// Mangle hooks.
		"mangle-PREROUTING":  {Name: "mangle-PREROUTING", Hook: &preroutingHook, Type: &filterType, Priority: &manglePriority},
		"mangle-INPUT":       {Name: "mangle-INPUT", Hook: &inputHook, Type: &filterType, Priority: &manglePriority},
		"mangle-FORWARD":     {Name: "mangle-FORWARD", Hook: &forwardHook, Type: &filterType, Priority: &manglePriority},
		"mangle-OUTPUT":      {Name: "mangle-OUTPUT", Hook: &outputHook, Type: &routeType, Priority: &manglePriority},
		"mangle-POSTROUTING": {Name: "mangle-POSTROUTING", Hook: &postroutingHook, Type: &filterType, Priority: &manglePriority},

		// Raw hooks.
		"raw-PREROUTING": {Name: "raw-PREROUTING", Hook: &preroutingHook, Type: &filterType, Priority: &rawPriority},
		"raw-OUTPUT":     {Name: "raw-OUTPUT", Hook: &outputHook, Type: &filterType, Priority: &rawPriority},
	}

	// Prometheus metrics.
	countNumRestoreCalls = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "felix_nft_calls",
		Help: "Number of nft calls.",
	})
	countNumRestoreErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "felix_nft_errors",
		Help: "Number of nft errors.",
	})
	countNumSaveCalls = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "felix_nft_list_calls",
		Help: "Number of nft list calls.",
	})
	countNumSaveErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "felix_nft_list_errors",
		Help: "Number of nft list errors.",
	})
	gaugeNumChains = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "felix_nft_chains",
		Help: "Number of active nft chains.",
	}, []string{"ip_version", "table"})
	gaugeNumRules = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "felix_nft_rules",
		Help: "Number of active nftables rules.",
	}, []string{"ip_version", "table"})
	countNumLinesExecuted = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "felix_nft_lines_executed",
		Help: "Number of nftables rule updates executed.",
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

// nftablesTable is an implementation of the generictables.Table interface that programs nftables. It represents a
// single nftables table.
type nftablesTable struct {
	common.IPSetsDataplane

	name      string
	ipVersion uint8
	nft       knftables.Interface

	// For rendering rules and chains.
	render NFTRenderer

	// featureDetector detects the features of the dataplane.
	featureDetector environment.FeatureDetectorIface

	// chainToInsertedRules maps from chain name to a list of rules to be inserted at the start
	// of that chain.  Rules are written with rule hash comments.  The Table cleans up inserted
	// rules with unknown hashes.
	chainToInsertedRules map[string][]generictables.Rule

	// chainToAppendRules maps from chain name to a list of rules to be appended at the end
	// of that chain.
	chainToAppendedRules map[string][]generictables.Rule

	dirtyBaseChains set.Set[string]

	// chainNameToChain contains the desired state of our chains, indexed by
	// chain name.
	chainNameToChain map[string]*generictables.Chain

	// chainRefCounts counts the number of chains that refer to a given chain.  Transitive
	// reachability isn't tracked but testing whether a chain is referenced does allow us to
	// avoid programming unreferenced leaf chains (for example, policies that aren't used in
	// this table).
	chainRefCounts map[string]int
	dirtyChains    set.Set[string]

	inSyncWithDataPlane bool

	// chainToDataplaneHashes contains the rule hashes that we think are in the dataplane.
	// it is updated when we write to the dataplane but it can also be read back and compared
	// to what we calculate from chainToContents.
	chainToDataplaneHashes map[string][]string

	// chainToFullRules contains the full rules for any chains that we may be hooking into, mapped from chain name
	// to slices of rules in that chain.
	chainToFullRules map[string][]*knftables.Rule

	// hashCommentPrefix holds the prefix that we prepend to our rule-tracking hashes.
	hashCommentPrefix string

	// ourChainsRegexp matches the names of chains that belong to this specicific table.
	ourChainsRegexp *regexp.Regexp

	// Record when we did our most recent reads and writes of the table.  We use these to
	// calculate the next time we should force a refresh.
	lastReadTime    time.Time
	refreshInterval time.Duration

	// Estimates for the time taken to do an nftables read / write.
	// When an nft command exceeds the one of these we update them immediately.
	// When a  nft command takes less time we decay them exponentially.
	peakNftablesReadTime  time.Duration
	peakNftablesWriteTime time.Duration

	logCxt               *log.Entry
	updateRateLimitedLog *logutilslc.RateLimitedLogger

	gaugeNumChains        prometheus.Gauge
	gaugeNumRules         prometheus.Gauge
	countNumLinesExecuted prometheus.Counter

	// Factory for making commands, used by UTs to shim exec.Command().
	newCmd cmdshim.CmdFactory

	// Shims for time.XXX functions:
	timeSleep func(d time.Duration)
	timeNow   func() time.Time

	onStillAlive func()
	opReporter   logutils.OpRecorder
	reason       string

	contextTimeout time.Duration
}

type TableOptions struct {
	// NewDataplane is an optional function to override the creation of the knftables client,
	// used for testing.
	NewDataplane func(knftables.Family, string) (knftables.Interface, error)

	RefreshInterval time.Duration

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
	featureDetector environment.FeatureDetectorIface,
	options TableOptions,
) generictables.Table {
	// Match the chain names that we program dynamically, which all start with "cali",
	// as well as the base chains that we program which start with "nat", "filter", "mangle", "raw".
	ourChainsRegexp := regexp.MustCompile("^(cali|nat|filter|mangle|raw)-.*")

	// Pre-populate the insert and append table with empty lists for each kernel chain.  Ensures that we
	// clean up any chains that we hooked on a previous run.
	inserts := map[string][]generictables.Rule{}
	appends := map[string][]generictables.Rule{}
	chainNameToChain := map[string]*generictables.Chain{}
	dirtyBaseChains := set.New[string]()
	refcounts := map[string]int{}

	for _, baseChain := range baseChains {
		inserts[baseChain.Name] = []generictables.Rule{}
		appends[baseChain.Name] = []generictables.Rule{}
		chainNameToChain[baseChain.Name] = &generictables.Chain{
			Name:  baseChain.Name,
			Rules: []generictables.Rule{},
		}
		dirtyBaseChains.Add(baseChain.Name)

		// Base chains are referred to by definition.
		refcounts[baseChain.Name] += 1
	}

	// Allow override of exec.Command() and time.Sleep() for test purposes.
	newCmd := cmdshim.NewRealCmd
	sleep := time.Sleep
	if options.SleepOverride != nil {
		sleep = options.SleepOverride
	}
	now := time.Now
	if options.NowOverride != nil {
		now = options.NowOverride
	}

	logFields := log.Fields{
		"ipVersion": ipVersion,
		"table":     name,
	}

	if options.NewDataplane == nil {
		options.NewDataplane = knftables.New
	}

	nftFamily := knftables.IPv4Family
	ipsetFamily := ipsets.IPFamilyV4
	if ipVersion == 6 {
		nftFamily = knftables.IPv6Family
		ipsetFamily = ipsets.IPFamilyV6
	}
	nft, err := options.NewDataplane(nftFamily, name)
	if err != nil {
		log.WithError(err).Panic("Failed to create knftables client")
	}
	ipv := ipsets.NewIPVersionConfig(ipsetFamily, ipsets.IPSetNamePrefix, nil, nil)

	table := &nftablesTable{
		IPSetsDataplane:        NewIPSets(ipv, nft, options.OpRecorder),
		name:                   name,
		nft:                    nft,
		render:                 NewNFTRenderer(hashPrefix, ipVersion),
		ipVersion:              ipVersion,
		featureDetector:        featureDetector,
		chainToInsertedRules:   inserts,
		chainToAppendedRules:   appends,
		dirtyBaseChains:        dirtyBaseChains,
		chainNameToChain:       chainNameToChain,
		chainRefCounts:         refcounts,
		dirtyChains:            set.New[string](),
		chainToDataplaneHashes: map[string][]string{},
		chainToFullRules:       map[string][]*knftables.Rule{},
		logCxt:                 log.WithFields(logFields),
		updateRateLimitedLog: logutilslc.NewRateLimitedLogger(
			logutilslc.OptInterval(30*time.Second),
			logutilslc.OptBurst(100),
		).WithFields(logFields),
		hashCommentPrefix: hashPrefix,
		ourChainsRegexp:   ourChainsRegexp,

		refreshInterval: options.RefreshInterval,

		newCmd:    newCmd,
		timeSleep: sleep,
		timeNow:   now,

		gaugeNumChains:        gaugeNumChains.WithLabelValues(fmt.Sprintf("%d", ipVersion), name),
		gaugeNumRules:         gaugeNumRules.WithLabelValues(fmt.Sprintf("%d", ipVersion), name),
		countNumLinesExecuted: countNumLinesExecuted.WithLabelValues(fmt.Sprintf("%d", ipVersion), name),
		opReporter:            options.OpRecorder,

		contextTimeout: defaultTimeout,
	}

	if options.OnStillAlive != nil {
		table.onStillAlive = options.OnStillAlive
	} else {
		table.onStillAlive = func() {}
	}

	return table
}

func (n *nftablesTable) Name() string {
	return n.name
}

func (n *nftablesTable) IPVersion() uint8 {
	return n.ipVersion
}

// InsertOrAppendRules sets the rules that should be inserted into or appended
// to the given base chain (depending on the chain insert mode).  See
// also AppendRules, which can be used to record additional rules that are
// always appended.
func (t *nftablesTable) InsertOrAppendRules(chainName string, rules []generictables.Rule) {
	t.logCxt.WithField("chainName", chainName).Debug("Updating rule insertions")
	oldRules := t.chainToInsertedRules[chainName]
	t.chainToInsertedRules[chainName] = rules
	numRulesDelta := len(rules) - len(oldRules)
	t.gaugeNumRules.Add(float64(numRulesDelta))
	t.dirtyBaseChains.Add(chainName)

	// Update the chain with the new rules.
	if chain := t.chainNameToChain[chainName]; chain != nil {
		chain.Rules = rules
	}

	// Incref any newly-referenced chains, then decref the old ones.  By incrementing first we
	// avoid marking a still-referenced chain as dirty.
	t.maybeIncrefReferredChains(chainName, rules)
	t.maybeDecrefReferredChains(chainName, oldRules)
}

// AppendRules sets the rules to be appended to a given non-Calico chain.
// These rules are always appended, even if chain insert mode is "insert".
// If chain insert mode is "append", these rules are appended after any
// rules added with InsertOrAppendRules.
func (t *nftablesTable) AppendRules(chainName string, rules []generictables.Rule) {
	t.logCxt.WithField("chainName", chainName).Debug("Updating rule appends")
	oldRules := t.chainToAppendedRules[chainName]
	t.chainToAppendedRules[chainName] = rules
	numRulesDelta := len(rules) - len(oldRules)
	t.gaugeNumRules.Add(float64(numRulesDelta))
	t.dirtyBaseChains.Add(chainName)

	// Incref any newly-referenced chains, then decref the old ones.  By incrementing first we
	// avoid marking a still-referenced chain as dirty.
	t.maybeIncrefReferredChains(chainName, rules)
	t.maybeDecrefReferredChains(chainName, oldRules)
}

func (t *nftablesTable) UpdateChains(chains []*generictables.Chain) {
	for _, chain := range chains {
		t.UpdateChain(chain)
	}
}

func (t *nftablesTable) UpdateChain(chain *generictables.Chain) {
	t.logCxt.WithField("chainName", chain.Name).Debug("Adding chain to available set.")
	oldNumRules := 0

	// Incref any newly-referenced chains, then decref the old ones.  By incrementing first we
	// avoid marking a still-referenced chain as dirty.
	t.maybeIncrefReferredChains(chain.Name, chain.Rules)
	if oldChain := t.chainNameToChain[chain.Name]; oldChain != nil {
		oldNumRules = len(oldChain.Rules)
		t.maybeDecrefReferredChains(chain.Name, oldChain.Rules)
	}
	t.chainNameToChain[chain.Name] = chain
	numRulesDelta := len(chain.Rules) - oldNumRules
	t.gaugeNumRules.Add(float64(numRulesDelta))
	if t.chainIsReferenced(chain.Name) {
		t.dirtyChains.Add(chain.Name)
	}
}

func (t *nftablesTable) RemoveChains(chains []*generictables.Chain) {
	for _, chain := range chains {
		t.RemoveChainByName(chain.Name)
	}
}

func (t *nftablesTable) RemoveChainByName(name string) {
	t.logCxt.WithField("chainName", name).Debug("Removing chain from available set.")
	if oldChain, known := t.chainNameToChain[name]; known {
		t.gaugeNumRules.Sub(float64(len(oldChain.Rules)))
		t.maybeDecrefReferredChains(name, oldChain.Rules)
		delete(t.chainNameToChain, name)
		if t.chainIsReferenced(name) {
			t.dirtyChains.Add(name)
		}
	}
}

func (t *nftablesTable) chainIsReferenced(name string) bool {
	return t.chainRefCounts[name] > 0
}

// maybeIncrefReferredChains checks whether the named chain is referenced;
// if so, it increfs all child chains.  If a child chain becomes newly
// referenced, its children are increffed recursively.
func (t *nftablesTable) maybeIncrefReferredChains(chainName string, rules []generictables.Rule) {
	if !t.chainIsReferenced(chainName) {
		return
	}
	for _, r := range rules {
		if ref, ok := r.Action.(Referrer); ok {
			t.increfChain(ref.ReferencedChain())
		}
	}
}

// maybeDecrefReferredChains checks whether the named chain is referenced;
// if so, it decrefs all child chains.  If a child chain becomes newly
// unreferenced, its children are decreffed recursively.
func (t *nftablesTable) maybeDecrefReferredChains(chainName string, rules []generictables.Rule) {
	if !t.chainIsReferenced(chainName) {
		return
	}
	for _, r := range rules {
		if ref, ok := r.Action.(Referrer); ok {
			t.decrefChain(ref.ReferencedChain())
		}
	}
}

// increfChain increments the refcount of the given chain; if the refcount transitions from 0,
// marks the chain dirty so it will be programmed.
func (t *nftablesTable) increfChain(chainName string) {
	t.logCxt.WithField("chainName", chainName).Debug("Incref chain")
	t.chainRefCounts[chainName] += 1
	if t.chainRefCounts[chainName] == 1 {
		t.updateRateLimitedLog.WithField("chainName", chainName).Info("Chain became referenced, marking it for programming")
		t.dirtyChains.Add(chainName)
		if chain := t.chainNameToChain[chainName]; chain != nil {
			// Recursively incref chains that this chain refers to.  If
			// chain == nil then the chain is likely about to be added, in
			// which case we'll handle this whe the chain is added.
			t.maybeIncrefReferredChains(chainName, chain.Rules)
		}
	}
}

// decrefChain decrements the refcount of the given chain; if the refcount transitions to 0,
// marks the chain dirty so it will be cleaned up.
func (t *nftablesTable) decrefChain(chainName string) {
	t.logCxt.WithField("chainName", chainName).Debug("Decref chain")
	if t.chainRefCounts[chainName] == 1 {
		t.updateRateLimitedLog.WithField("chainName", chainName).Info("Chain no longer referenced, marking it for removal")
		if chain := t.chainNameToChain[chainName]; chain != nil {
			// Recursively decref chains that this chain refers to.  If
			// chain == nil then the chain has probably already been deleted
			// in which case we'll already have done the decrefs.
			t.maybeDecrefReferredChains(chainName, chain.Rules)
		}
		delete(t.chainRefCounts, chainName)
		t.dirtyChains.Add(chainName)
		return
	}

	// Chain still referenced, just decrement.
	t.chainRefCounts[chainName] -= 1
}

func (t *nftablesTable) loadDataplaneState() {
	// Refresh the cache of feature data.
	t.featureDetector.RefreshFeatures()

	// Load the hashes from the dataplane.
	t.logCxt.Debug("Loading current nftables state and checking it is correct.")
	t.opReporter.RecordOperation(fmt.Sprintf("resync-%v-v%d", t.name, t.ipVersion))

	t.lastReadTime = t.timeNow()

	dataplaneHashes, dataplaneRules := t.getHashesAndRulesFromDataplane()

	// Check that the rules we think we've programmed are still there and mark any inconsistent
	// chains for refresh.
	for chainName, expectedHashes := range t.chainToDataplaneHashes {
		logCxt := t.logCxt.WithField("chainName", chainName)
		if t.dirtyChains.Contains(chainName) || t.dirtyBaseChains.Contains(chainName) {
			// Already an update pending for this chain; no point in flagging it as
			// out-of-sync.
			logCxt.Debug("Skipping known-dirty chain")
			continue
		}
		if !t.ourChainsRegexp.MatchString(chainName) {
			// This doesn't match the regex for chains programmed by us. Mark it as dirty so
			// that we clean it up on the next apply.
			logCxt.WithField("chain", chainName).Warn("Found chain that doesn't belong to us, marking for cleanup")
			t.dirtyChains.Add(chainName)
		} else {
			// One of our chains, should match exactly.
			dpHashes := dataplaneHashes[chainName]
			if !reflect.DeepEqual(dpHashes, expectedHashes) {
				logCxt.WithFields(log.Fields{
					"dpHashes":       dpHashes,
					"expectedHashes": expectedHashes,
				}).Warn("Detected out-of-sync Calico chain, marking for resync")
				t.dirtyChains.Add(chainName)
			}
		}
	}

	// Now scan for chains that shouldn't be there and mark for deletion.
	t.logCxt.Debug("Scanning for unexpected nftables chains")
	for chainName := range dataplaneHashes {
		logCxt := t.logCxt.WithField("chainName", chainName)
		if t.dirtyChains.Contains(chainName) || t.dirtyBaseChains.Contains(chainName) {
			// Already an update pending for this chain.
			logCxt.Debug("Skipping known-dirty chain")
			continue
		}
		if _, ok := t.chainToDataplaneHashes[chainName]; ok {
			// Chain expected, we'll have checked its contents above.
			logCxt.Debug("Skipping expected chain")
			continue
		}

		// Chain exists in dataplane but not in memory, mark as dirty so we'll clean it up.
		logCxt.WithField("chainName", chainName).Info("Found unexpected chain, marking for cleanup")
		t.dirtyChains.Add(chainName)
	}

	t.logCxt.Debug("Finished loading nftables state")
	t.chainToDataplaneHashes = dataplaneHashes
	t.chainToFullRules = dataplaneRules
	t.inSyncWithDataPlane = true
}

// expectedHashesForInsertAppendChain calculates the expected hashes for a whole top-level chain
// given our inserts and appends. Hashes for inserted rules are calculated first.
// To avoid recalculation, it returns the inserted rule hashes as a second output and appended rule hashes
// a third output.
func (t *nftablesTable) expectedHashesForInsertAppendChain(chainName string) (allHashes, ourInsertedHashes, ourAppendedHashes []string) {
	insertedRules := t.chainToInsertedRules[chainName]
	appendedRules := t.chainToAppendedRules[chainName]
	allHashes = make([]string, len(insertedRules)+len(appendedRules))
	features := t.featureDetector.GetFeatures()
	if len(insertedRules) > 0 {
		ourInsertedHashes = CalculateRuleHashes(chainName, insertedRules, features)
	}
	if len(appendedRules) > 0 {
		// Add *append* to chainName to produce a unique hash in case append chain/rules are same
		// as insert chain/rules above.
		ourAppendedHashes = CalculateRuleHashes(chainName+"*appends*", appendedRules, features)
	}
	offset := 0
	for i, hash := range ourInsertedHashes {
		allHashes[i+offset] = hash
	}

	offset = len(insertedRules)
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
func (t *nftablesTable) getHashesAndRulesFromDataplane() (hashes map[string][]string, rules map[string][]*knftables.Rule) {
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
			t.logCxt.WithError(err).WithField("stderr", stderr).Warn("nftables command failed")
			if retries > 0 {
				retries--
				t.timeSleep(retryDelay)
				retryDelay *= 2
			} else {
				t.logCxt.Panic("nftables command failed after retries")
			}
			continue
		}

		return hashes, rules
	}
}

// attemptToGetHashesAndRulesFromDataplane reads nftables state and loads it into memory.
func (t *nftablesTable) attemptToGetHashesAndRulesFromDataplane() (hashes map[string][]string, rules map[string][]*knftables.Rule, err error) {
	startTime := t.timeNow()
	defer func() {
		saveDuration := t.timeNow().Sub(startTime)
		t.peakNftablesReadTime = t.peakNftablesReadTime * 99 / 100
		if saveDuration > t.peakNftablesReadTime {
			t.logCxt.WithField("duration", saveDuration).Debug("Updating nftables peak duration.")
			t.peakNftablesReadTime = saveDuration
		}
	}()

	t.logCxt.Debug("Attmempting to get hashes and rules from nftables")

	hashes = make(map[string][]string)
	rules = make(map[string][]*knftables.Rule)

	ctx, cancel := context.WithTimeout(context.Background(), t.contextTimeout)
	defer cancel()

	// Add chains. We need to query this separately, as chains may exist without rules.
	allChains, err := t.nft.List(ctx, "chain")
	if err != nil {
		if knftables.IsNotFound(err) {
			err = nil
			return
		}
		return nil, nil, err
	}
	for _, chain := range allChains {
		hashes[chain] = []string{}
		rules[chain] = []*knftables.Rule{}
	}

	// List rules and extract the hashes.
	allRules, err := t.nft.ListRules(ctx, "")
	if err != nil {
		if knftables.IsNotFound(err) {
			err = nil
			return
		}
		return nil, nil, err
	}

	for _, rule := range allRules {
		// Add the rule to the list of rules for the chain.
		rules[rule.Chain] = append(rules[rule.Chain], rule)

		if rule.Comment != nil {
			// The rule has a comment, extract the hash.
			hash := strings.TrimPrefix(strings.Split(*rule.Comment, ";")[0], t.hashCommentPrefix)
			hashes[rule.Chain] = append(hashes[rule.Chain], hash)
		} else {
			// Otherwise, this rule has no hash and may not be ours. We don't expect these in our chains,
			// but might appear if someone else has modified our table.
			hashes[rule.Chain] = append(hashes[rule.Chain], "")
		}
	}
	return
}

func (t *nftablesTable) InvalidateDataplaneCache(reason string) {
	logCxt := t.logCxt.WithField("reason", reason)
	if !t.inSyncWithDataPlane {
		logCxt.Debug("Would invalidate dataplane cache but it was already invalid.")
		return
	}
	logCxt.Debug("Invalidating dataplane cache")
	t.inSyncWithDataPlane = false
	t.reason = reason
}

func (t *nftablesTable) Apply() (rescheduleAfter time.Duration) {
	now := t.timeNow()
	defer func() {
		if time.Since(now) > time.Second {
			t.logCxt.WithFields(log.Fields{
				"applyTime":      time.Since(now),
				"reasonForApply": t.reason,
			}).Info("Updating nftables took >1s")
		}
	}()

	// We _think_ we're in sync, check if there are any reasons to think we might
	// not be in sync.
	lastReadToNow := now.Sub(t.lastReadTime)
	if t.refreshInterval > 0 && lastReadToNow > t.refreshInterval {
		// Too long since we've forced a refresh.
		t.InvalidateDataplaneCache("refresh timer")
	}

	// Retry until we succeed. This could be a transient programming error. It's also possible that we're bugged
	// and trying to write bad data so we give up eventually.
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
				if retries < 6 {
					// If we hit multiple failures in a row, trigger a full table rebuild on the next iteration.
					// This can help in case we are trying to make a change that is incompatible with the current table state.
					t.logCxt.Warn("Recreating table due to prior nftables programming error")
					tx := t.nft.NewTransaction()
					tx.Delete(&knftables.Table{})
					tx.Add(&knftables.Table{})

					if err := t.runTransaction(tx); err != nil {
						t.logCxt.WithError(err).Warn("Failed to delete table, continuing anyway")
					}
				}

				// Reload the data plane state in case we're out of sync.
				t.loadDataplaneState()

				retries--
				t.logCxt.WithError(err).Warn("Failed to program nftables, will retry")
				t.timeSleep(backoffTime)
				backoffTime *= 2
				t.logCxt.WithError(err).Warn("Retrying...")
				failedAtLeastOnce = true
				continue
			} else {
				t.logCxt.WithError(err).Error("Failed to program nftables, loading diags before panic.")
				cmd := t.newCmd("nft", "list", "table", t.name)
				output, err2 := cmd.Output()
				if err2 != nil {
					t.logCxt.WithError(err2).Error("Failed to load nftables state")
				} else {
					t.logCxt.WithField("state", string(output)).Error("Current state of nftables")
				}
				t.logCxt.WithError(err).Panic("Failed to program nftables, giving up after retries")
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
		lastReadToNow = now.Sub(t.lastReadTime)

		// Refresh interval is set, start with that.
		logrus.WithFields(logrus.Fields{
			"lastReadToNow":   lastReadToNow,
			"refreshInterval": t.refreshInterval,
		}).Debug("Calculating reschedule time")
		rescheduleAfter = t.refreshInterval - lastReadToNow
	}
	return
}

func (t *nftablesTable) applyUpdates() error {
	// If needed, detect the dataplane features.
	features := t.featureDetector.GetFeatures()

	// Start a new nftables transaction.
	tx := t.nft.NewTransaction()

	// If we don't see any chains, then we need to create it.
	if len(t.chainToDataplaneHashes) == 0 {
		tx.Add(&knftables.Table{})
	}

	// Also make sure our base chains exist.
	for _, c := range baseChains {
		// Make a copy.
		baseChain := c
		if _, ok := t.chainToDataplaneHashes[baseChain.Name]; !ok {
			// Chain doesn't exist in dataplane, mark it for creation.
			tx.Add(&baseChain)
		}
	}

	// Make a pass over the dirty chains and generate a forward reference for any that we're about to update.
	// Writing a forward reference ensures that the chain exists and that it is empty.
	t.dirtyChains.Iter(func(chainName string) error {
		t.logCxt.WithField("chainName", chainName).Debug("Checking dirty chain")
		if _, present := t.desiredStateOfChain(chainName); !present {
			// About to delete this chain, flush it first to sever dependencies.
			t.logCxt.WithFields(logrus.Fields{
				"chainName": chainName,
			}).Debug("Flushing chain before deletion")
			tx.Flush(&knftables.Chain{Name: chainName})
		} else if _, ok := t.chainToDataplaneHashes[chainName]; !ok {
			// Chain doesn't exist in dataplane, mark it for creation.
			t.logCxt.WithFields(logrus.Fields{
				"chainName": chainName,
			}).Debug("Adding chain")
			tx.Add(&knftables.Chain{Name: chainName})
		}
		return nil
	})

	// Make a second pass over the dirty chains.  This time, we write out the rule changes.
	newHashes := map[string][]string{}
	t.dirtyChains.Iter(func(chainName string) error {
		if chain, ok := t.desiredStateOfChain(chainName); ok {
			// Chain update or creation.  Scan the chain against its previous hashes
			// and replace/append/delete as appropriate.
			previousHashes := t.chainToDataplaneHashes[chainName]
			currentHashes := t.render.RuleHashes(chain, features)
			newHashes[chainName] = currentHashes

			// Make sure sets are created for the chain, as nft will fail the transaction
			// if there are unreferenced sets.
			for _, setName := range chain.IPSetNames() {
				if set := t.IPSetsDataplane.(*IPSets).NFTablesSet(setName); set != nil {
					tx.Add(set)
				} else {
					t.logCxt.WithFields(logrus.Fields{
						"chain": chainName,
						"set":   setName,
					}).Warn("IP Set for chain has not yet been received by data plane")
				}
			}

			t.logCxt.WithFields(logrus.Fields{
				"chainName": chainName,
				"previous":  previousHashes,
				"current":   currentHashes,
			}).Debug("Comparing chain hashes")
			for i := 0; i < len(previousHashes) || i < len(currentHashes); i++ {
				if i < len(previousHashes) && i < len(currentHashes) {
					if previousHashes[i] == currentHashes[i] {
						continue
					}
					rendered := t.render.Render(chainName, currentHashes[i], chain.Rules[i], features)
					rendered.Handle = t.chainToFullRules[chainName][i].Handle
					t.logCxt.WithFields(logrus.Fields{
						"chainName": chainName,
						"handle":    *rendered.Handle,
					}).Debug("Replacing rule in chain")
					tx.Replace(rendered)
				} else if i < len(previousHashes) {
					// previousHashes was longer, remove the old rules from the end.
					t.logCxt.WithFields(logrus.Fields{
						"chainName": chainName,
					}).Debug("Deleting old rule from end of chain")
					tx.Delete(&knftables.Rule{
						Chain:  chainName,
						Handle: t.chainToFullRules[chainName][i].Handle,
					})
				} else {
					// currentHashes was longer.  Append.
					t.logCxt.WithFields(logrus.Fields{
						"chainName": chainName,
					}).Debug("Appending rule to chain")
					tx.Add(t.render.Render(chainName, currentHashes[i], chain.Rules[i], features))
				}
			}
		}
		return nil // Delay clearing the set until we've programmed nftables.
	})

	// Make a copy of our full rules map and keep track of all changes made while processing dirtyBaseChains.
	// When we've successfully updated nftables, we'll update our cache of chainToFullRules with this map.
	newChainToFullRules := map[string][]*knftables.Rule{}
	for chain, rules := range t.chainToFullRules {
		newChainToFullRules[chain] = make([]*knftables.Rule, len(rules))
		copy(newChainToFullRules[chain], rules)
	}

	// Now calculate nftables updates for our inserted and appended rules, which are used to hook top-level chains.
	t.dirtyBaseChains.Iter(func(chainName string) error {
		previousHashes := t.chainToDataplaneHashes[chainName]
		newRules := newChainToFullRules[chainName]

		// Calculate the hashes for our inserted and appended rules.
		newChainHashes, newInsertedRuleHashes, newAppendedRuleHashes := t.expectedHashesForInsertAppendChain(chainName)

		if reflect.DeepEqual(newChainHashes, previousHashes) {
			// Chain is in sync, skip to next one.
			return nil
		}

		// For simplicity, if we've discovered that we're out-of-sync, remove all our
		// rules from this chain, then re-insert/re-append them below.
		tx.Flush(&knftables.Chain{Name: chainName})
		t.logCxt.WithField("chainName", chainName).Info("Flushing chain")

		// Go over our slice of "new" rules and create a copy of the slice with just the rules we didn't empty out.
		copyOfNewRules := []*knftables.Rule{}
		for _, rule := range newRules {
			if rule != nil {
				copyOfNewRules = append(copyOfNewRules, rule)
			}
		}
		newRules = copyOfNewRules
		rules := t.chainToInsertedRules[chainName]

		// Add rules if there is any
		if len(rules) > 0 {
			t.logCxt.Debug("Rendering rules.")
			for i := 0; i < len(rules); i++ {
				tx.Add(t.render.Render(chainName, newInsertedRuleHashes[i], rules[i], features))
			}
		}

		// Add appended rules if there is any
		rules = t.chainToAppendedRules[chainName]
		if len(rules) > 0 {
			t.logCxt.Debug("Rendering specific append rules.")
			for i := 0; i < len(rules); i++ {
				tx.Add(t.render.Render(chainName, newAppendedRuleHashes[i], rules[i], features))
			}
		}

		newHashes[chainName] = newChainHashes
		newChainToFullRules[chainName] = newRules

		return nil // Delay clearing the set until we've programmed nftables.
	})

	// Do deletions at the end.  This ensures that we don't try to delete any chains that
	// are still referenced (because we'll have removed the references in the modify pass
	// above).
	t.dirtyChains.Iter(func(chainName string) error {
		if _, ok := t.desiredStateOfChain(chainName); !ok {
			// Chain deletion
			t.logCxt.WithFields(logrus.Fields{
				"chainName": chainName,
			}).Debug("Deleting chain that is no longer needed")
			tx.Delete(&knftables.Chain{Name: chainName})
			newHashes[chainName] = nil
		}
		return nil // Delay clearing the set until we've programmed nftables.
	})

	if tx.NumOperations() == 0 {
		t.logCxt.Debug("Update ended up being no-op, skipping call to nftables.")
	} else {
		// Run the transaction.
		t.opReporter.RecordOperation(fmt.Sprintf("update-%v-v%d", t.name, t.ipVersion))

		if logrus.IsLevelEnabled(logrus.TraceLevel) {
			t.logCxt.Tracef("Updating nftables: %s", tx.String())
		}

		if err := t.runTransaction(tx); err != nil {
			t.logCxt.WithField("tx", tx.String()).Error("Failed to run nft transaction")
			return fmt.Errorf("error performing nft transaction: %s", err)
		}
	}

	// Now we've successfully updated nftables, clear the dirty sets.  We do this even if we
	// found there was nothing to do above, since we may have found out that a dirty chain
	// was actually a no-op update.
	t.dirtyChains = set.New[string]()
	t.dirtyBaseChains = set.New[string]()

	// Store off the updates.
	for chainName, hashes := range newHashes {
		if hashes == nil {
			delete(t.chainToDataplaneHashes, chainName)
		} else {
			t.chainToDataplaneHashes[chainName] = hashes
		}
	}
	t.chainToFullRules = newChainToFullRules

	// Invalidate the in-memory dataplane state so that we reload on the next write. This ensures we have the correct handles
	// in-memory for each of the objects we've just written. nftables requires an object's handle in order to
	// perform update or delete operations.
	t.InvalidateDataplaneCache("post-write")
	return nil
}

func (t *nftablesTable) runTransaction(tx *knftables.Transaction) error {
	startTime := t.timeNow()
	defer func() {
		restoreDuration := t.timeNow().Sub(startTime)
		t.peakNftablesWriteTime = t.peakNftablesWriteTime * 99 / 100
		if restoreDuration > t.peakNftablesWriteTime {
			log.WithField("duration", restoreDuration).Debug("Updating nftables write-time peak duration.")
			t.peakNftablesWriteTime = restoreDuration
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), t.contextTimeout)
	defer cancel()
	return t.nft.Run(ctx, tx)
}

// CheckRulesPresent returns list of rules with the hashes that are already
// programmed. Return value of nil means that none of the rules are present.
func (t *nftablesTable) CheckRulesPresent(chain string, rules []generictables.Rule) []generictables.Rule {
	features := t.featureDetector.GetFeatures()
	hashes := CalculateRuleHashes(chain, rules, features)

	dpHashes, _ := t.getHashesAndRulesFromDataplane()
	dpHashesSet := set.New[string]()
	for _, h := range dpHashes[chain] {
		dpHashesSet.Add(h)
	}

	var present []generictables.Rule
	for i, r := range rules {
		if dpHashesSet.Contains(hashes[i]) {
			present = append(present, r)
		}
	}

	return present
}

// InsertRulesNow insets the given rules immediately without removing or syncing
// other rules. This is primarily useful when bootstrapping and we cannot wait
// until we have the full state.
func (t *nftablesTable) InsertRulesNow(chain string, rules []generictables.Rule) error {
	features := t.featureDetector.GetFeatures()
	hashes := CalculateRuleHashes(chain, rules, features)

	tx := t.nft.NewTransaction()
	tx.Add(&knftables.Table{})
	if baseChain, ok := baseChains[chain]; ok {
		tx.Add(&baseChain)
	}
	for i, r := range rules {
		tx.Insert(t.render.Render(chain, hashes[i], r, features))
	}

	// Run the transaction.
	if err := t.runTransaction(tx); err != nil {
		t.logCxt.WithField("tx", tx.String()).Error("Failed to run InsertRulesNow nft transaction")
		return fmt.Errorf("error performing InsertRulesNow nft transaction: %s", err)
	}

	return nil
}

// desiredStateOfChain returns the given chain, if and only if it exists in the cache and it is referenced by some
// other chain.  If the chain doesn't exist or it is not referenced, returns nil and false.
func (t *nftablesTable) desiredStateOfChain(chainName string) (chain *generictables.Chain, present bool) {
	if !t.chainIsReferenced(chainName) {
		return
	}
	chain, present = t.chainNameToChain[chainName]
	return
}

func CalculateRuleHashes(chainName string, rules []generictables.Rule, features *environment.Features) []string {
	chain := generictables.Chain{
		Name:  chainName,
		Rules: rules,
	}
	return NewNFTRenderer("", 4).RuleHashes(&chain, features)
}
