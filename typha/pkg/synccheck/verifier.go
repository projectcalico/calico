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

package synccheck

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/typha/pkg/promutils"
)

// MismatchAction selects what the Verifier does when it confirms a checksum
// mismatch between the upstream's reported snapshot and the local
// reconstruction of it.
type MismatchAction string

const (
	// MismatchActionLog logs and increments metrics but takes no corrective
	// action; the (possibly corrupt) cache keeps being served.
	MismatchActionLog MismatchAction = "log"
	// MismatchActionReconnect additionally asks the connection to be torn down
	// (rate-limited) so the existing restart/reconciliation path produces a
	// clean re-sync.  This is the default.
	MismatchActionReconnect MismatchAction = "reconnect"

	// defaultPersistChecks is the number of consecutive failed comparisons
	// required before a mismatch is treated as real.  In-flight skew (the local
	// pipeline not yet drained past the point the remote checksum describes)
	// clears within a check or two; a real divergence is permanent, so requiring
	// persistence eliminates false positives without missing real faults.
	defaultPersistChecks = 3

	// defaultReconnectMinInterval rate-limits forced reconnects so a persistent
	// mismatch can't melt the hierarchy with a reconnect loop.
	defaultReconnectMinInterval = 10 * time.Minute
)

var (
	syncerLabel = []string{"syncer"}

	counterVecChecksumMismatches = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "typha_checksum_mismatches_total",
		Help: "Number of confirmed snapshot checksum mismatches detected by this Typha acting as a " +
			"client of an upstream Typha.",
	}, syncerLabel)
	counterVecChecksumMatches = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "typha_checksum_matches_total",
		Help: "Number of snapshot checksum comparisons that matched the upstream Typha.",
	}, syncerLabel)
	gaugeVecChecksumLastMatch = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "typha_checksum_last_compare_ok",
		Help: "1 if the most recent snapshot checksum comparison against the upstream matched, 0 if it " +
			"mismatched.",
	}, syncerLabel)
)

func init() {
	prometheus.MustRegister(counterVecChecksumMismatches)
	promutils.PreCreateCounterPerSyncer(counterVecChecksumMismatches)
	prometheus.MustRegister(counterVecChecksumMatches)
	promutils.PreCreateCounterPerSyncer(counterVecChecksumMatches)
	prometheus.MustRegister(gaugeVecChecksumLastMatch)
	promutils.PreCreateGaugePerSyncer(gaugeVecChecksumLastMatch)
}

// CounterMismatchesForTest and CounterMatchesForTest expose the per-syncer
// metrics so tests in other packages (the chained fv-tests) can assert match /
// mismatch counts via prometheus testutil.  They are not part of the supported
// API.
func CounterMismatchesForTest(syncerType string) prometheus.Counter {
	return counterVecChecksumMismatches.WithLabelValues(syncerType)
}

func CounterMatchesForTest(syncerType string) prometheus.Counter {
	return counterVecChecksumMatches.WithLabelValues(syncerType)
}

// LocalChecksumProvider returns the current checksum (and KV count) of the
// local reconstruction of the upstream's snapshot.  For a follower Typha this
// is its own snapcache's current breadcrumb checksum.  It must be safe to call
// from any goroutine (snapcache.Cache.CurrentBreadcrumb is).
type LocalChecksumProvider interface {
	LocalChecksum() Checksum
}

// LocalChecksumFunc adapts a function to LocalChecksumProvider.
type LocalChecksumFunc func() Checksum

func (f LocalChecksumFunc) LocalChecksum() Checksum { return f() }

// VerifierConfig configures a Verifier.
type VerifierConfig struct {
	// SyncerType labels metrics and logs.
	SyncerType string
	// MismatchAction selects remediation; defaults to MismatchActionReconnect.
	MismatchAction MismatchAction
	// Local provides the local checksum to compare against the upstream's.
	Local LocalChecksumProvider
	// RequestReconnect is invoked (at most once per ReconnectMinInterval) when a
	// mismatch is confirmed and MismatchAction is reconnect.  It should tear the
	// connection down so the restart path re-syncs.  May be nil for log-only.
	RequestReconnect func()

	// PersistChecks overrides defaultPersistChecks (testing).
	PersistChecks int
	// ReconnectMinInterval overrides defaultReconnectMinInterval (testing).
	ReconnectMinInterval time.Duration
	// Now overrides time.Now (testing).
	Now func() time.Time
}

// Verifier performs deferred comparison of upstream checksums against the local
// reconstruction.  A single Verifier is used per syncclient connection-type
// (one per pipeline).  Its zero value is not usable; construct with NewVerifier.
//
// Concurrency: OnRemoteChecksum is called from the syncclient's message loop
// and Check from a polling goroutine; both take the lock.  The
// LocalChecksumProvider is read without the lock (it is independently
// goroutine-safe).
type Verifier struct {
	cfg  VerifierConfig
	now  func() time.Time
	logc *log.Entry

	counterMismatches prometheus.Counter
	counterMatches    prometheus.Counter
	gaugeLastOK       prometheus.Gauge

	lock sync.Mutex
	// expectation holds the most recent unmatched upstream checksum.  Newer
	// expectations supersede older ones: once the local state matches the latest
	// reported checksum, any earlier in-flight skew is irrelevant.
	expectation   *expectation
	failedChecks  int
	lastReconnect time.Time
}

type expectation struct {
	remote Checksum
	// countOnly is set when the upstream and we run different software versions:
	// re-serialization can legitimately change value bytes, so we compare
	// KVCount only (counts survive re-serialization).
	countOnly bool
}

// NewVerifier constructs a Verifier.  cfg.Local is required.
func NewVerifier(cfg VerifierConfig) *Verifier {
	if cfg.MismatchAction == "" {
		cfg.MismatchAction = MismatchActionReconnect
	}
	if cfg.PersistChecks <= 0 {
		cfg.PersistChecks = defaultPersistChecks
	}
	if cfg.ReconnectMinInterval <= 0 {
		cfg.ReconnectMinInterval = defaultReconnectMinInterval
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &Verifier{
		cfg:               cfg,
		now:               now,
		logc:              log.WithField("syncer", cfg.SyncerType),
		counterMismatches: counterVecChecksumMismatches.WithLabelValues(cfg.SyncerType),
		counterMatches:    counterVecChecksumMatches.WithLabelValues(cfg.SyncerType),
		gaugeLastOK:       gaugeVecChecksumLastMatch.WithLabelValues(cfg.SyncerType),
	}
}

// OnRemoteChecksum records a checksum reported by the upstream.  countOnly
// requests KVCount-only comparison (version skew).  The comparison itself is
// deferred to Check, because the deltas that produced this checksum are still
// flowing through the local pipeline when this is called.
func (v *Verifier) OnRemoteChecksum(remote Checksum, countOnly bool) {
	v.lock.Lock()
	defer v.lock.Unlock()
	v.expectation = &expectation{remote: remote, countOnly: countOnly}
	// Reset the persistence counter: this is a fresh expectation that supersedes
	// any earlier in-flight one.
	v.failedChecks = 0
	v.logc.WithFields(log.Fields{
		"remoteChecksum": remote.XOR,
		"remoteKVCount":  remote.KVCount,
		"countOnly":      countOnly,
	}).Debug("Recorded upstream checksum; comparison deferred.")
}

// Reset clears any pending expectation.  Called when the connection restarts so
// a stale expectation from the previous connection isn't compared against the
// new stream.
func (v *Verifier) Reset() {
	v.lock.Lock()
	defer v.lock.Unlock()
	v.expectation = nil
	v.failedChecks = 0
}

// Check performs one deferred comparison.  It is intended to be called
// periodically (e.g. once a second) by the owner.  If there is no pending
// expectation it is a no-op.  On a match it clears the expectation and records
// success.  On a mismatch it increments a persistence counter; once the
// mismatch has persisted across the configured number of checks it is treated
// as real: metrics + log, and (for the reconnect action) a rate-limited
// reconnect request.  Returns true if a real mismatch was confirmed on this
// call.
func (v *Verifier) Check() bool {
	v.lock.Lock()
	defer v.lock.Unlock()

	if v.expectation == nil {
		return false
	}
	local := v.cfg.Local.LocalChecksum()
	exp := v.expectation

	matched := exp.remote.KVCount == local.KVCount
	if matched && !exp.countOnly {
		matched = exp.remote.XOR == local.XOR
	}

	if matched {
		v.counterMatches.Inc()
		v.gaugeLastOK.Set(1)
		v.logc.WithFields(log.Fields{
			"checksum":  local.XOR,
			"kvCount":   local.KVCount,
			"countOnly": exp.countOnly,
		}).Debug("Snapshot checksum matched upstream.")
		v.expectation = nil
		v.failedChecks = 0
		return false
	}

	// Mismatch this round.  Wait for it to persist before alarming: in-flight
	// pipeline skew clears within a check or two.
	v.failedChecks++
	v.logc.WithFields(log.Fields{
		"localChecksum":  local.XOR,
		"localKVCount":   local.KVCount,
		"remoteChecksum": exp.remote.XOR,
		"remoteKVCount":  exp.remote.KVCount,
		"countOnly":      exp.countOnly,
		"failedChecks":   v.failedChecks,
		"needed":         v.cfg.PersistChecks,
	}).Debug("Snapshot checksum did not (yet) match upstream.")
	if v.failedChecks < v.cfg.PersistChecks {
		return false
	}

	// Confirmed mismatch.
	v.counterMismatches.Inc()
	v.gaugeLastOK.Set(0)
	v.logc.WithFields(log.Fields{
		"localChecksum":  local.XOR,
		"localKVCount":   local.KVCount,
		"remoteChecksum": exp.remote.XOR,
		"remoteKVCount":  exp.remote.KVCount,
		"countOnly":      exp.countOnly,
		"action":         v.cfg.MismatchAction,
	}).Error("Snapshot checksum mismatch confirmed between this Typha and its upstream. " +
		"A hop dropped, duplicated or corrupted data.")

	// Clear the expectation so we don't re-alarm on every subsequent check for
	// the same divergence; the next upstream checksum will set a fresh one.
	v.expectation = nil
	v.failedChecks = 0

	if v.cfg.MismatchAction == MismatchActionReconnect && v.cfg.RequestReconnect != nil {
		now := v.now()
		if now.Sub(v.lastReconnect) < v.cfg.ReconnectMinInterval {
			v.logc.Warn("Suppressing reconnect after checksum mismatch (rate-limited); continuing to " +
				"serve current cache.")
		} else {
			v.lastReconnect = now
			v.logc.Warn("Requesting reconnect to upstream to recover from checksum mismatch.")
			// Call the reconnect hook without holding the lock to avoid any risk
			// of deadlock if it re-enters.
			reconnect := v.cfg.RequestReconnect
			v.lock.Unlock()
			reconnect()
			v.lock.Lock()
		}
	}
	return true
}
