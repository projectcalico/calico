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

// Package rolemanager implements the promotion/demotion state machine that
// drives a hierarchical Typha deployment.  It subscribes to slot-acquirer role
// transitions and, for each syncer pipeline, swaps the pipeline's source between
// a real datastore syncer (LEADER), an upstream-Typha syncclient pointed at the
// leader (TIER1), and an upstream-Typha syncclient pointed at the tier-1 Service
// (TIER2) — all behind the pipeline's permanently-installed dedupe buffer.
//
// State machine (three roles; in single-tier mode — Tier1Count=0 — the acquirer
// never emits TIER1, so this collapses to the two-state LEADER↔TIER2 machine
// that WS-C shipped, byte-for-byte):
//
//	          ┌──────────┐        ┌──────────┐        ┌──────────┐
//	start ───→│  TIER2   │───────→│  TIER1   │───────→│  LEADER  │
//	          │(src=t1   │←───────│(src=     │←───────│(real     │
//	          │ service) │        │ leader)  │        │ syncers) │
//	          └──────────┘        └──────────┘        └──────────┘
//	    (any role may transition directly to any other; the diagram
//	     shows the promotion ladder, not the only edges.)
//
// The very first transition starts from the SOURCELESS state (no source has
// been started yet), so "stop the old source" is a no-op on cold start.
//
// Per-pipeline transition procedure (identical for all role changes), run
// concurrently across the four pipelines but strictly serialised per role
// change by the single Run goroutine:
//
//  1. oldSource.Stop() — blocks until no more callbacks can be delivered into
//     the dedupe buffer (the SyncerSource.Stop contract).  This ordering is
//     what makes the swap race-free.
//  2. dedupeBuffer.OnTyphaConnectionRestarted() — the buffer snapshots its
//     live-key set and discards queued in-flight updates.
//  3. newSource.Start(ctx) — the fresh source delivers WaitForDatastore →
//     ResyncInProgress → snapshot → InSync; at InSync the buffer synthesizes
//     deletes for keys that vanished while we were switching.  Downstream
//     (validator → snapcache → connected clients) sees an ordinary resync.
//
// See typha/DESIGN.md, "Role state machine (promotion/demotion)" and
// "Two-tier fan-out".
package rolemanager

import (
	"context"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/typha/pkg/slotacquirer"
	"github.com/projectcalico/calico/typha/pkg/syncsource"
)

// Role is the role this Typha is acting as.  Note this is the *acted* role (the
// sources actually running) which may briefly lag the desired role published by
// the acquirer while a transition is in flight.
type Role int

const (
	// Sourceless is the initial state: no source has been started on any
	// pipeline yet.  The first transition always starts here so the "stop old
	// source" step is a no-op on cold start.
	Sourceless Role = iota
	// Tier2 means the pipelines are sourced from an upstream tier-1 Typha (or,
	// in single-tier mode, directly from the leader).  This is the leaf role and
	// the bootstrap role.
	Tier2
	// Tier1 means the pipelines are sourced from an upstream connection to the
	// leader, and this Typha fans out to tier-2 Typhas.  Only reached when
	// tiering is active (Tier1Count>0).
	Tier1
	// Leader means the pipelines run real datastore syncers.
	Leader
)

func (r Role) String() string {
	switch r {
	case Leader:
		return "Leader"
	case Tier1:
		return "Tier1"
	case Tier2:
		return "Tier2"
	default:
		return "Sourceless"
	}
}

// roleFromAcquirer maps a slot-acquirer role to the role manager's acted role.
func roleFromAcquirer(r slotacquirer.Role) Role {
	switch r {
	case slotacquirer.Leader:
		return Leader
	case slotacquirer.Tier1:
		return Tier1
	default:
		return Tier2
	}
}

// RestartSignaller is the part of the dedupe buffer the role manager needs:
// the "a fresh snapshot is coming" signal.  *dedupebuffer.DedupeBuffer
// satisfies it; tests substitute a spy to verify call ordering.
type RestartSignaller interface {
	OnTyphaConnectionRestarted()
}

// Pipeline is one syncer pipeline that the role manager owns the source of.  The
// dedupe buffer is the stable element installed for the lifetime of the process;
// the role manager creates/stops sources behind it via the per-role factory.
type Pipeline struct {
	// Name is used only for logging (typically the syncer type).
	Name string
	// Buffer is the pipeline's permanently-installed dedupe buffer (the sink
	// every source delivers into).
	Buffer RestartSignaller
	// NewSourceForRole builds a fresh source feeding Buffer appropriate for the
	// target role (Leader → datastore syncer; Tier1 → upstream-to-leader;
	// Tier2 → upstream-to-tier1-or-leader).  Called on every promotion/demotion.
	// It is never called with Sourceless.
	NewSourceForRole func(role Role) syncsource.SyncerSource

	// current is the source currently attached (nil in the Sourceless state).
	current syncsource.SyncerSource
}

// RoleSource publishes desired-role transitions.  *slotacquirer.Acquirer
// satisfies it; unit tests substitute a fake.
type RoleSource interface {
	// Roles delivers a Role each time the held slot changes.  The channel is
	// level-ish: the manager always converges to the latest received value, so
	// dropped intermediate values are harmless.
	Roles() <-chan slotacquirer.Role
}

// ClientDrainer drains off-node client connections from the local server.  Used
// when this Typha is promoted out of Tier2 (it should no longer serve off-node
// leaf clients; they re-discover and land on a tier-2 Typha).  nil disables
// draining (e.g. tests, or single-tier mode where the leader keeps serving all
// clients).
type ClientDrainer interface {
	// DrainOffNodeClients gracefully drops connections from clients that are not
	// on this Typha's node, without shutting the server down.  Same-node clients
	// (which always prefer their local Typha, whatever its tier) are kept.
	DrainOffNodeClients(reason string)
}

// Labeller applies/removes the tier label on this Typha's own pod so clients and
// other Typhas can discover it via the per-tier Services.  Implementations must
// be idempotent and safe to call from the Run goroutine.
type Labeller interface {
	// SetTierLabel sets the pod's tier label to the value implied by role
	// ("leader"/"1"/"2").  Called after the new sources have started.
	SetTierLabel(ctx context.Context, role Role) error
}

// Config holds the tunables for the role manager.
type Config struct {
	// Debounce is how long the desired role must be stable before we act on it.
	// A transition already in flight is never interrupted; this only gates
	// starting a new one.  Defaults to 2s.
	Debounce time.Duration
}

func (c *Config) applyDefaults() {
	if c.Debounce <= 0 {
		c.Debounce = 2 * time.Second
	}
}

// Manager is the promotion/demotion state machine.  Construct with New and run
// with Run.
type Manager struct {
	cfg       Config
	roleSrc   RoleSource
	pipelines []*Pipeline
	labeller  Labeller
	drainer   ClientDrainer

	// mu guards currentRole so Role() can be read from other goroutines (tests,
	// readiness).
	mu          sync.Mutex
	currentRole Role
}

// New constructs a Manager.  labeller and drainer may be nil (e.g. static
// tests), in which case tier labelling / client draining are skipped.
func New(cfg Config, roleSrc RoleSource, labeller Labeller, drainer ClientDrainer, pipelines []*Pipeline) *Manager {
	cfg.applyDefaults()
	return &Manager{
		cfg:         cfg,
		roleSrc:     roleSrc,
		pipelines:   pipelines,
		labeller:    labeller,
		drainer:     drainer,
		currentRole: Sourceless,
	}
}

// Role returns the role the manager has most recently transitioned the
// pipelines into.  Used by tests and readiness reporting.
func (m *Manager) Role() Role {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.currentRole
}

// Run drives the state machine until ctx is cancelled.  It must be called
// exactly once, typically in a goroutine.
//
// The loop is deliberately single-threaded: it reads desired-role transitions
// from the acquirer, debounces them, and only ever runs one transition at a
// time.  New role events that arrive during a transition are absorbed (we read
// the *latest* desired role after each transition completes), so we never
// interrupt a transition mid-flight and we always converge to the latest role.
func (m *Manager) Run(ctx context.Context) {
	log.Info("Role manager starting.")
	defer m.shutdown()

	// desired tracks the latest role the acquirer wants us in.  Until the first
	// acquirer result arrives we want to be Tier2 (the bootstrap state): a
	// cold-start cluster has no leader, so every Typha is a leaf until the slots
	// are filled and everyone discovers their upstream.
	desired := Tier2

	// debounceTimer fires Debounce after the desired role last changed; we only
	// transition when it fires (or immediately on the very first convergence).
	var debounceC <-chan time.Time
	armDebounce := func() {
		timer := time.NewTimer(m.cfg.Debounce)
		debounceC = timer.C
	}

	// On startup, converge to the bootstrap (Tier2) role immediately rather than
	// waiting a debounce period — there is nothing to flap against yet.
	m.transitionTo(ctx, desired)

	for {
		select {
		case <-ctx.Done():
			return
		case role := <-m.roleSrc.Roles():
			newDesired := roleFromAcquirer(role)
			if newDesired == desired {
				// Re-affirmation of the same desired role; nothing to do.
				continue
			}
			log.WithFields(log.Fields{
				"from": desired,
				"to":   newDesired,
			}).Info("Desired role changed; debouncing before acting.")
			desired = newDesired
			armDebounce()
		case <-debounceC:
			debounceC = nil
			if m.Role() == desired {
				// Already converged (e.g. flapped back to where we were).
				continue
			}
			m.transitionTo(ctx, desired)
		}
	}
}

// transitionTo moves all pipelines into the target role.  Per-pipeline swaps
// run concurrently; transitionTo blocks until they all complete, which keeps
// the Run loop strictly serial (no overlapping transitions).
func (m *Manager) transitionTo(ctx context.Context, target Role) {
	from := m.Role()
	if from == target {
		return
	}
	logCxt := log.WithFields(log.Fields{"from": from, "to": target})
	logCxt.Info("Role transition starting.")

	// Demotion (to a lower tier): re-label *before* swapping sources so that
	// clients and downstream Typhas stop being directed at us at the old (higher)
	// tier as early as possible — the WS-C "remove leader label first on demotion"
	// ordering, generalised to tiers.  Promotion labels *after* the swap (below).
	demoting := target < from && from != Sourceless
	if demoting && m.labeller != nil {
		if err := m.labeller.SetTierLabel(ctx, target); err != nil {
			logCxt.WithError(err).Warn("Failed to set tier label before demotion swap; continuing.")
		}
	}

	var wg sync.WaitGroup
	for _, p := range m.pipelines {
		wg.Add(1)
		go func(p *Pipeline) {
			defer wg.Done()
			m.swapPipelineSource(ctx, p, target)
		}(p)
	}
	wg.Wait()

	m.mu.Lock()
	m.currentRole = target
	m.mu.Unlock()

	// Promotion (or cold start): advertise our new tier via the pod label *after*
	// starting the new sources, so a client/Typha never discovers us in a tier
	// whose sources haven't begun (final InSync gating is via pod readiness on
	// the Services).
	if !demoting && m.labeller != nil {
		if err := m.labeller.SetTierLabel(ctx, target); err != nil {
			logCxt.WithError(err).Warn("Failed to set tier label after transition; will rely on readiness gating.")
		}
	}

	// On promotion *out of* Tier2 (to Tier1 or Leader), off-node leaf clients
	// should no longer be served by us.  Drain them so they re-discover and land
	// on a tier-2 Typha; same-node clients (which always prefer their local Typha)
	// are kept by the drainer.  We do this after the source swap so we keep
	// serving during the transition itself.
	if from == Tier2 && target != Tier2 && m.drainer != nil {
		logCxt.Info("Promoted out of Tier2; draining off-node client connections.")
		m.drainer.DrainOffNodeClients("promoted out of tier-2; off-node clients should use a tier-2 Typha")
	}

	logCxt.Info("Role transition complete.")
}

// swapPipelineSource performs the three-step swap for a single pipeline:
// stop the old source, signal the buffer, start the new source.
func (m *Manager) swapPipelineSource(ctx context.Context, p *Pipeline, target Role) {
	logCxt := log.WithFields(log.Fields{"pipeline": p.Name, "to": target})

	// 1. Stop the old source.  This blocks until no more callbacks can be
	//    delivered into the buffer, so step 2 cannot race with old callbacks.
	if p.current != nil {
		logCxt.Debug("Stopping old source.")
		p.current.Stop()
		p.current = nil
	}

	// 2. Tell the buffer a "connection restart" is happening so it snapshots its
	//    live-key set and reconciles (synthesizes deletes) at the next InSync.
	logCxt.Debug("Signalling dedupe buffer of source swap.")
	p.Buffer.OnTyphaConnectionRestarted()

	// 3. Build and start the new source for the target role.
	if target == Sourceless {
		logCxt.Panic("swapPipelineSource called with Sourceless target")
	}
	newSrc := p.NewSourceForRole(target)
	logCxt.Debug("Starting new source.")
	if err := newSrc.Start(ctx); err != nil {
		// Start should not normally fail (the upstream source retries internally;
		// the datastore source's syncer.Start is best-effort).  Log loudly and
		// leave the pipeline sourceless — the next transition will retry.  We do
		// not panic: a single failed pipeline must not crash the whole process.
		logCxt.WithError(err).Error("Failed to start new pipeline source.")
		return
	}
	p.current = newSrc
}

// shutdown stops every running source.  Called when Run returns (context
// cancelled).  Stopping the sources blocks until their callbacks have drained;
// this is the in-process analogue of releasing the lease before draining clients
// (the daemon releases the lease by cancelling the acquirer's context before this
// runs).
func (m *Manager) shutdown() {
	log.Info("Role manager stopping; tearing down sources.")
	var wg sync.WaitGroup
	for _, p := range m.pipelines {
		if p.current == nil {
			continue
		}
		wg.Add(1)
		go func(p *Pipeline) {
			defer wg.Done()
			p.current.Stop()
			p.current = nil
		}(p)
	}
	wg.Wait()
	m.mu.Lock()
	m.currentRole = Sourceless
	m.mu.Unlock()
	log.Info("Role manager stopped.")
}
