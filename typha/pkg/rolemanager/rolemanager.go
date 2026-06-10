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
// drives a hierarchical Typha deployment (WS-C).  It subscribes to leader
// election role transitions and, for each syncer pipeline, swaps the pipeline's
// source between a real datastore syncer (LEADER) and an upstream-Typha
// syncclient (FOLLOWER) behind the pipeline's permanently-installed dedupe
// buffer.
//
// State machine:
//
//	           ┌────────────┐  Leader role   ┌──────────────┐
//	start ────→│  FOLLOWER  │───────────────→│   LEADER     │
//	           │ (upstream  │←───────────────│ (real        │
//	           │  sources)  │  Follower role │  syncers)    │
//	           └────────────┘                └──────────────┘
//
// The very first transition starts from the SOURCELESS state (no source has
// been started yet), so "stop the old source" is a no-op on cold start.
//
// Per-pipeline transition procedure (identical in both directions), run
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
// See typha/DESIGN.md, "Role state machine (promotion/demotion)".
package rolemanager

import (
	"context"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/typha/pkg/leaderelection"
	"github.com/projectcalico/calico/typha/pkg/syncsource"
)

// Role is the role this Typha is acting as.  Note this is the *acted* role (the
// sources actually running) which may briefly lag the desired role published by
// the elector while a transition is in flight.
type Role int

const (
	// Sourceless is the initial state: no source has been started on any
	// pipeline yet.  The first transition always starts here so the "stop old
	// source" step is a no-op on cold start.
	Sourceless Role = iota
	// Follower means the pipelines are sourced from an upstream Typha.
	Follower
	// Leader means the pipelines run real datastore syncers.
	Leader
)

func (r Role) String() string {
	switch r {
	case Leader:
		return "Leader"
	case Follower:
		return "Follower"
	default:
		return "Sourceless"
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
// the role manager creates/stops sources behind it via the two factory funcs.
type Pipeline struct {
	// Name is used only for logging (typically the syncer type).
	Name string
	// Buffer is the pipeline's permanently-installed dedupe buffer (the sink
	// every source delivers into).
	Buffer RestartSignaller
	// NewDatastoreSource builds a fresh datastore-backed source feeding Buffer.
	// Called each time we promote to Leader.
	NewDatastoreSource func() syncsource.SyncerSource
	// NewUpstreamSource builds a fresh upstream-Typha source feeding Buffer.
	// Called each time we demote to Follower.
	NewUpstreamSource func() syncsource.SyncerSource

	// current is the source currently attached (nil in the Sourceless state).
	current syncsource.SyncerSource
}

// Elector is the subset of leaderelection.Elector that the role manager
// consumes.  Defined as an interface so unit tests can drive the state machine
// with a fake elector.
type Elector interface {
	// Roles delivers a Role each time leadership is acquired or lost.  The
	// channel is level-ish: the manager always converges to the latest received
	// value, so dropped intermediate values (the real Elector drops the oldest
	// on overflow) are harmless.
	Roles() <-chan leaderelection.Role
}

// Labeller applies/removes the leader role label on this Typha's own pod so
// followers can discover the leader via the leader Service.  Implementations
// must be idempotent and safe to call from the Run goroutine.
type Labeller interface {
	// SetLeaderLabel adds the leader role label to our own pod.  Called after
	// the real syncers have reached InSync on promotion.
	SetLeaderLabel(ctx context.Context) error
	// RemoveLeaderLabel removes the leader role label from our own pod.  Called
	// at the start of demotion and on graceful shutdown.
	RemoveLeaderLabel(ctx context.Context) error
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
	elector   Elector
	pipelines []*Pipeline
	labeller  Labeller

	// mu guards currentRole so Role() can be read from other goroutines (tests,
	// readiness).
	mu          sync.Mutex
	currentRole Role
}

// New constructs a Manager.  labeller may be nil (e.g. static-upstream tests),
// in which case leader labelling is skipped.
func New(cfg Config, elector Elector, labeller Labeller, pipelines []*Pipeline) *Manager {
	cfg.applyDefaults()
	return &Manager{
		cfg:         cfg,
		elector:     elector,
		pipelines:   pipelines,
		labeller:    labeller,
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
// from the elector, debounces them, and only ever runs one transition at a
// time.  New role events that arrive during a transition are absorbed (we read
// the *latest* desired role after each transition completes), so we never
// interrupt a transition mid-flight and we always converge to the latest role.
func (m *Manager) Run(ctx context.Context) {
	log.Info("Role manager starting.")
	defer m.shutdown()

	// desired tracks the latest role the elector wants us in.  Until the first
	// election result arrives we want to be a Follower (the bootstrap state):
	// a cold-start cluster has no leader, so every Typha follows until one is
	// elected and then everyone discovers it.
	desired := Follower

	// debounceTimer fires Debounce after the desired role last changed; we only
	// transition when it fires (or immediately on the very first convergence).
	var debounceC <-chan time.Time
	armDebounce := func() {
		timer := time.NewTimer(m.cfg.Debounce)
		debounceC = timer.C
	}

	// On startup, converge to the bootstrap (Follower) role immediately rather
	// than waiting a debounce period — there is nothing to flap against yet.
	m.transitionTo(ctx, desired)

	for {
		select {
		case <-ctx.Done():
			return
		case role := <-m.elector.Roles():
			newDesired := desiredFromElectorRole(role)
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

// desiredFromElectorRole maps a leader-election role to the role manager's
// desired acted role.
func desiredFromElectorRole(r leaderelection.Role) Role {
	if r == leaderelection.Leader {
		return Leader
	}
	return Follower
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

	// On demotion, drop our leader label *before* we stop serving as a leader so
	// that followers stop being directed at us as early as possible.
	if from == Leader && m.labeller != nil {
		if err := m.labeller.RemoveLeaderLabel(ctx); err != nil {
			logCxt.WithError(err).Warn("Failed to remove leader label during demotion; continuing.")
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

	// On promotion, advertise ourselves as leader only after the real syncers
	// have started (and, ideally, reached InSync).  We start the sources above;
	// the snapcache readiness reporters reflect InSync, and the leader Service
	// can additionally be readiness-gated.  We apply the label after starting
	// the sources so a follower never discovers a leader whose syncers haven't
	// begun; final InSync gating is provided by pod readiness on the Service.
	if target == Leader && m.labeller != nil {
		if err := m.labeller.SetLeaderLabel(ctx); err != nil {
			logCxt.WithError(err).Warn("Failed to set leader label during promotion; will rely on readiness gating.")
		}
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

	// 3. Build and start the new source.
	var newSrc syncsource.SyncerSource
	switch target {
	case Leader:
		newSrc = p.NewDatastoreSource()
	case Follower:
		newSrc = p.NewUpstreamSource()
	default:
		logCxt.Panic("swapPipelineSource called with non-source target")
	}
	logCxt.Debug("Starting new source.")
	if err := newSrc.Start(ctx); err != nil {
		// Start should not normally fail (the upstream source retries
		// internally; the datastore source's syncer.Start is best-effort).  Log
		// loudly and leave the pipeline sourceless — the next transition will
		// retry.  We do not panic: a single failed pipeline must not crash the
		// whole process.
		logCxt.WithError(err).Error("Failed to start new pipeline source.")
		return
	}
	p.current = newSrc
}

// shutdown stops every running source and removes the leader label.  Called when
// Run returns (context cancelled).  Stopping the sources blocks until their
// callbacks have drained; this is the in-process analogue of releasing the lease
// before draining clients (the daemon releases the lease by cancelling the
// elector's context before this runs).
func (m *Manager) shutdown() {
	log.Info("Role manager stopping; tearing down sources.")
	if m.labeller != nil {
		// Best-effort: use a short bounded context since our own ctx is done.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := m.labeller.RemoveLeaderLabel(ctx); err != nil {
			log.WithError(err).Warn("Failed to remove leader label on shutdown.")
		}
	}
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
