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

package rolemanager_test

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/projectcalico/calico/typha/pkg/rolemanager"
	"github.com/projectcalico/calico/typha/pkg/slotacquirer"
	"github.com/projectcalico/calico/typha/pkg/syncsource"
)

// event is a record of one lifecycle callback, used to verify ordering.
type event struct {
	pipeline string
	kind     string // "stop", "restart", "start"
	source   string // "datastore", "tier1" or "tier2"
}

// recorder collects ordering events from the fakes.  All fakes share one
// recorder so we can reason about the global ordering invariants.
type recorder struct {
	mu     sync.Mutex
	events []event
	// active counts, per pipeline, how many sources are currently "running"
	// (started but not stopped).  The swap invariant is that this never exceeds
	// 1 — the old source must be fully stopped before the new one starts.
	active   map[string]int
	overlaps int
}

func newRecorder() *recorder {
	return &recorder{active: map[string]int{}}
}

func (r *recorder) record(e event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
	switch e.kind {
	case "start":
		r.active[e.pipeline]++
		if r.active[e.pipeline] > 1 {
			r.overlaps++
		}
	case "stop":
		r.active[e.pipeline]--
	}
}

func (r *recorder) snapshot() []event {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]event, len(r.events))
	copy(out, r.events)
	return out
}

func (r *recorder) overlapCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.overlaps
}

// fakeSource is a SyncerSource that records its lifecycle on the shared
// recorder and honours the Stop-blocks contract (Stop returns only after the
// source is fully stopped; Done is closed then).
type fakeSource struct {
	pipeline string
	kind     string
	rec      *recorder

	mu      sync.Mutex
	started bool
	stopped bool
	done    chan struct{}
}

func newFakeSource(pipeline, kind string, rec *recorder) *fakeSource {
	return &fakeSource{pipeline: pipeline, kind: kind, rec: rec, done: make(chan struct{})}
}

func (s *fakeSource) Start(_ context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started || s.stopped {
		return nil
	}
	s.started = true
	s.rec.record(event{pipeline: s.pipeline, kind: "start", source: s.kind})
	return nil
}

func (s *fakeSource) Stop() {
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return
	}
	s.stopped = true
	started := s.started
	s.mu.Unlock()
	if started {
		s.rec.record(event{pipeline: s.pipeline, kind: "stop", source: s.kind})
	}
	close(s.done)
}

func (s *fakeSource) Done() <-chan struct{} { return s.done }

var _ syncsource.SyncerSource = (*fakeSource)(nil)

// sourceKindForRole names the fake source kind for a target role, matching the
// real daemon's per-role source selection.
func sourceKindForRole(role rolemanager.Role) string {
	switch role {
	case rolemanager.Leader:
		return "datastore"
	case rolemanager.Tier1:
		return "tier1"
	default:
		return "tier2"
	}
}

// spyBuffer records OnTyphaConnectionRestarted on the shared recorder.
type spyBuffer struct {
	pipeline string
	rec      *recorder
}

func (b *spyBuffer) OnTyphaConnectionRestarted() {
	b.rec.record(event{pipeline: b.pipeline, kind: "restart"})
}

// fakeRoleSource implements rolemanager.RoleSource with a channel we drive.
type fakeRoleSource struct {
	ch chan slotacquirer.Role
}

func newFakeRoleSource() *fakeRoleSource {
	return &fakeRoleSource{ch: make(chan slotacquirer.Role, 16)}
}

func (e *fakeRoleSource) Roles() <-chan slotacquirer.Role { return e.ch }

func (e *fakeRoleSource) send(r slotacquirer.Role) { e.ch <- r }

// fakeLabeller records the sequence of tier labels applied.
type fakeLabeller struct {
	mu     sync.Mutex
	labels []rolemanager.Role
}

func (l *fakeLabeller) SetTierLabel(_ context.Context, role rolemanager.Role) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.labels = append(l.labels, role)
	return nil
}

func (l *fakeLabeller) seq() []rolemanager.Role {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]rolemanager.Role, len(l.labels))
	copy(out, l.labels)
	return out
}

// fakeDrainer counts how many times off-node clients were drained.
type fakeDrainer struct {
	mu     sync.Mutex
	drains int
}

func (d *fakeDrainer) DrainOffNodeClients(string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.drains++
}

func (d *fakeDrainer) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.drains
}

// buildPipelines makes n pipelines wired to the shared recorder.  Each
// NewSourceForRole returns a fresh fakeSource tagged with the role's source
// kind.
func buildPipelines(n int, rec *recorder) []*rolemanager.Pipeline {
	pipelines := make([]*rolemanager.Pipeline, n)
	for i := range pipelines {
		name := fmt.Sprintf("p%d", i)
		pipelines[i] = &rolemanager.Pipeline{
			Name:   name,
			Buffer: &spyBuffer{pipeline: name, rec: rec},
			NewSourceForRole: func(role rolemanager.Role) syncsource.SyncerSource {
				return newFakeSource(name, sourceKindForRole(role), rec)
			},
		}
	}
	return pipelines
}

func waitForRole(t *testing.T, m *rolemanager.Manager, want rolemanager.Role, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if m.Role() == want {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for role %v; current %v", want, m.Role())
}

// assertSwapOrdering checks that, within each pipeline, the events obey the
// stop → restart → start ordering for every swap and that a "start" of a new
// source is always preceded by the "restart" signal (and, after the first
// transition, by a "stop" of the previous source).
func assertSwapOrdering(t *testing.T, events []event, pipeline string) {
	t.Helper()
	var seq []string
	for _, e := range events {
		if e.pipeline != pipeline {
			continue
		}
		seq = append(seq, e.kind)
	}
	// The first event for a pipeline is always a restart followed by a start
	// (cold start: no previous source to stop).  Every subsequent source change
	// is stop, restart, start.
	i := 0
	first := true
	for i < len(seq) {
		if !first {
			if seq[i] != "stop" {
				t.Fatalf("pipeline %s: expected 'stop' at position %d, got sequence %v", pipeline, i, seq)
			}
			i++
		}
		first = false
		if i >= len(seq) || seq[i] != "restart" {
			t.Fatalf("pipeline %s: expected 'restart' at position %d, got sequence %v", pipeline, i, seq)
		}
		i++
		if i >= len(seq) || seq[i] != "start" {
			t.Fatalf("pipeline %s: expected 'start' at position %d, got sequence %v", pipeline, i, seq)
		}
		i++
	}
}

// TestBootstrapToTier2 verifies the manager converges to Tier2 on startup (no
// slot held yet) and starts tier-2 upstream sources on every pipeline.
func TestBootstrapToTier2(t *testing.T) {
	rec := newRecorder()
	el := newFakeRoleSource()
	pipelines := buildPipelines(4, rec)
	m := rolemanager.New(rolemanager.Config{Debounce: 20 * time.Millisecond}, el, nil, nil, pipelines)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Run(ctx)

	waitForRole(t, m, rolemanager.Tier2, 2*time.Second)

	events := rec.snapshot()
	starts := map[string]int{}
	for _, e := range events {
		if e.kind == "start" {
			starts[e.source]++
		}
	}
	if starts["tier2"] != 4 {
		t.Fatalf("expected 4 tier2 starts, got %v", starts)
	}
	if starts["datastore"] != 0 || starts["tier1"] != 0 {
		t.Fatalf("expected no datastore/tier1 starts on bootstrap, got %v", starts)
	}
}

// TestSingleTierReproducesWSC is the regression guard: with only Leader/Tier2
// roles ever emitted (the Tier1Count=0 case — the acquirer never produces
// Tier1), the manager behaves exactly like WS-C's two-state machine: bootstrap
// to leaf, promote to leader (datastore syncers), demote back to leaf, with the
// stop→restart→start ordering and no source overlap.
func TestSingleTierReproducesWSC(t *testing.T) {
	rec := newRecorder()
	el := newFakeRoleSource()
	lab := &fakeLabeller{}
	pipelines := buildPipelines(4, rec)
	m := rolemanager.New(rolemanager.Config{Debounce: 20 * time.Millisecond}, el, lab, nil, pipelines)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Run(ctx)

	waitForRole(t, m, rolemanager.Tier2, 2*time.Second)

	// Promote straight to Leader (no Tier1 in between — single-tier).
	el.send(slotacquirer.Leader)
	waitForRole(t, m, rolemanager.Leader, 2*time.Second)

	// Demote straight back to Tier2.
	el.send(slotacquirer.Tier2)
	waitForRole(t, m, rolemanager.Tier2, 2*time.Second)

	events := rec.snapshot()
	for i := 0; i < 4; i++ {
		assertSwapOrdering(t, events, fmt.Sprintf("p%d", i))
	}
	if got := rec.overlapCount(); got != 0 {
		t.Fatalf("expected no overlapping sources, got %d overlaps; events %v", got, events)
	}
	// Only datastore and tier2 sources are ever used — never tier1.
	for _, e := range events {
		if e.source == "tier1" {
			t.Fatalf("tier1 source used in single-tier mode; events %v", events)
		}
	}
	// Tier label sequence: bootstrap(2) → leader → 2.
	if seq := lab.seq(); len(seq) != 3 ||
		seq[0] != rolemanager.Tier2 || seq[1] != rolemanager.Leader || seq[2] != rolemanager.Tier2 {
		t.Fatalf("unexpected tier label sequence %v", seq)
	}
}

// TestThreeRolePromotionLadder verifies the full ladder Tier2→Tier1→Leader and
// back, with correct per-pipeline swap ordering, no overlap, and the right
// source kind for each role.
func TestThreeRolePromotionLadder(t *testing.T) {
	rec := newRecorder()
	el := newFakeRoleSource()
	lab := &fakeLabeller{}
	drainer := &fakeDrainer{}
	pipelines := buildPipelines(4, rec)
	m := rolemanager.New(rolemanager.Config{Debounce: 20 * time.Millisecond}, el, lab, drainer, pipelines)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Run(ctx)

	waitForRole(t, m, rolemanager.Tier2, 2*time.Second)

	el.send(slotacquirer.Tier1)
	waitForRole(t, m, rolemanager.Tier1, 2*time.Second)

	el.send(slotacquirer.Leader)
	waitForRole(t, m, rolemanager.Leader, 2*time.Second)

	el.send(slotacquirer.Tier1)
	waitForRole(t, m, rolemanager.Tier1, 2*time.Second)

	el.send(slotacquirer.Tier2)
	waitForRole(t, m, rolemanager.Tier2, 2*time.Second)

	events := rec.snapshot()
	for i := 0; i < 4; i++ {
		assertSwapOrdering(t, events, fmt.Sprintf("p%d", i))
	}
	if got := rec.overlapCount(); got != 0 {
		t.Fatalf("source overlap during ladder: %d; events %v", got, events)
	}

	// Per pipeline, the source-kind sequence should be tier2, tier1, datastore,
	// tier1, tier2.
	want := []string{"tier2", "tier1", "datastore", "tier1", "tier2"}
	gotByPipeline := map[string][]string{}
	for _, e := range events {
		if e.kind == "start" {
			gotByPipeline[e.pipeline] = append(gotByPipeline[e.pipeline], e.source)
		}
	}
	for i := 0; i < 4; i++ {
		p := fmt.Sprintf("p%d", i)
		if fmt.Sprint(gotByPipeline[p]) != fmt.Sprint(want) {
			t.Fatalf("pipeline %s source sequence %v, want %v", p, gotByPipeline[p], want)
		}
	}

	// Drained off-node clients exactly twice: Tier2→Tier1 and (later) Tier2→...
	// only the first promotion out of tier-2 happens here (Tier2→Tier1).  The
	// Tier1→Leader promotion is not "out of tier-2".  And the final Tier1→Tier2
	// is a demotion.  So exactly one drain.
	if got := drainer.count(); got != 1 {
		t.Fatalf("expected exactly 1 off-node drain (on leaving Tier2), got %d", got)
	}
}

// TestDrainOnlyWhenLeavingTier2 verifies the drainer fires on Tier2→Leader (a
// direct promotion out of tier-2) but not on Tier1→Leader.
func TestDrainOnlyWhenLeavingTier2(t *testing.T) {
	rec := newRecorder()
	el := newFakeRoleSource()
	drainer := &fakeDrainer{}
	pipelines := buildPipelines(1, rec)
	m := rolemanager.New(rolemanager.Config{Debounce: 20 * time.Millisecond}, el, nil, drainer, pipelines)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Run(ctx)
	waitForRole(t, m, rolemanager.Tier2, 2*time.Second)

	// Tier2 → Leader directly: one drain.
	el.send(slotacquirer.Leader)
	waitForRole(t, m, rolemanager.Leader, 2*time.Second)
	if got := drainer.count(); got != 1 {
		t.Fatalf("expected 1 drain on Tier2→Leader, got %d", got)
	}

	// Leader → Tier1 (demotion): no drain.
	el.send(slotacquirer.Tier1)
	waitForRole(t, m, rolemanager.Tier1, 2*time.Second)
	if got := drainer.count(); got != 1 {
		t.Fatalf("expected no extra drain on Leader→Tier1, got %d", got)
	}

	// Tier1 → Leader (promotion, but not out of tier-2): no drain.
	el.send(slotacquirer.Leader)
	waitForRole(t, m, rolemanager.Leader, 2*time.Second)
	if got := drainer.count(); got != 1 {
		t.Fatalf("expected no extra drain on Tier1→Leader, got %d", got)
	}
}

// TestDebounceCoalescesFlap verifies that a quick Tier2→Leader→Tier2 flap within
// the debounce window does not produce a transition to Leader at all.
func TestDebounceCoalescesFlap(t *testing.T) {
	rec := newRecorder()
	el := newFakeRoleSource()
	pipelines := buildPipelines(1, rec)
	m := rolemanager.New(rolemanager.Config{Debounce: 200 * time.Millisecond}, el, nil, nil, pipelines)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Run(ctx)

	waitForRole(t, m, rolemanager.Tier2, 2*time.Second)

	el.send(slotacquirer.Leader)
	time.Sleep(20 * time.Millisecond)
	el.send(slotacquirer.Tier2)

	time.Sleep(400 * time.Millisecond)

	if m.Role() != rolemanager.Tier2 {
		t.Fatalf("expected to remain Tier2 after flap, got %v", m.Role())
	}
	for _, e := range rec.snapshot() {
		if e.kind == "start" && e.source == "datastore" {
			t.Fatalf("datastore source started despite debounced flap; events %v", rec.snapshot())
		}
	}
}

// TestFlapStorm toggles the role every 100ms for 10s (under -race) and asserts
// the manager converges to the final role, never overlaps sources, and leaks no
// goroutines.
func TestFlapStorm(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping flap storm in -short mode")
	}
	rec := newRecorder()
	el := newFakeRoleSource()
	lab := &fakeLabeller{}
	pipelines := buildPipelines(4, rec)
	m := rolemanager.New(rolemanager.Config{Debounce: 30 * time.Millisecond}, el, lab, nil, pipelines)

	baseGoroutines := runtime.NumGoroutine()

	ctx, cancel := context.WithCancel(context.Background())
	go m.Run(ctx)

	waitForRole(t, m, rolemanager.Tier2, 2*time.Second)

	end := time.Now().Add(10 * time.Second)
	roles := []slotacquirer.Role{slotacquirer.Leader, slotacquirer.Tier1, slotacquirer.Tier2}
	i := 0
	for time.Now().Before(end) {
		el.send(roles[i%len(roles)])
		i++
		time.Sleep(100 * time.Millisecond)
	}

	el.send(slotacquirer.Leader)
	waitForRole(t, m, rolemanager.Leader, 5*time.Second)

	if got := rec.overlapCount(); got != 0 {
		t.Fatalf("source overlap during flap storm: %d", got)
	}

	cancel()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if m.Role() == rolemanager.Sourceless {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if m.Role() != rolemanager.Sourceless {
		t.Fatalf("manager did not return to Sourceless after shutdown; role %v", m.Role())
	}
	time.Sleep(200 * time.Millisecond)
	if leaked := runtime.NumGoroutine() - baseGoroutines; leaked > 5 {
		t.Fatalf("possible goroutine leak: %d extra goroutines", leaked)
	}
}

// TestShutdownStopsSources verifies that cancelling Run's context stops all
// running sources.
func TestShutdownStopsSources(t *testing.T) {
	rec := newRecorder()
	el := newFakeRoleSource()
	pipelines := buildPipelines(4, rec)
	m := rolemanager.New(rolemanager.Config{Debounce: 20 * time.Millisecond}, el, nil, nil, pipelines)

	ctx, cancel := context.WithCancel(context.Background())
	go m.Run(ctx)
	waitForRole(t, m, rolemanager.Tier2, 2*time.Second)
	el.send(slotacquirer.Leader)
	waitForRole(t, m, rolemanager.Leader, 2*time.Second)

	cancel()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && m.Role() != rolemanager.Sourceless {
		time.Sleep(5 * time.Millisecond)
	}
	if m.Role() != rolemanager.Sourceless {
		t.Fatalf("expected Sourceless after shutdown, got %v", m.Role())
	}

	stops := 0
	for _, e := range rec.snapshot() {
		if e.kind == "stop" && e.source == "datastore" {
			stops++
		}
	}
	if stops != 4 {
		t.Fatalf("expected 4 datastore stops on shutdown, got %d", stops)
	}
}
