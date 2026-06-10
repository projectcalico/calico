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

	"github.com/projectcalico/calico/typha/pkg/leaderelection"
	"github.com/projectcalico/calico/typha/pkg/rolemanager"
	"github.com/projectcalico/calico/typha/pkg/syncsource"
)

// event is a record of one lifecycle callback, used to verify ordering.
type event struct {
	pipeline string
	kind     string // "stop", "restart", "start"
	source   string // "datastore" or "upstream"
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

// spyBuffer records OnTyphaConnectionRestarted on the shared recorder.
type spyBuffer struct {
	pipeline string
	rec      *recorder
}

func (b *spyBuffer) OnTyphaConnectionRestarted() {
	b.rec.record(event{pipeline: b.pipeline, kind: "restart"})
}

// fakeElector implements rolemanager.Elector with a channel we drive directly.
type fakeElector struct {
	ch chan leaderelection.Role
}

func newFakeElector() *fakeElector {
	return &fakeElector{ch: make(chan leaderelection.Role, 16)}
}

func (e *fakeElector) Roles() <-chan leaderelection.Role { return e.ch }

func (e *fakeElector) send(r leaderelection.Role) { e.ch <- r }

// fakeLabeller records set/remove calls.
type fakeLabeller struct {
	mu       sync.Mutex
	setCalls int
	rmCalls  int
}

func (l *fakeLabeller) SetLeaderLabel(context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.setCalls++
	return nil
}

func (l *fakeLabeller) RemoveLeaderLabel(context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.rmCalls++
	return nil
}

func (l *fakeLabeller) counts() (set, rm int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.setCalls, l.rmCalls
}

// buildPipelines makes n pipelines wired to the shared recorder.  Each
// NewDatastoreSource / NewUpstreamSource returns a fresh fakeSource.
func buildPipelines(n int, rec *recorder) []*rolemanager.Pipeline {
	pipelines := make([]*rolemanager.Pipeline, n)
	for i := range pipelines {
		name := fmt.Sprintf("p%d", i)
		pipelines[i] = &rolemanager.Pipeline{
			Name:               name,
			Buffer:             &spyBuffer{pipeline: name, rec: rec},
			NewDatastoreSource: func() syncsource.SyncerSource { return newFakeSource(name, "datastore", rec) },
			NewUpstreamSource:  func() syncsource.SyncerSource { return newFakeSource(name, "upstream", rec) },
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

// TestBootstrapToFollower verifies the manager converges to Follower on startup
// (no leader yet) and starts upstream sources on every pipeline.
func TestBootstrapToFollower(t *testing.T) {
	rec := newRecorder()
	el := newFakeElector()
	pipelines := buildPipelines(4, rec)
	m := rolemanager.New(rolemanager.Config{Debounce: 20 * time.Millisecond}, el, nil, pipelines)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Run(ctx)

	waitForRole(t, m, rolemanager.Follower, 2*time.Second)

	// Every pipeline should have an upstream source started, no datastore.
	events := rec.snapshot()
	starts := map[string]int{}
	for _, e := range events {
		if e.kind == "start" {
			starts[e.source]++
		}
	}
	if starts["upstream"] != 4 {
		t.Fatalf("expected 4 upstream starts, got %v", starts)
	}
	if starts["datastore"] != 0 {
		t.Fatalf("expected 0 datastore starts, got %v", starts)
	}
}

// TestPromoteThenDemote verifies a follower promotes to leader (datastore
// sources) and back, with correct per-pipeline swap ordering and no overlap.
func TestPromoteThenDemote(t *testing.T) {
	rec := newRecorder()
	el := newFakeElector()
	lab := &fakeLabeller{}
	pipelines := buildPipelines(4, rec)
	m := rolemanager.New(rolemanager.Config{Debounce: 20 * time.Millisecond}, el, lab, pipelines)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Run(ctx)

	waitForRole(t, m, rolemanager.Follower, 2*time.Second)

	// Promote.
	el.send(leaderelection.Leader)
	waitForRole(t, m, rolemanager.Leader, 2*time.Second)

	// Demote.
	el.send(leaderelection.Follower)
	waitForRole(t, m, rolemanager.Follower, 2*time.Second)

	events := rec.snapshot()
	for i := 0; i < 4; i++ {
		assertSwapOrdering(t, events, fmt.Sprintf("p%d", i))
	}
	if got := rec.overlapCount(); got != 0 {
		t.Fatalf("expected no overlapping sources, got %d overlaps; events %v", got, events)
	}

	// Label applied on promotion, removed on demotion (and possibly on
	// shutdown, but we haven't cancelled yet).
	set, rm := lab.counts()
	if set != 1 {
		t.Fatalf("expected 1 SetLeaderLabel, got %d", set)
	}
	if rm != 1 {
		t.Fatalf("expected 1 RemoveLeaderLabel (demotion), got %d", rm)
	}
}

// TestDebounceCoalescesFlap verifies that a quick Leader→Follower flap within
// the debounce window does not produce a transition to Leader at all.
func TestDebounceCoalescesFlap(t *testing.T) {
	rec := newRecorder()
	el := newFakeElector()
	pipelines := buildPipelines(1, rec)
	m := rolemanager.New(rolemanager.Config{Debounce: 200 * time.Millisecond}, el, nil, pipelines)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Run(ctx)

	waitForRole(t, m, rolemanager.Follower, 2*time.Second)

	// Flap Leader then back to Follower well within the debounce window.
	el.send(leaderelection.Leader)
	time.Sleep(20 * time.Millisecond)
	el.send(leaderelection.Follower)

	// Give the debounce timer time to fire.
	time.Sleep(400 * time.Millisecond)

	if m.Role() != rolemanager.Follower {
		t.Fatalf("expected to remain Follower after flap, got %v", m.Role())
	}
	// No datastore source should ever have started.
	for _, e := range rec.snapshot() {
		if e.kind == "start" && e.source == "datastore" {
			t.Fatalf("datastore source started despite debounced flap; events %v", rec.snapshot())
		}
	}
}

// TestFlapStorm toggles the role every 100ms for 10s (under the race detector
// via -race) and asserts the manager converges to the final role, never
// overlaps sources, and leaks no goroutines.
func TestFlapStorm(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping flap storm in -short mode")
	}
	rec := newRecorder()
	el := newFakeElector()
	lab := &fakeLabeller{}
	pipelines := buildPipelines(4, rec)
	// Small debounce so transitions actually happen during the storm.
	m := rolemanager.New(rolemanager.Config{Debounce: 30 * time.Millisecond}, el, lab, pipelines)

	baseGoroutines := runtime.NumGoroutine()

	ctx, cancel := context.WithCancel(context.Background())
	go m.Run(ctx)

	waitForRole(t, m, rolemanager.Follower, 2*time.Second)

	end := time.Now().Add(10 * time.Second)
	toggle := leaderelection.Leader
	for time.Now().Before(end) {
		el.send(toggle)
		if toggle == leaderelection.Leader {
			toggle = leaderelection.Follower
		} else {
			toggle = leaderelection.Leader
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Settle on Leader and let the manager converge.
	el.send(leaderelection.Leader)
	waitForRole(t, m, rolemanager.Leader, 5*time.Second)

	if got := rec.overlapCount(); got != 0 {
		t.Fatalf("source overlap during flap storm: %d", got)
	}

	// Shut down and confirm no goroutine leak.
	cancel()
	// Manager.Run returns after shutdown(); give it a moment.
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
	// Allow transient goroutines to exit.
	time.Sleep(200 * time.Millisecond)
	if leaked := runtime.NumGoroutine() - baseGoroutines; leaked > 5 {
		t.Fatalf("possible goroutine leak: %d extra goroutines", leaked)
	}
}

// TestShutdownStopsSources verifies that cancelling Run's context stops all
// running sources and removes the leader label.
func TestShutdownStopsSources(t *testing.T) {
	rec := newRecorder()
	el := newFakeElector()
	lab := &fakeLabeller{}
	pipelines := buildPipelines(4, rec)
	m := rolemanager.New(rolemanager.Config{Debounce: 20 * time.Millisecond}, el, lab, pipelines)

	ctx, cancel := context.WithCancel(context.Background())
	go m.Run(ctx)
	waitForRole(t, m, rolemanager.Follower, 2*time.Second)
	el.send(leaderelection.Leader)
	waitForRole(t, m, rolemanager.Leader, 2*time.Second)

	cancel()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && m.Role() != rolemanager.Sourceless {
		time.Sleep(5 * time.Millisecond)
	}
	if m.Role() != rolemanager.Sourceless {
		t.Fatalf("expected Sourceless after shutdown, got %v", m.Role())
	}

	// Each pipeline's running datastore source should have been stopped.
	stops := 0
	for _, e := range rec.snapshot() {
		if e.kind == "stop" && e.source == "datastore" {
			stops++
		}
	}
	if stops != 4 {
		t.Fatalf("expected 4 datastore stops on shutdown, got %d", stops)
	}
	// Label removed at least once (demotion-from-leader on shutdown).
	if _, rm := lab.counts(); rm < 1 {
		t.Fatalf("expected leader label removed on shutdown")
	}
}
