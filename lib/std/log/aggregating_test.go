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

// These tests sit inside the package so they can drive sample() with an explicit clock, which keeps
// them off the wall clock and out of sleeps.
package log

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"
)

// t0 anchors every test to a fixed instant, so results never depend on when the suite runs.
var t0 = time.Unix(1_700_000_000, 0)

const testInterval = 5 * time.Minute

// TestAggregatingLoggerFloodOfOneValue covers the simplest flood shape: one value recurring over and
// over on a hot path. The repeats must collapse to one window per interval, and that window must
// still account for every occurrence it swallowed.
func TestAggregatingLoggerFloodOfOneValue(t *testing.T) {
	a := NewAggregatingLogger("IPSet not found", "ipsets", OptInterval(testInterval))

	const occurrences = 100
	var emitted []*aggregateWindow
	for i := range occurrences {
		// All inside one interval, so only the very first occurrence emits.
		if w := a.sample("s:missing", t0.Add(time.Duration(i)*time.Millisecond)); w != nil {
			emitted = append(emitted, w)
		}
	}

	if len(emitted) != 1 {
		t.Fatalf("expected 1 emitted window within the interval, got %d", len(emitted))
	}
	// The first occurrence emits immediately, with nothing accumulated behind it yet.
	mustNameExactly(t, emitted[0], "s:missing")
	mustTotal(t, emitted[0], 1)
	mustUnnamed(t, emitted[0], 0)

	// Once the interval elapses the next occurrence emits, reporting every repeat it suppressed.
	w := a.sample("s:missing", t0.Add(testInterval+time.Second))
	if w == nil {
		t.Fatal("expected an emitted window once the interval had elapsed")
	}
	mustNameExactly(t, w, "s:missing")
	mustUnnamed(t, w, 0)
	// occurrences-1 suppressed (the first emitted in its own window), plus this emitting one.
	mustTotal(t, w, occurrences)
}

// TestAggregatingLoggerNamesEveryDistinctValue covers the shape that motivates this type: not one
// value repeated but many distinct ones, each hit at volume. Suppressing by time alone would name
// only whichever value tripped the timer; this must name them all.
func TestAggregatingLoggerNamesEveryDistinctValue(t *testing.T) {
	a := NewAggregatingLogger("IPSet not found", "ipsets", OptInterval(testInterval))

	// The first occurrence emits immediately, carrying only itself.
	first := a.sample("s:missing-00", t0)
	if first == nil {
		t.Fatal("expected the first occurrence to emit")
	}
	mustNameExactly(t, first, "s:missing-00")

	// A burst of further distinct values inside the interval: all folded in, none emitted.
	const distinct = 50
	var want []string
	for i := 1; i < distinct; i++ {
		value := fmt.Sprintf("s:missing-%02d", i)
		want = append(want, value)
		if w := a.sample(value, t0.Add(time.Duration(i)*time.Millisecond)); w != nil {
			t.Fatalf("occurrence %d emitted inside the interval, expected it to be folded in", i)
		}
	}

	// The next occurrence after the interval emits, naming every value accumulated in the window.
	// s:missing-00 emitted in its own window and so is not carried into this one.
	want = append(want, "s:missing-final")
	slices.Sort(want)

	w := a.sample("s:missing-final", t0.Add(testInterval+time.Second))
	if w == nil {
		t.Fatal("expected an emitted window once the interval had elapsed")
	}
	mustNameExactly(t, w, want...)
	mustUnnamed(t, w, 0)
	mustTotal(t, w, distinct)
}

// TestAggregatingLoggerClosesAWindowThatGoesQuiet covers the burst that stops. Draining only when
// the next occurrence arrives would leave everything the burst accumulated unreported until the
// condition recurred - hours later for a transient fault, or never - and would then report it as
// though it were happening at that moment. The window must close on its own instead.
func TestAggregatingLoggerClosesAWindowThatGoesQuiet(t *testing.T) {
	capture := &captureLogger{level: LevelDebug}
	timer := &fakeTimer{}
	a := NewAggregatingLogger("IPSet not found", "ipsets", OptInterval(testInterval), OptLogger(capture))
	a.afterFunc = timer.afterFunc

	// The first occurrence emits on its own, as Record would write it.
	w := a.sample("s:missing-00", t0)
	if w == nil {
		t.Fatal("expected the first occurrence to emit")
	}
	a.emit(capture, w)

	// The rest of the burst folds in behind it, and then the condition clears: nothing arrives after
	// this to drain what they left.
	const distinct = 20
	var want []string
	for i := 1; i < distinct; i++ {
		value := fmt.Sprintf("s:missing-%02d", i)
		want = append(want, value)
		if w := a.sample(value, t0.Add(time.Duration(i)*time.Millisecond)); w != nil {
			t.Fatalf("occurrence %d emitted inside the interval, expected it to be folded in", i)
		}
	}
	slices.Sort(want)

	// One close per window, however many occurrences join it, and scheduled for the end of the
	// window rather than an interval after whichever occurrence happened to schedule it.
	if len(timer.armed) != 1 {
		t.Fatalf("scheduled %d closes for one window, expected 1", len(timer.armed))
	}
	if got := timer.armed[0].after; got != testInterval-time.Millisecond {
		t.Errorf("close scheduled in %v, expected %v", got, testInterval-time.Millisecond)
	}

	// The window closes on its own, naming everything held in it.
	timer.armed[0].fire()
	if len(capture.lines) != 2 {
		t.Fatalf("wrote %d lines, expected the first occurrence and then the closed window",
			len(capture.lines))
	}
	mustLoggedArgs(t, capture.last(), "ipsets", AggregatedValues(want), fieldTotalEvents, distinct-1)
}

// TestAggregatingLoggerCloseYieldsToARecordThatDrainedFirst covers the two ways a window can end
// meeting each other. An occurrence arriving after the interval drains the window itself, so the
// close scheduled for that window must do nothing rather than write a second, empty line - while the
// window opened behind it still gets a close of its own.
func TestAggregatingLoggerCloseYieldsToARecordThatDrainedFirst(t *testing.T) {
	capture := &captureLogger{level: LevelDebug}
	timer := &fakeTimer{}
	a := NewAggregatingLogger("IPSet not found", "ipsets", OptInterval(testInterval), OptLogger(capture))
	a.afterFunc = timer.afterFunc

	if w := a.sample("s:seed", t0); w == nil {
		t.Fatal("expected the first occurrence to emit")
	}
	if w := a.sample("s:held", t0.Add(time.Second)); w != nil {
		t.Fatal("expected the second occurrence to fold into the window")
	}

	// An occurrence after the interval drains the window, taking what was held with it.
	w := a.sample("s:drains-it", t0.Add(testInterval+time.Second))
	if w == nil {
		t.Fatal("expected the occurrence after the interval to emit")
	}
	mustNameExactly(t, w, "s:drains-it", "s:held")
	a.emit(capture, w)

	// So the close scheduled for that window has nothing left to write.
	timer.armed[0].fire()
	if len(capture.lines) != 1 {
		t.Fatalf("wrote %d lines, expected the overtaken close to write nothing", len(capture.lines))
	}

	// The window the drain opened schedules its own close, and that one does write.
	if w := a.sample("s:next", t0.Add(testInterval+2*time.Second)); w != nil {
		t.Fatal("expected the next occurrence to fold into the new window")
	}
	if len(timer.armed) != 2 {
		t.Fatalf("scheduled %d closes, expected one per window", len(timer.armed))
	}
	timer.armed[1].fire()
	if len(capture.lines) != 2 {
		t.Fatalf("wrote %d lines, expected the new window to close too", len(capture.lines))
	}
	mustLoggedArgs(t, capture.last(), "ipsets", AggregatedValues{"s:next"}, fieldTotalEvents, 1)
}

// fakeTimer stands in for time.AfterFunc, holding the window closes an AggregatingLogger schedules
// so that a test can fire them where a real timer would, with no sleep and no wall clock.
type fakeTimer struct {
	armed []scheduledClose
}

type scheduledClose struct {
	after time.Duration
	fire  func()
}

func (f *fakeTimer) afterFunc(d time.Duration, fn func()) {
	f.armed = append(f.armed, scheduledClose{after: d, fire: fn})
}

// TestAggregatingLoggerCapsNamedValues asserts the cap bounds both the emitted line and the memory
// held behind it: past maxNamed distinct values, further ones are counted, not named.
func TestAggregatingLoggerCapsNamedValues(t *testing.T) {
	const maxNamed = 10
	a := NewAggregatingLogger("IPSet not found", "ipsets",
		OptInterval(testInterval), OptMaxNamed(maxNamed))

	// Emit and reset the initial window so the next one starts empty.
	if w := a.sample("s:seed", t0); w == nil {
		t.Fatal("expected the first occurrence to emit")
	}

	// Feed far more distinct values than the cap, all inside the interval.
	const distinct = 100
	for i := range distinct {
		a.sample(fmt.Sprintf("s:over-%03d", i), t0.Add(time.Duration(i+1)*time.Millisecond))
	}

	w := a.sample("s:trigger", t0.Add(testInterval+time.Second))
	if w == nil {
		t.Fatal("expected an emitted window once the interval had elapsed")
	}
	if len(w.named) != maxNamed {
		t.Errorf("named %d values, expected the cap of %d", len(w.named), maxNamed)
	}
	// Everything that did not fit under the cap is counted instead: the distinct over-values plus
	// the triggering one, less the maxNamed that were named.
	mustUnnamed(t, w, distinct+1-maxNamed)
	mustTotal(t, w, distinct+1)
	// The accumulator itself never grew past the cap either.
	if len(a.named) != 0 {
		t.Errorf("accumulator holds %d values after draining, expected 0", len(a.named))
	}
}

// TestAggregatingLoggerCountsOverflowOccurrences pins down what the overflow counter means, which is
// the thing easiest to get wrong: it counts *occurrences* that could not be named, never distinct
// values. One value hammering the hot path past the cap must not read as thousands of distinct
// values - inferring a distinct count from these occurrences would overstate the problem by three
// orders of magnitude, exactly when someone is trying to size it.
func TestAggregatingLoggerCountsOverflowOccurrences(t *testing.T) {
	const maxNamed = 3
	capture := &captureLogger{level: LevelDebug}
	a := NewAggregatingLogger("IPSet not found", "ipsets",
		OptInterval(testInterval), OptMaxNamed(maxNamed), OptLogger(capture))

	if w := a.sample("s:seed", t0); w == nil {
		t.Fatal("expected the first occurrence to emit")
	}

	// Fill the cap.
	for i := range maxNamed {
		a.sample(fmt.Sprintf("s:in-cap-%d", i), t0.Add(time.Duration(i+1)*time.Millisecond))
	}
	// Then a single further value, recurring the way a hot path makes it recur.
	const repeats = 1000
	for i := range repeats {
		a.sample("s:overflow", t0.Add(time.Duration(maxNamed+1+i)*time.Millisecond))
	}

	w := a.sample("s:overflow", t0.Add(testInterval+time.Second))
	if w == nil {
		t.Fatal("expected an emitted window once the interval had elapsed")
	}
	mustNameExactly(t, w, "s:in-cap-0", "s:in-cap-1", "s:in-cap-2")
	// Four distinct values occurred; 1001 occurrences of the fourth went unnamed.
	mustUnnamed(t, w, repeats+1)
	mustTotal(t, w, maxNamed+repeats+1)

	// And the emitted line says so in those terms. The arguments are asserted exhaustively: a line
	// carrying anything that reads as a distinct-value count would be claiming 1004 where the truth
	// is 4, and would do so precisely when a reader is trying to size the problem.
	a.emit(capture, w)
	mustLoggedArgs(t, capture.last(),
		"ipsets", w.named,
		fieldTotalEvents, maxNamed+repeats+1,
		fieldUnnamedEvents, repeats+1,
		fieldMaxNamed, maxNamed,
	)
}

// TestAggregatingLoggerEmittedArgs covers the shape of the line itself: an uncapped window says only
// what it saw, and a capped one adds the two values that flag the list as partial.
func TestAggregatingLoggerEmittedArgs(t *testing.T) {
	const maxNamed = 2
	capture := &captureLogger{level: LevelDebug}
	a := NewAggregatingLogger("IPSet not found", "ipsets",
		OptInterval(testInterval), OptMaxNamed(maxNamed), OptLogger(capture))

	// An uncapped window: the value list is complete, so nothing flags it as partial.
	a.emit(capture, &aggregateWindow{named: AggregatedValues{"s:a", "s:b"}, total: 7})
	if got := capture.last().msg; got != "IPSet not found" {
		t.Errorf("message %q, expected %q", got, "IPSet not found")
	}
	mustLoggedArgs(t, capture.last(), "ipsets", AggregatedValues{"s:a", "s:b"}, fieldTotalEvents, 7)

	// A capped window: same values plus the two that say the list is short of the whole story.
	a.emit(capture, &aggregateWindow{named: AggregatedValues{"s:a", "s:b"}, unnamed: 40, total: 47})
	mustLoggedArgs(t, capture.last(),
		"ipsets", AggregatedValues{"s:a", "s:b"},
		fieldTotalEvents, 47,
		fieldUnnamedEvents, 40,
		fieldMaxNamed, maxNamed,
	)
}

// TestAggregatingLoggerReportsAtItsLevel asserts the level is the aggregator's, not a fixed Warn:
// whatever OptLevel names is the method the line goes out on. The conditions worth aggregating span
// Debug through Error - a missing entry is a warning, an uncompilable expression is an error - and
// each wants reporting at its own severity.
func TestAggregatingLoggerReportsAtItsLevel(t *testing.T) {
	for _, tc := range []struct {
		level      Level
		wantMethod string
	}{
		{LevelError, "Error"},
		{LevelWarn, "Warn"},
		{LevelInfo, "Info"},
		{LevelDebug, "Debug"},
	} {
		t.Run(tc.wantMethod, func(t *testing.T) {
			capture := &captureLogger{level: LevelDebug}
			a := NewAggregatingLogger("condition", "values",
				OptLevel(tc.level), OptLogger(capture))

			a.Record("v:one")

			if len(capture.lines) != 1 {
				t.Fatalf("wrote %d lines, expected 1", len(capture.lines))
			}
			if capture.last().method != tc.wantMethod {
				t.Errorf("wrote via %s, expected %s", capture.last().method, tc.wantMethod)
			}
		})
	}
}

// TestAggregatingLoggerDefaultsToWarn pins the default, since most callers will not name a level.
func TestAggregatingLoggerDefaultsToWarn(t *testing.T) {
	capture := &captureLogger{level: LevelDebug}
	a := NewAggregatingLogger("condition", "values", OptLogger(capture))

	a.Record("v:one")

	if len(capture.lines) != 1 {
		t.Fatalf("wrote %d lines, expected 1", len(capture.lines))
	}
	if capture.last().method != "Warn" {
		t.Errorf("wrote via %s, expected Warn", capture.last().method)
	}
}

// TestAggregatingLoggerSkipsWorkBelowItsLevel asserts the level guard, and that it tracks the
// aggregator's own level rather than a fixed one: when the Logger is not writing at that level,
// Record must cost nothing at all, not merely write nothing. Being cheap on a hot path is the whole
// point of the type.
func TestAggregatingLoggerSkipsWorkBelowItsLevel(t *testing.T) {
	// An Info-level aggregator against a Logger writing only Warn and above: nothing it records
	// would ever reach the output.
	capture := &captureLogger{level: LevelWarn}
	a := NewAggregatingLogger("condition", "values",
		OptLevel(LevelInfo), OptInterval(testInterval), OptLogger(capture))

	for range 100 {
		a.Record("v:one")
	}

	if len(capture.lines) != 0 {
		t.Errorf("wrote %d lines below its level, expected none", len(capture.lines))
	}
	if a.total != 0 || len(a.named) != 0 {
		t.Errorf("accumulated total=%d named=%d below its level, expected no bookkeeping at all",
			a.total, len(a.named))
	}

	// Turning the Logger up to Info resumes both.
	capture.setLevel(LevelInfo)
	a.Record("v:one")
	if len(capture.lines) != 1 {
		t.Errorf("wrote %d lines once the Logger reached Info, expected 1", len(capture.lines))
	}
}

// TestAggregatingLoggerFollowsTheDefaultLogger covers the trap this type is most likely to fall
// into. An AggregatingLogger is meant to be a package-level variable, so it is constructed during
// package initialisation - before main installs the real backend, when Default() is still the no-op.
// Resolving the Logger once at construction would pin that no-op and silently drop every line, which
// is worse than the flood it replaces. It must read Default() at the point it writes.
func TestAggregatingLoggerFollowsTheDefaultLogger(t *testing.T) {
	saved := Default()
	defer SetDefaultLogger(saved)

	// Construct while the no-op default is installed, as a package-level variable would.
	SetDefaultLogger(nil)
	a := NewAggregatingLogger("condition", "values")

	// Nothing is written, and the no-op reports nothing enabled, so nothing accumulates either.
	a.Record("v:one")

	// Now the backend registers, the way main does at process start.
	capture := &captureLogger{level: LevelDebug}
	SetDefaultLogger(capture)

	a.Record("v:two")

	if len(capture.lines) != 1 {
		t.Fatalf("wrote %d lines after the backend registered, expected 1", len(capture.lines))
	}
	mustLoggedArgs(t, capture.last(), "values", AggregatedValues{"v:two"}, fieldTotalEvents, 1)
}

// TestAggregatingLoggerRecordUsesWallClock covers the one thing sample() cannot: that Record wires
// itself to the real clock, so a second call inside the interval is suppressed.
func TestAggregatingLoggerRecordUsesWallClock(t *testing.T) {
	capture := &captureLogger{level: LevelDebug}
	a := NewAggregatingLogger("condition", "values", OptInterval(time.Hour), OptLogger(capture))

	a.Record("v:first")
	a.Record("v:second")

	if len(capture.lines) != 1 {
		t.Fatalf("wrote %d lines within the interval, expected 1", len(capture.lines))
	}
	mustLoggedArgs(t, capture.last(), "values", AggregatedValues{"v:first"}, fieldTotalEvents, 1)
}

// TestAggregatingLoggerRecordSchedulesTheWindowClose covers the other half of that wiring: Record
// schedules the close as well as folding the occurrence in, so what it folded in is written out
// without a further Record to drain it.
func TestAggregatingLoggerRecordSchedulesTheWindowClose(t *testing.T) {
	capture := &captureLogger{level: LevelDebug}
	timer := &fakeTimer{}
	a := NewAggregatingLogger("condition", "values", OptInterval(time.Hour), OptLogger(capture))
	a.afterFunc = timer.afterFunc

	a.Record("v:first")  // Emits immediately.
	a.Record("v:second") // Folds into the window behind it, and schedules that window's close.

	if len(timer.armed) != 1 {
		t.Fatalf("scheduled %d closes, expected 1", len(timer.armed))
	}
	timer.armed[0].fire()

	if len(capture.lines) != 2 {
		t.Fatalf("wrote %d lines, expected the first occurrence and then the closed window",
			len(capture.lines))
	}
	mustLoggedArgs(t, capture.last(), "values", AggregatedValues{"v:second"}, fieldTotalEvents, 1)
}

// captureLogger is a Logger that records what it was asked to write, so a test can assert on it.
type captureLogger struct {
	mu    sync.Mutex
	level Level
	lines []loggedLine
}

type loggedLine struct {
	method string // which of Debug/Info/Warn/Error carried the line
	msg    string
	args   []any
}

func (c *captureLogger) Debug(msg string, args ...any) { c.record("Debug", msg, args) }
func (c *captureLogger) Info(msg string, args ...any)  { c.record("Info", msg, args) }
func (c *captureLogger) Warn(msg string, args ...any)  { c.record("Warn", msg, args) }
func (c *captureLogger) Error(msg string, args ...any) { c.record("Error", msg, args) }

func (c *captureLogger) With(args ...any) Logger { return c }

func (c *captureLogger) Enabled(_ context.Context, level Level) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return level >= c.level
}

func (c *captureLogger) record(method, msg string, args []any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lines = append(c.lines, loggedLine{method: method, msg: msg, args: args})
}

func (c *captureLogger) setLevel(l Level) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.level = l
}

func (c *captureLogger) last() loggedLine {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.lines) == 0 {
		return loggedLine{}
	}
	return c.lines[len(c.lines)-1]
}

var _ Logger = (*captureLogger)(nil)

// mustLoggedArgs asserts the line carried exactly the given key/value args, in order. Exhaustive by
// design: an extra argument is as much a defect as a missing one.
func mustLoggedArgs(t *testing.T, line loggedLine, want ...any) {
	t.Helper()
	if len(line.args) != len(want) {
		t.Fatalf("line carried %d args %v, expected %d %v", len(line.args), line.args, len(want), want)
	}
	for i := range want {
		got, expected := line.args[i], want[i]
		if gotSlice, ok := got.(AggregatedValues); ok {
			expectedSlice, ok := expected.(AggregatedValues)
			if !ok || !slices.Equal(gotSlice, expectedSlice) {
				t.Errorf("arg %d is %v, expected %v", i, got, expected)
			}
			continue
		}
		if got != expected {
			t.Errorf("arg %d is %v, expected %v", i, got, expected)
		}
	}
}

func mustNameExactly(t *testing.T, w *aggregateWindow, want ...string) {
	t.Helper()
	if !slices.Equal(w.named, AggregatedValues(want)) {
		t.Errorf("named %v, expected %v", w.named, want)
	}
}

func mustTotal(t *testing.T, w *aggregateWindow, want int) {
	t.Helper()
	if w.total != want {
		t.Errorf("total %d, expected %d", w.total, want)
	}
}

func mustUnnamed(t *testing.T, w *aggregateWindow, want int) {
	t.Helper()
	if w.unnamed != want {
		t.Errorf("unnamed %d, expected %d", w.unnamed, want)
	}
}
