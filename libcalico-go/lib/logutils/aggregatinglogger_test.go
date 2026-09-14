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
package logutils

import (
	"fmt"
	"io"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

// t0 anchors every test to a fixed instant, so results never depend on when the suite runs.
var t0 = time.Unix(1_700_000_000, 0)

const testInterval = 5 * time.Minute

// TestAggregatingLoggerFloodOfOneValue covers the simplest flood shape: one value recurring over and
// over on a hot path. The repeats must collapse to one window per interval, and that window must
// still account for every occurrence it swallowed.
func TestAggregatingLoggerFloodOfOneValue(t *testing.T) {
	a := NewAggregatingLogger("IPSet not found", "ipsets", OptAggregationInterval(testInterval))

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
	a := NewAggregatingLogger("IPSet not found", "ipsets", OptAggregationInterval(testInterval))

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
	capture := newCaptureLogger(logrus.DebugLevel)
	timer := &fakeTimer{}
	a := NewAggregatingLogger("IPSet not found", "ipsets",
		OptAggregationInterval(testInterval), OptAggregationLogger(capture.Logger))
	a.afterFunc = timer.afterFunc

	// The first occurrence emits on its own, as Record would write it.
	w := a.sample("s:missing-00", t0)
	if w == nil {
		t.Fatal("expected the first occurrence to emit")
	}
	a.emit(capture.Logger, w)

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
	if n := capture.count(); n != 2 {
		t.Fatalf("wrote %d lines, expected the first occurrence and then the closed window", n)
	}
	mustLoggedFields(t, capture.last(), logrus.Fields{
		"ipsets": AggregatedValues(want), fieldTotalEvents: distinct - 1,
	})
}

// TestAggregatingLoggerCloseYieldsToARecordThatDrainedFirst covers the two ways a window can end
// meeting each other. An occurrence arriving after the interval drains the window itself, so the
// close scheduled for that window must do nothing rather than write a second, empty line - while the
// window opened behind it still gets a close of its own.
func TestAggregatingLoggerCloseYieldsToARecordThatDrainedFirst(t *testing.T) {
	capture := newCaptureLogger(logrus.DebugLevel)
	timer := &fakeTimer{}
	a := NewAggregatingLogger("IPSet not found", "ipsets",
		OptAggregationInterval(testInterval), OptAggregationLogger(capture.Logger))
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
	a.emit(capture.Logger, w)

	// So the close scheduled for that window has nothing left to write.
	timer.armed[0].fire()
	if n := capture.count(); n != 1 {
		t.Fatalf("wrote %d lines, expected the overtaken close to write nothing", n)
	}

	// The window the drain opened schedules its own close, and that one does write.
	if w := a.sample("s:next", t0.Add(testInterval+2*time.Second)); w != nil {
		t.Fatal("expected the next occurrence to fold into the new window")
	}
	if len(timer.armed) != 2 {
		t.Fatalf("scheduled %d closes, expected one per window", len(timer.armed))
	}
	timer.armed[1].fire()
	if n := capture.count(); n != 2 {
		t.Fatalf("wrote %d lines, expected the new window to close too", n)
	}
	mustLoggedFields(t, capture.last(), logrus.Fields{
		"ipsets": AggregatedValues{"s:next"}, fieldTotalEvents: 1,
	})
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
		OptAggregationInterval(testInterval), OptAggregationMaxNamed(maxNamed))

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
	capture := newCaptureLogger(logrus.DebugLevel)
	a := NewAggregatingLogger("IPSet not found", "ipsets",
		OptAggregationInterval(testInterval), OptAggregationMaxNamed(maxNamed),
		OptAggregationLogger(capture.Logger))

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

	// And the emitted line says so in those terms. The fields are asserted exhaustively: a line
	// carrying anything that reads as a distinct-value count would be claiming 1004 where the truth
	// is 4, and would do so precisely when a reader is trying to size the problem.
	a.emit(capture.Logger, w)
	mustLoggedFields(t, capture.last(), logrus.Fields{
		"ipsets":           w.named,
		fieldTotalEvents:   maxNamed + repeats + 1,
		fieldUnnamedEvents: repeats + 1,
		fieldMaxNamed:      maxNamed,
	})
}

// TestAggregatingLoggerEmittedFields covers the shape of the line itself: an uncapped window says
// only what it saw, and a capped one adds the two values that flag the list as partial.
func TestAggregatingLoggerEmittedFields(t *testing.T) {
	const maxNamed = 2
	capture := newCaptureLogger(logrus.DebugLevel)
	a := NewAggregatingLogger("IPSet not found", "ipsets",
		OptAggregationInterval(testInterval), OptAggregationMaxNamed(maxNamed),
		OptAggregationLogger(capture.Logger))

	// An uncapped window: the value list is complete, so nothing flags it as partial.
	a.emit(capture.Logger, &aggregateWindow{named: AggregatedValues{"s:a", "s:b"}, total: 7})
	if got := capture.last().Message; got != "IPSet not found" {
		t.Errorf("message %q, expected %q", got, "IPSet not found")
	}
	mustLoggedFields(t, capture.last(), logrus.Fields{
		"ipsets": AggregatedValues{"s:a", "s:b"}, fieldTotalEvents: 7,
	})

	// A capped window: same values plus the two that say the list is short of the whole story.
	a.emit(capture.Logger, &aggregateWindow{named: AggregatedValues{"s:a", "s:b"}, unnamed: 40, total: 47})
	mustLoggedFields(t, capture.last(), logrus.Fields{
		"ipsets":           AggregatedValues{"s:a", "s:b"},
		fieldTotalEvents:   47,
		fieldUnnamedEvents: 40,
		fieldMaxNamed:      maxNamed,
	})
}

// TestAggregatingLoggerReportsAtItsLevel asserts the level is the aggregator's, not a fixed Warn:
// whatever OptAggregationLevel names is the level the line goes out at. The conditions worth
// aggregating span Debug through Error - a missing entry is a warning, an uncompilable expression
// is an error - and each wants reporting at its own severity.
func TestAggregatingLoggerReportsAtItsLevel(t *testing.T) {
	for _, level := range []logrus.Level{
		logrus.ErrorLevel, logrus.WarnLevel, logrus.InfoLevel, logrus.DebugLevel,
	} {
		t.Run(level.String(), func(t *testing.T) {
			capture := newCaptureLogger(logrus.DebugLevel)
			a := NewAggregatingLogger("condition", "values",
				OptAggregationLevel(level), OptAggregationLogger(capture.Logger))

			a.Record("v:one")

			if n := capture.count(); n != 1 {
				t.Fatalf("wrote %d lines, expected 1", n)
			}
			if got := capture.last().Level; got != level {
				t.Errorf("wrote at %v, expected %v", got, level)
			}
		})
	}
}

// TestAggregatingLoggerDefaultsToWarn pins the default, since most callers will not name a level.
func TestAggregatingLoggerDefaultsToWarn(t *testing.T) {
	capture := newCaptureLogger(logrus.DebugLevel)
	a := NewAggregatingLogger("condition", "values", OptAggregationLogger(capture.Logger))

	a.Record("v:one")

	if n := capture.count(); n != 1 {
		t.Fatalf("wrote %d lines, expected 1", n)
	}
	if got := capture.last().Level; got != logrus.WarnLevel {
		t.Errorf("wrote at %v, expected Warn", got)
	}
}

// TestAggregatingLoggerSkipsWorkBelowItsLevel asserts the level guard, and that it tracks the
// aggregator's own level rather than a fixed one: when the logger is not writing at that level,
// Record must cost nothing at all, not merely write nothing. Being cheap on a hot path is the whole
// point of the type.
func TestAggregatingLoggerSkipsWorkBelowItsLevel(t *testing.T) {
	// An Info-level aggregator against a logger writing only Warn and above: nothing it records
	// would ever reach the output.
	capture := newCaptureLogger(logrus.WarnLevel)
	a := NewAggregatingLogger("condition", "values",
		OptAggregationLevel(logrus.InfoLevel), OptAggregationInterval(testInterval),
		OptAggregationLogger(capture.Logger))

	for range 100 {
		a.Record("v:one")
	}

	if n := capture.count(); n != 0 {
		t.Errorf("wrote %d lines below its level, expected none", n)
	}
	if a.total != 0 || len(a.named) != 0 {
		t.Errorf("accumulated total=%d named=%d below its level, expected no bookkeeping at all",
			a.total, len(a.named))
	}

	// Turning the logger up to Info resumes both.
	capture.SetLevel(logrus.InfoLevel)
	a.Record("v:one")
	if n := capture.count(); n != 1 {
		t.Errorf("wrote %d lines once the logger reached Info, expected 1", n)
	}
}

// TestAggregatingLoggerFollowsTheStandardLogger covers the trap this type is most likely to fall
// into. An AggregatingLogger is meant to be a package-level variable, so it is constructed during
// package initialisation - before main configures logging. Whatever it captured of the standard
// logger's configuration at that point would be stale; it must consult the standard logger at the
// point it writes, so that a level set later is the level it honours.
func TestAggregatingLoggerFollowsTheStandardLogger(t *testing.T) {
	std := logrus.StandardLogger()
	savedLevel, savedOut := std.GetLevel(), std.Out
	savedHooks := std.ReplaceHooks(make(logrus.LevelHooks))
	t.Cleanup(func() {
		std.SetLevel(savedLevel)
		std.SetOutput(savedOut)
		std.ReplaceHooks(savedHooks)
	})
	std.SetOutput(io.Discard)
	recorder := &entryRecorder{}
	std.AddHook(recorder)

	// Construct while the standard logger sits above the aggregator's level, as a package-level
	// variable might before main has configured logging.
	std.SetLevel(logrus.ErrorLevel)
	a := NewAggregatingLogger("condition", "values")

	// Nothing is written, and since nothing would be, nothing accumulates either.
	a.Record("v:one")
	if n := recorder.count(); n != 0 {
		t.Fatalf("wrote %d lines while the standard logger was above Warn, expected none", n)
	}
	if a.total != 0 {
		t.Fatalf("accumulated total=%d while the standard logger was above Warn, expected 0", a.total)
	}

	// Now main configures the level, and the aggregator follows.
	std.SetLevel(logrus.WarnLevel)
	a.Record("v:two")

	if n := recorder.count(); n != 1 {
		t.Fatalf("wrote %d lines after the standard logger reached Warn, expected 1", n)
	}
	mustLoggedFields(t, recorder.last(), logrus.Fields{
		"values": AggregatedValues{"v:two"}, fieldTotalEvents: 1,
	})
}

// TestAggregatingLoggerRecordUsesWallClock covers the one thing sample() cannot: that Record wires
// itself to the real clock, so a second call inside the interval is suppressed.
func TestAggregatingLoggerRecordUsesWallClock(t *testing.T) {
	capture := newCaptureLogger(logrus.DebugLevel)
	a := NewAggregatingLogger("condition", "values",
		OptAggregationInterval(time.Hour), OptAggregationLogger(capture.Logger))

	a.Record("v:first")
	a.Record("v:second")

	if n := capture.count(); n != 1 {
		t.Fatalf("wrote %d lines within the interval, expected 1", n)
	}
	mustLoggedFields(t, capture.last(), logrus.Fields{
		"values": AggregatedValues{"v:first"}, fieldTotalEvents: 1,
	})
}

// TestAggregatingLoggerRecordSchedulesTheWindowClose covers the other half of that wiring: Record
// schedules the close as well as folding the occurrence in, so what it folded in is written out
// without a further Record to drain it.
func TestAggregatingLoggerRecordSchedulesTheWindowClose(t *testing.T) {
	capture := newCaptureLogger(logrus.DebugLevel)
	timer := &fakeTimer{}
	a := NewAggregatingLogger("condition", "values",
		OptAggregationInterval(time.Hour), OptAggregationLogger(capture.Logger))
	a.afterFunc = timer.afterFunc

	a.Record("v:first")  // Emits immediately.
	a.Record("v:second") // Folds into the window behind it, and schedules that window's close.

	if len(timer.armed) != 1 {
		t.Fatalf("scheduled %d closes, expected 1", len(timer.armed))
	}
	timer.armed[0].fire()

	if n := capture.count(); n != 2 {
		t.Fatalf("wrote %d lines, expected the first occurrence and then the closed window", n)
	}
	mustLoggedFields(t, capture.last(), logrus.Fields{
		"values": AggregatedValues{"v:second"}, fieldTotalEvents: 1,
	})
}

// TestAggregatedValuesRenderAsAList pins the text form the formatters in this package write: a
// bracketed comma-separated list, not a Go slice literal, in which a value that could be misread
// is quoted and every other value is written as it is. The formatters write a Stringer verbatim,
// so this is the only place the list can be made unambiguous - and the principal site feeds it
// whatever string a peer presented.
func TestAggregatedValuesRenderAsAList(t *testing.T) {
	for _, tc := range []struct {
		values AggregatedValues
		want   string
	}{
		{AggregatedValues{"s:a", "s:b"}, "[s:a,s:b]"},
		{AggregatedValues{"spiffe://cluster.local/ns/a/sa/b"}, "[spiffe://cluster.local/ns/a/sa/b]"},
		// Two values that would otherwise read as one, and one that would read as two.
		{AggregatedValues{"a", "b", "a,b"}, `[a,b,"a,b"]`},
		{AggregatedValues{"has space", "tab\there"}, `["has space","tab\there"]`},
		{AggregatedValues{"line\nbreak"}, `["line\nbreak"]`},
		{AggregatedValues{`q"uote`, `back\slash`, "[bracketed]"}, `["q\"uote","back\\slash","[bracketed]"]`},
		{AggregatedValues{""}, `[""]`},
		{AggregatedValues{}, "[]"},
	} {
		if got := tc.values.String(); got != tc.want {
			t.Errorf("%q rendered as %s, expected %s", []string(tc.values), got, tc.want)
		}
	}
}

// TestAggregatingLoggerClampsLevelsAboveError pins the contract OptAggregationLevel documents: a
// level more severe than Error is written at Error. logrus panics on a line written at Panic, and
// this logger writes from a timer goroutine, where that panic would take the process down.
func TestAggregatingLoggerClampsLevelsAboveError(t *testing.T) {
	for _, level := range []logrus.Level{logrus.PanicLevel, logrus.FatalLevel} {
		t.Run(level.String(), func(t *testing.T) {
			capture := newCaptureLogger(logrus.DebugLevel)
			capture.ExitFunc = func(int) { t.Fatal("the logger exited the process") }
			a := NewAggregatingLogger("condition", "values",
				OptAggregationLevel(level), OptAggregationLogger(capture.Logger))

			a.Record("v:one") // Must neither panic nor exit.

			if n := capture.count(); n != 1 {
				t.Fatalf("wrote %d lines, expected 1", n)
			}
			if got := capture.last().Level; got != logrus.ErrorLevel {
				t.Errorf("wrote at %v, expected Error", got)
			}
		})
	}
}

// TestAggregatingLoggerRejectsReservedFields pins the other constructor contract: the list of values
// cannot be written under the name of one of the counters the same line carries, or one would
// silently overwrite the other.
func TestAggregatingLoggerRejectsReservedFields(t *testing.T) {
	for _, field := range []string{fieldTotalEvents, fieldUnnamedEvents, fieldMaxNamed} {
		t.Run(field, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Errorf("NewAggregatingLogger accepted the reserved field %q", field)
				}
			}()
			NewAggregatingLogger("condition", field)
		})
	}
}

// captureLogger is a logrus.Logger that records what it was asked to write, so a test can assert
// on it. Windows close on a timer, so lines can arrive on a goroutine of their own; the recorder's
// mutex is what lets a test read them while that is happening.
type captureLogger struct {
	*logrus.Logger
	entryRecorder
}

func newCaptureLogger(level logrus.Level) *captureLogger {
	c := &captureLogger{Logger: logrus.New()}
	c.SetOutput(io.Discard)
	c.SetLevel(level)
	c.AddHook(&c.entryRecorder)
	return c
}

// entryRecorder is a logrus hook that keeps every entry written through it.
type entryRecorder struct {
	mu      sync.Mutex
	entries []*logrus.Entry
}

func (r *entryRecorder) Levels() []logrus.Level { return logrus.AllLevels }

func (r *entryRecorder) Fire(e *logrus.Entry) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries = append(r.entries, e)
	return nil
}

func (r *entryRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.entries)
}

func (r *entryRecorder) last() *logrus.Entry {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.entries) == 0 {
		return &logrus.Entry{}
	}
	return r.entries[len(r.entries)-1]
}

// mustLoggedFields asserts the entry carried exactly the given fields. Exhaustive by design: an
// extra field is as much a defect as a missing one.
func mustLoggedFields(t *testing.T, entry *logrus.Entry, want logrus.Fields) {
	t.Helper()
	if len(entry.Data) != len(want) {
		t.Fatalf("line carried %d fields %v, expected %d %v", len(entry.Data), entry.Data, len(want), want)
	}
	for key, expected := range want {
		got, ok := entry.Data[key]
		if !ok {
			t.Errorf("field %q missing from %v", key, entry.Data)
			continue
		}
		if gotSlice, ok := got.(AggregatedValues); ok {
			expectedSlice, ok := expected.(AggregatedValues)
			if !ok || !slices.Equal(gotSlice, expectedSlice) {
				t.Errorf("field %q is %v, expected %v", key, got, expected)
			}
			continue
		}
		if got != expected {
			t.Errorf("field %q is %v, expected %v", key, got, expected)
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
