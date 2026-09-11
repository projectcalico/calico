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

package log

import (
	"context"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	fieldTotalEvents   = "totalEvents"
	fieldUnnamedEvents = "unnamedEvents"
	fieldMaxNamed      = "maxNamed"

	defaultAggregationInterval = 5 * time.Minute
	defaultAggregationLevel    = LevelWarn
	defaultMaxNamed            = 100
)

// NewAggregatingLogger returns an AggregatingLogger that writes msg at most once per interval,
// listing under field the distinct values that provoked it since the last line.
//
// Reach for it on a hot path where the same "should not happen" condition recurs keyed on some
// value - an ID, a name, an address. Logging each occurrence floods the output; logging only the
// first loses the fact that it is still happening; logging one arbitrary occurrence per interval
// cannot tell one bad value from a hundred. AggregatingLogger names every distinct value it saw in
// the interval on a single line, so the flood is suppressed without losing what caused it.
//
// Typical use is a package-level variable, since the aggregation window is shared process-wide:
//
//	var missingIPSets = log.NewAggregatingLogger("IPSet not found", "ipsets")
//
//	func lookup(id string) *ipSet {
//	  s, ok := store[id]
//	  if !ok {
//	    missingIPSets.Record(id)
//	    return nil
//	  }
//	  return s
//	}
//
// The options are optional; see the Opt* functions for the defaults. A given condition is reported
// at one severity, so the level is set here rather than per call - use OptLevel to report at
// anything other than Warn.
func NewAggregatingLogger(msg, field string, opts ...AggregatingLoggerOpt) *AggregatingLogger {
	a := &AggregatingLogger{
		msg:       msg,
		field:     field,
		level:     defaultAggregationLevel,
		interval:  defaultAggregationInterval,
		maxNamed:  defaultMaxNamed,
		named:     map[string]struct{}{},
		afterFunc: func(d time.Duration, f func()) { time.AfterFunc(d, f) },
	}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

type AggregatingLoggerOpt func(*AggregatingLogger)

// OptLevel sets the level the aggregated line is written at, and so also the level below which
// Record does nothing at all. Defaults to LevelWarn.
func OptLevel(l Level) AggregatingLoggerOpt {
	return func(a *AggregatingLogger) {
		a.level = l
	}
}

// OptInterval sets the minimum gap between two emitted lines. Defaults to five minutes.
func OptInterval(d time.Duration) AggregatingLoggerOpt {
	return func(a *AggregatingLogger) {
		a.interval = d
	}
}

// OptMaxNamed caps how many distinct values one line will name, which also caps how many the logger
// holds between lines. Defaults to 100. Occurrences of further values are counted rather than named
// - see AggregatingLogger.Record.
func OptMaxNamed(n int) AggregatingLoggerOpt {
	return func(a *AggregatingLogger) {
		a.maxNamed = n
	}
}

// OptLogger writes to the given Logger rather than to whichever Logger is installed as the default
// when a line is emitted. Mostly useful in tests; production callers should leave it unset so their
// output follows the process-wide backend.
func OptLogger(l Logger) AggregatingLoggerOpt {
	return func(a *AggregatingLogger) {
		a.logger = l
	}
}

// AggregatingLogger collapses a flood of one recurring log line into a single line per interval
// naming the distinct values behind it. Construct one with NewAggregatingLogger. Safe for
// concurrent use.
type AggregatingLogger struct {
	msg   string // the message every emitted line carries
	field string // key the list of distinct values is written under

	level    Level // level every emitted line is written at
	interval time.Duration
	maxNamed int

	// Logger to write to, or nil to use whichever Logger is default at the time a line is emitted.
	logger Logger

	// How a window's close is scheduled. time.AfterFunc in production; tests replace it to fire the
	// close where a real timer would, without a sleep.
	afterFunc func(time.Duration, func())

	// Lock over the window state below. Never held while writing a log.
	mu         sync.Mutex
	named      map[string]struct{} // distinct values to name next line, at most maxNamed of them
	unnamed    int                 // occurrences of values maxNamed kept out of named
	total      int                 // occurrences this window, named and unnamed alike
	nextEmit   time.Time
	started    bool   // whether a line has ever been emitted; until then the next Record emits
	closeArmed bool   // whether this window's close is already scheduled
	gen        uint64 // counts windows, so a close that a Record beat to the drain can tell
}

// Record notes one occurrence of the condition for value. It writes the aggregated line if this
// occurrence is the first ever, or the first since the interval elapsed; otherwise the occurrence
// folds into the current window silently and costs only a mutex and a map lookup.
//
// A window is written out when the interval elapses, whether or not anything else has happened by
// then, so a burst that stops as abruptly as it started is still reported one interval later. It is
// not held until the condition next recurs, which for a transient fault could be hours away, or
// never - and which would report a flood that is long over as though it were happening now.
//
// Once maxNamed distinct values are held, occurrences of further values are counted into the
// unnamedEvents field rather than named. That count is a number of occurrences, not of distinct
// values: how many distinct values sit behind them cannot be known without retaining them, which is
// what the cap exists to prevent.
func (a *AggregatingLogger) Record(value string) {
	logger := a.target()
	if !logger.Enabled(context.Background(), a.level) {
		// Nothing would be written, so skip the bookkeeping too.
		return
	}
	if w := a.sample(value, time.Now()); w != nil {
		a.emit(logger, w)
	}
}

// target resolves the Logger to write to. When none was given it reads the default on every use
// rather than capturing it once: an AggregatingLogger is typically a package-level variable, so it
// is constructed during package initialisation, long before main installs the real backend. Holding
// the Logger found at construction would pin the no-op default and silently drop every line.
func (a *AggregatingLogger) target() Logger {
	if a.logger != nil {
		return a.logger
	}
	return Default()
}

// sample folds one occurrence of value into the current window, and returns the drained window when
// this occurrence trips the interval gate. Otherwise it returns nil, meaning nothing to write yet,
// and schedules the close that will write the window out when the interval elapses. Taking now as a
// parameter is what keeps the tests off the wall clock.
func (a *AggregatingLogger) sample(value string, now time.Time) *aggregateWindow {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.total++
	if _, ok := a.named[value]; !ok {
		if len(a.named) < a.maxNamed {
			a.named[value] = struct{}{}
		} else {
			a.unnamed++
		}
	}

	if a.started && now.Before(a.nextEmit) {
		a.armCloseLocked(now)
		return nil
	}
	return a.drainLocked(now)
}

// armCloseLocked schedules the close of the window this occurrence has just joined, unless the
// window's close is scheduled already. Without it a window would only be written by the next
// occurrence to arrive after the interval, so the tail of a burst that stops would sit unreported
// until the condition recurred.
func (a *AggregatingLogger) armCloseLocked(now time.Time) {
	if a.closeArmed {
		return
	}
	a.closeArmed = true
	// The deadline stands in for the clock at close time. Using it rather than whenever the callback
	// happens to run keeps windows exactly one interval apart, however late the timer is.
	deadline, gen := a.nextEmit, a.gen
	a.afterFunc(deadline.Sub(now), func() { a.closeWindow(gen, deadline) })
}

// closeWindow writes out the window the timer was armed for. A Record may have drained that window
// first, in which case the generation has moved on and this timer has nothing to do.
func (a *AggregatingLogger) closeWindow(gen uint64, deadline time.Time) {
	logger := a.target()

	a.mu.Lock()
	if a.gen != gen || a.total == 0 {
		a.mu.Unlock()
		return
	}
	w := a.drainLocked(deadline)
	a.mu.Unlock()

	a.emit(logger, w)
}

// drainLocked takes everything the current window holds, leaving an empty one behind that runs for
// the next interval from now.
func (a *AggregatingLogger) drainLocked(now time.Time) *aggregateWindow {
	w := &aggregateWindow{
		named:   AggregatedValues(slices.Sorted(maps.Keys(a.named))), // sorted so repeated lines are comparable
		unnamed: a.unnamed,
		total:   a.total,
	}

	clear(a.named)
	a.unnamed = 0
	a.total = 0
	a.nextEmit = now.Add(a.interval)
	a.started = true
	a.closeArmed = false
	a.gen++
	return w
}

func (a *AggregatingLogger) emit(logger Logger, w *aggregateWindow) {
	args := []any{a.field, w.named, fieldTotalEvents, w.total}
	if w.unnamed > 0 {
		// The value list is short of the whole story. Say how many occurrences went unnamed and what
		// cap caused it, so a reader knows the list is partial.
		args = append(args, fieldUnnamedEvents, w.unnamed, fieldMaxNamed, a.maxNamed)
	}

	// Logger exposes one method per level rather than a level argument, matching slog. Levels
	// between the named ones round down, as slog handlers do.
	switch {
	case a.level >= LevelError:
		logger.Error(a.msg, args...)
	case a.level >= LevelWarn:
		logger.Warn(a.msg, args...)
	case a.level >= LevelInfo:
		logger.Info(a.msg, args...)
	default:
		logger.Debug(a.msg, args...)
	}
}

// aggregateWindow is one interval's worth of drained state, ready to be written as a single line.
type aggregateWindow struct {
	named   AggregatedValues // distinct values seen this window, sorted, at most maxNamed of them
	unnamed int              // occurrences whose value the cap kept out of named
	total   int              // occurrences this window, named and unnamed alike
}

// AggregatedValues is the list of distinct values an emitted line names. It is a type of its own so
// that a text backend renders it as a bracketed comma-separated list - a Logger given a plain
// []string writes it as a Go slice literal, which is the difference between reading a hundred IP set
// IDs and reading a hundred IP set IDs wrapped in quotes, commas and a type name. A structured
// backend still sees a list of strings.
type AggregatedValues []string

func (v AggregatedValues) String() string {
	return "[" + strings.Join(v, ",") + "]"
}
