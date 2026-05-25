// Copyright (c) 2020-2026 Tigera, Inc. All rights reserved.
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
	"sort"
	"strings"
	"sync"
	"time"
)

// OpRecorder is the interface a Summarizer satisfies: code in a loop calls
// RecordOperation as work happens, then EndOfIteration at the end.
type OpRecorder interface {
	RecordOperation(name string)
}

// Summarizer collects per-iteration operation names from a loop and
// periodically emits one Info-level log line summarising what happened
// (count of iterations, avg duration, longest iteration's operations).
//
// A summary is emitted at most once per minute under normal logging, and on
// every iteration when debug logging is enabled.
type Summarizer struct {
	lock        sync.Mutex
	lastLogTime time.Time

	currentIteration *iteration
	iterations       []*iteration
	loopName         string
}

var _ OpRecorder = (*Summarizer)(nil)

type iteration struct {
	Operations []string
	Duration   time.Duration
}

func (i *iteration) RecordOperation(name string) {
	i.Operations = append(i.Operations, name)
}

// NewSummarizer constructs a Summarizer for the given loop name; the loop
// name appears verbatim in summary log lines.
func NewSummarizer(loopName string) *Summarizer {
	return &Summarizer{
		currentIteration: &iteration{},
		lastLogTime:      time.Now(),
		loopName:         loopName,
	}
}

// RecordOperation records a named operation in the current iteration.
func (s *Summarizer) RecordOperation(name string) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.currentIteration.RecordOperation(name)
}

// EndOfIteration marks the end of one loop iteration. If enough time has
// passed (or debug is enabled), a summary log line is emitted and the
// accumulated iterations are reset.
func (s *Summarizer) EndOfIteration(duration time.Duration) {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.currentIteration.Duration = duration
	s.iterations = append(s.iterations, s.currentIteration)
	s.currentIteration = &iteration{}
	if time.Since(s.lastLogTime) > time.Minute || IsLevelEnabled(DebugLevel) {
		s.doLog()
		s.iterations = s.iterations[:0]
		s.lastLogTime = time.Now()
	}
}

// DoLog forces immediate emission of the summary. Mainly for tests; normal
// use relies on EndOfIteration's internal cadence.
func (s *Summarizer) DoLog() {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.doLog()
}

func (s *Summarizer) doLog() {
	numUpdates := len(s.iterations)
	var longestIteration *iteration
	var sumOfDurations time.Duration
	for _, it := range s.iterations {
		sumOfDurations += it.Duration
		if longestIteration == nil || it.Duration > longestIteration.Duration {
			longestIteration = it
		}
	}
	if longestIteration == nil {
		return
	}
	avgDuration := (sumOfDurations / time.Duration(numUpdates)).Round(time.Millisecond)
	longestOps := longestIteration.Operations
	sort.Strings(longestOps)
	Infof("Summarising %d %s over %v: avg=%v longest=%v (%v)",
		numUpdates, s.loopName, time.Since(s.lastLogTime).Round(100*time.Millisecond), avgDuration,
		longestIteration.Duration.Round(time.Millisecond),
		strings.Join(longestOps, ","))
}
