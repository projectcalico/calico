// Copyright (c) 2020 Tigera, Inc. All rights reserved.
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

package intdataplane

import (
	"sort"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/libcalico-go/lib/set"
)

type DurationStat struct {
	Name       string
	LogIfAbove time.Duration
}

type LogAccumulator struct {
	lock        sync.Mutex
	lastLogTime time.Time

	currentIteration *iteration
	iterations       []*iteration
}

func (l *LogAccumulator) Reset() {
	l.iterations = l.iterations[:0]
}

type iteration struct {
	Operations []string
	Duration   time.Duration
}

func (i *iteration) RecordOperation(name string) {
	i.Operations = append(i.Operations, name)
}

func NewLogAccumulator() *LogAccumulator {
	return &LogAccumulator{
		currentIteration: &iteration{},
		lastLogTime:      time.Now(),
	}
}

func (l *LogAccumulator) RecordOperation(name string) {
	l.lock.Lock()
	defer l.lock.Unlock()

	l.currentIteration.RecordOperation(name)
}

// EndOfIteration should be called at the end of the loop, it will trigger logging of noteworthy logs.
func (l *LogAccumulator) EndOfIteration(duration time.Duration) {
	l.lock.Lock()
	defer l.lock.Unlock()

	lastIteration := l.currentIteration
	lastIteration.Duration = duration
	l.iterations = append(l.iterations, lastIteration)
	l.currentIteration = &iteration{}
	if time.Since(l.lastLogTime) > time.Minute {
		l.DoLog()
		l.Reset()
		l.lastLogTime = time.Now()
	}
}

func (l *LogAccumulator) DoLog() {
	numUpdates := len(l.iterations)
	allOps := set.New()
	var longestIteration *iteration
	var sumOfDurations time.Duration
	for _, it := range l.iterations {
		allOps.AddAll(it.Operations)
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
	log.Infof("Summarising %d dataplane reconciliation loops over %v: avg=%v longest=%v (%v)",
		numUpdates, time.Since(l.lastLogTime).Round(100*time.Millisecond), avgDuration,
		longestIteration.Duration.Round(time.Millisecond),
		strings.Join(longestOps, ","))
}
