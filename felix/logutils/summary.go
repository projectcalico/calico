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

package logutils

import (
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

type OpRecorder interface {
	RecordOperation(name string)
}

type Summarizer struct {
	lock        sync.Mutex
	lastLogTime time.Time

	currentIteration *iteration
	iterations       []*iteration
	loopName         string
}

func (l *Summarizer) Reset() {
	l.iterations = l.iterations[:0]
}

var _ OpRecorder = (*Summarizer)(nil)

type iteration struct {
	Operations []string
	Duration   time.Duration
}

func (i *iteration) RecordOperation(name string) {
	i.Operations = append(i.Operations, name)
}

func NewSummarizer(loopName string) *Summarizer {
	return &Summarizer{
		currentIteration: &iteration{},
		lastLogTime:      time.Now(),
		loopName:         loopName,
	}
}

func (l *Summarizer) RecordOperation(name string) {
	l.lock.Lock()
	defer l.lock.Unlock()

	l.currentIteration.RecordOperation(name)
}

// EndOfIteration should be called at the end of the loop, it will trigger logging of noteworthy logs.
func (l *Summarizer) EndOfIteration(duration time.Duration) {
	l.lock.Lock()
	defer l.lock.Unlock()

	l.currentIteration.Duration = duration
	l.iterations = append(l.iterations, l.currentIteration)
	l.currentIteration = &iteration{}
	if time.Since(l.lastLogTime) > time.Minute || logrus.GetLevel() >= logrus.DebugLevel {
		l.DoLog()
		l.Reset()
		l.lastLogTime = time.Now()
	}
}

func (l *Summarizer) DoLog() {
	numUpdates := len(l.iterations)
	var longestIteration *iteration
	var sumOfDurations time.Duration
	for _, it := range l.iterations {
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
	logrus.Infof("Summarising %d %s over %v: avg=%v longest=%v (%v)",
		numUpdates, l.loopName, time.Since(l.lastLogTime).Round(100*time.Millisecond), avgDuration,
		longestIteration.Duration.Round(time.Millisecond),
		strings.Join(longestOps, ","))
}
