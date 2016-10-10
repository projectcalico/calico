// Copyright (c) 2016 Tigera, Inc. All rights reserved.
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

package jitter

import (
	"github.com/Sirupsen/logrus"
	"math/rand"
	"time"
)

// Ticker tries to emit events on channel C at minDuration intervals plus up to maxJitter.
type Ticker struct {
	C           <-chan time.Time
	minDuration time.Duration
	maxJitter   time.Duration
}

func NewTicker(minDuration time.Duration, maxJitter time.Duration) *Ticker {
	if minDuration < 0 {
		logrus.WithField("duration", minDuration).Panic("Negative duration")
	}
	if maxJitter < 0 {
		logrus.WithField("jitter", minDuration).Panic("Negative jitter")
	}
	c := make(chan time.Time, 1)
	ticker := &Ticker{
		C:           c,
		minDuration: minDuration,
		maxJitter:   maxJitter,
	}
	go ticker.loop(c)
	return ticker
}

func (t *Ticker) loop(c chan time.Time) {
	for {
		jitter := time.Duration(rand.Int63n(int64(t.maxJitter)))
		delay := t.minDuration + jitter
		time.Sleep(delay)
		// Send best-effort then go back to sleep.
		select {
		case c <- time.Now():
		default:
		}
	}
}
