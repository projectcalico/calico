// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.
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
	"math/rand"
	"time"

	log "github.com/sirupsen/logrus"
)

// Ticker tries to emit events on channel C at minDuration intervals plus up to maxJitter.
type Ticker struct {
	C           <-chan time.Time
	stop        chan struct{}
	MinDuration time.Duration
	MaxJitter   time.Duration
}

func NewTicker(minDuration time.Duration, maxJitter time.Duration) *Ticker {
	if minDuration < 0 {
		log.WithField("duration", minDuration).Panic("Negative duration")
	}
	if maxJitter < 0 {
		log.WithField("jitter", minDuration).Panic("Negative jitter")
	}
	c := make(chan time.Time, 1)
	ticker := &Ticker{
		C:           c,
		stop:        make(chan struct{}),
		MinDuration: minDuration,
		MaxJitter:   maxJitter,
	}
	go ticker.loop(c)
	return ticker
}

func (t *Ticker) loop(c chan time.Time) {
	timer := time.NewTimer(t.calculateDelay())
	var outCOrNil chan time.Time
tickLoop:
	for {
		select {
		case <-t.stop:
			log.Info("Stopping jittered ticker")
			close(c)
			timer.Stop()
			break tickLoop
		case <-timer.C:
			outCOrNil = c
			timer.Reset(t.calculateDelay())
		case outCOrNil <- time.Now():
			outCOrNil = nil
		}
	}
}

func (t *Ticker) calculateDelay() time.Duration {
	jitter := time.Duration(rand.Int63n(int64(t.MaxJitter)))
	delay := t.MinDuration + jitter
	return delay
}

func (t *Ticker) Stop() {
	close(t.stop)
}
