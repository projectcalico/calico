// Copyright (c) 2025 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package time

import (
	"sync"
	"sync/atomic"
	"time"
)

// ControlledClock is a Clock whose current time can be controlled by the caller. The current time can be changed using
// the Advance and Set methods.
//
// This time is thread safe, all calls that read and write from and to the internal state are protected by a mutex.
type ControlledClock interface {
	Clock

	Advance(Duration)
	Set(Time)
}

func NewControlledClock(now int64) ControlledClock {
	return &controlledClock{
		now:    now,
		timers: map[int64]*controlledTimer{},
	}
}

// time is a helper structure for tests that need control over
type controlledClock struct {
	sync.Mutex
	now int64

	nextID int64

	// timers is a map of all the timers that have been created by this time. The key is the timer ID. Whenever the
	// current time is changed, all the timers are notified about the change. The timers are removed from the map when
	// they are explicitly stopped or if they expire.
	//
	// controlledTimers can be set to be tickers, in which case they never expire.
	timers map[int64]*controlledTimer
}

func (clock *controlledClock) getNextID() int64 {
	clock.ensureLocked()

	clock.nextID++
	return clock.nextID
}

func (clock *controlledClock) ensureLocked() {
	if clock.TryLock() {
		panic("lock is not held but required")
	}
}

func (clock *controlledClock) Since(t Time) Duration {
	clock.Lock()
	defer clock.Unlock()
	return clock.Unix(clock.now, 0).Sub(t)
}

func (clock *controlledClock) Until(t Time) Duration {
	clock.Lock()
	defer clock.Unlock()
	return t.Sub(clock.Unix(clock.now, 0))
}

func (clock *controlledClock) After(d Duration) <-chan Time {
	clock.Lock()
	defer clock.Unlock()

	return clock.newTimer(d).c
}

func (clock *controlledClock) Sleep(d Duration) {
	clock.Lock()
	defer clock.Unlock()

	<-clock.newTimer(d).c
}

func (clock *controlledClock) Unix(sec int64, nsec int64) Time {
	return time.Unix(sec, nsec)
}

func (clock *controlledClock) Now() Time {
	clock.Lock()
	defer clock.Unlock()

	return clock.Unix(clock.now, 0)
}

func (clock *controlledClock) NewTimer(d Duration) Timer {
	clock.Lock()
	defer clock.Unlock()

	return clock.newTimer(d)
}

func (clock *controlledClock) NewTicker(d Duration) Ticker {
	clock.Lock()
	defer clock.Unlock()

	timer := clock.newTimer(d)
	return &controlledTicker{timer}
}

func (clock *controlledClock) Advance(d Duration) {
	clock.Lock()
	defer clock.Unlock()

	clock.setNow(clock.now + int64(d.Seconds()))
}

func (clock *controlledClock) Set(t Time) {
	clock.Lock()
	defer clock.Unlock()

	clock.setNow(t.Unix())
}

func (clock *controlledClock) setNow(now int64) {
	clock.ensureLocked()

	clock.now = now

	clock.notifyTimeChange()
}

func (clock *controlledClock) notifyTimeChange() {
	clock.ensureLocked()

	for _, timer := range clock.timers {
		timer.notifyTimeChange()
	}
}

func (clock *controlledClock) newTimer(interval Duration) *controlledTimer {
	id := clock.getNextID()
	timer := &controlledTimer{
		id:       id,
		clock:    clock,
		c:        make(chan Time, 1),
		start:    clock.now,
		next:     clock.now + int64(interval.Seconds()),
		interval: interval,
	}
	clock.timers[id] = timer
	return timer
}

type controlledTimer struct {
	done atomic.Uint32

	id int64

	start    int64
	next     int64
	interval Duration

	clock *controlledClock

	c chan Time

	isTicker bool
}

func (t *controlledTimer) Stop() bool {
	t.clock.Lock()
	defer t.clock.Unlock()

	return t.stop()
}

func (t *controlledTimer) notifyTimeChange() {
	t.clock.ensureLocked()
	if t.isDone() {
		return
	}

	if t.next <= t.clock.now {
		t.c <- t.clock.Unix(t.clock.now, 0)

		if t.isTicker {
			intervalSeconds := int64(t.interval.Seconds())

			// Set the next to be (t.start + d*interval) such that d is the lowest value where
			// (t.start + d*interval) > t.time.now is true.
			quotient := (t.clock.now - t.start) / intervalSeconds
			t.next = t.start + (quotient+1)*intervalSeconds
		} else {
			t.stop()
		}
	}
}

func (t *controlledTimer) stop() bool {
	t.clock.ensureLocked()

	// Since we ensure this block is locked, we can safely read use the atomic done value to ensure we only do this
	// once
	if !t.isDone() {
		close(t.c)
		delete(t.clock.timers, t.id)
		t.done.Store(1)

		return true
	}

	return false
}

func (t *controlledTimer) isDone() bool {
	return t.done.Load() == 1
}

func (t *controlledTimer) Reset(d Duration) bool {
	t.clock.Lock()
	defer t.clock.Unlock()

	if t.isDone() {
		return false
	}

	t.start = t.clock.now
	t.next = t.start + int64(d.Seconds())

	return true
}

func (t *controlledTimer) Chan() <-chan Time {
	return t.c
}

type controlledTicker struct {
	*controlledTimer
}

func (t *controlledTicker) Reset(d Duration) {
	t.controlledTimer.Reset(d)
}

func (t *controlledTicker) Stop() {
	t.controlledTimer.Stop()
}
