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

package mocktime

import (
	"sort"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/timeshim"
)

var StartTime, _ = time.Parse(time.RFC3339, "2006-01-02T15:04:05Z")
var StartKTime = 1000 * time.Hour
var KTimeEpoch = StartTime.Add(-StartKTime)

func New() *MockTime {
	return &MockTime{
		currentTime: StartTime,
	}
}

var _ timeshim.Interface = (*MockTime)(nil)

type MockTime struct {
	lock sync.Mutex

	currentTime   time.Time
	autoIncrement time.Duration
	timers        []*mockTimer
}

func (m *MockTime) NewTimer(d timeshim.Duration) timeshim.Timer {
	timer := &mockTimer{
		mockTime: m,
		C:        make(chan time.Time, 1), // Capacity 1 so we don't block on firing,
	}
	m.scheduleTimer(timer, d) // Takes the lock.

	return timer
}

type mockTimer struct {
	mockTime   *MockTime
	TimeToFire time.Time
	C          chan time.Time
}

func (m *mockTimer) fire() {
	select {
	case m.C <- m.TimeToFire: // Should never block since there channel has cap 1.
	default:
		logrus.Panic("Blocked while trying to fire timer")
	}
}

func (m *mockTimer) Stop() bool {
	return m.mockTime.stopTimer(m)
}

func (m *mockTimer) Reset(duration timeshim.Duration) {
	m.mockTime.scheduleTimer(m, duration)
}

func (m *mockTimer) Chan() <-chan timeshim.Time {
	return m.C
}

func (m *MockTime) Until(t time.Time) time.Duration {
	return t.Sub(m.Now())
}

func (m *MockTime) After(t time.Duration) <-chan time.Time {
	timer := m.NewTimer(t)
	return timer.Chan()
}

func (m *MockTime) scheduleTimer(timer *mockTimer, duration time.Duration) {
	m.lock.Lock()
	defer m.lock.Unlock()

	timer.TimeToFire = m.currentTime.Add(duration)
	m.timers = append(m.timers, timer)
}

func (m *MockTime) stopTimer(timer *mockTimer) bool {
	m.lock.Lock()
	defer m.lock.Unlock()

	// Look for the timer in the queue; if we find it then we successfully stopped the timer.
	// Otherwise, the timer must have fired.
	timerWasPending := false
	timers := m.timers[:0]
	for _, t := range m.timers {
		if t == timer {
			// Timer was in the queue
			timerWasPending = true
			continue
		}
		timers = append(timers, t)
	}
	m.timers = timers

	return timerWasPending
}

func (m *MockTime) Now() time.Time {
	m.lock.Lock()
	defer m.lock.Unlock()

	t := m.currentTime
	m.incrementTimeLockHeld(m.autoIncrement)
	return t
}

func (m *MockTime) KTimeNanos() int64 {
	m.lock.Lock()
	defer m.lock.Unlock()
	// Kernel time isn't necessarily coupled to the same epoch so use a different one.
	return int64(m.currentTime.Sub(KTimeEpoch))
}

func (m *MockTime) Since(t time.Time) time.Duration {
	return m.Now().Sub(t)
}

func (m *MockTime) SetAutoIncrement(t time.Duration) {
	m.autoIncrement = t
}

func (m *MockTime) IncrementTime(t time.Duration) {
	m.lock.Lock()
	defer m.lock.Unlock()

	m.incrementTimeLockHeld(t)
}

func (m *MockTime) HasTimers() bool {
	m.lock.Lock()
	defer m.lock.Unlock()

	return len(m.timers) > 0
}

func (m *MockTime) incrementTimeLockHeld(t time.Duration) {
	if t == 0 {
		return
	}

	m.currentTime = m.currentTime.Add(t)
	logrus.WithField("increment", t).WithField("t", m.currentTime.Sub(StartTime)).Info("Incrementing time")

	if len(m.timers) == 0 {
		return
	}

	sort.Slice(m.timers, func(i, j int) bool {
		return m.timers[i].TimeToFire.Before(m.timers[j].TimeToFire)
	})

	logrus.WithField("delay", m.timers[0].TimeToFire.Sub(m.currentTime)).Info("Next timer.")

	for len(m.timers) > 0 &&
		(m.timers[0].TimeToFire.Before(m.currentTime) ||
			m.timers[0].TimeToFire.Equal(m.currentTime)) {
		logrus.WithField("timer", m.timers[0]).Info("Firing timer.")
		m.timers[0].fire()
		m.timers = m.timers[1:]
	}
}
