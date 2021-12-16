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

package timeshim

import (
	"time"

	"github.com/projectcalico/calico/felix/bpf"
)

// Time is our shim interface to the time package.
type Interface interface {
	Now() time.Time
	Since(t time.Time) time.Duration
	Until(t time.Time) time.Duration
	After(t time.Duration) <-chan time.Time
	NewTimer(d Duration) Timer
	KTimeNanos() int64
}

type Time = time.Time
type Duration = time.Duration

type Timer interface {
	Stop() bool
	Reset(clean Duration)
	Chan() <-chan Time
}

var singleton realTime

func RealTime() Interface {
	return singleton
}

// realTime is the real implementation of timeIface, which calls through to the real time package.
type realTime struct{}

func (t realTime) NewTimer(d Duration) Timer {
	timer := time.NewTimer(d)
	return (*timerWrapper)(timer)
}

type timerWrapper time.Timer

func (t *timerWrapper) Stop() bool {
	return (*time.Timer)(t).Stop()
}

func (t *timerWrapper) Reset(duration Duration) {
	(*time.Timer)(t).Reset(duration)
}

func (t *timerWrapper) Chan() <-chan Time {
	return (*time.Timer)(t).C
}

func (realTime) Until(t time.Time) time.Duration {
	return time.Until(t)
}

func (realTime) After(t time.Duration) <-chan time.Time {
	return time.After(t)
}

func (realTime) Now() time.Time {
	return time.Now()
}

func (realTime) Since(t time.Time) time.Duration {
	return time.Since(t)
}

func (realTime) KTimeNanos() int64 {
	return bpf.KTimeNanos()
}
