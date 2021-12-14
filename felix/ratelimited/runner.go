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

package ratelimited

import (
	"context"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/timeshim"
)

func NewRunner(minInterval timeshim.Duration, f func(ctx context.Context), opts ...RunnerOpt) *Runner {
	r := &Runner{
		minInterval: minInterval,
		callback:    f,
		triggerC:    make(chan struct{}, 1),
		time:        timeshim.RealTime(),
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

type RunnerOpt func(*Runner)

func WithTimeShim(t timeshim.Interface) RunnerOpt {
	return func(runner *Runner) {
		runner.time = t
	}
}

type Runner struct {
	minInterval timeshim.Duration
	callback    func(ctx context.Context)
	triggerC    chan struct{}
	time        timeshim.Interface
}

func (r *Runner) Start(ctx context.Context) {
	go r.loop(ctx)
}

func (r *Runner) Trigger() {
	select {
	case r.triggerC <- struct{}{}:
	default:
		log.Debug("Already triggered")
	}
}

func (r *Runner) loop(ctx context.Context) {
	log.Info("Rate-limited Runner goroutine started")
	triggered := true
	var lastTriggerTime timeshim.Time
	var timer timeshim.Timer
	var timerC <-chan timeshim.Time
	for {
		select {
		case <-ctx.Done():
			log.Info("Context finished")
			return
		case <-r.triggerC:
			log.Debug("Triggered.")
			triggered = true
		case <-timerC:
			log.Debug("Timer popped.")
			timerC = nil
		}
		sinceLastClean := r.time.Since(lastTriggerTime)
		delayToNextClean := r.minInterval - sinceLastClean
		if triggered && delayToNextClean <= 0 {
			log.Debug("Executing callback.")
			r.callback(ctx)
			triggered = false
			lastTriggerTime = r.time.Now()
		} else if timerC == nil {
			log.WithField("delay", delayToNextClean).Debug("Rate limited: starting timer.")
			if timer == nil {
				timer = r.time.NewTimer(delayToNextClean)
			} else {
				// We know we've received the last timer tick so the timer must be in the stopped state.
				// Hence, it's safe to call Reset straight away.
				timer.Reset(delayToNextClean)
			}
			timerC = timer.Chan()
		}
	}
}
