// Copyright (c) 2025 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package utils_test

import (
	"testing"
	"time"

	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/utils"
)

func TestRetryController(t *testing.T) {
	t.Run("It should schedule a retry", func(t *testing.T) {
		ch := make(chan struct{}, 1)

		c := utils.NewRetryController(
			func() time.Duration { return 1 * time.Second },
			func() { ch <- struct{}{} },
			func() {},
		)

		// Should not get trigger to start.
		expectNoRetry(t, ch, 100*time.Millisecond)

		// Trigger a retry.
		c.ScheduleRetry()

		// We should get a kick in 1s, not less.
		expectNoRetry(t, ch, 900*time.Millisecond)
		expectRetry(t, ch, 200*time.Millisecond)
	})

	t.Run("It should allow multiple retry calls", func(t *testing.T) {
		ch := make(chan struct{}, 1)

		c := utils.NewRetryController(
			func() time.Duration { return 1 * time.Second },
			func() { ch <- struct{}{} },
			func() {},
		)

		// Trigger a bunch of retries.
		c.ScheduleRetry()
		c.ScheduleRetry()
		c.ScheduleRetry()
		c.ScheduleRetry()
		c.ScheduleRetry()

		// We should only get one update.
		expectRetry(t, ch, 2*time.Second)
		expectNoRetry(t, ch, 1*time.Second)
	})
}

func expectRetry(t *testing.T, ch chan struct{}, d time.Duration) {
	select {
	case <-ch:
	case <-time.After(d):
		t.Fatal("never received expected retry")
	}
}

func expectNoRetry(t *testing.T, ch chan struct{}, d time.Duration) {
	select {
	case <-ch:
		t.Fatal("unexpected retry detected")
	case <-time.After(d):
	}
}
