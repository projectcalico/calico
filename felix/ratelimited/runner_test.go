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
	"testing"
	"time"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/timeshim/mocktime"
)

func TestRunner(t *testing.T) {
	RegisterTestingT(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	kicks := make(chan struct{})

	mockTime := mocktime.New()
	callback := func(ctx context.Context) {
		kicks <- struct{}{}
	}
	runner := NewRunner(10*time.Second, callback, WithTimeShim(mockTime))
	runner.Start(ctx)

	t.Log("There should be no start-of day kick")
	mockTime.IncrementTime(20 * time.Second)
	Consistently(kicks).ShouldNot(Receive())

	t.Log("First trigger should kick immediately but only once")
	runner.Trigger()
	Eventually(kicks).Should(Receive())

	t.Log("Second trigger shouldn't kick after 9s")
	runner.Trigger()
	Consistently(kicks).ShouldNot(Receive()) // Needed to make sure runner's loop completes before increment.
	mockTime.IncrementTime(9 * time.Second)
	Consistently(kicks).ShouldNot(Receive())

	t.Log("Second trigger should kick after 10s")
	mockTime.IncrementTime(1 * time.Second)
	Eventually(kicks).Should(Receive())

	t.Log("Multiple triggers should only kick once")
	runner.Trigger()
	runner.Trigger()
	Consistently(kicks).ShouldNot(Receive()) // Needed to make sure runner's loop completes.
	runner.Trigger()
	mockTime.IncrementTime(9 * time.Second)
	Consistently(kicks).ShouldNot(Receive())
	mockTime.IncrementTime(1 * time.Second)
	Eventually(kicks).Should(Receive())

	Expect(mockTime.HasTimers()).To(BeFalse(), "Should be no pending timers left")
}

func TestRunner_Trigger(t *testing.T) {
	RegisterTestingT(t)
	r := NewRunner(10*time.Second, func(ctx context.Context) {
		panic("shouldn't be called")
	})

	t.Log("Trigger should not block even if loop is not running")
	done := make(chan struct{})
	go func() {
		r.Trigger()
		r.Trigger()
		r.Trigger()
		r.Trigger()
		close(done)
	}()
	Eventually(done).Should(BeClosed())
}
