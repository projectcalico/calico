// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

package testutils_test

import (
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
	"github.com/projectcalico/calico/libcalico-go/lib/watch"
)

// slowWatch is a watch.Interface whose events are delivered on a caller-controlled
// schedule.  It is used to simulate watch-event delivery lagging under a loaded
// apiserver, which is what made the clientv3 *_e2e_test.go watch specs flaky.
//
// A forwarder goroutine is the sole sender on the result channel, so it can
// safely close that channel on Stop() as required by the watch.Interface
// contract without racing an in-flight send.
type slowWatch struct {
	in       chan watch.Event
	ch       chan watch.Event
	stopOnce sync.Once
	stopped  chan struct{}
}

var _ watch.Interface = (*slowWatch)(nil)

func newSlowWatch() *slowWatch {
	w := &slowWatch{
		in:      make(chan watch.Event),
		ch:      make(chan watch.Event),
		stopped: make(chan struct{}),
	}
	go w.loop()
	return w
}

// loop forwards events queued via send() to the result channel until the
// watch is stopped, then closes the result channel.
func (w *slowWatch) loop() {
	defer close(w.ch)
	for {
		select {
		case e := <-w.in:
			select {
			case w.ch <- e:
			case <-w.stopped:
				return
			}
		case <-w.stopped:
			return
		}
	}
}

func (w *slowWatch) ResultChan() <-chan watch.Event { return w.ch }

// Stop terminates the watch; the forwarder goroutine closes the result channel.
func (w *slowWatch) Stop() {
	w.stopOnce.Do(func() { close(w.stopped) })
}

// send delivers an event, abandoning the send if the watcher has been stopped.
// It cannot block forever: loop() only exits after stopped is closed, and once
// stopped is closed the second select case is always ready.
func (w *slowWatch) send(e watch.Event) {
	select {
	case w.in <- e:
	case <-w.stopped:
	}
}

// tier returns a minimally-populated Tier that satisfies the resource matcher
// (correct GVK and a non-empty resource version).
func tier(name string) *apiv3.Tier {
	t := apiv3.NewTier()
	t.Name = name
	t.ResourceVersion = "1"
	return t
}

var _ = Describe("TestResourceWatch event waiting", func() {
	// Regression test for the flaky clientv3 watch specs ("should handle watch
	// events for different resource versions and event types").  The shared
	// ExpectEvents helper used to give up after ~1s of quiescence; when watch
	// events were delivered more slowly than that under CI load it bailed with
	// too few events and failed.  Deliver each event after a delay longer than
	// that former 1s window and assert the helper still receives them all.
	It("waits past the old 1s quiescence window for slowly-delivered events", func() {
		w := newSlowWatch()
		tw := testutils.NewTestResourceWatch(apiconfig.EtcdV3, w)
		defer tw.Stop()

		res1 := tier("tier-1")
		res2 := tier("tier-2")

		go func() {
			defer GinkgoRecover()
			time.Sleep(1200 * time.Millisecond)
			w.send(watch.Event{Type: watch.Added, Object: res1})
			time.Sleep(1200 * time.Millisecond)
			w.send(watch.Event{Type: watch.Added, Object: res2})
		}()

		tw.ExpectEvents(apiv3.KindTier, []watch.Event{
			{Type: watch.Added, Object: res1},
			{Type: watch.Added, Object: res2},
		})
	})

	It("treats a closed result channel as end-of-stream", func() {
		w := newSlowWatch()
		tw := testutils.NewTestResourceWatch(apiconfig.EtcdV3, w)
		defer tw.Stop()

		res1 := tier("tier-1")
		go func() {
			defer GinkgoRecover()
			w.send(watch.Event{Type: watch.Added, Object: res1})
		}()
		tw.ExpectEvents(apiv3.KindTier, []watch.Event{
			{Type: watch.Added, Object: res1},
		})

		// Stop the watch directly; per the watch.Interface contract this
		// closes the result channel.  The event-collection loop must treat
		// that as end-of-stream - it used to spin on the closed channel,
		// appending zero-value events.  ExpectEvents consumed the event
		// above, so no further events should be observed.
		//
		// The sleep cannot make this test flake: with a correct collection
		// loop nothing can deliver events after Stop(), so the final check
		// is deterministic.  It only gives a regressed (spinning) loop time
		// to append events before the check; the loop is internal to the
		// harness, so there is nothing to synchronize on instead.
		w.Stop()
		time.Sleep(200 * time.Millisecond)
		tw.ExpectEvents(apiv3.KindTier, []watch.Event{})
	})
})
