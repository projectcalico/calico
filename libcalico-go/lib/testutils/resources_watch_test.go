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
type slowWatch struct {
	ch       chan watch.Event
	stopOnce sync.Once
	stopped  chan struct{}
}

func newSlowWatch() *slowWatch {
	return &slowWatch{
		ch:      make(chan watch.Event),
		stopped: make(chan struct{}),
	}
}

func (w *slowWatch) ResultChan() <-chan watch.Event { return w.ch }

func (w *slowWatch) Stop() {
	w.stopOnce.Do(func() { close(w.stopped) })
}

// send delivers an event, abandoning the send if the watcher has been stopped.
func (w *slowWatch) send(e watch.Event) {
	select {
	case w.ch <- e:
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
})
