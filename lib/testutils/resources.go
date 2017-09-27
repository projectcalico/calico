// Copyright (c) 2017 Tigera, Inc. All rights reserved.

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
package testutils

import (
	"sync"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/projectcalico/libcalico-go/lib/apiv2"
	"github.com/projectcalico/libcalico-go/lib/watch"
	"k8s.io/apimachinery/pkg/conversion"
)

// ExpectResource is a test validation function that checks the specified resource
// matches the key attributes: kind, namespace, name and the supplied Spec.  This
// should be called within a Ginkgo test.
const ExpectNoNamespace = ""

func ExpectResource(res runtime.Object, kind, namespace, name string, spec interface{}) {
	ma := res.(v1.ObjectMetaAccessor)
	Expect(ma.GetObjectMeta().GetNamespace()).To(Equal(namespace))
	Expect(ma.GetObjectMeta().GetName()).To(Equal(name))
	Expect(ma.GetObjectMeta().GetResourceVersion()).ToNot(BeEmpty())
	Expect(res.GetObjectKind().GroupVersionKind().Kind).To(Equal(kind))
	Expect(res.GetObjectKind().GroupVersionKind().Group).To(Equal(apiv2.Group))
	Expect(res.GetObjectKind().GroupVersionKind().Version).To(Equal(apiv2.VersionCurrent))
	Expect(getSpec(res)).To(Equal(spec))
}

// TestResourceWatch is a test helper used to validate a set of events are received
// from a watcher.  The caller creates a watch.Interface from the resource-specific
// client and passes that to TestResourceWatch to create a TestResourceWatchInterface.
func TestResourceWatch(w watch.Interface) TestResourceWatchInterface {
	tw := &testResourceWatcher{
		watch:         w,
		events:        []watch.Event{},
		watchClosedCh: make(chan struct{}),
	}
	go tw.run()
	return tw
}

// TestResourceWatchInterface provides methods to terminate a resource watch test, and to
// validate the events received by the Watch.
type TestResourceWatchInterface interface {
	// Stop is used to free up resources associated with the test watcher.  The caller
	// must call this when they are finished with the watcher.
	Stop()

	// ExpectEvents is used to validate the events received by the Watcher match the
	// set of expected events.
	ExpectEvents(kind string, events []watch.Event)
}

// testResourceWatch implements the set of watch-test function described in the docs
// for testResourceWatch.  Do not instantiate this struct directly.
type testResourceWatcher struct {
	watch         watch.Interface
	events        []watch.Event
	watchClosedCh chan struct{}
	closing       bool
	lock          sync.Mutex
}

// run is the main loop that consumes and stores the watch events.
func (t *testResourceWatcher) run() {
	for {
		select {
		case event := <-t.watch.ResultChan():
			t.lock.Lock()
			t.events = append(t.events, event)
			t.lock.Unlock()
		case <-t.watchClosedCh:
			log.Info("Exiting test watch loop")
			return
		}
	}
}

// Stop closes down the Watcher and the main watch loop.
func (t *testResourceWatcher) Stop() {
	t.lock.Lock()
	defer t.lock.Unlock()
	if !t.closing {
		t.watch.Stop()
		close(t.watchClosedCh)
		t.closing = true
	}
}

// ExpectEvents validates the received events match those expected.  This should be called
// within a Ginkgo test.
func (t *testResourceWatcher) ExpectEvents(kind string, events []watch.Event) {
	By("Waiting for the correct number of events")
	log.Infof("Start waiting at %s", time.Now())
	t.lock.Lock()
	cur := len(t.events)
	t.lock.Unlock()
	for ii := 0; ii < 10 && cur != len(events); ii++ {
		time.Sleep(100 * time.Millisecond)
		t.lock.Lock()
		newcur := len(t.events)
		t.lock.Unlock()
		if newcur != cur {
			// We've got new events, so reset the counter.
			ii = 0
			cur = newcur
		}
	}
	log.Infof("Finish waiting at %s", time.Now())

	// We either have the correct number of events now, or we don't.  In any case
	// lock the events list and compare the events.
	t.lock.Lock()
	defer t.lock.Unlock()
	Expect(t.events).To(HaveLen(len(events)))
	for i, event := range events {
		Expect(t.events[i].Type).To(Equal(event.Type))
		if event.Object != nil {
			Expect(t.events[i].Object).NotTo(BeNil())
			ExpectResource(
				t.events[i].Object,
				kind,
				event.Object.(v1.ObjectMetaAccessor).GetObjectMeta().GetNamespace(),
				event.Object.(v1.ObjectMetaAccessor).GetObjectMeta().GetName(),
				getSpec(event.Object),
			)
		} else {
			Expect(t.events[i].Object).To(BeNil())
		}
		if event.Previous != nil {
			Expect(t.events[i].Previous).NotTo(BeNil())
			ExpectResource(
				t.events[i].Previous,
				kind,
				event.Previous.(v1.ObjectMetaAccessor).GetObjectMeta().GetNamespace(),
				event.Previous.(v1.ObjectMetaAccessor).GetObjectMeta().GetName(),
				getSpec(event.Previous),
			)
		} else {
			Expect(t.events[i].Previous).To(BeNil())
		}
	}

	// Remove the events we've already validated.
	t.events = t.events[len(events):]
}

// getSpec returns the Spec structure from the supplied resource.
func getSpec(res runtime.Object) interface{} {
	v, err := conversion.EnforcePtr(res)
	Expect(err).NotTo(HaveOccurred())

	spec := v.FieldByName("Spec")
	return spec.Interface()
}
