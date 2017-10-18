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
	"sort"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	apiv2 "github.com/projectcalico/libcalico-go/lib/apis/v2"
	"github.com/projectcalico/libcalico-go/lib/watch"
	"k8s.io/apimachinery/pkg/conversion"
	"github.com/projectcalico/libcalico-go/lib/apiconfig"
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
func NewTestResourceWatch(datastoreType apiconfig.DatastoreType, w watch.Interface) TestResourceWatchInterface {
	tw := &testResourceWatcher{
		datastoreType: datastoreType,
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

	// ExpectEventsAnyOrder is used to validate the events received by the Watcher match the
	// set of expected events.  The order of events is not important.  This should only be
	// called with sets of added events (not deleted or modified), and is used to verify an
	// initial snapshot.
	ExpectEventsAnyOrder(kind string, events []watch.Event)
}

// testResourceWatch implements the set of watch-test function described in the docs
// for testResourceWatch.  Do not instantiate this struct directly.
type testResourceWatcher struct {
	datastoreType apiconfig.DatastoreType
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
func (t *testResourceWatcher) ExpectEvents(kind string, expectedEvents []watch.Event) {
	t.expectEvents(kind, true, expectedEvents)
}

// ExpectEventsAnyOrder validates the received events match those expected but the order
// is not necessarily fixed.  KDD watch without a resource version does not appear to be
// deterministic in the order of events from the initial "list".
//
// This should be called within a Ginkgo test, and should only be called when listing the
// current snapshot - it should only include added event types.
func (t *testResourceWatcher) ExpectEventsAnyOrder(kind string, expectedEvents []watch.Event) {
	for _, e := range expectedEvents {
		Expect(e.Type).To(Equal(watch.Added))
	}
	t.expectEvents(kind, true, expectedEvents)
}

// ExpectEvents validates the received events match those expected.  This should be called
// within a Ginkgo test.
func (t *testResourceWatcher) expectEvents(kind string, fixedOrder bool, expectedEvents []watch.Event) {
	By("Waiting for the correct number of events")
	log.Infof("Start waiting at %s", time.Now())
	t.lock.Lock()
	cur := len(t.events)
	t.lock.Unlock()
	for ii := 0; ii < 10 && cur != len(expectedEvents); ii++ {
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

	// If the order is not fixed, sort the expected and actual events based on name.
	actualEvents := t.events[:len(expectedEvents)]
	if !fixedOrder {
		expectedEvents = t.sortEvents(expectedEvents)
		actualEvents = t.sortEvents(actualEvents)
	}

	Expect(t.events).To(HaveLen(len(expectedEvents)))
	for i, expectedEvent := range expectedEvents {
		Expect(actualEvents[i].Type).To(Equal(expectedEvent.Type))
		if expectedEvent.Object != nil {
			Expect(actualEvents[i].Object).NotTo(BeNil())
			ExpectResource(
				actualEvents[i].Object,
				kind,
				expectedEvent.Object.(v1.ObjectMetaAccessor).GetObjectMeta().GetNamespace(),
				expectedEvent.Object.(v1.ObjectMetaAccessor).GetObjectMeta().GetName(),
				getSpec(expectedEvent.Object),
			)
		} else {
			Expect(actualEvents[i].Object).To(BeNil())
		}

		// Kubernetes does not provide the "previous" value in a modified event, so don't
		// check for that if the datastore is KDD.
		if expectedEvent.Previous != nil  && (expectedEvent.Type == watch.Deleted || t.datastoreType != apiconfig.Kubernetes){
			Expect(actualEvents[i].Previous).NotTo(BeNil())
			ExpectResource(
				actualEvents[i].Previous,
				kind,
				expectedEvent.Previous.(v1.ObjectMetaAccessor).GetObjectMeta().GetNamespace(),
				expectedEvent.Previous.(v1.ObjectMetaAccessor).GetObjectMeta().GetName(),
				getSpec(expectedEvent.Previous),
			)
		} else {
			Expect(actualEvents[i].Previous).To(BeNil())
		}
	}

	// Remove the events we've already validated.
	t.events = t.events[len(expectedEvents):]
}

// sortEvents sorts the events by name order.  Only one event should exist per name.
func (t *testResourceWatcher) sortEvents(events []watch.Event) []watch.Event {
	names := []string{}
	eventsByName := map[string]watch.Event{}
	ordered := []watch.Event{}

	for _, e := range events {
		var name string
		if e.Object != nil {
			name = e.Object.(v1.ObjectMetaAccessor).GetObjectMeta().GetName()
		} else {
			name = e.Previous.(v1.ObjectMetaAccessor).GetObjectMeta().GetName()
		}
		names = append(names, name)

		// Makes sure we don't have multiple entries for the same name.
		Expect(eventsByName[name]).To(BeNil())
		eventsByName[name] = e
	}

	sort.Strings(names)

	for _, name := range names {
		ordered = append(ordered, eventsByName[name])
	}

	return ordered
}

// getSpec returns the Spec structure from the supplied resource.
func getSpec(res runtime.Object) interface{} {
	v, err := conversion.EnforcePtr(res)
	Expect(err).NotTo(HaveOccurred())

	spec := v.FieldByName("Spec")
	return spec.Interface()
}
