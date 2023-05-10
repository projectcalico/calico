// Copyright (c) 2017-2018, 2020 Tigera, Inc. All rights reserved.

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
package testutils

import (
	"reflect"
	"sort"
	"sync"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"fmt"

	"k8s.io/apimachinery/pkg/conversion"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/go-yaml-wrapper"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/calico/libcalico-go/lib/watch"
)

const ExpectNoNamespace = ""

type resourceMatcher struct {
	kind, namespace, name string
	spec                  interface{}
	status                interface{}
}

func Resource(kind, namespace, name string, spec interface{}, optionalDescription ...interface{}) *resourceMatcher {
	return &resourceMatcher{kind, namespace, name, spec, nil}
}

func ResourceWithStatus(kind, namespace, name string, spec, status interface{}, optionalDescription ...interface{}) *resourceMatcher {
	return &resourceMatcher{kind, namespace, name, spec, status}
}

// Another name for the same matcher (which reads better when checking a single item).
var MatchResource = Resource
var MatchResourceWithStatus = ResourceWithStatus

func (m *resourceMatcher) Match(actual interface{}) (success bool, err error) {
	// 'actual' here may be a resource struct like v3.HostEndpoint, or a pointer to a resource
	// struct.  If it's a pointer we can immediately convert it to runtime.Object.
	res, ok := actual.(runtime.Object)
	if !ok {
		// It must be a resource struct.  For conversion to runtime.Object we need a pointer
		// to a resource struct, which we can get as follows.
		ptr := reflect.New(reflect.TypeOf(actual))
		ptr.Elem().Set(reflect.ValueOf(actual))
		res = ptr.Interface().(runtime.Object)
	}
	ma := res.(v1.ObjectMetaAccessor)
	success = (ma.GetObjectMeta().GetNamespace() == m.namespace) &&
		(ma.GetObjectMeta().GetName() == m.name) &&
		(ma.GetObjectMeta().GetResourceVersion() != "") &&
		(res.GetObjectKind().GroupVersionKind().Kind == m.kind) &&
		(res.GetObjectKind().GroupVersionKind().Group == apiv3.Group) &&
		(res.GetObjectKind().GroupVersionKind().Version == apiv3.VersionCurrent) &&
		(m.spec == nil || reflect.DeepEqual(getSpec(res), m.spec)) &&
		(m.status == nil || reflect.DeepEqual(getStatus(res), m.status))
	return
}

func (m *resourceMatcher) FailureMessage(actual interface{}) (message string) {
	message = fmt.Sprintf("Expected\n\t%#v\nto match\n\t%#v", actual, m)
	return
}

func (m *resourceMatcher) NegatedFailureMessage(actual interface{}) (message string) {
	message = fmt.Sprintf("Expected\n\t%#v\nnot to match\n\t%#v", actual, m)
	return
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
	t.expectEvents(kind, false, expectedEvents)
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
func (t *testResourceWatcher) expectEvents(kind string, anyOrder bool, expectedEvents []watch.Event) {
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

	// If the events may be expected in any order, then sort the events so that we
	// can compare like with like.  We may not actually have the correct number of
	// events, so protect against that scenario - we'll check later once we've
	// constructed useful diagnostics.
	var actualEvents []watch.Event
	log.Infof("Received %s events, expected %d", len(t.events), len(expectedEvents))
	if len(t.events) != len(expectedEvents) {
		// Log out the events we received before failing the test.
		log.Errorf("Number of received events does not match expected.")
		for _, e := range t.events {
			var o runtime.Object
			if e.Type == watch.Deleted {
				o = e.Previous
			} else {
				o = e.Object
			}
			log.Infof(
				"Received event: EventType:%s; Kind:%s; Name:%s; Namespace:%s",
				e.Type,
				o.GetObjectKind().GroupVersionKind(),
				o.(v1.ObjectMetaAccessor).GetObjectMeta().GetName(),
				o.(v1.ObjectMetaAccessor).GetObjectMeta().GetNamespace(),
			)
		}

		// Fail the test.
		Expect(len(t.events)).To(Equal(len(expectedEvents)))
	} else {
		actualEvents = t.events
	}

	if anyOrder {
		log.Info("Ordering events")
		expectedEvents = t.sortEvents(expectedEvents)
		actualEvents = t.sortEvents(actualEvents)
	}

	// Trace out logs summarizing the set of events.
	log.Info("Comparing actual events against expected events.  Summary:")
	var expectedObject runtime.Object
	var actualObject runtime.Object
	for i, expectedEvent := range expectedEvents {
		if expectedEvent.Type == watch.Deleted {
			expectedObject = expectedEvent.Previous
		} else {
			expectedObject = expectedEvent.Object
		}
		log.Infof(
			"Expected: EventType:%s; Kind:%s; Name:%s; Namespace:%s",
			expectedEvent.Type,
			expectedObject.GetObjectKind().GroupVersionKind(),
			expectedObject.(v1.ObjectMetaAccessor).GetObjectMeta().GetName(),
			expectedObject.(v1.ObjectMetaAccessor).GetObjectMeta().GetNamespace(),
		)

		if i < len(actualEvents) {
			actualEvent := actualEvents[i]
			if actualEvent.Type == watch.Deleted {
				actualObject = actualEvent.Previous
			} else {
				actualObject = actualEvent.Object
			}
			if actualObject != nil {
				log.Infof(
					"Actual:   EventType:%s; Kind:%s; Name:%s; Namespace:%s",
					actualEvent.Type,
					actualObject.GetObjectKind().GroupVersionKind(),
					actualObject.(v1.ObjectMetaAccessor).GetObjectMeta().GetName(),
					actualObject.(v1.ObjectMetaAccessor).GetObjectMeta().GetNamespace(),
				)
			} else {
				log.Warnf("Actual:    EventType:%s, Object: <nil>; Error: %s", actualEvent.Type, actualEvent.Error)
			}
		} else {
			log.Error("Actual:   Event missing")
		}
	}

	// And verify we got the correct number of events.
	Expect(actualEvents).To(HaveLen(len(expectedEvents)))

	for i, expectedEvent := range expectedEvents {
		actualEvent := actualEvents[i]
		actualYaml, _ := yaml.Marshal(actualEvent)
		expectedYaml, _ := yaml.Marshal(expectedEvent)
		traceString := fmt.Sprintf("\nTracing out event details\nActual event: %s\nExpected event: %s\n", actualYaml, expectedYaml)

		Expect(actualEvent.Type).To(Equal(expectedEvent.Type), traceString)
		if expectedEvent.Object != nil {
			Expect(actualEvent.Object).NotTo(BeNil(), traceString)
			Expect(actualEvent.Object).To(MatchResourceWithStatus(
				kind,
				expectedEvent.Object.(v1.ObjectMetaAccessor).GetObjectMeta().GetNamespace(),
				expectedEvent.Object.(v1.ObjectMetaAccessor).GetObjectMeta().GetName(),
				getSpec(expectedEvent.Object),
				getStatus(expectedEvent.Object),
				traceString,
			))
		} else {
			Expect(actualEvent.Object).To(BeNil(), traceString)
		}

		// Kubernetes does not provide the "previous" value in a modified event, so don't
		// check for that if the datastore is KDD.
		if expectedEvent.Previous != nil && (expectedEvent.Type == watch.Deleted || t.datastoreType != apiconfig.Kubernetes) {
			Expect(actualEvent.Previous).NotTo(BeNil(), traceString)
			Expect(actualEvent.Previous).To(MatchResourceWithStatus(
				kind,
				expectedEvent.Previous.(v1.ObjectMetaAccessor).GetObjectMeta().GetNamespace(),
				expectedEvent.Previous.(v1.ObjectMetaAccessor).GetObjectMeta().GetName(),
				getSpec(expectedEvent.Previous),
				getStatus(expectedEvent.Previous),
				traceString,
			))
		} else {
			Expect(actualEvent.Previous).To(BeNil(), traceString)
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
		Expect(eventsByName).To(Not(HaveKey(name)))
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
	if !spec.IsValid() {
		return nil
	}
	return spec.Interface()
}

// getStatus returns the Status structure from the supplied resource.
func getStatus(res runtime.Object) interface{} {
	v, err := conversion.EnforcePtr(res)
	Expect(err).NotTo(HaveOccurred())

	status := v.FieldByName("Status")
	if !status.IsValid() {
		return nil
	}
	return status.Interface()
}
