// Copyright (c) 2016-2019 Tigera, Inc. All rights reserved.

package calico

import (
	"reflect"
	"testing"
	"time"

	calico "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/options"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/apiserver/pkg/storage"
)

func TestWatch(t *testing.T) {
	testWatch(t, false)
}

func TestWatchList(t *testing.T) {
	testWatch(t, true)
}

// It tests that
// - first occurrence of objects should notify Add event
// - update should trigger Modified event
// - update that gets filtered should trigger Deleted event
func testWatch(t *testing.T, list bool) {
	ctx, store, gnpStore := testSetup(t)
	defer func() {
		testCleanup(t, ctx, store, gnpStore)
		store.client.NetworkPolicies().Delete(ctx, "default", "foo", options.DeleteOptions{})
		store.client.NetworkPolicies().Delete(ctx, "default", "bar", options.DeleteOptions{})
	}()

	policyFoo := &calico.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "foo"}}
	policyFoo.SetCreationTimestamp(metav1.Time{Time: time.Now()})
	policyFoo.SetUID("test_uid_foo")
	policyBar := &calico.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "bar"}}
	policyBar.SetCreationTimestamp(metav1.Time{Time: time.Now()})
	policyBar.SetUID("test_uid_bar")

	policyBar.Spec.Selector = "my_label == \"set\""

	tests := []struct {
		pred       storage.SelectionPredicate
		watchTests []*testWatchStruct
	}{{ // create a key
		watchTests: []*testWatchStruct{
			{
				key:         "projectcalico.org/networkpolicies/default/foo",
				obj:         policyFoo,
				expectEvent: true,
				watchType:   watch.Added,
			},
		},
		pred: storage.Everything,
	}, { // create a key but obj gets filtered. Then update it with unfiltered obj
		watchTests: []*testWatchStruct{
			{
				key:         "projectcalico.org/networkpolicies/default/foo",
				obj:         policyFoo,
				expectEvent: false,
				watchType:   "",
			},
			{
				key:         "projectcalico.org/networkpolicies/default/bar",
				obj:         policyBar,
				expectEvent: true,
				watchType:   watch.Added,
			},
		},
		pred: storage.SelectionPredicate{
			Label: labels.Everything(),
			Field: fields.ParseSelectorOrDie("metadata.name=bar"),
			GetAttrs: func(obj runtime.Object) (labels.Set, fields.Set, error) {
				policy := obj.(*calico.NetworkPolicy)
				return nil, fields.Set{"metadata.name": policy.Name}, nil
			},
		},
	}}
	for i, tt := range tests {
		var w watch.Interface
		var err error
		if list {
			w, err = store.watchResource(ctx, "0", tt.pred, "", "default")
			if err != nil {
				t.Fatalf("Watch failed: %v", err)
			}
		}
		var prevObj *calico.NetworkPolicy
		for _, watchTest := range tt.watchTests {
			if !list {
				ns, name, err := NamespaceAndNameFromKey(watchTest.key, true)
				if err != nil {
					t.Fatalf("Test failed")
				}
				if list {
					name = ""
				}
				w, err = store.watchResource(ctx, "0", tt.pred, name, ns)
				if err != nil {
					t.Fatalf("Watch failed: %v", err)
				}
			}
			out := &calico.NetworkPolicy{}
			err = store.GuaranteedUpdate(ctx, watchTest.key, out, true, nil, storage.SimpleUpdate(
				func(runtime.Object) (runtime.Object, error) {
					return watchTest.obj, nil
				}), nil)
			if err != nil {
				t.Fatalf("GuaranteedUpdate failed: %v", err)
			}
			if watchTest.expectEvent {
				expectObj := out
				if watchTest.watchType == watch.Deleted {
					expectObj = prevObj
					expectObj.ResourceVersion = out.ResourceVersion
				}
				testCheckResult(t, i, watchTest.watchType, w, expectObj)
			}
			prevObj = out
			if !list {
				w.Stop()
				testCheckStop(t, i, w)
			}
		}
		if list {
			w.Stop()
			testCheckStop(t, i, w)
		}
	}
}

type testWatchStruct struct {
	key         string
	obj         *calico.NetworkPolicy
	expectEvent bool
	watchType   watch.EventType
}

func testCheckEventType(t *testing.T, expectEventType watch.EventType, w watch.Interface) {
	select {
	case res := <-w.ResultChan():
		if res.Type != expectEventType {
			t.Errorf("event type want=%v, get=%v", expectEventType, res.Type)
		}
	case <-time.After(wait.ForeverTestTimeout):
		t.Errorf("time out after waiting %v on ResultChan", wait.ForeverTestTimeout)
	}
}

func testCheckResult(t *testing.T, i int, expectEventType watch.EventType, w watch.Interface, expectObj *calico.NetworkPolicy) {
	select {
	case res := <-w.ResultChan():
		if res.Type != expectEventType {
			t.Errorf("#%d: event type want=%v, get=%v", i, expectEventType, res.Type)
			return
		}
		if !reflect.DeepEqual(expectObj, res.Object) {
			t.Errorf("#%d: obj want=\n%#v\nget=\n%#v", i, expectObj, res.Object)
		}
	case <-time.After(wait.ForeverTestTimeout):
		t.Errorf("#%d: time out after waiting %v on ResultChan", i, wait.ForeverTestTimeout)
	}
}

func testCheckStop(t *testing.T, i int, w watch.Interface) {
	select {
	case e, ok := <-w.ResultChan():
		if ok {
			var obj string
			switch e.Object.(type) {
			case *calico.NetworkPolicy:
				obj = e.Object.(*calico.NetworkPolicy).Name
			case *metav1.Status:
				obj = e.Object.(*metav1.Status).Message
			}
			t.Errorf("#%d: ResultChan should have been closed. Event: %s. Object: %s", i, e.Type, obj)
		}
	case <-time.After(wait.ForeverTestTimeout):
		t.Errorf("#%d: time out after waiting 1s on ResultChan", i)
	}
}
