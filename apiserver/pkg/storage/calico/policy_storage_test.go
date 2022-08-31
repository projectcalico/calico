// Copyright (c) 2019 Tigera, Inc. All rights reserved.

package calico

import (
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/apitesting"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/klog/v2"

	calico "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"

	"k8s.io/apiserver/pkg/registry/generic"
	"k8s.io/apiserver/pkg/storage"
	"k8s.io/apiserver/pkg/storage/storagebackend"

	"golang.org/x/net/context"
)

var scheme = runtime.NewScheme()
var codecs = serializer.NewCodecFactory(scheme)

func init() {
	metav1.AddToGroupVersion(scheme, metav1.SchemeGroupVersion)
	calico.AddToScheme(scheme)
}

func TestNetworkPolicyCreate(t *testing.T) {
	ctx, store, gnpStore := testSetup(t)
	defer testCleanup(t, ctx, store, gnpStore)

	key := "projectcalico.org/networkpolicies/default/foo"
	out := &calico.NetworkPolicy{}
	obj := &calico.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "foo"}}

	// verify that kv pair is empty before set
	libcPolicy, err := store.client.NetworkPolicies().Get(ctx, "default", "foo", options.GetOptions{})
	if libcPolicy != nil {
		t.Fatalf("expecting empty result on key: %s", key)
	}

	err = store.Create(ctx, key, obj, out, 0)
	if err != nil {
		t.Fatalf("Set failed: %v", err)
	}
	// basic tests of the output
	if obj.ObjectMeta.Name != out.ObjectMeta.Name {
		t.Errorf("pod name want=%s, get=%s", obj.ObjectMeta.Name, out.ObjectMeta.Name)
	}
	if out.ResourceVersion == "" {
		t.Errorf("output should have non-empty resource version")
	}

	// verify that kv pair is not empty after set
	libcPolicy, err = store.client.NetworkPolicies().Get(ctx, "default", "foo", options.GetOptions{})
	if err != nil {
		t.Fatalf("libcalico networkpolicy client get failed: %v", err)
	}
	if libcPolicy == nil {
		t.Fatalf("expecting empty result on key: %s", key)
	}
}

func TestNetworkPolicyCreateWithTTL(t *testing.T) {
	ctx, store, gnpStore := testSetup(t)
	defer testCleanup(t, ctx, store, gnpStore)

	input := &calico.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "foo"}}
	key := "projectcalico.org/networkpolicies/default/foo"

	out := &calico.NetworkPolicy{}
	if err := store.Create(ctx, key, input, out, 1); err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	opts := storage.ListOptions{ResourceVersion: out.ResourceVersion, Predicate: storage.Everything}
	w, err := store.Watch(ctx, key, opts)
	if err != nil {
		t.Fatalf("Watch failed: %v", err)
	}
	testCheckEventType(t, watch.Deleted, w)
}

func TestNetworkPolicyCreateWithKeyExist(t *testing.T) {
	ctx, store, gnpStore := testSetup(t)
	defer testCleanup(t, ctx, store, gnpStore)

	obj := &calico.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "foo"}}
	key, _ := testPropogateStore(ctx, t, store, obj)
	out := &calico.NetworkPolicy{}
	err := store.Create(ctx, key, obj, out, 0)
	if err == nil || !storage.IsExist(err) {
		t.Errorf("expecting key exists error, but get: %s", err)
	}
}

func TestNetworkPolicyCreateDisallowK8sPrefix(t *testing.T) {
	ctx, store, gnpStore := testSetup(t)
	defer testCleanup(t, ctx, store, gnpStore)
	name := "knp.default.foo"
	ns := "default"

	key := fmt.Sprintf("projectcalico.org/networkpolicies/%s/%s", ns, name)
	out := &calico.NetworkPolicy{}
	obj := &calico.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}}

	libcPolicy, err := store.client.NetworkPolicies().Get(ctx, ns, name, options.GetOptions{})
	if libcPolicy != nil {
		t.Fatalf("expecting empty result on key: %s", key)
	}

	err = store.Create(ctx, key, obj, out, 0)
	if err == nil {
		t.Fatalf("Expected Create of a policy with prefix 'knp.default.' to fail")
	}
}

func TestNetworkPolicyGet(t *testing.T) {
	ctx, store, gnpStore := testSetup(t)
	defer testCleanup(t, ctx, store, gnpStore)

	key, storedObj := testPropogateStore(ctx, t, store, &calico.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "foo"}})

	tests := []struct {
		key               string
		ignoreNotFound    bool
		expectNotFoundErr bool
		expectedOut       *calico.NetworkPolicy
	}{{ // test get on existing item
		key:               key,
		ignoreNotFound:    false,
		expectNotFoundErr: false,
		expectedOut:       storedObj,
	}, { // test get on non-existing item with ignoreNotFound=false
		key:               "projectcalico.org/networkpolicies/default/non-existing",
		ignoreNotFound:    false,
		expectNotFoundErr: true,
	}, { // test get on non-existing item with ignoreNotFound=true
		key:               "projectcalico.org/networkpolicies/default/non-existing",
		ignoreNotFound:    true,
		expectNotFoundErr: false,
		expectedOut:       &calico.NetworkPolicy{},
	}}

	for i, tt := range tests {
		out := &calico.NetworkPolicy{}
		opts := storage.GetOptions{IgnoreNotFound: tt.ignoreNotFound}
		err := store.Get(ctx, tt.key, opts, out)
		if tt.expectNotFoundErr {
			if err == nil || !storage.IsNotFound(err) {
				t.Errorf("#%d: expecting not found error, but get: %s", i, err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("Get failed: %v", err)
		}
		if !reflect.DeepEqual(tt.expectedOut, out) {
			t.Errorf("#%d: pod want=%#v, get=%#v", i, tt.expectedOut, out)
		}
	}
}

func TestNetworkPolicyUnconditionalDelete(t *testing.T) {
	ctx, store, gnpStore := testSetup(t)
	defer testCleanup(t, ctx, store, gnpStore)

	key, storedObj := testPropogateStore(ctx, t, store, &calico.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "foo"}})

	tests := []struct {
		key               string
		expectedObj       *calico.NetworkPolicy
		expectNotFoundErr bool
	}{{ // test unconditional delete on existing key
		key:               key,
		expectedObj:       storedObj,
		expectNotFoundErr: false,
	}, { // test unconditional delete on non-existing key
		key:               "projectcalico.org/networkpolicies/default/non-existing",
		expectedObj:       nil,
		expectNotFoundErr: true,
	}}

	for i, tt := range tests {
		out := &calico.NetworkPolicy{} // reset
		err := store.Delete(ctx, tt.key, out, nil, nil, nil)
		if tt.expectNotFoundErr {
			if err == nil || !storage.IsNotFound(err) {
				t.Errorf("#%d: expecting not found error, but get: %s", i, err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("Delete failed: %v", err)
		}
		if !reflect.DeepEqual(tt.expectedObj, out) {
			t.Errorf("#%d: pod want=%#v, get=%#v", i, tt.expectedObj, out)
		}
	}
}

func TestNetworkPolicyConditionalDelete(t *testing.T) {
	ctx, store, gnpStore := testSetup(t)
	defer testCleanup(t, ctx, store, gnpStore)

	key, storedObj := testPropogateStore(ctx, t, store, &calico.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "foo", UID: "A"}})

	tests := []struct {
		precondition        *storage.Preconditions
		expectInvalidObjErr bool
	}{{ // test conditional delete with UID match
		precondition:        storage.NewUIDPreconditions("A"),
		expectInvalidObjErr: false,
	}, { // test conditional delete with UID mismatch
		precondition:        storage.NewUIDPreconditions("B"),
		expectInvalidObjErr: true,
	}}

	for i, tt := range tests {
		out := &calico.NetworkPolicy{}
		err := store.Delete(ctx, key, out, tt.precondition, nil, nil)
		if tt.expectInvalidObjErr {
			if err == nil || !storage.IsInvalidObj(err) {
				t.Errorf("#%d: expecting invalid UID error, but get: %s", i, err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("Delete failed: %v", err)
		}
		if !reflect.DeepEqual(storedObj, out) {
			t.Errorf("#%d: pod want=%#v, get=%#v", i, storedObj, out)
		}
		key, storedObj = testPropogateStore(ctx, t, store, &calico.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "foo", UID: "A"}})
	}
}

func TestNetworkPolicyDeleteDisallowK8sPrefix(t *testing.T) {
	ctx, store, gnpStore := testSetup(t)
	defer testCleanup(t, ctx, store, gnpStore)
	name := "knp.default.foo"
	ns := "default"

	key := fmt.Sprintf("projectcalico.org/networkpolicies/%s/%s", ns, name)
	out := &calico.NetworkPolicy{}
	err := store.Delete(ctx, key, out, nil, nil, nil)
	if err == nil {
		t.Fatalf("Expected deleting a k8s network policy to error")
	}
}

func TestNetworkPolicyGetList(t *testing.T) {
	ctx, store, gnpStore := testSetup(t)
	defer testCleanup(t, ctx, store, gnpStore)

	key, storedObj := testPropogateStore(ctx, t, store, &calico.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "foo"}})

	tests := []struct {
		key         string
		pred        storage.SelectionPredicate
		expectedOut []*calico.NetworkPolicy
	}{{ // test GetList on existing key
		key:         key,
		pred:        storage.Everything,
		expectedOut: []*calico.NetworkPolicy{storedObj},
	}, { // test GetList on non-existing key
		key:         "projectcalico.org/networkpolicies/default/non-existing",
		pred:        storage.Everything,
		expectedOut: nil,
	}, { // test GetList with matching policy name
		key: "projectcalico.org/networkpolicies/default/non-existing",
		pred: storage.SelectionPredicate{
			Label: labels.Everything(),
			Field: fields.ParseSelectorOrDie("metadata.name!=" + storedObj.Name),
			GetAttrs: func(obj runtime.Object) (labels.Set, fields.Set, error) {
				policy := obj.(*calico.NetworkPolicy)
				return nil, fields.Set{"metadata.name": policy.Name}, nil
			},
		},
		expectedOut: nil,
	}}

	for i, tt := range tests {
		out := &calico.NetworkPolicyList{}
		opts := storage.ListOptions{Predicate: tt.pred}
		err := store.GetList(ctx, tt.key, opts, out)
		if err != nil {
			t.Fatalf("GetList failed: %v", err)
		}
		if len(out.Items) != len(tt.expectedOut) {
			t.Errorf("#%d: length of list want=%d, get=%d", i, len(tt.expectedOut), len(out.Items))
			continue
		}
		for j, wantPolicy := range tt.expectedOut {
			getPolicy := &out.Items[j]
			if !reflect.DeepEqual(wantPolicy, getPolicy) {
				t.Errorf("#%d: pod want=%#v, get=%#v", i, wantPolicy, getPolicy)
			}
		}
	}
}

func TestNetworkPolicyGuaranteedUpdate(t *testing.T) {
	ctx, store, gnpStore := testSetup(t)
	defer func() {
		testCleanup(t, ctx, store, gnpStore)
		store.client.NetworkPolicies().Delete(ctx, "default", "non-existing", options.DeleteOptions{})
	}()
	key, storeObj := testPropogateStore(ctx, t, store, &calico.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "foo", UID: "A"}})

	tests := []struct {
		key                 string
		ignoreNotFound      bool
		precondition        *storage.Preconditions
		expectNotFoundErr   bool
		expectInvalidObjErr bool
		expectNoUpdate      bool
		transformStale      bool
	}{{ // GuaranteedUpdate on non-existing key with ignoreNotFound=false
		key:                 "projectcalico.org/networkpolicies/default/non-existing",
		ignoreNotFound:      false,
		precondition:        nil,
		expectNotFoundErr:   true,
		expectInvalidObjErr: false,
		expectNoUpdate:      false,
	}, { // GuaranteedUpdate on non-existing key with ignoreNotFound=true
		// This would update datastore revision.
		key:                 "projectcalico.org/networkpolicies/default/non-existing",
		ignoreNotFound:      true,
		precondition:        nil,
		expectNotFoundErr:   false,
		expectInvalidObjErr: false,
		expectNoUpdate:      false,
	}, { // GuaranteedUpdate on existing key
		key:                 key,
		ignoreNotFound:      false,
		precondition:        nil,
		expectNotFoundErr:   false,
		expectInvalidObjErr: false,
		expectNoUpdate:      false,
	}, { // GuaranteedUpdate with same data
		key:                 key,
		ignoreNotFound:      false,
		precondition:        nil,
		expectNotFoundErr:   false,
		expectInvalidObjErr: false,
		expectNoUpdate:      true,
	}, { // GuaranteedUpdate with same data but stale
		key:                 key,
		ignoreNotFound:      false,
		precondition:        nil,
		expectNotFoundErr:   false,
		expectInvalidObjErr: false,
		expectNoUpdate:      false,
		transformStale:      true,
	}, { // GuaranteedUpdate with UID match
		key:                 key,
		ignoreNotFound:      false,
		precondition:        storage.NewUIDPreconditions("A"),
		expectNotFoundErr:   false,
		expectInvalidObjErr: false,
		expectNoUpdate:      true,
	}, { // GuaranteedUpdate with UID mismatch
		key:                 key,
		ignoreNotFound:      false,
		precondition:        storage.NewUIDPreconditions("B"),
		expectNotFoundErr:   false,
		expectInvalidObjErr: true,
		expectNoUpdate:      true,
	}}

	for i, tt := range tests {
		klog.Infof("Start to run test on tt: %+v", tt)
		out := &calico.NetworkPolicy{}
		selector := fmt.Sprintf("my_label == \"foo-%d\"", i)
		if tt.expectNoUpdate {
			selector = ""
		}
		version := storeObj.ResourceVersion
		versionInt, err := strconv.Atoi(version)
		if err != nil {
			t.Errorf("#%d: failed to convert original version %s to int", i, version)
		}
		err = store.GuaranteedUpdate(ctx, tt.key, out, tt.ignoreNotFound, tt.precondition,
			storage.SimpleUpdate(func(obj runtime.Object) (runtime.Object, error) {
				if tt.expectNotFoundErr && tt.ignoreNotFound {
					if policy := obj.(*calico.NetworkPolicy); policy.Spec.Selector != "" {
						t.Errorf("#%d: expecting zero value, but get=%#v", i, policy)
					}
				}

				policy := *storeObj
				// Set correct resource name, don't update "non-existing" to "foo"
				if strings.Contains(tt.key, "non-existing") {
					policy.Name = "non-existing"
					// Clean resource version for non-existing object
					policy.GetObjectMeta().SetResourceVersion("")

				}
				if !tt.expectNoUpdate {
					policy.Spec.Selector = selector
				}
				return &policy, nil
			}), nil)

		if tt.expectNotFoundErr {
			if err == nil || !storage.IsNotFound(err) {
				t.Errorf("#%d: expecting not found error, but get: %v", i, err)
			}
			continue
		}
		if tt.expectInvalidObjErr {
			if err == nil || !storage.IsInvalidObj(err) {
				t.Errorf("#%d: expecting invalid UID error, but get: %s", i, err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("GuaranteedUpdate failed: %v", err)
		}
		if !tt.expectNoUpdate {
			if out.Spec.Selector != selector {
				t.Errorf("#%d: policy selector want=%s, get=%s", i, selector, out.Spec.Selector)
			}
		}
		switch tt.expectNoUpdate {
		case true:
			outInt, err := strconv.Atoi(out.ResourceVersion)
			if err != nil {
				t.Errorf("#%d: failed to convert out resource version %s to int", i, out.ResourceVersion)
			}
			// After creation of a "non-existing" object by previous test, the resource version has increased by 1 for
			// new updates.
			if outInt != (versionInt + 1) {
				t.Errorf("#%d: expect no version change, before=%s, after=%s", i, version, out.ResourceVersion)
			}
		case false:
			if version == out.ResourceVersion {
				t.Errorf("#%d: expect version change, but get the same version=%s", i, version)
			}
		}
		storeObj = out
	}
}

func TestNetworkPolicyGuaranteedUpdateWithTTL(t *testing.T) {
	ctx, store, gnpStore := testSetup(t)
	defer testCleanup(t, ctx, store, gnpStore)

	input := &calico.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "foo"}}
	input.SetCreationTimestamp(metav1.Time{Time: time.Now()})
	input.SetUID("test_uid")
	key := "projectcalico.org/networkpolicies/default/foo"

	out := &calico.NetworkPolicy{}
	err := store.GuaranteedUpdate(ctx, key, out, true, nil,
		func(_ runtime.Object, _ storage.ResponseMeta) (runtime.Object, *uint64, error) {
			ttl := uint64(1)
			return input, &ttl, nil
		}, nil)
	if err != nil {
		t.Fatalf("Guaranteed Update failed: %v", err)
	}

	opts := storage.ListOptions{ResourceVersion: out.ResourceVersion, Predicate: storage.Everything}
	w, err := store.Watch(ctx, key, opts)
	if err != nil {
		t.Fatalf("Watch failed: %v", err)
	}
	testCheckEventType(t, watch.Deleted, w)
}

func TestNetworkPolicyGuaranteedUpdateWithConflict(t *testing.T) {
	ctx, store, gnpStore := testSetup(t)
	defer testCleanup(t, ctx, store, gnpStore)
	key, _ := testPropogateStore(ctx, t, store, &calico.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "foo"}})

	errChan := make(chan error, 1)
	var firstToFinish sync.WaitGroup
	var secondToEnter sync.WaitGroup
	firstToFinish.Add(1)
	secondToEnter.Add(1)

	go func() {
		err := store.GuaranteedUpdate(ctx, key, &calico.NetworkPolicy{}, false, nil,
			storage.SimpleUpdate(func(obj runtime.Object) (runtime.Object, error) {
				policy := obj.(*calico.NetworkPolicy)
				policy.Spec.Selector = "my_label == \"foo-1\""
				secondToEnter.Wait()
				return policy, nil
			}), nil)
		firstToFinish.Done()
		errChan <- err
	}()

	updateCount := 0
	err := store.GuaranteedUpdate(ctx, key, &calico.NetworkPolicy{}, false, nil,
		storage.SimpleUpdate(func(obj runtime.Object) (runtime.Object, error) {
			if updateCount == 0 {
				secondToEnter.Done()
				firstToFinish.Wait()
			}
			updateCount++
			policy := obj.(*calico.NetworkPolicy)
			policy.Spec.Selector = "my_label == \"foo-2\""
			return policy, nil
		}), nil)
	if err != nil {
		t.Fatalf("Second GuaranteedUpdate error %#v", err)
	}
	if err := <-errChan; err != nil {
		t.Fatalf("First GuaranteedUpdate error %#v", err)
	}

	if updateCount != 2 {
		t.Errorf("Should have conflict and called update func twice")
	}
}

func TestNetworkPolicyList(t *testing.T) {
	ctx, store, _ := testSetup(t)
	defer func() {
		store.client.NetworkPolicies().Delete(ctx, "default", "foo", options.DeleteOptions{})
		store.client.NetworkPolicies().Delete(ctx, "default1", "foo", options.DeleteOptions{})
		store.client.NetworkPolicies().Delete(ctx, "default1", "bar", options.DeleteOptions{})
	}()

	preset := []struct {
		key       string
		obj       *calico.NetworkPolicy
		storedObj *calico.NetworkPolicy
	}{{
		key: "projectcalico.org/networkpolicies/default/foo",
		obj: &calico.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "foo"}},
	}, {
		key: "projectcalico.org/networkpolicies/default1/foo",
		obj: &calico.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "default1", Name: "foo"}},
	}, {
		key: "projectcalico.org/networkpolicies/default1/bar",
		obj: &calico.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "default1", Name: "bar"}},
	}}

	for i, ps := range preset {
		preset[i].storedObj = &calico.NetworkPolicy{}
		err := store.Create(ctx, ps.key, ps.obj, preset[i].storedObj, 0)
		if err != nil {
			t.Fatalf("Set failed: %v", err)
		}
	}

	tests := []struct {
		prefix      string
		pred        storage.SelectionPredicate
		expectedOut []*calico.NetworkPolicy
	}{{ // test List on existing key
		prefix:      "projectcalico.org/networkpolicies/default/",
		pred:        storage.Everything,
		expectedOut: []*calico.NetworkPolicy{preset[0].storedObj},
	}, { // test List on non-existing key
		prefix:      "projectcalico.org/networkpolicies/non-existing/",
		pred:        storage.Everything,
		expectedOut: nil,
	}, { // test List with policy name matching
		prefix: "projectcalico.org/networkpolicies/default/",
		pred: storage.SelectionPredicate{
			Label: labels.Everything(),
			Field: fields.ParseSelectorOrDie("metadata.name!=" + preset[0].storedObj.Name),
			GetAttrs: func(obj runtime.Object) (labels.Set, fields.Set, error) {
				policy := obj.(*calico.NetworkPolicy)
				return nil, fields.Set{"metadata.name": policy.Name}, nil
			},
		},
		expectedOut: nil,
	}, { // test List with multiple levels of directories and expect flattened result
		prefix:      "projectcalico.org/networkpolicies/",
		pred:        storage.Everything,
		expectedOut: []*calico.NetworkPolicy{preset[0].storedObj, preset[2].storedObj, preset[1].storedObj},
	}}

	for i, tt := range tests {
		out := &calico.NetworkPolicyList{}
		opts := storage.ListOptions{ResourceVersion: "0", Predicate: tt.pred}
		err := store.List(ctx, tt.prefix, opts, out)
		if err != nil {
			t.Fatalf("List failed: %v", err)
		}
		if len(tt.expectedOut) != len(out.Items) {
			t.Errorf("#%d: length of list want=%d, get=%d", i, len(tt.expectedOut), len(out.Items))
			continue
		}
		for j, wantPolicy := range tt.expectedOut {
			getPolicy := &out.Items[j]
			if !reflect.DeepEqual(wantPolicy, getPolicy) {
				t.Errorf("#%d: pod want=%#v, get=%#v", i, wantPolicy, getPolicy)
			}
		}
	}
}

func testSetup(t *testing.T) (context.Context, *resourceStore, *resourceStore) {
	codec := apitesting.TestCodec(codecs, calico.SchemeGroupVersion)
	cfg, err := apiconfig.LoadClientConfig("")
	if err != nil {
		klog.Errorf("Failed to load client config: %q", err)
		os.Exit(1)
	}
	cfg.Spec.DatastoreType = "etcdv3"
	cfg.Spec.EtcdEndpoints = "http://localhost:2379"
	c, err := clientv3.New(*cfg)
	if err != nil {
		klog.Errorf("Failed creating client: %q", err)
		os.Exit(1)
	}

	klog.Infof("Client: %v", c)
	opts := Options{
		RESTOptions: generic.RESTOptions{
			StorageConfig: &storagebackend.ConfigForResource{
				Config: storagebackend.Config{
					Codec: codec,
				},
			},
		},
	}
	store, _ := NewNetworkPolicyStorage(opts)
	gnpStore, _ := NewGlobalNetworkPolicyStorage(opts)
	ctx := context.Background()

	return ctx, store.Storage.(*resourceStore), gnpStore.Storage.(*resourceStore)
}

func testCleanup(t *testing.T, ctx context.Context, store, gnpStore *resourceStore) {
	np, _ := store.client.NetworkPolicies().Get(ctx, "default", "foo", options.GetOptions{})
	if np != nil {
		store.client.NetworkPolicies().Delete(ctx, "default", "foo", options.DeleteOptions{})
	}
	gnp, _ := gnpStore.client.GlobalNetworkPolicies().Get(ctx, "foo", options.GetOptions{})
	if gnp != nil {
		gnpStore.client.GlobalNetworkPolicies().Delete(ctx, "foo", options.DeleteOptions{})
	}
}

// testPropogateStore helps propagates store with objects, automates key generation, and returns
// keys and stored objects.
func testPropogateStore(ctx context.Context, t *testing.T, store *resourceStore, obj *calico.NetworkPolicy) (string, *calico.NetworkPolicy) {
	// Setup store with a key and grab the output for returning.
	key := "projectcalico.org/networkpolicies/default/foo"
	setOutput := &calico.NetworkPolicy{}
	err := store.Create(ctx, key, obj, setOutput, 0)
	if err != nil {
		t.Fatalf("Set failed: %v", err)
	}
	return key, setOutput
}
