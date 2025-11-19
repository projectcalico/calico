// Copyright (c) 2024-2025 Tigera, Inc. All rights reserved.

package calico

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/sirupsen/logrus"
	apitesting "k8s.io/apimachinery/pkg/api/apitesting"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/apiserver/pkg/registry/generic"
	"k8s.io/apiserver/pkg/storage"
	"k8s.io/apiserver/pkg/storage/storagebackend"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/names"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

func init() {
	metav1.AddToGroupVersion(scheme, metav1.SchemeGroupVersion)
	_ = v3.AddToScheme(scheme)
}

func TestTierCreate(t *testing.T) {
	ctx, store := testTierSetup(t)
	defer testTierCleanup(t, ctx, store)

	key := "projectcalico.org/tiers/foo"
	out := &v3.Tier{}
	obj := makeTierWithDefaults()

	// verify that kv pair is empty before set
	libcTier, _ := store.client.Tiers().Get(ctx, "foo", options.GetOptions{})
	if libcTier != nil {
		t.Fatalf("expecting empty result on key: %s", key)
	}

	err := store.Create(ctx, key, obj, out, 0)
	if err != nil {
		t.Fatalf("Set failed: %v", err)
	}
	// basic tests of the output
	if obj.Name != out.Name {
		t.Errorf("pod name want=%s, get=%s", obj.Name, out.Name)
	}
	if out.ResourceVersion == "" {
		t.Errorf("output should have non-empty resource version")
	}

	// verify that kv pair is not empty after set
	libcTier, err = store.client.Tiers().Get(ctx, "foo", options.GetOptions{})
	if err != nil {
		t.Fatalf("libcalico Tier client get failed: %v", err)
	}
	if libcTier == nil {
		t.Fatalf("expecting empty result on key: %s", key)
	}
}

func TestTierCreateWithTTL(t *testing.T) {
	ctx, store := testTierSetup(t)
	defer testTierCleanup(t, ctx, store)

	input := makeTierWithDefaults()
	key := "projectcalico.org/tiers/foo"

	out := &v3.Tier{}
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

func TestTierCreateWithKeyExist(t *testing.T) {
	ctx, store := testTierSetup(t)
	defer testTierCleanup(t, ctx, store)

	obj := makeTierWithDefaults()
	key, _ := testTierPropogateStore(ctx, t, store, obj)
	out := &v3.Tier{}
	err := store.Create(ctx, key, obj, out, 0)
	if err == nil || !storage.IsExist(err) {
		t.Errorf("expecting key exists error, but get: %s", err)
	}
}

func TestTierGet(t *testing.T) {
	ctx, store := testTierSetup(t)
	defer testTierCleanup(t, ctx, store)

	key, storedObj := testTierPropogateStore(ctx, t, store, makeTierWithDefaults())

	tests := []struct {
		key               string
		ignoreNotFound    bool
		expectNotFoundErr bool
		expectedOut       *v3.Tier
	}{{ // test get on existing item
		key:               key,
		ignoreNotFound:    false,
		expectNotFoundErr: false,
		expectedOut:       storedObj,
	}, { // test get on non-existing item with ignoreNotFound=false
		key:               "projectcalico.org/tiers/non-existing",
		ignoreNotFound:    false,
		expectNotFoundErr: true,
	}, { // test get on non-existing item with ignoreNotFound=true
		key:               "projectcalico.org/tiers/non-existing",
		ignoreNotFound:    true,
		expectNotFoundErr: false,
		expectedOut:       &v3.Tier{},
	}}

	for i, tt := range tests {
		out := &v3.Tier{}
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

func TestTierUnconditionalDelete(t *testing.T) {
	ctx, store := testTierSetup(t)
	defer testTierCleanup(t, ctx, store)

	key, storedObj := testTierPropogateStore(ctx, t, store, makeTierWithDefaults())

	tests := []struct {
		key               string
		expectedObj       *v3.Tier
		expectNotFoundErr bool
	}{{ // test unconditional delete on existing key
		key:               key,
		expectedObj:       storedObj,
		expectNotFoundErr: false,
	}, { // test unconditional delete on non-existing key
		key:               "projectcalico.org/tiers/non-existing",
		expectedObj:       nil,
		expectNotFoundErr: true,
	}}

	for i, tt := range tests {
		out := &v3.Tier{} // reset
		err := store.Delete(ctx, tt.key, out, nil, nil, nil, storage.DeleteOptions{})
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

func TestTierConditionalDelete(t *testing.T) {
	ctx, store := testTierSetup(t)
	defer testTierCleanup(t, ctx, store)

	key, storedObj := testTierPropogateStore(ctx, t, store, makeTier("foo", "A", 10.0))

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
		out := &v3.Tier{}
		err := store.Delete(ctx, key, out, tt.precondition, nil, nil, storage.DeleteOptions{})
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
		key, storedObj = testTierPropogateStore(ctx, t, store, makeTier("foo", "A", 10.0))
	}
}

func TestTierGetList(t *testing.T) {
	ctx, store := testTierSetup(t)
	defer testTierCleanup(t, ctx, store)

	key, storedObj := testTierPropogateStore(ctx, t, store, makeTierWithDefaults())

	tests := []struct {
		key         string
		pred        storage.SelectionPredicate
		expectedOut []*v3.Tier
	}{{ // test GetList on existing key
		key:         key,
		pred:        storage.Everything,
		expectedOut: []*v3.Tier{storedObj},
	}, { // test GetList on non-existing key
		key:         "projectcalico.org/tiers/non-existing",
		pred:        storage.Everything,
		expectedOut: nil,
	}, { // test GetList with matching tier name
		key: "projectcalico.org/tiers/non-existing",
		pred: storage.SelectionPredicate{
			Label: labels.Everything(),
			Field: fields.ParseSelectorOrDie("metadata.name!=" + storedObj.Name),
			GetAttrs: func(obj runtime.Object) (labels.Set, fields.Set, error) {
				tier := obj.(*v3.Tier)
				return nil, fields.Set{"metadata.name": tier.Name}, nil
			},
		},
		expectedOut: nil,
	}}

	for i, tt := range tests {
		out := &v3.TierList{}
		opts := storage.ListOptions{Predicate: tt.pred}
		err := store.GetList(ctx, tt.key, opts, out)
		if err != nil {
			t.Fatalf("GetList failed: %v", err)
		}
		if len(out.Items) != len(tt.expectedOut) {
			t.Errorf("#%d: length of list want=%d, get=%d", i, len(tt.expectedOut), len(out.Items))
			continue
		}
		for j, wantTier := range tt.expectedOut {
			getTier := &out.Items[j]
			if !reflect.DeepEqual(wantTier, getTier) {
				t.Errorf("#%d: pod want=%#v, get=%#v", i, wantTier, getTier)
			}
		}
	}
}

func TestTierGuaranteedUpdate(t *testing.T) {
	ctx, store := testTierSetup(t)
	defer func() {
		testTierCleanup(t, ctx, store)
		_, _ = store.client.Tiers().Delete(ctx, "non-existing", options.DeleteOptions{})
	}()
	key, storeObj := testTierPropogateStore(ctx, t, store, makeTier("foo", "A", 10.0))

	tests := []struct {
		key                 string
		ignoreNotFound      bool
		precondition        *storage.Preconditions
		expectNotFoundErr   bool
		expectInvalidObjErr bool
		expectNoUpdate      bool
		transformStale      bool
	}{{ // GuaranteedUpdate on non-existing key with ignoreNotFound=false
		key:                 "projectcalico.org/tiers/non-existing",
		ignoreNotFound:      false,
		precondition:        nil,
		expectNotFoundErr:   true,
		expectInvalidObjErr: false,
		expectNoUpdate:      false,
	}, { // GuaranteedUpdate on non-existing key with ignoreNotFound=true
		// This would update datastore revision.
		key:                 "projectcalico.org/tiers/non-existing",
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
		logrus.Infof("Start to run test on tt: %+v", tt)
		out := &v3.Tier{}
		selector := fmt.Sprintf("foo-%d", i)
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
					if tier := obj.(*v3.Tier); tier.GenerateName != "" {
						t.Errorf("#%d: expecting zero value, but get=%#v", i, tier)
					}
				}
				tier := *storeObj
				// Set correct resource name, don't update "non-existing" to "foo"
				if strings.Contains(tt.key, "non-existing") {
					tier.Name = "non-existing"
					// Clean resource version for non-existing object
					tier.GetObjectMeta().SetResourceVersion("")

				}
				if !tt.expectNoUpdate {
					tier.GenerateName = selector
				}
				return &tier, nil
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
			if out.GenerateName != selector {
				t.Errorf("#%d: tier selector want=%s, get=%s", i, selector, out.GenerateName)
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

func TestTierGuaranteedUpdateWithTTL(t *testing.T) {
	ctx, store := testTierSetup(t)
	defer testTierCleanup(t, ctx, store)

	input := makeTierWithDefaults()
	input.SetCreationTimestamp(metav1.Time{Time: time.Now()})
	input.SetUID("test_uid")
	key := "projectcalico.org/tiers/foo"

	out := &v3.Tier{}
	err := store.GuaranteedUpdate(ctx, key, out, true, nil,
		func(_ runtime.Object, _ storage.ResponseMeta) (runtime.Object, *uint64, error) {
			ttl := uint64(1)
			return input, &ttl, nil
		}, nil)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	opts := storage.ListOptions{ResourceVersion: out.ResourceVersion, Predicate: storage.Everything}
	w, err := store.Watch(ctx, key, opts)
	if err != nil {
		t.Fatalf("Watch failed: %v", err)
	}
	testCheckEventType(t, watch.Deleted, w)
}

func TestTierGuaranteedUpdateWithConflict(t *testing.T) {
	ctx, store := testTierSetup(t)
	defer testTierCleanup(t, ctx, store)
	key, _ := testTierPropogateStore(ctx, t, store, makeTierWithDefaults())

	errChan := make(chan error, 1)
	var firstToFinish sync.WaitGroup
	var secondToEnter sync.WaitGroup
	firstToFinish.Add(1)
	secondToEnter.Add(1)

	go func() {
		err := store.GuaranteedUpdate(ctx, key, &v3.Tier{}, false, nil,
			storage.SimpleUpdate(func(obj runtime.Object) (runtime.Object, error) {
				tier := obj.(*v3.Tier)
				tier.GenerateName = "foo-1"
				secondToEnter.Wait()
				return tier, nil
			}), nil)
		firstToFinish.Done()
		errChan <- err
	}()

	updateCount := 0
	err := store.GuaranteedUpdate(ctx, key, &v3.Tier{}, false, nil,
		storage.SimpleUpdate(func(obj runtime.Object) (runtime.Object, error) {
			if updateCount == 0 {
				secondToEnter.Done()
				firstToFinish.Wait()
			}
			updateCount++
			tier := obj.(*v3.Tier)
			tier.GenerateName = "foo-2"
			return tier, nil
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

func TestTierList(t *testing.T) {
	ctx, store := testTierSetup(t)
	defer func() {
		_, _ = store.client.Tiers().Delete(ctx, "foo", options.DeleteOptions{})
		_, _ = store.client.Tiers().Delete(ctx, "bar", options.DeleteOptions{})
	}()

	preset := []struct {
		key       string
		obj       *v3.Tier
		storedObj *v3.Tier
	}{{
		key: "projectcalico.org/tiers/foo",
		obj: makeTierWithDefaults(),
	}, {
		key: "projectcalico.org/tiers/bar",
		obj: makeTier("bar", "", 20.0),
	}}

	for i, ps := range preset {
		preset[i].storedObj = &v3.Tier{}
		err := store.Create(ctx, ps.key, ps.obj, preset[i].storedObj, 0)
		if err != nil {
			t.Fatalf("Set failed: %v", err)
		}
	}

	opts := storage.GetOptions{IgnoreNotFound: false}

	tierPath := func(name string) string {
		return fmt.Sprintf("projectcalico.org/tiers/%s", name)
	}

	kubeAdminTier := makeTier(names.KubeAdminTierName, "", v3.KubeAdminTierOrder)
	err := store.Get(ctx, tierPath(names.KubeAdminTierName), opts, kubeAdminTier)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	defaultTier := makeTier(names.DefaultTierName, "", v3.DefaultTierOrder)
	err = store.Get(ctx, tierPath(names.DefaultTierName), opts, defaultTier)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	kubeBaselineTier := makeTier(names.KubeBaselineTierName, "", v3.KubeBaselineTierOrder)
	err = store.Get(ctx, tierPath(names.KubeBaselineTierName), opts, kubeBaselineTier)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	tests := []struct {
		prefix      string
		pred        storage.SelectionPredicate
		expectedOut []*v3.Tier
	}{{ // test List at cluster scope
		prefix:      "projectcalico.org/tiers/foo",
		pred:        storage.Everything,
		expectedOut: []*v3.Tier{preset[0].storedObj},
	}, { // test List with tier name matching
		prefix: "projectcalico.org/tiers/",
		pred: storage.SelectionPredicate{
			Label: labels.Everything(),
			Field: fields.ParseSelectorOrDie("metadata.name!=" + preset[0].storedObj.Name),
			GetAttrs: func(obj runtime.Object) (labels.Set, fields.Set, error) {
				tier := obj.(*v3.Tier)
				return nil, fields.Set{"metadata.name": tier.Name}, nil
			},
		},
		// Tiers are returned in name order.
		expectedOut: []*v3.Tier{preset[1].storedObj, defaultTier, kubeAdminTier, kubeBaselineTier},
	}}

	for i, tt := range tests {
		out := &v3.TierList{}
		opts := storage.ListOptions{ResourceVersion: "0", Predicate: tt.pred}
		err := store.List(ctx, tt.prefix, opts, out)
		if err != nil {
			t.Fatalf("List failed: %v", err)
		}
		if len(tt.expectedOut) != len(out.Items) {
			t.Errorf("#%d: length of list want=%d, get=%d", i, len(tt.expectedOut), len(out.Items))
			continue
		}
		var wantNames, gotNames []string
		for _, wantTier := range tt.expectedOut {
			wantNames = append(wantNames, wantTier.Name)
		}
		for _, getTier := range out.Items {
			gotNames = append(gotNames, getTier.Name)
		}
		if !reflect.DeepEqual(wantNames, gotNames) {
			t.Errorf("#%d: tier names want=%v, get=%v", i, wantNames, gotNames)
		}

		for j, wantTier := range tt.expectedOut {
			getTier := &out.Items[j]
			if !reflect.DeepEqual(wantTier, getTier) {
				t.Errorf("#%d: tier want=%#v, get=%#v", i, wantTier, getTier)
			}
		}
	}
}

func testTierSetup(t *testing.T) (context.Context, *resourceStore) {
	codec := apitesting.TestCodec(codecs, v3.SchemeGroupVersion)
	cfg, err := apiconfig.LoadClientConfig("")
	if err != nil {
		logrus.Errorf("Failed to load client config: %q", err)
		os.Exit(1)
	}
	cfg.Spec.DatastoreType = "etcdv3"
	cfg.Spec.EtcdEndpoints = "http://localhost:2379"
	c, err := clientv3.New(*cfg)
	if err != nil {
		logrus.Errorf("Failed creating client: %q", err)
		os.Exit(1)
	}
	logrus.Tracef("Client: %v", c)

	opts := Options{
		RESTOptions: generic.RESTOptions{
			StorageConfig: &storagebackend.ConfigForResource{
				GroupResource: schema.GroupResource{
					Group:    "projectcalico.org/v3",
					Resource: "tiers",
				},
				Config: storagebackend.Config{
					Codec: codec,
				},
			},
		},
	}
	store, _ := NewTierStorage(opts)
	ctx := context.Background()

	return ctx, store.Storage.(*resourceStore)
}

func testTierCleanup(t *testing.T, ctx context.Context, store *resourceStore) {
	tr, _ := store.client.Tiers().Get(ctx, "default", options.GetOptions{})
	if tr != nil {
		_, _ = store.client.Tiers().Delete(ctx, "foo", options.DeleteOptions{})
	}
}

// testTierPropogateStore helps propogates store with objects, automates key generation, and returns
// keys and stored objects.
func testTierPropogateStore(ctx context.Context, t *testing.T, store *resourceStore, obj *v3.Tier) (string, *v3.Tier) {
	// Setup store with a key and grab the output for returning.
	key := "projectcalico.org/tiers/foo"
	setOutput := &v3.Tier{}
	err := store.Create(ctx, key, obj, setOutput, 0)
	if err != nil {
		t.Fatalf("Set failed: %v", err)
	}
	return key, setOutput
}

func makeTierWithDefaults() *v3.Tier {
	return makeTier("foo", "", 10.0)
}

func makeTier(name, uid string, order float64) *v3.Tier {
	meta := metav1.ObjectMeta{Name: name}
	if uid != "" {
		meta = metav1.ObjectMeta{Name: name, UID: types.UID(uid)}
	}
	return &v3.Tier{
		ObjectMeta: meta,
		Spec: v3.TierSpec{
			Order: &order,
		},
	}
}
