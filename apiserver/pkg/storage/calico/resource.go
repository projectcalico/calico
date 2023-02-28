// Copyright (c) 2017-2019 Tigera, Inc. All rights reserved.

package calico

import (
	"bytes"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"time"

	"golang.org/x/net/context"

	aapierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/conversion"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	k8swatch "k8s.io/apimachinery/pkg/watch"
	"k8s.io/apiserver/pkg/storage"
	"k8s.io/klog/v2"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	calicowatch "github.com/projectcalico/calico/libcalico-go/lib/watch"
)

type resourceObject interface {
	runtime.Object
	metav1.ObjectMetaAccessor
}

type resourceListObject interface {
	runtime.Object
	metav1.ListMetaAccessor
}

type resourceConverter interface {
	convertToLibcalico(runtime.Object) resourceObject
	convertToAAPI(resourceObject, runtime.Object)
	convertToAAPIList(resourceListObject, runtime.Object, storage.SelectionPredicate)
}
type clientOpts interface{}

type (
	clientObjectOperator func(context.Context, clientv3.Interface, resourceObject, clientOpts) (resourceObject, error)
	clientNameOperator   func(context.Context, clientv3.Interface, string, string, clientOpts) (resourceObject, error)
	clientLister         func(context.Context, clientv3.Interface, clientOpts) (resourceListObject, error)
	clientWatcher        func(context.Context, clientv3.Interface, clientOpts) (calicowatch.Interface, error)
)

type resourceStore struct {
	client            clientv3.Interface
	codec             runtime.Codec
	versioner         storage.Versioner
	aapiType          reflect.Type
	aapiListType      reflect.Type
	libCalicoType     reflect.Type
	libCalicoListType reflect.Type
	isNamespaced      bool
	create            clientObjectOperator
	update            clientObjectOperator
	get               clientNameOperator
	delete            clientNameOperator
	list              clientLister
	watch             clientWatcher
	resourceName      string
	converter         resourceConverter
}

func CreateClientFromConfig() clientv3.Interface {
	// TODO(doublek): nicer errors returned
	cfg, err := apiconfig.LoadClientConfig("")
	if err != nil {
		klog.Errorf("Failed to load client config: %q", err)
		os.Exit(1)
	}

	c, err := clientv3.New(*cfg)
	if err != nil {
		klog.Errorf("Failed creating client: %q", err)
		os.Exit(1)
	}

	err = c.EnsureInitialized(context.Background(), "", "")
	if err != nil {
		klog.Errorf("Failed initializing client: %q", err)
		os.Exit(1)
	}

	return c
}

// Versioned returns the versioned associated with this interface
func (rs *resourceStore) Versioner() storage.Versioner {
	return rs.versioner
}

func validationError(err error, qualifiedKind schema.GroupKind, name string) *aapierrors.StatusError {
	errs := field.ErrorList{}
	calErrors := err.(errors.ErrorValidation)
	for _, calErr := range calErrors.ErroredFields {
		err := &field.Error{
			Type:     field.ErrorTypeInvalid,
			Field:    calErr.Name,
			Detail:   calErr.Reason,
			BadValue: calErr.Value,
		}
		errs = append(errs, err)
	}
	return aapierrors.NewInvalid(qualifiedKind, name, errs)
}

// Create adds a new object at a key unless it already exists. 'ttl' is time-to-live
// in seconds (0 means forever). If no error is returned and out is not nil, out will be
// set to the read value from database.
func (rs *resourceStore) Create(ctx context.Context, key string, obj, out runtime.Object, ttl uint64) error {
	klog.Infof("Create called with key: %v for resource %v\n", key, rs.resourceName)
	lcObj := rs.converter.convertToLibcalico(obj)

	opts := options.SetOptions{TTL: time.Duration(ttl) * time.Second}
	createdObj, err := rs.create(ctx, rs.client, lcObj, opts)
	if err != nil {
		klog.Errorf("Error creating resource %v key %v error %v\n", rs.resourceName, key, err)
		switch err.(type) {
		case errors.ErrorValidation:
			rObj := obj.(resourceObject)
			return validationError(err, rObj.GetObjectKind().GroupVersionKind().GroupKind(), rObj.GetObjectMeta().GetName())
		default:
			return aapiError(err, key)
		}
	}
	rs.converter.convertToAAPI(createdObj, out)
	return nil
}

// Delete removes the specified key and returns the value that existed at that spot.
// If key didn't exist, it will return NotFound storage error.
func (rs *resourceStore) Delete(ctx context.Context, key string, out runtime.Object,
	preconditions *storage.Preconditions, validateDeletion storage.ValidateObjectFunc,
	cachedExistingObject runtime.Object) error {
	klog.Infof("Delete called with key: %v for resource %v\n", key, rs.resourceName)

	ns, name, err := NamespaceAndNameFromKey(key, rs.isNamespaced)
	if err != nil {
		return err
	}
	delOpts := options.DeleteOptions{}
	if preconditions != nil {
		// Get the object to check for validity of UID
		opts := options.GetOptions{}
		// TODO use the cachedExisting object if it exists to check the preconditions. When this is done, we'll
		// need to add the resource version of the cached object and retry if the delete failed because the
		// the resource version was out of sync (first getting a new object from the k8s API).
		libcalicoObj, err := rs.get(ctx, rs.client, ns, name, opts)
		if err != nil {
			return aapiError(err, key)
		}
		aapiObj := reflect.New(rs.aapiType).Interface().(runtime.Object)
		rs.converter.convertToAAPI(libcalicoObj, aapiObj)
		if err := checkPreconditions(key, preconditions, aapiObj); err != nil {
			return err
		}
		// Set the Resource Version for Deletion
		delOpts.ResourceVersion = aapiObj.(resourceObject).GetObjectMeta().GetResourceVersion()
	}

	libcalicoObj, err := rs.delete(ctx, rs.client, ns, name, delOpts)
	if err != nil {
		klog.Errorf("Clientv3 error deleting resource %v with key %v error %v\n", rs.resourceName, key, err)
		return aapiError(err, key)
	}

	rs.converter.convertToAAPI(libcalicoObj, out)
	return nil
}

func checkPreconditions(key string, preconditions *storage.Preconditions, out runtime.Object) error {
	if preconditions == nil {
		return nil
	}
	objMeta, err := meta.Accessor(out)
	if err != nil {
		return storage.NewInternalErrorf("can't enforce preconditions %v on un-introspectable object %v, got error: %v", *preconditions, out, err)
	}
	if preconditions.UID != nil && *preconditions.UID != objMeta.GetUID() {
		errMsg := fmt.Sprintf("Precondition failed: UID in precondition: %v, UID in object meta: %v", *preconditions.UID, objMeta.GetUID())
		return storage.NewInvalidObjError(key, errMsg)
	}
	return nil
}

// Watch begins watching the specified key. Events are decoded into API objects,
// and any items selected by 'p' are sent down to returned k8swatch.Interface.
// resourceVersion may be used to specify what version to begin watching,
// which should be the current resourceVersion, and no longer rv+1
// (e.g. reconnecting without missing any updates).
// If resource version is "0", this interface will get current object at given key
// and send it in an "ADDED" event, before watch starts.
func (rs *resourceStore) Watch(ctx context.Context, key string, opts storage.ListOptions) (k8swatch.Interface, error) {
	klog.Infof("Watch called with key: %v on resource %v\n", key, rs.resourceName)
	ns, name, err := NamespaceAndNameFromKey(key, rs.isNamespaced)
	if err != nil {
		return nil, err
	}
	return rs.watchResource(ctx, opts.ResourceVersion, opts.Predicate, name, ns)
}

// WatchList begins watching the specified key's items. Items are decoded into API
// objects and any item selected by 'p' are sent down to returned k8swatch.Interface.
// resourceVersion may be used to specify what version to begin watching,
// which should be the current resourceVersion, and no longer rv+1
// (e.g. reconnecting without missing any updates).
// If resource version is "0", this interface will list current objects directory defined by key
// and send them in "ADDED" events, before watch starts.
func (rs *resourceStore) WatchList(ctx context.Context, key string, opts storage.ListOptions) (k8swatch.Interface, error) {
	klog.Infof("WatchList called with key: %v on resource %v\n", key, rs.resourceName)
	ns, name, err := NamespaceAndNameFromKey(key, rs.isNamespaced)
	if err != nil {
		return nil, err
	}
	return rs.watchResource(ctx, opts.ResourceVersion, opts.Predicate, name, ns)
}

// Get unmarshals json found at key into objPtr. On a not found error, will either
// return a zero object of the requested type, or an error, depending on ignoreNotFound.
// Treats empty responses and nil response nodes exactly like a not found error.
// The returned contents may be delayed, but it is guaranteed that they will
// be have at least 'resourceVersion'.
func (rs *resourceStore) Get(ctx context.Context, key string, optsK8s storage.GetOptions,
	out runtime.Object) error {
	klog.Infof("Get called with key: %v on resource %v\n", key, rs.resourceName)
	ns, name, err := NamespaceAndNameFromKey(key, rs.isNamespaced)
	if err != nil {
		return err
	}
	opts := options.GetOptions{ResourceVersion: optsK8s.ResourceVersion}
	libcalicoObj, err := rs.get(ctx, rs.client, ns, name, opts)
	if err != nil {
		e := aapiError(err, key)
		if storage.IsNotFound(e) && optsK8s.IgnoreNotFound {
			return runtime.SetZeroValue(out)
		}
		return e
	}
	rs.converter.convertToAAPI(libcalicoObj, out)
	return nil
}

// GetList unmarshalls objects found at key into a *List api object (an object
// that satisfies runtime.IsList definition).
// If 'opts.Recursive' is false, 'key' is used as an exact match. If `opts.Recursive'
// is true, 'key' is used as a prefix.
// The returned contents may be delayed, but it is guaranteed that they will
// match 'opts.ResourceVersion' according 'opts.ResourceVersionMatch'.
func (rs *resourceStore) GetList(ctx context.Context, key string, opts storage.ListOptions, listObj runtime.Object) error {
	klog.Infof("GetList called with key: %v on resource %v\n", key, rs.resourceName)
	return rs.List(ctx, key, opts, listObj)
}

// List unmarshalls jsons found at directory defined by key and opaque them
// into *List api object (an object that satisfies runtime.IsList definition).
// The returned contents may be delayed, but it is guaranteed that they will
// be have at least 'resourceVersion'.
func (rs *resourceStore) List(ctx context.Context, key string, optsK8s storage.ListOptions, listObj runtime.Object) error {
	klog.Infof("List called with key: %v on resource %v\n", key, rs.resourceName)
	ns, name, err := NamespaceAndNameFromKey(key, rs.isNamespaced)
	if err != nil {
		return err
	}
	opts := options.ListOptions{Namespace: ns, Name: name, ResourceVersion: optsK8s.ResourceVersion}
	libcalicoObjList, err := rs.list(ctx, rs.client, opts)
	if err != nil {
		e := aapiError(err, key)
		if storage.IsNotFound(e) {
			rs.converter.convertToAAPIList(libcalicoObjList, listObj, optsK8s.Predicate)
			return nil
		}
		return e
	}
	rs.converter.convertToAAPIList(libcalicoObjList, listObj, optsK8s.Predicate)
	return nil
}

type objState struct {
	obj  runtime.Object
	meta *storage.ResponseMeta
	rev  int64
	data []byte
}

func (rs *resourceStore) getStateFromObject(obj runtime.Object) (*objState, error) {
	state := &objState{
		obj:  obj,
		meta: &storage.ResponseMeta{},
	}

	rv, err := rs.versioner.ObjectResourceVersion(obj)
	if err != nil {
		return nil, fmt.Errorf("couldn't get resource version: %v", err)
	}
	state.rev = int64(rv)
	state.meta.ResourceVersion = uint64(state.rev)

	state.data, err = runtime.Encode(rs.codec, obj)
	if err != nil {
		return nil, err
	}

	return state, nil
}

func decode(
	codec runtime.Codec,
	value []byte,
	objPtr runtime.Object,
) error {
	if _, err := conversion.EnforcePtr(objPtr); err != nil {
		panic("unable to convert output object to pointer")
	}
	_, _, err := codec.Decode(value, nil, objPtr)
	if err != nil {
		return err
	}
	return nil
}

// GuaranteedUpdate keers calling 'tryUpdate()' to update key 'key' (of type 'ptrToType')
// retrying the update until success if there is index conflict.
// Note that object passed to tryUpdate may change across invocations of tryUpdate() if
// other writers are simultaneously updating it, so tryUpdate() needs to take into account
// the current contents of the object when deciding how the update object should look.
// If the key doesn't exist, it will return NotFound storage error if ignoreNotFound=false
// or zero value in 'ptrToType' parameter otherwise.
// If the object to update has the same value as previous, it won't do any update
// but will return the object in 'ptrToType' parameter.
// If 'suggestion' can contain zero or one element - in such case this can be used as
// a suggestion about the current version of the object to avoid read operation from
// storage to get it.
//
// Example:
//
// s := /* implementation of Interface */
// err := s.GuaranteedUpdate(
//
//	    "myKey", &MyType{}, true,
//	    func(input runtime.Object, res ResponseMeta) (runtime.Object, *uint64, error) {
//	      // Before each incovation of the user defined function, "input" is reset to
//	      // current contents for "myKey" in database.
//	      curr := input.(*MyType)  // Guaranteed to succeed.
//
//	      // Make the modification
//	      curr.Counter++
//
//	      // Return the modified object - return an error to stop iterating. Return
//	      // a uint64 to alter the TTL on the object, or nil to keep it the same value.
//	      return cur, nil, nil
//	   }
//	})
func (rs *resourceStore) GuaranteedUpdate(
	ctx context.Context, key string, out runtime.Object, ignoreNotFound bool,
	preconditions *storage.Preconditions, userUpdate storage.UpdateFunc, cachedExistingObject runtime.Object) error {
	klog.V(6).Infof("GuaranteedUpdate called with key: %v on resource %v\n", key, rs.resourceName)
	// If a cachedExistingObject was passed, use that as the initial object, otherwise use Get() to retrieve it
	var initObj runtime.Object
	if cachedExistingObject != nil {
		initObj = cachedExistingObject
	} else {
		initObj = reflect.New(rs.aapiType).Interface().(runtime.Object)
		opts := storage.GetOptions{IgnoreNotFound: ignoreNotFound}
		if err := rs.Get(ctx, key, opts, initObj); err != nil {
			klog.Errorf("getting initial object (%s)", err)
			return aapiError(err, key)
		}
	}
	// In either case, extract current state from the initial object
	curState, err := rs.getStateFromObject(initObj)
	if err != nil {
		klog.Errorf("getting state from initial object (%s)", err)
		return err
	}

	shouldCreateOnUpdate := func() bool {
		// return true if initObj has zero revision (object not found) and ignoreNotFound is true.
		return (curState.rev == 0) && ignoreNotFound
	}

	// Loop until update succeeds or we get an error
	// Check count to avoid an infinite loop in case of any issues
	totalLoopCount := 0
	for totalLoopCount < 5 {
		totalLoopCount++

		if err := checkPreconditions(key, preconditions, curState.obj); err != nil {
			klog.Errorf("checking preconditions (%s)", err)
			return err
		}
		// update the object by applying the userUpdate func & encode it
		updatedObj, ttl, err := userUpdate(curState.obj, *curState.meta)
		if err != nil {
			klog.Errorf("applying user update: (%s)", err)
			return err
		}

		updatedData, err := runtime.Encode(rs.codec, updatedObj)
		if err != nil {
			klog.Errorf("encoding candidate obj (%s)", err)
			return err
		}

		// figure out what the new "current state" of the object is for this loop iteration
		if bytes.Equal(updatedData, curState.data) {
			// If the candidate matches what we already have, then all we need to do is
			// decode into the out object
			return decode(rs.codec, updatedData, out)
		}

		// Apply Update
		// Check for Revision no. If not set or less than the current version then set it
		// to latest
		accessor, err := meta.Accessor(updatedObj)
		if err != nil {
			return err
		}
		revInt, _ := strconv.Atoi(accessor.GetResourceVersion())
		updatedRes := updatedObj.(resourceObject)
		if !shouldCreateOnUpdate() {
			if updatedRes.GetObjectMeta().GetResourceVersion() == "" || revInt < int(curState.rev) {
				updatedRes.(resourceObject).GetObjectMeta().SetResourceVersion(strconv.FormatInt(curState.rev, 10))
			}
		}
		libcalicoObj := rs.converter.convertToLibcalico(updatedRes)

		var opts options.SetOptions
		if ttl != nil {
			opts = options.SetOptions{TTL: time.Duration(*ttl) * time.Second}
		}
		if shouldCreateOnUpdate() {
			klog.V(6).Infof("Create on Update with key: %v on resource %v\n", key, rs.resourceName)
			createdLibcalicoObj, err := rs.create(ctx, rs.client, libcalicoObj, opts)
			if err != nil {
				klog.Errorf("creating new object (%s) on PATCH", err)
				return err
			}
			rs.converter.convertToAAPI(createdLibcalicoObj, out)
			return nil
		}

		createdLibcalicoObj, err := rs.update(ctx, rs.client, libcalicoObj, opts)
		if err != nil {
			switch err.(type) {
			case errors.ErrorValidation:
				return validationError(err, updatedRes.GetObjectKind().GroupVersionKind().GroupKind(), updatedRes.GetObjectMeta().GetName())
			default:
				e := aapiError(err, key)
				if storage.IsConflict(e) {
					klog.V(4).Infof(
						"GuaranteedUpdate of %s failed because of a conflict, going to retry",
						key,
					)
					newCurObj := reflect.New(rs.aapiType).Interface().(runtime.Object)
					opts := storage.GetOptions{IgnoreNotFound: ignoreNotFound}
					if err := rs.Get(ctx, key, opts, newCurObj); err != nil {
						klog.Errorf("getting new current object (%s)", err)
						return aapiError(err, key)
					}
					ncs, err := rs.getStateFromObject(newCurObj)
					if err != nil {
						klog.Errorf("getting state from new current object (%s)", err)
						return err
					}
					curState = ncs
					continue
				}
				return e
			}
		}
		rs.converter.convertToAAPI(createdLibcalicoObj, out)
		return nil
	}
	klog.Errorf("GuaranteedUpdate failed.")
	return nil
}

// Count returns number of different entries under the key (generally being path prefix).
func (rs *resourceStore) Count(key string) (int64, error) {
	return 0, fmt.Errorf("Count not supported for key: %s", key)
}
