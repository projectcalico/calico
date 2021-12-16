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

package resources

import (
	"context"
	"reflect"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/errors"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// Interface required to satisfy use as a Kubernetes Custom Resource type.
type CustomK8sResource interface {
	runtime.Object
	metav1.ObjectMetaAccessor
}

// Interface required to satisfy use as a Kubernetes Custom Resource List type.
type CustomK8sList interface {
	runtime.Object
	metav1.ListMetaAccessor
}

// CustomK8sResourceConverter defines an interface to map between KVPair representation
// and a custom Kubernetes resource.
type CustomK8sResourceConverter interface {
	// ListInterfaceToKey converts a ListInterface to a Key if the
	// ListInterface specifies a specific instance, otherwise returns nil.
	ListInterfaceToKey(model.ListInterface) model.Key

	// Convert the Key to the Resource name.
	KeyToName(model.Key) (string, error)

	// Convert the Resource name to the Key.
	NameToKey(string) (model.Key, error)

	// Convert the Resource to a KVPair.
	ToKVPair(CustomK8sResource) (*model.KVPair, error)

	// Convert a KVPair to a Resource.
	FromKVPair(*model.KVPair) (CustomK8sResource, error)
}

// customK8sResourceClient implements the K8sResourceClient interface and provides a generic
// mechanism for a 1:1 mapping between a Calico Resource and an equivalent Kubernetes
// custom resource type.
type customK8sResourceClient struct {
	clientSet       *kubernetes.Clientset
	restClient      *rest.RESTClient
	name            string
	resource        string
	description     string
	k8sResourceType reflect.Type
	k8sListType     reflect.Type
	converter       CustomK8sResourceConverter
}

// Get gets an existing Custom K8s Resource instance in the k8s API using the supplied Key.
func (c *customK8sResourceClient) Get(key model.Key) (*model.KVPair, error) {
	logContext := log.WithFields(log.Fields{
		"Key":      key,
		"Resource": c.resource,
	})
	logContext.Debug("Get custom Kubernetes resource")
	name, err := c.converter.KeyToName(key)
	if err != nil {
		logContext.WithError(err).Info("Error getting resource")
		return nil, err
	}

	// Add the name to the log context now that we know it, and query
	// Kubernetes.
	logContext = logContext.WithField("Name", name)
	logContext.Debug("Get custom Kubernetes resource by name")
	resOut := reflect.New(c.k8sResourceType).Interface().(CustomK8sResource)
	err = c.restClient.Get().
		Resource(c.resource).
		Name(name).
		Do(context.Background()).Into(resOut)
	if err != nil {
		logContext.WithError(err).Info("Error getting resource")
		return nil, K8sErrorToCalico(err, key)
	}

	return c.converter.ToKVPair(resOut)
}

// List lists configured Custom K8s Resource instances in the k8s API matching the
// supplied ListInterface.
func (c *customK8sResourceClient) List(list model.ListInterface) ([]*model.KVPair, string, error) {
	logContext := log.WithFields(log.Fields{
		"ListInterface": list,
		"Resource":      c.resource,
	})
	logContext.Debug("List Custom K8s Resource")
	kvps := []*model.KVPair{}

	// Attempt to convert the ListInterface to a Key.  If possible, the parameters
	// indicate a fully qualified resource, and we'll need to use Get instead of
	// List.
	if key := c.converter.ListInterfaceToKey(list); key != nil {
		logContext.Debug("Performing List using Get")
		if kvp, err := c.Get(key); err != nil {
			// The error will already be a Calico error type.  Ignore
			// error that it doesn't exist - we'll return an empty
			// list.
			if _, ok := err.(errors.ErrorResourceDoesNotExist); !ok {
				log.WithField("Resource", c.resource).WithError(err).Info("Error listing resource")
				return nil, "", err
			}
			return kvps, "", nil
		} else {
			kvps = append(kvps, kvp)
			return kvps, kvp.Revision, nil
		}
	}

	// Since we are not performing an exact Get, Kubernetes will return a
	// list of resources.
	reslOut := reflect.New(c.k8sListType).Interface().(CustomK8sList)

	// Perform the request.
	err := c.restClient.Get().
		Resource(c.resource).
		Do(context.Background()).Into(reslOut)
	if err != nil {
		// Don't return errors for "not found".  This just
		// means there are no matching Custom K8s Resources, and we should return
		// an empty list.
		if !kerrors.IsNotFound(err) {
			log.WithError(err).Info("Error listing resources")
			return nil, "", K8sErrorToCalico(err, list)
		}
		return kvps, reslOut.GetListMeta().GetResourceVersion(), nil
	}

	// We expect the list type to have an "Items" field that we can
	// iterate over.
	elem := reflect.ValueOf(reslOut).Elem()
	items := reflect.ValueOf(elem.FieldByName("Items").Interface())
	for idx := 0; idx < items.Len(); idx++ {
		res := items.Index(idx).Addr().Interface().(CustomK8sResource)

		if kvp, err := c.converter.ToKVPair(res); err == nil {
			kvps = append(kvps, kvp)
		} else {
			logContext.WithError(err).WithField("Item", res).Warning("unable to process resource, skipping")
		}
	}
	return kvps, reslOut.GetListMeta().GetResourceVersion(), nil
}
