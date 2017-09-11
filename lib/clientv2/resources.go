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

package clientv2

import (
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/libcalico-go/lib/apiv2"
	bapi "github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	cerrors "github.com/projectcalico/libcalico-go/lib/errors"
	"github.com/projectcalico/libcalico-go/lib/namespace"
	"github.com/projectcalico/libcalico-go/lib/options"
)

const (
	AllNames      = ""
	AllNamespaces = ""
	NoNamespace   = ""
)

// All Calico resources implement the resource interface.
type resource interface {
	runtime.Object
	v1.ObjectMetaAccessor
}

// All Calico resource lists implement the resourceList interface.
type resourceList interface {
	runtime.Object
	v1.ListMetaAccessor
}

// resourceInterface has methods to work with generic resource types.
type resourceInterface interface {
	Create(opts options.SetOptions, kind, ns string, in resource) (resource, error)
	Update(opts options.SetOptions, kind, ns string, in resource) (resource, error)
	Delete(opts options.DeleteOptions, kind, ns, name string) error
	Get(opts options.GetOptions, kind, ns, name string) (resource, error)
	List(opts options.ListOptions, kind, listkind, ns, name string, inout resourceList) error
	Watch(opts options.ListOptions, kind, ns, name string) (watch.Interface, error)
}

// resources implements resourceInterface.
type resources struct {
	backend bapi.Client
}

// Create creates a resource in the backend datastore.
func (c *resources) Create(opts options.SetOptions, kind, ns string, in resource) (resource, error) {
	// A ResourceVersion should never be specified on a Create.
	if len(in.GetObjectMeta().GetResourceVersion()) != 0 {
		logWithResource(in).Info("Rejecting Create request with non-empty resource version")
		return nil, cerrors.ErrorValidation{
			ErroredFields: []cerrors.ErroredField{{
				Name:   "Metadata.ResourceVersion",
				Reason: "field must not be set for a Create request",
				Value:  in.GetObjectMeta().GetResourceVersion(),
			}},
		}
	}

	// Handle namespace field processing common to Create and Update.
	if err := c.handleNamespace(ns, kind, in); err != nil {
		return nil, err
	}

	// Convert the resource to a KVPair and pass that to the backend datastore, converting
	// the response (if we get one) back to a resource.
	kvp, err := c.backend.Create(c.resourceToKVPair(opts, kind, in))
	if kvp != nil {
		return c.kvPairToResource(kvp), err
	}
	return nil, err
}

// Update updates a resource in the backend datastore.
func (c *resources) Update(opts options.SetOptions, kind, ns string, in resource) (resource, error) {
	// A ResourceVersion should always be specified on an Update.
	if len(in.GetObjectMeta().GetResourceVersion()) == 0 {
		logWithResource(in).Info("Rejecting Update request with empty resource version")
		return nil, cerrors.ErrorValidation{
			ErroredFields: []cerrors.ErroredField{{
				Name:   "Metadata.ResourceVersion",
				Reason: "field must be set for an Update request",
				Value:  in.GetObjectMeta().GetResourceVersion(),
			}},
		}
	}

	// Handle namespace field processing common to Create and Update.
	if err := c.handleNamespace(ns, kind, in); err != nil {
		return nil, err
	}

	// Convert the resource to a KVPair and pass that to the backend datastore, converting
	// the response (if we get one) back to a resource.
	kvp, err := c.backend.Update(c.resourceToKVPair(opts, kind, in))
	if kvp != nil {
		return c.kvPairToResource(kvp), err
	}
	return nil, err
}

// Delete deletes a resource from the backend datastore.
func (c *resources) Delete(opts options.DeleteOptions, kind, ns, name string) error {
	// Create a ResourceKey and pass that to the backend datastore.
	key := model.ResourceKey{
		Kind:      kind,
		Name:      name,
		Namespace: ns,
	}
	return c.backend.Delete(key, opts.ResourceVersion)
}

// Get gets a resource from the backend datastore.
func (c *resources) Get(opts options.GetOptions, kind, ns, name string) (resource, error) {
	key := model.ResourceKey{
		Kind:      kind,
		Name:      name,
		Namespace: ns,
	}
	kvp, err := c.backend.Get(key, opts.ResourceVersion)
	if err != nil {
		return nil, err
	}
	out := c.kvPairToResource(kvp)
	return out, nil
}

// List lists a resource from the backend datastore.
func (c *resources) List(opts options.ListOptions, kind, listKind, ns, name string, listObj resourceList) error {
	key := model.ResourceListOptions{
		Kind:      kind,
		Name:      name,
		Namespace: ns,
	}

	// Query the backend.
	kvps, err := c.backend.List(key, opts.ResourceVersion)
	if err != nil {
		return err
	}

	// Convert the slice of KVPairs to a slice of Objects.
	resources := []runtime.Object{}
	for _, kvp := range kvps.KVPairs {
		resources = append(resources, c.kvPairToResource(kvp))
	}
	err = meta.SetList(listObj, resources)
	if err != nil {
		return err
	}

	// Finally, set the resource version and api group version of the list object.
	listObj.GetListMeta().SetResourceVersion(kvps.Revision)
	listObj.GetObjectKind().SetGroupVersionKind(schema.GroupVersionKind{
		Group:   apiv2.Group,
		Version: apiv2.VersionCurrent,
		Kind:    listKind,
	})

	return nil
}

// Watch watches a specific resource or resource type.
func (c *resources) Watch(opts options.ListOptions, kind, ns, name string) (watch.Interface, error) {
	panic("Not implemented")
	return nil, nil
}

// resourceToKVPair converts the resource to a KVPair that can be consumed by the
// backend datastore client.
func (c *resources) resourceToKVPair(opts options.SetOptions, kind string, in resource) *model.KVPair {
	// Prepare the resource to remove non-persisted fields.
	rv := in.GetObjectMeta().GetResourceVersion()
	in.GetObjectMeta().SetResourceVersion("")
	in.GetObjectMeta().SetSelfLink("")

	// Make sure the kind and version are set before storing.
	in.GetObjectKind().SetGroupVersionKind(schema.GroupVersionKind{
		Group:   apiv2.Group,
		Version: apiv2.VersionCurrent,
		Kind:    kind,
	})

	// Create a KVPair using the "generic" resource Key, and the actual object as
	// the value.
	return &model.KVPair{
		TTL:   opts.TTL,
		Value: in,
		Key: model.ResourceKey{
			Kind:      kind,
			Name:      in.GetObjectMeta().GetName(),
			Namespace: in.GetObjectMeta().GetNamespace(),
		},
		Revision: rv,
	}
}

// kvPairToResource converts a KVPair returned by the backend datastore client to a
// resource.
func (c *resources) kvPairToResource(kvp *model.KVPair) resource {
	// Extract the resource from the returned value - the backend will already have
	// decoded it.
	out := kvp.Value.(resource)

	// Remove the SelfLink which Calico does not use, and set the ResourceVersion from the
	// value returned from the backend datastore.
	out.GetObjectMeta().SetSelfLink("")
	out.GetObjectMeta().SetResourceVersion(kvp.Revision)

	return out
}

// handleNamespace fills in the namespace information in the resource (if required),
// and validates the namespace depending on whether or not a namespace should be
// provided based on the resource kind.
func (c *resources) handleNamespace(ns, kind string, in resource) error {
	// If the namespace is not specified in the resource, assign it using the namespace supplied,
	// otherwise validate that they match.
	if in.GetObjectMeta().GetNamespace() == "" {
		in.GetObjectMeta().SetNamespace(ns)
	} else if in.GetObjectMeta().GetNamespace() != ns {
		return cerrors.ErrorValidation{
			ErroredFields: []cerrors.ErroredField{{
				Name:   "Metadata.Namespace",
				Reason: "Namespace does not match client namespace",
				Value:  in.GetObjectMeta().GetNamespace(),
			}},
		}
	}

	// Validate that a namespace is supplied if one is required for the resource kind.
	if namespace.IsNamespaced(kind) {
		if in.GetObjectMeta().GetNamespace() == "" {
			return cerrors.ErrorValidation{
				ErroredFields: []cerrors.ErroredField{{
					Name:   "Metadata.Namespace",
					Reason: "Namespace should be specified",
					Value:  in.GetObjectMeta().GetNamespace(),
				}},
			}
		}
	} else if in.GetObjectMeta().GetNamespace() != "" {
		return cerrors.ErrorValidation{
			ErroredFields: []cerrors.ErroredField{{
				Name:   "Metadata.Namespace",
				Reason: "Namespace should not be specified",
				Value:  in.GetObjectMeta().GetNamespace(),
			}},
		}
	}
	return nil
}

func logWithResource(res resource) *log.Entry {
	return log.WithFields(log.Fields{
		"Kind": res.GetObjectKind().GroupVersionKind(),
		"Name": res.GetObjectMeta().GetName(),
		"Namespace": res.GetObjectMeta().GetNamespace(),
		"ResourceVersion": res.GetObjectMeta().GetResourceVersion(),
	})
}