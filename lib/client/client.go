// Copyright (c) 2016 Tigera, Inc. All rights reserved.

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

package client

import (
	"encoding/json"
	"io/ioutil"
	"reflect"

	"github.com/ghodss/yaml"
	"github.com/golang/glog"
	"github.com/kelseyhightower/envconfig"
	"github.com/tigera/libcalico-go/lib/api"
	"github.com/tigera/libcalico-go/lib/backend"
)

type Client struct {
	backend *backend.Client
}

// Interface used to convert between backand and API representations of our
// objects.
type conversionHelper interface {
	convertAPIToBackend(interface{}) (interface{}, error)
	convertBackendToAPI(interface{}) (interface{}, error)
	convertMetadataToKeyInterface(interface{}) (backend.KeyInterface, error)
	convertMetadataToListInterface(interface{}) (backend.ListInterface, error)
	copyKeyValues([]backend.KeyValue, interface{})
}

// Interface used to read and write a single backend object to the backend client.
// List operations are handled differently.
type backendObjectReaderWriter interface {
	backendCreate(key backend.KeyInterface, obj interface{}) error
	backendUpdate(key backend.KeyInterface, obj interface{}) error
	backendApply(key backend.KeyInterface, obj interface{}) error
	backendGet(key backend.KeyInterface, objp interface{}) (interface{}, error)
	backendListConvert([]backend.KeyValue) [][]backend.KeyValue
	unmarshalIntoNewBackendStruct(kvs []backend.KeyValue, backendObjectp interface{}) (interface{}, error)
}

// Return a new connected Client.
func New(config *api.ClientConfig) (c *Client, err error) {
	cc := Client{}
	cc.backend, err = backend.NewClient(config)
	return &cc, err
}

func (c *Client) Policies() PolicyInterface {
	return newPolicies(c)
}

func (c *Client) Profiles() ProfileInterface {
	return newProfiles(c)
}

func (c *Client) HostEndpoints() HostEndpointInterface {
	return newHostEndpoints(c)
}

// Load the client config from the specified file (if specified) and from environment
// variables.  The values from both locations are merged together, with file values
// taking precedence).
func LoadClientConfig(f *string) (*api.ClientConfig, error) {
	var c api.ClientConfig

	// Load client config from environment variables first.
	if err := envconfig.Process("calico", &c); err != nil {
		return nil, err
	}

	// Override / merge with values loaded from the specified file.
	if f != nil {
		if b, err := ioutil.ReadFile(*f); err != nil {
			return nil, err
		} else if err := yaml.Unmarshal(b, &c); err != nil {
			return nil, err
		}
	}

	return &c, nil
}

// Untyped interface for creating an API object.  This is called from the
// typed interface.  This assumes a 1:1 mapping between the API resource and
// the backend object.
func (c *Client) create(apiObject interface{}, helper conversionHelper, rw backendObjectReaderWriter) error {
	if rw == nil {
		rw = c
	}
	// All API objects have a Metadata, so extract it.
	metadata := reflect.ValueOf(apiObject).FieldByName("Metadata").Interface()
	if k, err := helper.convertMetadataToKeyInterface(metadata); err != nil {
		return err
	} else if b, err := helper.convertAPIToBackend(apiObject); err != nil {
		return err
	} else {
		return rw.backendCreate(k, b)
	}
}

// Untyped interface for updating an API object.  This is called from the
// typed interface.
func (c *Client) update(apiObject interface{}, helper conversionHelper, rw backendObjectReaderWriter) error {
	if rw == nil {
		rw = c
	}
	// All API objects have a Metadata, so extract it.
	metadata := reflect.ValueOf(apiObject).FieldByName("Metadata").Interface()
	if k, err := helper.convertMetadataToKeyInterface(metadata); err != nil {
		return err
	} else if b, err := helper.convertAPIToBackend(apiObject); err != nil {
		return err
	} else {
		err = rw.backendUpdate(k, b)
		return err
	}
}

// Untyped interface for applying an API object.  This is called from the
// typed interface.
func (c *Client) apply(apiObject interface{}, helper conversionHelper, rw backendObjectReaderWriter) error {
	if rw == nil {
		rw = c
	}
	// All API objects have a Metadata, so extract it.
	metadata := reflect.ValueOf(apiObject).FieldByName("Metadata").Interface()
	if k, err := helper.convertMetadataToKeyInterface(metadata); err != nil {
		return err
	} else if b, err := helper.convertAPIToBackend(apiObject); err != nil {
		return err
	} else {
		err = rw.backendApply(k, b)
		return err
	}
}

// Untyped get interface for getting a single API object.  This is called from the typed
// interface.  The result is
func (c *Client) get(backendObject interface{}, metadata interface{}, helper conversionHelper, rw backendObjectReaderWriter) (interface{}, error) {
	if rw == nil {
		rw = c
	}
	if k, err := helper.convertMetadataToKeyInterface(metadata); err != nil {
		return nil, err
	} else if pb, err := rw.backendGet(k, backendObject); err != nil {
		return nil, err
	} else if a, err := helper.convertBackendToAPI(pb); err != nil {
		return nil, err
	} else {
		return a, nil
	}
}

// Untyped get interface for deleting a single API object.  This is called from the typed
// interface.
func (c *Client) delete(metadata interface{}, helper conversionHelper) error {
	if k, err := helper.convertMetadataToKeyInterface(metadata); err != nil {
		return err
	} else if err := c.backend.Delete(k); err != nil {
		return err
	} else {
		return nil
	}
}

// Untyped get interface for getting a list of API objects.  This is called from the typed
// interface.
// Returns a list of pointers to backend objects.
func (c *Client) list(backendObject interface{}, metadata interface{}, helper conversionHelper, rw backendObjectReaderWriter) ([]interface{}, error) {
	if rw == nil {
		rw = c
	}
	if l, err := helper.convertMetadataToListInterface(metadata); err != nil {
		return nil, err
	} else if kvs, err := c.backend.List(l); err != nil {
		return nil, err
	} else {
		kpr := rw.backendListConvert(kvs)
		as := make([]interface{}, 0, len(kpr))
		for _, kvs := range kpr {
			if b, err := rw.unmarshalIntoNewBackendStruct(kvs, backendObject); err != nil {
				return nil, err
			} else {
				helper.copyKeyValues(kvs, b)
				if a, err := helper.convertBackendToAPI(b); err != nil {
					return nil, err
				} else {
					as = append(as, a)
				}
			}
		}

		return as, nil
	}
}

// Unmarshall a list of backend data values into a new instance of the supplied backend type.
// Returns an interface containing the a pointer to the new instance.
func (c *Client) unmarshalIntoNewBackendStruct(kvs []backend.KeyValue, backendObjectp interface{}) (interface{}, error) {
	new := reflect.New(reflect.TypeOf(backendObjectp)).Interface()
	for _, kv := range kvs {
		if err := json.Unmarshal(kv.Value, new); err != nil {
			return nil, err
		}
	}
	return new, nil
}

// Convert the supplied object into a value string and create the object in the
// backend client.
func (c *Client) backendCreate(k backend.KeyInterface, obj interface{}) error {
	if obj == nil {
		glog.V(2).Info("Skipping empty data")
		return nil
	}
	if v, err := json.Marshal(obj); err != nil {
		return err
	} else {
		return c.backend.Create(backend.KeyValue{Key: k, Value: v})
	}
}

// Convert the supplied object into a value string and update the object in the
// backend client.
func (c *Client) backendUpdate(k backend.KeyInterface, obj interface{}) error {
	if obj == nil {
		glog.V(2).Info("Skipping empty data")
		return nil
	}
	if v, err := json.Marshal(obj); err != nil {
		return err
	} else {
		return c.backend.Update(backend.KeyValue{Key: k, Value: v})
	}
}

// Convert the supplied object into a value string and apply (create or update) the
// object in the backend client.
func (c *Client) backendApply(k backend.KeyInterface, obj interface{}) error {
	if obj == nil {
		glog.V(2).Info("Skipping empty data")
		return nil
	}
	if v, err := json.Marshal(obj); err != nil {
		return err
	} else {
		return c.backend.Apply(backend.KeyValue{Key: k, Value: v})
	}
}

// Get the entry from the datastore reference by the key, and unmarshal into a
// new instance of the supplied backend structure.
func (c *Client) backendGet(k backend.KeyInterface, objp interface{}) (interface{}, error) {
	if kv, err := c.backend.Get(k); err != nil {
		return nil, err
	} else {
		kvs := []backend.KeyValue{kv}
		return c.unmarshalIntoNewBackendStruct(kvs, objp)
	}
}

// Convert the list of enumerated key-values into a list of groups of key-value each
// belonging to a single resource.  The default processing assumes a single key-value
// for each resource, so there is no additional sorting required.
func (c *Client) backendListConvert(in []backend.KeyValue) [][]backend.KeyValue {
	out := make([][]backend.KeyValue, len(in))
	for i, k := range in {
		out[i] = []backend.KeyValue{k}
	}
	return out
}
