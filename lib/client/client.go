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
	"io/ioutil"
	"reflect"

	"errors"
	"fmt"
	"github.com/ghodss/yaml"
	"github.com/golang/glog"
	"github.com/kelseyhightower/envconfig"
	"github.com/tigera/libcalico-go/lib/api"
	"github.com/tigera/libcalico-go/lib/backend"
	"github.com/tigera/libcalico-go/lib/backend/model"
)

// Client contains
type Client struct {
	backend backend.Client
}

// New returns a connected Client.
func New(config *api.ClientConfig) (c *Client, err error) {
	cc := Client{}
	cc.backend, err = backend.NewClient(config)
	return &cc, err
}

// Policies returns an interface for managing policy resources.
func (c *Client) Policies() PolicyInterface {
	return newPolicies(c)
}

// Pools returns an interface for managing pool resources.
func (c *Client) Pools() PoolInterface {
	return newPools(c)
}

// Profiles returns an interface for managing profile resources.
func (c *Client) Profiles() ProfileInterface {
	return newProfiles(c)
}

// HostEndpoints returns an interface for managing host endpoint resources.
func (c *Client) HostEndpoints() HostEndpointInterface {
	return newHostEndpoints(c)
}

// WorkloadEndpoints returns an interface for managing workload endpoint resources.
func (c *Client) WorkloadEndpoints() WorkloadEndpointInterface {
	return newWorkloadEndpoints(c)
}

// IPAM returns an interface for managing IP address assignment and releasing.
func (c *Client) IPAM() IPAMInterface {
	return newIPAM(c)
}

// LoadClientConfig loads the client config from the specified file (if specified)
// or from environment variables (if the file does not exist, or is not specified).
func LoadClientConfig(f *string) (*api.ClientConfig, error) {
	var c api.ClientConfig

	// Override / merge with values loaded from the specified file.
	if f != nil {
		b, err := ioutil.ReadFile(*f)
		if err != nil {
			return nil, err
		}
		// First unmarshall should fill in the BackendType field only.
		if err := yaml.Unmarshal(b, &c); err != nil {
			return nil, err
		}
		glog.V(1).Info("Datastore type: ", c.BackendType)
		c.BackendConfig = c.BackendType.NewConfig()
		if c.BackendConfig == nil {
			return nil, errors.New(fmt.Sprintf("Unknown datastore type: %v", c.BackendType))
		}
		// Now unmarshall into the store-specific config struct.
		if err := yaml.Unmarshal(b, c.BackendConfig); err != nil {
			return nil, err
		}
		return &c, nil
	}

	// Load client config from environment variables.
	glog.V(1).Info("No config file specified, loading config from environment")
	if err := envconfig.Process("calico", &c); err != nil {
		return nil, err
	}
	c.BackendConfig = c.BackendType.NewConfig()
	glog.V(1).Info("Datastore type: ", c.BackendType)
	if c.BackendConfig == nil {
		return nil, errors.New(fmt.Sprintf("Unknown datastore type: %v", c.BackendType))
	}
	if err := envconfig.Process("calico", c.BackendConfig); err != nil {
		return nil, err
	}
	return &c, nil
}

// Interface used to convert between backend and API representations of our
// objects.
type conversionHelper interface {
	convertAPIToKVPair(interface{}) (*model.KVPair, error)
	convertKVPairToAPI(*model.KVPair) (interface{}, error)
	convertMetadataToKeyInterface(interface{}) (model.Key, error)
	convertMetadataToListInterface(interface{}) (model.ListInterface, error)
}

//TODO Plumb through revision data so that front end can do atomic operations.

// Untyped interface for creating an API object.  This is called from the
// typed interface.  This assumes a 1:1 mapping between the API resource and
// the backend object.
func (c *Client) create(apiObject interface{}, helper conversionHelper) error {
	if d, err := helper.convertAPIToKVPair(apiObject); err != nil {
		return err
	} else if d, err = c.backend.Create(d); err != nil {
		return err
	} else {
		return nil
	}
}

// Untyped interface for updating an API object.  This is called from the
// typed interface.
func (c *Client) update(apiObject interface{}, helper conversionHelper) error {
	if d, err := helper.convertAPIToKVPair(apiObject); err != nil {
		return err
	} else if d, err = c.backend.Update(d); err != nil {
		return err
	} else {
		return nil
	}
}

// Untyped interface for applying an API object.  This is called from the
// typed interface.
func (c *Client) apply(apiObject interface{}, helper conversionHelper) error {
	if d, err := helper.convertAPIToKVPair(apiObject); err != nil {
		return err
	} else if d, err = c.backend.Apply(d); err != nil {
		return err
	} else {
		return nil
	}
}

// Untyped get interface for deleting a single API object.  This is called from the typed
// interface.
func (c *Client) delete(metadata interface{}, helper conversionHelper) error {
	if k, err := helper.convertMetadataToKeyInterface(metadata); err != nil {
		return err
	} else if err := c.backend.Delete(&model.KVPair{Key: k}); err != nil {
		return err
	} else {
		return nil
	}
}

// Untyped get interface for getting a single API object.  This is called from the typed
// interface.  The result is
func (c *Client) get(metadata interface{}, helper conversionHelper) (interface{}, error) {
	if k, err := helper.convertMetadataToKeyInterface(metadata); err != nil {
		return nil, err
	} else if d, err := c.backend.Get(k); err != nil {
		return nil, err
	} else if a, err := helper.convertKVPairToAPI(d); err != nil {
		return nil, err
	} else {
		return a, nil
	}
}

// Untyped get interface for getting a list of API objects.  This is called from the typed
// interface.  This updates the Items slice in the supplied List resource object.
func (c *Client) list(metadata interface{}, helper conversionHelper, listp interface{}) error {
	if l, err := helper.convertMetadataToListInterface(metadata); err != nil {
		return err
	} else if dos, err := c.backend.List(l); err != nil {
		return err
	} else {
		// The supplied resource list object will have an Items field.  Append the
		// enumerated resources to this field.
		e := reflect.ValueOf(listp).Elem()
		f := e.FieldByName("Items")
		i := reflect.ValueOf(f.Interface())

		for _, d := range dos {
			if a, err := helper.convertKVPairToAPI(d); err != nil {
				return err
			} else {
				i = reflect.Append(i, reflect.ValueOf(a).Elem())
			}
		}

		f.Set(i)
	}

	return nil
}
