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

	log "github.com/Sirupsen/logrus"
	"github.com/ghodss/yaml"
	"github.com/kelseyhightower/envconfig"
	"github.com/projectcalico/libcalico-go/lib/api"
	"github.com/projectcalico/libcalico-go/lib/api/unversioned"
	"github.com/projectcalico/libcalico-go/lib/backend"
	bapi "github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
)

// Client contains
type Client struct {
	backend bapi.Client
}

// New returns a connected Client.  This is the only mechanism by which to create a
// Client.  The ClientConfig can either be created explicitly, or can be loaded from
// a config file or environment variables using the LoadClientConfig() function.
func New(config api.ClientConfig) (*Client, error) {
	var err error
	cc := Client{}
	if cc.backend, err = backend.NewClient(config); err != nil {
		return nil, err
	}
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

// BGPPeers returns an interface for managing BGP peer resources.
func (c *Client) BGPPeers() BGPPeerInterface {
	return newBGPPeers(c)
}

// IPAM returns an interface for managing IP address assignment and releasing.
func (c *Client) IPAM() IPAMInterface {
	return newIPAM(c)
}

// LoadClientConfig loads the ClientConfig from the specified file (if specified)
// or from environment variables (if the file is not specified).
func LoadClientConfig(filename string) (*api.ClientConfig, error) {
	var c api.ClientConfig

	// Override / merge with values loaded from the specified file.
	if filename != "" {
		b, err := ioutil.ReadFile(filename)
		if err != nil {
			return nil, err
		}

		// Default the backend type to be etcd v2.  This will be overridden if
		// explicitly specified in the file.
		c = api.ClientConfig{BackendType: api.EtcdV2}

		// First unmarshal should fill in the BackendType field only.
		if err := yaml.Unmarshal(b, &c); err != nil {
			return nil, err
		}
		log.Info("Datastore type: ", c.BackendType)
		c.BackendConfig = c.BackendType.NewConfig()
		if c.BackendConfig == nil {
			return nil, errors.New(fmt.Sprintf("Unknown datastore type: %v", c.BackendType))
		}
		// Now unmarshal into the store-specific config struct.
		if err := yaml.Unmarshal(b, c.BackendConfig); err != nil {
			return nil, err
		}
		return &c, nil
	}

	// Load client config from environment variables.
	log.Info("No config file specified, loading config from environment")
	if err := envconfig.Process("calico", &c); err != nil {
		return nil, err
	}
	c.BackendConfig = c.BackendType.NewConfig()
	log.Info("Datastore type: ", c.BackendType)
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
	convertAPIToKVPair(unversioned.Resource) (*model.KVPair, error)
	convertKVPairToAPI(*model.KVPair) (unversioned.Resource, error)
	convertMetadataToKey(unversioned.ResourceMetadata) (model.Key, error)
	convertMetadataToListInterface(unversioned.ResourceMetadata) (model.ListInterface, error)
}

//TODO Plumb through revision data so that front end can do atomic operations.

// Untyped interface for creating an API object.  This is called from the
// typed interface.  This assumes a 1:1 mapping between the API resource and
// the backend object.
func (c *Client) create(apiObject unversioned.Resource, helper conversionHelper) error {
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
func (c *Client) update(apiObject unversioned.Resource, helper conversionHelper) error {
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
func (c *Client) apply(apiObject unversioned.Resource, helper conversionHelper) error {
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
func (c *Client) delete(metadata unversioned.ResourceMetadata, helper conversionHelper) error {
	if k, err := helper.convertMetadataToKey(metadata); err != nil {
		return err
	} else if err := c.backend.Delete(&model.KVPair{Key: k}); err != nil {
		return err
	} else {
		return nil
	}
}

// Untyped get interface for getting a single API object.  This is called from the typed
// interface.  The result is
func (c *Client) get(metadata unversioned.ResourceMetadata, helper conversionHelper) (unversioned.Resource, error) {
	if k, err := helper.convertMetadataToKey(metadata); err != nil {
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
func (c *Client) list(metadata unversioned.ResourceMetadata, helper conversionHelper, listp interface{}) error {
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
