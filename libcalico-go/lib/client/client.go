// Copyright (c) 2016-2018 Tigera, Inc. All rights reserved.

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
	"context"
	goerrors "errors"
	"fmt"
	"os"
	"reflect"

	"github.com/kelseyhightower/envconfig"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/go-yaml-wrapper"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	api "github.com/projectcalico/calico/libcalico-go/lib/apis/v1"
	"github.com/projectcalico/calico/libcalico-go/lib/apis/v1/unversioned"
	"github.com/projectcalico/calico/libcalico-go/lib/backend"
	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	validator "github.com/projectcalico/calico/libcalico-go/lib/validator/v1"
)

// Client contains
type Client struct {
	// The backend client is currently public to allow access to datastore
	// specific functions that are used by calico/node.  This is a temporary
	// measure and users of the client API should not assume that the backend
	// will be available in the future.
	Backend bapi.Client
}

// New returns a connected Client. The ClientConfig can either be created explicitly,
// or can be loaded from a config file or environment variables using the LoadClientConfig() function.
func New(config apiconfig.CalicoAPIConfig) (*Client, error) {
	var err error
	cc := Client{}
	if cc.Backend, err = backend.NewClient(config); err != nil {
		return nil, err
	}
	return &cc, err
}

// NewFromEnv loads the config from ENV variables and returns a connected Client.
func NewFromEnv() (*Client, error) {

	config, err := apiconfig.LoadClientConfigFromEnvironment()
	if err != nil {
		return nil, err
	}

	return New(*config)
}

// Nodes returns an interface for managing node resources.
func (c *Client) Nodes() NodeInterface {
	return newNodes(c)
}

// Policies returns an interface for managing policy resources.
func (c *Client) Policies() PolicyInterface {
	return newPolicies(c)
}

// IPPools returns an interface for managing IP pool resources.
func (c *Client) IPPools() IPPoolInterface {
	return newIPPools(c)
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

// Config returns an interface for managing system configuration..
func (c *Client) Config() ConfigInterface {
	return newConfigs(c)
}

// EnsureInitialized is used to ensure the backend datastore is correctly
// initialized for use by Calico.  This method may be called multiple times, and
// will have no effect if the datastore is already correctly initialized.
//
// Most Calico deployment scenarios will automatically implicitly invoke this
// method and so a general consumer of this API can assume that the datastore
// is already initialized.
func (c *Client) EnsureInitialized() error {
	// Perform datastore specific initialization first.
	if err := c.Backend.EnsureInitialized(); err != nil {
		return err
	}

	return nil
}

// LoadClientConfig loads the ClientConfig from the specified file (if specified)
// or from environment variables (if the file is not specified).
func LoadClientConfig(filename string) (*api.CalicoAPIConfig, error) {

	// Override / merge with values loaded from the specified file.
	if filename != "" {
		b, err := os.ReadFile(filename)
		if err != nil {
			return nil, err
		}

		c, err := LoadClientConfigFromBytes(b)
		if err != nil {
			return nil, fmt.Errorf("syntax error in %s: %v", filename, err)
		}
		return c, nil
	} else {
		return LoadClientConfigFromEnvironment()
	}
}

// LoadClientConfig loads the ClientConfig from the supplied bytes containing
// YAML or JSON format data.
func LoadClientConfigFromBytes(b []byte) (*api.CalicoAPIConfig, error) {
	var c api.CalicoAPIConfig

	// Default the backend type to be etcd v3.  This will be overridden if
	// explicitly specified in the file.
	log.Info("Loading config from JSON or YAML data")
	c = api.CalicoAPIConfig{
		Spec: api.CalicoAPIConfigSpec{
			DatastoreType: api.EtcdV2,
		},
	}

	if err := yaml.UnmarshalStrict(b, &c); err != nil {
		return nil, err
	}

	// Validate the version and kind.
	if c.APIVersion != unversioned.VersionCurrent {
		return nil, goerrors.New("invalid config file: unknown APIVersion '" + c.APIVersion + "'")
	}
	if c.Kind != "calicoApiConfig" {
		return nil, goerrors.New("invalid config file: expected kind 'calicoApiConfig', got '" + c.Kind + "'")
	}

	log.Info("Datastore type: ", c.Spec.DatastoreType)
	return &c, nil
}

// LoadClientConfig loads the ClientConfig from the specified file (if specified)
// or from environment variables (if the file is not specified).
func LoadClientConfigFromEnvironment() (*api.CalicoAPIConfig, error) {
	c := api.NewCalicoAPIConfig()

	// Load client config from environment variables.
	log.Info("Loading config from environment")
	if err := envconfig.Process("calico", &c.Spec); err != nil {
		return nil, err
	}

	return c, nil
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
func (c *Client) create(apiObject unversioned.ResourceObject, helper conversionHelper) error {
	// Validate the supplied data before writing to the datastore.
	if err := validator.Validate(apiObject); err != nil {
		return err
	}

	if err := validator.ValidateMetadataIDsAssigned(apiObject.GetResourceMetadata()); err != nil {
		return err
	}

	if d, err := helper.convertAPIToKVPair(apiObject); err != nil {
		return err
	} else if d, err = c.Backend.Create(context.Background(), d); err != nil {
		return err
	} else {
		return nil
	}
}

// Untyped interface for updating an API object.  This is called from the
// typed interface.
func (c *Client) update(apiObject unversioned.ResourceObject, helper conversionHelper) error {
	// Validate the supplied data before writing to the datastore.
	if err := validator.Validate(apiObject); err != nil {
		return err
	}

	if err := validator.ValidateMetadataIDsAssigned(apiObject.GetResourceMetadata()); err != nil {
		return err
	}

	if d, err := helper.convertAPIToKVPair(apiObject); err != nil {
		return err
	} else if d, err = c.Backend.Update(context.Background(), d); err != nil {
		return err
	} else {
		return nil
	}
}

// Untyped interface for applying an API object.  This is called from the
// typed interface.
func (c *Client) apply(apiObject unversioned.ResourceObject, helper conversionHelper) error {
	// Validate the supplied data before writing to the datastore.
	if err := validator.Validate(apiObject); err != nil {
		return err
	}

	if err := validator.ValidateMetadataIDsAssigned(apiObject.GetResourceMetadata()); err != nil {
		return err
	}

	if d, err := helper.convertAPIToKVPair(apiObject); err != nil {
		return err
	} else if d, err = c.Backend.Apply(context.Background(), d); err != nil {
		return err
	} else {
		return nil
	}
}

// Untyped get interface for deleting a single API object.  This is called from the typed
// interface.
func (c *Client) delete(metadata unversioned.ResourceMetadata, helper conversionHelper) error {
	// Validate the supplied Metadata.
	if err := validator.Validate(metadata); err != nil {
		return err
	}

	if err := validator.ValidateMetadataIDsAssigned(metadata); err != nil {
		return err
	}

	// Convert the Metadata to a Key and combine with the Metadata revision to create
	// a KVPair for the delete operation.  At the moment only the WorkloadEndpoint Get
	// operations fills in the revision information.
	if k, err := helper.convertMetadataToKey(metadata); err != nil {
		return err
	} else if _, err := c.Backend.Delete(context.Background(), k, metadata.GetObjectMetadata().Revision); err != nil {
		return err
	} else {
		return nil
	}
}

// Untyped get interface for getting a single API object.  This is called from the typed
// interface.  The result is
func (c *Client) get(metadata unversioned.ResourceMetadata, helper conversionHelper) (unversioned.Resource, error) {
	// Validate the supplied Metadata.
	if err := validator.Validate(metadata); err != nil {
		return nil, err
	}

	if err := validator.ValidateMetadataIDsAssigned(metadata); err != nil {
		return nil, err
	}

	if k, err := helper.convertMetadataToKey(metadata); err != nil {
		return nil, err
	} else if d, err := c.Backend.Get(context.Background(), k, ""); err != nil {
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
	// Validate the supplied Metadata.
	if err := validator.Validate(metadata); err != nil {
		return err
	}

	if l, err := helper.convertMetadataToListInterface(metadata); err != nil {
		return err
	} else if dos, err := c.Backend.List(context.Background(), l, ""); err != nil {
		return err
	} else {
		// The supplied resource list object will have an Items field.  Append the
		// enumerated resources to this field.
		e := reflect.ValueOf(listp).Elem()
		f := e.FieldByName("Items")
		i := reflect.ValueOf(f.Interface())

		for _, d := range dos.KVPairs {
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
