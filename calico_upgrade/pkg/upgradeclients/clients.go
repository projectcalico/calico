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

package upgradeclients

import (
	"errors"
	"fmt"
	"io/ioutil"

	"github.com/kelseyhightower/envconfig"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/calico_upgrade/pkg/upgradeclients/v1/compat"
	"github.com/projectcalico/calico/calico_upgrade/pkg/upgradeclients/v1/etcdv2"
	yaml "github.com/projectcalico/go-yaml-wrapper"
	"github.com/projectcalico/libcalico-go/lib/apiconfig"
	apiv1 "github.com/projectcalico/libcalico-go/lib/apis/v1"
	"github.com/projectcalico/libcalico-go/lib/apis/v1/unversioned"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/clientv3"
)

type V1ClientInterface interface {
	Apply(d *model.KVPair) (*model.KVPair, error)
	Get(k model.Key) (*model.KVPair, error)
	List(l model.ListInterface) ([]*model.KVPair, error)
	IsKDD() bool
}

func LoadClients(v3Config, v1Config string) (clientv3.Interface, V1ClientInterface, error) {
	// Load the v3 client config - either from file or environments.
	v3ApiConfig, err := apiconfig.LoadClientConfig(v3Config)
	if err != nil {
		return nil, nil, err
	}

	// Create the front end v3 client and extract the backend client from it.
	clientv3, err := clientv3.New(*v3ApiConfig)
	if err != nil {
		return nil, nil, err
	}

	// If this is Kubernetes then that's all we need.
	if v3ApiConfig.Spec.DatastoreType == apiconfig.Kubernetes {
		return nil, nil, errors.New("Upgrade script is not yet supported for KDD")
	}

	// This must be an etcd backend.  Grab the Calico v1 API config (which must be specified).
	// We'll need to convert to the v3 API config format to create the etcdv2 backend client.
	v1ApiConfig, err := loadClientConfigV1(v1Config)
	if v1ApiConfig.Spec.DatastoreType != apiv1.EtcdV2 {
		return nil, nil, fmt.Errorf("expecting Calico v2 datastore to be 'etcdv2', got '%s'", v1ApiConfig.Spec.DatastoreType)
	}
	// Create the back end etcdv2 client.  We wrap this in the compat module to handle
	// multi-key backed resources.
	etcdv1, err := etcdv2.NewEtcdClient(&v1ApiConfig.Spec.EtcdConfig)
	backendv1 := compat.NewAdaptor(etcdv1)
	if err != nil {
		return nil, nil, err
	}

	return clientv3, backendv1, nil
}

type backend interface {
	Backend() clientv3.Interface
}

// loadClientConfigV1 loads the ClientConfig from the specified file (if specified)
// or from environment variables (if the file is not specified).
func loadClientConfigV1(filename string) (*apiv1.CalicoAPIConfig, error) {

	// Override / merge with values loaded from the specified file.
	if filename != "" {
		b, err := ioutil.ReadFile(filename)
		if err != nil {
			return nil, err
		}

		c, err := loadClientConfigFromBytesV1(b)
		if err != nil {
			return nil, fmt.Errorf("syntax error in %s: %s", filename, err)
		}
		return c, nil
	} else {
		return loadClientConfigFromEnvironmentV1()
	}
}

// loadClientConfigFromBytesV1 loads the ClientConfig from the supplied bytes containing
// YAML or JSON format data.
func loadClientConfigFromBytesV1(b []byte) (*apiv1.CalicoAPIConfig, error) {
	var c apiv1.CalicoAPIConfig

	// Default the backend type to be etcd v2.  This will be overridden if
	// explicitly specified in the file.
	log.Info("Loading config from JSON or YAML data")
	c = apiv1.CalicoAPIConfig{
		Spec: apiv1.CalicoAPIConfigSpec{
			DatastoreType: apiv1.EtcdV2,
		},
	}

	if err := yaml.UnmarshalStrict(b, &c); err != nil {
		return nil, err
	}

	// Validate the version and kind.
	if c.APIVersion != unversioned.VersionCurrent {
		return nil, errors.New("invalid config file: unknown APIVersion '" + c.APIVersion + "'")
	}
	if c.Kind != "calicoApiConfig" {
		return nil, errors.New("invalid config file: expected kind 'calicoApiConfig', got '" + c.Kind + "'")
	}

	log.Info("Datastore type: ", c.Spec.DatastoreType)
	return &c, nil
}

// loadClientConfigFromEnvironmentV1 loads the ClientConfig from the specified file (if specified)
// or from environment variables (if the file is not specified).
func loadClientConfigFromEnvironmentV1() (*apiv1.CalicoAPIConfig, error) {
	c := apiv1.NewCalicoAPIConfig()

	// Load client config from environment variables.
	log.Info("Loading config from environment")
	if err := envconfig.Process("V1", &c.Spec); err != nil {
		return nil, err
	}

	return c, nil
}
