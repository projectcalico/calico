// Copyright (c) 2017-2018 Tigera, Inc. All rights reserved.

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

package clients

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/kelseyhightower/envconfig"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/go-yaml-wrapper"
	"github.com/projectcalico/libcalico-go/lib/apiconfig"
	apiv1 "github.com/projectcalico/libcalico-go/lib/apis/v1"
	"github.com/projectcalico/libcalico-go/lib/apis/v1/unversioned"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/libcalico-go/lib/upgrade/migrator/clients/v1/compat"
	"github.com/projectcalico/libcalico-go/lib/upgrade/migrator/clients/v1/etcdv2"
	"github.com/projectcalico/libcalico-go/lib/upgrade/migrator/clients/v1/k8s"
)

const (
	DefaultConfigPathV1 = "/etc/calico/apiconfigv1.cfg"
	DefaultConfigPathV3 = "/etc/calico/apiconfigv3.cfg"
)

type V1ClientInterface interface {
	Apply(d *model.KVPair) (*model.KVPair, error)
	Update(d *model.KVPair) (*model.KVPair, error)
	Get(k model.Key) (*model.KVPair, error)
	List(l model.ListInterface) ([]*model.KVPair, error)
	IsKDD() bool
}

// LoadClients loads the v3 and v1 clients required for the migration.
// v3Config and v1Config are the full file paths to the v3 APIConfig
// and the v1 APIConfig respectively.  If either are blank, then this
// loads config from the environments.
//
// If using Kubernetes API as the datastore, only the v3Config, or
// v3 environments need to be specified.  The v1 client uses identical
// configuration for this datastore type.
func LoadClients(v3Config, v1Config string) (clientv3.Interface, V1ClientInterface, error) {
	// If the v3Config or v1Config are the default paths, and those files do not exist, then
	// switch to using environments by settings the path to an empty string.
	if _, err := os.Stat(v3Config); err != nil {
		if v3Config != DefaultConfigPathV3 {
			return nil, nil, fmt.Errorf("Error reading apiconfigv3 file: %s\n", v3Config)
		}
		log.Infof("Config file: %s cannot be read - reading config from environment", v3Config)
		v3Config = ""
	}
	if _, err := os.Stat(v1Config); err != nil {
		if v1Config != DefaultConfigPathV1 {
			return nil, nil, fmt.Errorf("Error reading apiconfigv1 file: %s\n", v1Config)
		}
		log.Infof("Config file: %s cannot be read - reading config from environment", v1Config)
		v1Config = ""
	}

	// Load the v3 client config - either from file or environments.
	apiConfigv3, err := apiconfig.LoadClientConfig(v3Config)
	if err != nil {
		return nil, nil, fmt.Errorf("error with apiconfigv3: %v", err)
	}

	var bv1 V1ClientInterface
	if apiConfigv3.Spec.DatastoreType == apiconfig.Kubernetes {
		log.Info("v3 API is using Kubernetes API - use same for v1")
		bv1, err = LoadKDDClientV1FromAPIConfigV3(apiConfigv3)
		if err != nil {
			return nil, nil, fmt.Errorf("error with apiconfigv1: %v", err)
		}
	} else {
		// Grab the Calico v1 API config (which must be specified).
		apiConfigv1, err := loadClientConfigV1(v1Config)
		if apiConfigv1.Spec.DatastoreType != apiv1.EtcdV2 {
			return nil, nil, fmt.Errorf("expecting apiconfigv1 datastore to be 'etcdv2', got '%s'", apiConfigv1.Spec.DatastoreType)
		}

		// Create the backend etcdv2 client (v1 API). We wrap this in the compat module to handle
		// multi-key backed resources.
		ev1, err := etcdv2.NewEtcdClient(&apiConfigv1.Spec.EtcdConfig)
		if err != nil {
			return nil, nil, fmt.Errorf("error with apiconfigv1: %v", err)
		}
		bv1 = compat.NewAdaptor(ev1)
	}

	// Create the front end v3 client.
	cv3, err := clientv3.New(*apiConfigv3)
	if err != nil {
		return nil, nil, fmt.Errorf("error with apiconfigv3: %v", err)
	}
	return cv3, bv1, nil
}

// LoadKDDClientV1FromAPIConfigV3 loads the KDD v1 client given the
// v3 API Config (since the v1 and v3 client use the same access information).
func LoadKDDClientV1FromAPIConfigV3(apiConfigv3 *apiconfig.CalicoAPIConfig) (V1ClientInterface, error) {
	if apiConfigv3.Spec.DatastoreType != apiconfig.Kubernetes {
		return nil, fmt.Errorf("not valid for this datastore type: %s", apiConfigv3.Spec.DatastoreType)
	}
	kc := &apiv1.KubeConfig{
		Kubeconfig:               apiConfigv3.Spec.Kubeconfig,
		K8sAPIEndpoint:           apiConfigv3.Spec.K8sAPIEndpoint,
		K8sKeyFile:               apiConfigv3.Spec.K8sKeyFile,
		K8sCertFile:              apiConfigv3.Spec.K8sCertFile,
		K8sCAFile:                apiConfigv3.Spec.K8sCAFile,
		K8sAPIToken:              apiConfigv3.Spec.K8sAPIToken,
		K8sInsecureSkipTLSVerify: apiConfigv3.Spec.K8sInsecureSkipTLSVerify,
	}

	// Create the backend etcdv2 client (v1 API). We wrap this in the compat module to handle
	// multi-key backed resources.
	return k8s.NewKubeClient(kc)
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
	}
	return loadClientConfigFromEnvironmentV1()
}

// loadClientConfigFromBytesV1 loads the ClientConfig from the supplied bytes containing
// YAML or JSON format data.
func loadClientConfigFromBytesV1(b []byte) (*apiv1.CalicoAPIConfig, error) {
	var c apiv1.CalicoAPIConfig

	// Default the backend type to be etcd v2. This will be overridden if
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
	if err := envconfig.Process("CALICO", &c.Spec); err != nil {
		return nil, err
	}

	return c, nil
}
