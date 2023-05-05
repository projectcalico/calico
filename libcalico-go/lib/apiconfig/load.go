// Copyright (c) 2017-2020 Tigera, Inc. All rights reserved.

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

package apiconfig

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/kelseyhightower/envconfig"
	log "github.com/sirupsen/logrus"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	yaml "github.com/projectcalico/go-yaml-wrapper"
)

// LoadClientConfig loads the ClientConfig from the specified file (if specified)
// or from environment variables (if the file is not specified).
func LoadClientConfig(filename string) (*CalicoAPIConfig, error) {
	// Override / merge with values loaded from the specified file.
	if filename != "" {
		return LoadClientConfigFromFile(filename)
	} else {
		return LoadClientConfigFromEnvironment()
	}
}

// LoadClientConfigFromFile loads the ClientConfig from the specified file, which must exist.
// The datastore type is defaulted if not specified.
func LoadClientConfigFromFile(filename string) (*CalicoAPIConfig, error) {
	b, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	c, err := LoadClientConfigFromBytes(b)
	if err != nil {
		return nil, fmt.Errorf("syntax error in %s: %v", filename, err)
	}

	return c, nil
}

// LoadClientConfigFromBytes loads the ClientConfig from the supplied bytes containing YAML or JSON format data.
// The datastore type is defaulted if not specified.
func LoadClientConfigFromBytes(b []byte) (*CalicoAPIConfig, error) {
	var c CalicoAPIConfig

	log.Debug("Loading config from JSON or YAML data")
	if err := yaml.UnmarshalStrict(b, &c); err != nil {
		return nil, fmt.Errorf("failed to parse config as YAML/JSON: %w", err)
	}

	// Validate the version and kind.
	if c.APIVersion != apiv3.GroupVersionCurrent {
		return nil, errors.New("invalid config file: unknown APIVersion '" + c.APIVersion + "'")
	}
	if c.Kind != KindCalicoAPIConfig {
		return nil, errors.New("invalid config file: expected kind '" + KindCalicoAPIConfig + "', got '" + c.Kind + "'")
	}

	applyConfigDefaults(&c)
	log.Debug("Datastore type: ", c.Spec.DatastoreType)
	return &c, nil
}

// LoadClientConfigFromEnvironment loads a client config from the environment.
// The datastore type is defaulted if not specified.
func LoadClientConfigFromEnvironment() (*CalicoAPIConfig, error) {
	c := NewCalicoAPIConfig()
	if err := envconfig.Process("calico", &c.Spec); err != nil {
		return nil, fmt.Errorf("failed to load config from env vars: %w", err)
	}
	applyConfigDefaults(c)
	return c, nil
}

// applyConfigDefaults tries to detect the correct datastore type and config parameters.
func applyConfigDefaults(c *CalicoAPIConfig) {
	if c.Spec.DatastoreType == "" {
		log.Debug("Datastore type isn't set, trying to detect it")
		if c.Spec.EtcdEndpoints != "" {
			log.Debug("EtcdEndpoints specified, detected etcdv3.")
			c.Spec.DatastoreType = EtcdV3
		} else {
			log.Debug("No EtcdEndpoints specified, defaulting to kubernetes.")
			c.Spec.DatastoreType = Kubernetes
		}
	}

	if c.Spec.DatastoreType == Kubernetes {
		// Default to using $(HOME)/.kube/config, unless another means has been configured.
		switch {
		case c.Spec.Kubeconfig != "":
			log.WithField("kubeconfig", c.Spec.Kubeconfig).Debug("kubeconfig provided.")
		case c.Spec.K8sAPIEndpoint != "":
			log.WithField("apiEndpoint", c.Spec.K8sAPIEndpoint).Debug("API endpoint provided.")
		case os.Getenv("HOME") == "":
			// No home directory, can't build a default config path.
			log.Debug("No home directory, default path doesn't apply.")
		default:
			// Default the kubeconfig.
			kubeconfig := filepath.Join(os.Getenv("HOME"), ".kube", "config")
			if _, err := os.Stat(kubeconfig); err == nil {
				c.Spec.Kubeconfig = kubeconfig
				log.WithField("kubeconfig", c.Spec.Kubeconfig).Debug("Using default kubeconfig path.")
			} else {
				// The Kubernetes client can try other defaults if we leave the field blank (for example, the
				// in cluster config).
				log.Debug("No kubeconfig file at default path, leaving blank.")
			}
		}
	}
}
