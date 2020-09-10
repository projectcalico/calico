package apiconfig

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/kelseyhightower/envconfig"
	log "github.com/sirupsen/logrus"

	yaml "github.com/projectcalico/go-yaml-wrapper"
	apiv3 "github.com/projectcalico/libcalico-go/lib/apis/v3"
)

// LoadClientConfig loads the ClientConfig from the specified file (if specified)
// or from environment variables (if the file is not specified).
func LoadClientConfig(filename string) (*CalicoAPIConfig, error) {
	var c *CalicoAPIConfig
	var err error

	// Override / merge with values loaded from the specified file.
	if filename != "" {
		b, err := ioutil.ReadFile(filename)
		if err != nil {
			return nil, err
		}

		c, err = LoadClientConfigFromBytes(b)
		if err != nil {
			return nil, fmt.Errorf("syntax error in %s: %v", filename, err)
		}

	} else {
		c, err = LoadClientConfigFromEnvironment()
	}

	// If EtcdEndpoints is set and DatastoreType is missing set it to EtcdV3
	// otherwise set default Datastoretype to Kubernetes
	if c.Spec.DatastoreType == "" && c.Spec.EtcdEndpoints != "" {
		c.Spec.DatastoreType = EtcdV3
	} else if c.Spec.DatastoreType == "" {
		c.Spec.DatastoreType = Kubernetes
	}

	if c.Spec.DatastoreType == Kubernetes {
		// Default to using $(HOME)/.kube/config, unless another means has been configured.
		switch {
		case c.Spec.Kubeconfig != "":
			// A kubeconfig has already been provided.
		case c.Spec.K8sAPIEndpoint != "":
			// A k8s API endpoint has been specified explicitly.
		case os.Getenv("HOME") == "":
			// No home directory, can't build a default config path.
		default:
			// Default the kubeconfig.
			c.Spec.Kubeconfig = filepath.Join(os.Getenv("HOME"), ".kube", "config")
		}
	}

	return c, err
}

// LoadClientConfig loads the ClientConfig from the supplied bytes containing
// YAML or JSON format data.
func LoadClientConfigFromBytes(b []byte) (*CalicoAPIConfig, error) {
	var c CalicoAPIConfig

	log.Debug("Loading config from JSON or YAML data")

	if err := yaml.UnmarshalStrict(b, &c); err != nil {
		return nil, err
	}

	// Validate the version and kind.
	if c.APIVersion != apiv3.GroupVersionCurrent {
		return nil, errors.New("invalid config file: unknown APIVersion '" + c.APIVersion + "'")
	}
	if c.Kind != KindCalicoAPIConfig {
		return nil, errors.New("invalid config file: expected kind '" + KindCalicoAPIConfig + "', got '" + c.Kind + "'")
	}

	log.Debug("Datastore type: ", c.Spec.DatastoreType)
	return &c, nil
}

// LoadClientConfig loads the ClientConfig from the specified file (if specified)
// or from environment variables (if the file is not specified).
func LoadClientConfigFromEnvironment() (*CalicoAPIConfig, error) {
	c := NewCalicoAPIConfig()

	// Load client config from environment variables.
	log.Debug("Loading config from environment")
	if err := envconfig.Process("calico", &c.Spec); err != nil {
		return nil, err
	}

	return c, nil
}
