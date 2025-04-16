// Copyright (c) 2016-2025 Tigera, Inc. All rights reserved.

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

package clientmgr

import (
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"

	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/constants"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
)

// NewClient creates a new CalicoClient using connection information in the specified
// filename (if it exists), dropping back to environment variables for any
// parameter not loaded from file.
func NewClient(cf string) (client.Interface, error) {
	cfg, err := LoadClientConfig(cf)
	if err != nil {
		log.Info("Error loading config")
		return nil, err
	}
	log.Infof("Loaded client config: %#v", cfg.Spec)
	return NewClientFromConfig(cfg)
}

func NewClientFromConfig(cfg *apiconfig.CalicoAPIConfig) (client.Interface, error) {
	c, err := client.New(*cfg)
	if err != nil {
		return nil, err
	}

	return c, err
}

// LoadClientConfig loads the client config from file if the file exists,
// otherwise will load from environment variables.
func LoadClientConfig(cf string) (*apiconfig.CalicoAPIConfig, error) {
	if _, err := os.Stat(cf); err != nil {
		if cf != constants.DefaultConfigPath {
			fmt.Printf("Error reading config file: %s\n", cf)
			os.Exit(1)
		}
		log.Infof("Config file: %s cannot be read - reading config from environment", cf)
		cf = ""
	}

	return apiconfig.LoadClientConfig(cf)
}

func GetClients(cf string) (kubeClient *kubernetes.Clientset, calicoClient client.Interface, bc bapi.Client, err error) {
	calicoClient, err = NewClient(cf)
	if err != nil {
		return
	}

	// Get the backend client.
	type accessor interface {
		Backend() bapi.Client
	}
	bc = calicoClient.(accessor).Backend()

	// Get a kube-client. If this is a kdd cluster, we can pull this from the backend.
	// Otherwise, we need to build one ourselves.
	if kc, ok := bc.(*k8s.KubeClient); ok {
		// Pull from the kdd client.
		kubeClient = kc.ClientSet
	}
	// TODO: Support etcd mode. For now, this is OK since we don't actually
	// use the kubeClient yet. But we will do so eventually.

	return
}
