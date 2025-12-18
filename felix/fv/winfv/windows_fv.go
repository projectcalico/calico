// Copyright (c) 2021-2025 Tigera, Inc. All rights reserved.
//
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

package winfv

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	log "github.com/sirupsen/logrus"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

type CalicoBackEnd string

const (
	CalicoBackendBGP   CalicoBackEnd = "bgp"
	CalicoBackendVXLAN CalicoBackEnd = "vxlan"
)

type WinFV struct {
	rootDir    string
	flowLogDir string
	configFile string

	dnsCacheFile string

	// The original content of config.ps1.
	originalConfig          string
	originalDatastoreConfig apiv3.FelixConfiguration

	client clientv3.Interface

	backend CalicoBackEnd
}

func NewClient() (clientv3.Interface, error) {
	cfg := apiconfig.NewCalicoAPIConfig()
	cfg.Spec.DatastoreType = apiconfig.Kubernetes
	cfg.Spec.Kubeconfig = `c:\k\config`
	client, err := clientv3.New(*cfg)
	if err != nil {
		return nil, err
	}
	err = InitDatastore(client)
	if err != nil {
		return nil, err
	}
	return client, nil
}

func InitDatastore(client clientv3.Interface) error {
	for try := range 10 {
		log.WithField("try", try).Info("Initializing the datastore...")
		ctx, cancelFun := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancelFun()
		err := client.EnsureInitialized(
			ctx,
			"v3.0.0-test",
			"felix-fv",
		)
		log.WithError(err).Info("EnsureInitialized result")
		if err != nil {
			continue
		}

		return err

	}

	return fmt.Errorf("maximum number of tries for InitDatastore() exceeded")
}

func (f *WinFV) GetBackendType() CalicoBackEnd {
	return f.backend
}

func (f *WinFV) GetDatastoreFelixConfig() (*apiv3.FelixConfiguration, error) {
	return getDatastoreFelixConfig(f.client)
}
func getDatastoreFelixConfig(client clientv3.Interface) (*apiv3.FelixConfiguration, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := client.FelixConfigurations().Get(ctx, "default", options.GetOptions{})
	if err != nil {
		// Create the default config if it doesn't already exist.
		var errorNotExist cerrors.ErrorResourceDoesNotExist
		if errors.As(err, &errorNotExist) {
			c = apiv3.NewFelixConfiguration()
			c.Name = "default"
			c, err = client.FelixConfigurations().Create(ctx, c, options.SetOptions{})
			if err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}
	return c, nil
}

// HPC env variable is set by the Windows FV tests (run-fv-full.ps1) runner during infra set up
func IsRunningHPC() bool {
	return os.Getenv("HPC") == "true"
}
