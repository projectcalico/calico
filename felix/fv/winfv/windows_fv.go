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
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
	"github.com/tigera/windows-networking/pkg/testutils"

	"github.com/projectcalico/calico/felix/collector/flowlog"
	"github.com/projectcalico/calico/felix/fv/flowlogs"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
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

func NewWinFV(rootDir, flowLogDir, dnsCacheFile string) (*WinFV, error) {
	var b []byte
	configFile := filepath.Join(rootDir, "config.ps1")

	var client clientv3.Interface
	var felixConfig *apiv3.FelixConfiguration
	if IsRunningHPC() {
		log.Infof("Storing original FelixConfiguration")
		var err error
		client, err = NewClient()
		if err != nil {
			return nil, err
		}
		felixConfig, err = getDatastoreFelixConfig(client)
		if err != nil {
			return nil, err
		}
		felixConfig.ResourceVersion = ""
	} else {
		var err error
		b, err = os.ReadFile(configFile) // just pass the file name
		if err != nil {
			return nil, err
		}
	}

	var backend CalicoBackEnd
	networkType, _ := testutils.Powershell(`Get-HnsNetwork | Where name -EQ Calico | Select Type`)
	log.Infof("Windows network type %s", networkType)
	if strings.Contains(strings.ToLower(networkType), "l2bridge") {
		backend = CalicoBackendBGP
	} else if strings.Contains(strings.ToLower(networkType), "overlay") {
		backend = CalicoBackendVXLAN
	} else {
		return nil, fmt.Errorf("wrong Windows network type")
	}

	return &WinFV{
		rootDir:                 rootDir,
		flowLogDir:              flowLogDir,
		dnsCacheFile:            dnsCacheFile,
		configFile:              configFile,
		originalConfig:          string(b),
		originalDatastoreConfig: *felixConfig,
		backend:                 backend,
		client:                  client,
	}, nil
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
			"v2.0.0-test",
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

func (f *WinFV) Restart() {
	if IsRunningHPC() {
		log.Infof("Skip restarting Felix, running on HPC...")
		return
	}
	log.Infof("Restarting Felix...")
	testutils.Powershell(filepath.Join(f.rootDir, "restart-felix.ps1"))
	log.Infof("Felix Restarted.")
}

func (f *WinFV) RestartFelix() {
	if IsRunningHPC() {
		log.Infof("Skip restarting Felix, running on HPC...")
		return
	}
	log.Infof("Restarting Felix...")
	testutils.Powershell(filepath.Join(f.rootDir, "restart-felix.ps1"))
	log.Infof("Felix Restarted.")
}

func (f *WinFV) RestoreConfig() error {
	if IsRunningHPC() {
		log.Infof("Restoring original FelixConfiguration")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, err := f.client.FelixConfigurations().Delete(ctx, "default", options.DeleteOptions{})
		if err != nil {
			return err
		}
		_, err = f.client.FelixConfigurations().Create(ctx, &f.originalDatastoreConfig, options.SetOptions{})
		if err != nil {
			return err
		}
		return nil
	}
	err := os.WriteFile(f.configFile, []byte(f.originalConfig), 0644)
	if err != nil {
		return err
	}
	return nil
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

// Add config items to config.ps1.
func (f *WinFV) AddConfigItems(configs map[string]any) error {
	if IsRunningHPC() {
		c, err := f.GetDatastoreFelixConfig()
		logrus.WithFields(logrus.Fields{"felixconfiguration": c, "adding configs": configs}).Info("Updating FelixConfiguration")
		val := reflect.ValueOf(&c.Spec).Elem()
		for key, value := range configs {
			// Get the field by name within the struct
			field := val.FieldByName(key)

			if !field.IsValid() {
				// Skip if the field doesn't exist
				fmt.Printf("No such field: %s in FelixConfig Spec\n", key)
				continue
			}
			if !field.CanSet() {
				// Skip if field is not settable (unexported/private)
				fmt.Printf("Cannot set field: %s in FelixConfig Spec\n", key)
				continue
			}

			// Get the value from the map and set it based on its type
			fieldValue := reflect.ValueOf(value)
			if field.Kind() == fieldValue.Kind() {
				field.Set(fieldValue)
			} else {
				return fmt.Errorf("type mismatch for field: %s, field.Kind(): %s, fieldValue.Kind(): %s", key, field.Kind(), fieldValue.Kind())
			}
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, err = f.client.FelixConfigurations().Update(ctx, c, options.SetOptions{})
		if err != nil {
			return err
		}
		return nil
	}
	var entry, items string

	items = f.originalConfig
	// Convert config map to string
	for name, value := range configs {
		switch c := value.(type) {
		case int:
			entry = fmt.Sprintf("$env:FELIX_%s = %d", name, c)
		case string:
			entry = fmt.Sprintf("$env:FELIX_%s = %q", name, c)
		case metav1.Duration:
			entry = fmt.Sprintf("$env:FELIX_%s = %s", name, c)
		default:
			return fmt.Errorf("wrong config value type")
		}

		items = fmt.Sprintf("%s\n%s\n", items, entry)
	}

	err := os.WriteFile(f.configFile, []byte(items), 0644)
	if err != nil {
		return err
	}
	return nil
}

func (f *WinFV) FlowLogs() ([]flowlog.FlowLog, error) {
	return flowlogs.ReadFlowLogsFile(f.flowLogDir)
}

type JsonMappingV1 struct {
	LHS    string
	RHS    string
	Expiry string
	Type   string
}

func (f *WinFV) ReadDnsCacheFile() ([]JsonMappingV1, error) {
	result := []JsonMappingV1{}

	log.WithField("file", f.dnsCacheFile).Info("Reading DNS Cache from file")
	logFile, err := os.Open(f.dnsCacheFile)
	if err != nil {
		return result, err
	}
	defer logFile.Close()

	s := bufio.NewScanner(logFile)
	for s.Scan() {
		var m JsonMappingV1

		// filter out anything other than a valid entry
		if !strings.Contains(s.Text(), "LHS") {
			continue
		}
		err = json.Unmarshal(s.Bytes(), &m)
		if err != nil {
			all, _ := os.ReadFile(f.dnsCacheFile)
			return result, fmt.Errorf("error unmarshaling dns log: %v\nLog:\n%s\nFile:\n%s", err, string(s.Bytes()), string(all))
		}
		result = append(result, m)
	}
	return result, nil
}

// HPC env variable is set by the Windows FV tests (run-fv-full.ps1) runner during infra set up
func IsRunningHPC() bool {
	return os.Getenv("HPC") == "true"
}
