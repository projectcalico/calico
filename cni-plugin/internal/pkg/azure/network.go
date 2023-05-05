// Copyright (c) 2018 Tigera, Inc. All rights reserved.

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

package azure

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"github.com/natefinch/atomic"
	"github.com/sirupsen/logrus"
)

var networksDir string = "/var/run/calico/azure/networks/"

// AzureNetwork facilitates the manipulation of state associated with an Azure
// network. It can be stored and used across executions of the plugin.
type AzureNetwork struct {
	Name    string
	Subnets []string
}

func (an *AzureNetwork) Write() error {
	// Make sure the directory exists.
	err := an.ensureDir()
	if err != nil {
		return err
	}

	// Write the network struct to disk.
	b, err := json.Marshal(an)
	if err != nil {
		return err
	}
	r := bytes.NewReader(b)
	if err := atomic.WriteFile(an.filename(), r); err != nil {
		return err
	}
	logrus.Infof("Stored AzureNetwork: %#v", an)
	return nil
}

func (an *AzureNetwork) Load() error {
	bytes, err := os.ReadFile(an.filename())
	if err != nil {
		return nil
	}
	logrus.Infof("Loaded AzureNetwork: %s", bytes)
	return json.Unmarshal(bytes, an)
}

func (an *AzureNetwork) filename() string {
	return fmt.Sprintf(networksDir + an.Name + "/network.json")
}

func (an *AzureNetwork) ensureDir() error {
	return os.MkdirAll(networksDir+an.Name, os.ModePerm)
}
