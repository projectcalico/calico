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

// AzureEndpoint represents a container networked using Calico in conjunction with
// the azure-vnet-ipam plugin. We need to store state about the containers we've networked
// so we can pass the correct information to the IPAM plugin on delete. This structure
// handles the manipulation of that state.
type AzureEndpoint struct {
	Network     string
	ContainerID string
	Interface   string
	Addresses   []string
}

func (ae *AzureEndpoint) Write() error {
	b, err := json.Marshal(ae)
	if err != nil {
		return err
	}
	r := bytes.NewReader(b)
	if err := atomic.WriteFile(ae.filename(), r); err != nil {
		return err
	}
	logrus.Infof("Stored AzureEndpoint: %#v", ae)
	return nil
}

func (ae *AzureEndpoint) Load() error {
	bytes, err := os.ReadFile(ae.filename())
	if err != nil {
		return nil
	}
	logrus.Infof("Loaded AzureEndpoint: %s", bytes)
	return json.Unmarshal(bytes, ae)
}

func (ae *AzureEndpoint) Delete() error {
	logrus.Infof("Deleting AzureEndpoint: %#v", ae)
	return os.Remove(ae.filename())
}

func (ae *AzureEndpoint) filename() string {
	return fmt.Sprintf("%s/%s/%s-%s",
		networksDir,
		ae.Network,
		ae.ContainerID,
		ae.Interface,
	)
}
