// Copyright (c) 2016 Tigera, Inc. All rights reserved.

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
	"os"

	log "github.com/Sirupsen/logrus"
	"github.com/projectcalico/libcalico-go/lib/api"
	"github.com/projectcalico/libcalico-go/lib/client"
)

// NewClient creates a new CalicoClient using connection information in the specified
// filename (if it exists), dropping back to environment variables for any
// parameter not loaded from file.
func NewClient(cf string) (*client.Client, error) {
	cfg, err := LoadClientConfig(cf)
	if err != nil {
		log.Info("Error loading config")
		return nil, err
	}
	log.Infof("Loaded client config: %#v", cfg.Spec)

	c, err := client.New(*cfg)
	if err != nil {
		return nil, err
	}

	return c, err
}

// LoadClientConfig loads the client config from file if the file exists,
// otherwise will load from environment variables.
func LoadClientConfig(cf string) (*api.CalicoAPIConfig, error) {
	if _, err := os.Stat(cf); err != nil {
		log.Infof("Config file cannot be read - reading config from environment")
		cf = ""
	}

	return client.LoadClientConfig(cf)
}
