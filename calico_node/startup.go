// Copyright (c) 2016 Tigera, Inc. All rights reserved.
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
package main

import (
	"encoding/hex"
	"fmt"

	"github.com/satori/go.uuid"

	log "github.com/Sirupsen/logrus"
	"github.com/projectcalico/libcalico-go/lib/backend"
	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/client"
	"github.com/projectcalico/libcalico-go/lib/errors"
)

// main performs startup operations for a node.
// For now, this only creates the ClusterGUID.  Ultimately,
// all of the function from startup.py will be moved here.
func main() {
	// Build a Calico client.
	log.Info("Creating Calico client")
	cfg, err := client.LoadClientConfig("")
	if err != nil {
		panic(fmt.Sprintf("Error loading config: %s", err))
	}
	c, err := backend.NewClient(*cfg)
	if err != nil {
		panic(fmt.Sprintf("Error creating client: %s", err))
	}
	log.Info("Ensuring datastore is initialized")
	err = c.EnsureInitialized()
	if err != nil {
		panic(fmt.Sprintf("Error initializing datastore: %s", err))
	}
	log.Info("Datastore is initialized")

	// Make sure we have a global cluster ID set.
	log.Info("Ensuring a cluster guid is set")
	ensureClusterGuid(c)
}

// ensureClusterGuid assigns a cluster GUID if one doesn't exist.
func ensureClusterGuid(c api.Client) {
	guid := hex.EncodeToString(uuid.NewV4().Bytes())
	_, err := c.Create(&model.KVPair{
		Key:   model.GlobalConfigKey{Name: "ClusterGUID"},
		Value: guid,
	})
	if err != nil {
		if _, ok := err.(errors.ErrorResourceAlreadyExists); !ok {
			log.Warnf("Failed to set ClusterGUID: %s", err)
			panic(err)
		}
		log.Infof("Using previously configured ClusterGUID")
		return
	}
	log.Infof("Assigned ClusterGUID %s", guid)
}
