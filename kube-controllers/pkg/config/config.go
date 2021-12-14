// Copyright (c) 2017-2020 Tigera, Inc. All rights reserved.
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

package config

import (
	"github.com/kelseyhightower/envconfig"
)

const (
	EnvLogLevel           = "LOG_LEVEL"
	EnvReconcilerPeriod   = "RECONCILER_PERIOD"
	EnvEnabledControllers = "ENABLED_CONTROLLERS"
	EnvCompactionPeriod   = "COMPACTION_PERIOD"
	EnvHealthEnabled      = "HEALTH_ENABLED"
	EnvSyncNodeLabels     = "SYNC_NODE_LABELS"
	EnvAutoHostEndpoints  = "AUTO_HOST_ENDPOINTS"
)

var AllEnvs = []string{EnvLogLevel, EnvReconcilerPeriod, EnvEnabledControllers, EnvCompactionPeriod, EnvHealthEnabled, EnvSyncNodeLabels, EnvAutoHostEndpoints}

// Config represents the configuration we load from the environment variables
type Config struct {
	// Minimum log level to emit.
	LogLevel string `default:"info" split_words:"true"`

	// Number of workers to run for each controller.
	WorkloadEndpointWorkers int `default:"1" split_words:"true"`
	ProfileWorkers          int `default:"1" split_words:"true"`
	PolicyWorkers           int `default:"1" split_words:"true"`
	NodeWorkers             int `default:"1" split_words:"true"`

	// Path to a kubeconfig file to use for accessing the k8s API.
	Kubeconfig string `default:"" split_words:"false"`

	// etcdv3 or kubernetes
	DatastoreType string `default:"etcdv3" split_words:"true"`
}

// Parse parses envconfig and stores in Config struct
func (c *Config) Parse() error {
	return envconfig.Process("", c)
}
