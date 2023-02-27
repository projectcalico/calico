// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.
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

// The config package provides config inheritance for Typha.
//
// It supports loading config from various sources, parsing and validating the
// config and merging the config according to the priority of the sources.
//
// # Usage
//
// To use it, create a Config object with:
//
//	config.New()
//
// Load some raw config using:
//
//	envConfig := config.LoadConfigFromEnvironment()
//	fileConfig, err := config.LoadConfigFile()
//
// Then feed it to the config object:
//
//	changed, err := config.UpdateFrom(envConfig, config.EnvironmentVariable)
//	...
//	changed, err = config.UpdateFrom(fileConfig, config.ConfigFile)
//
// # Config inheritance
//
// Config from higher-priority sources overrides config from lower-priority
// sources.  The priorities, in increasing order of priority, are:
//
//	Default              // Default value of a parameter
//	DatastoreGlobal      // Cluster-wide config parameters from the datastore.
//	DatastorePerHost     // Per-host overrides from the datastore.
//	ConfigFile           // The local config file.
//	EnvironmentVariable  // Environment variables.
package config
