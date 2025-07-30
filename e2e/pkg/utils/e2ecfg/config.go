// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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

package e2ecfg

import "os"

type configType struct {
	envVarName   string
	helpText     string
	defaultValue string
	actualValue  string
	envValue     string
	cmdLineValue string
}

const (
	remoteKubeConfig = "REMOTE_KUBECONFIG"
)

var config = map[string]*configType{
	remoteKubeConfig: {
		envVarName:   remoteKubeConfig,
		helpText:     "The fully qualified path to the admin kubeconfig file of the remote cluster.",
		defaultValue: "",
	},
}

func RemoteClusterKubeconfig() string {
	return config[remoteKubeConfig].actualValue
}

func init() {
	// Load defaults and env variables
	for _, c := range config {
		if ev, exists := os.LookupEnv(c.envVarName); exists {
			if ev == "" {
				c.envValue = "<empty-string>"
			} else {
				c.envValue = ev
			}
		} else if c.defaultValue != "" {
			_ = os.Setenv(c.envVarName, os.ExpandEnv(c.defaultValue))
		}
	}
	for _, c := range config {
		if ev, exists := os.LookupEnv(c.envVarName); exists && ev != "" {
			c.actualValue = os.ExpandEnv(ev)
		} else {
			c.actualValue = os.ExpandEnv(c.defaultValue)
		}
	}
}
