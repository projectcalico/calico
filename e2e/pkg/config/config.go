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

package config

import (
	"flag"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
)

type configOption struct {
	envVarName   string
	helpText     string
	defaultValue string
	actualValue  string
	envValue     string
	cmdLineValue string
}

// cliName returns the command line flag name for this config option.
func (c *configOption) cliName() string {
	return "calico." + strings.ToLower(strings.ReplaceAll(c.envVarName, "_", "-"))
}

const (
	remoteKubeConfig = "REMOTE_KUBECONFIG"
	logLevel         = "LOG_LEVEL"

	// Configuration options for tests that use SSH to connect to an external machine.
	externalNodeIP       = "EXT_IP"
	externalNodeSSHKey   = "EXT_KEY"
	externalNodeUsername = "EXT_USER"
)

var allConfigOptions = map[string]*configOption{
	remoteKubeConfig: {
		envVarName:   remoteKubeConfig,
		helpText:     "The fully qualified path to the admin kubeconfig file of a remote cluster for federation tests.",
		defaultValue: "",
	},
	logLevel: {
		envVarName:   logLevel,
		helpText:     "The log level to use for the tests. Valid values are: panic, fatal, error, warn, info, debug, trace.",
		defaultValue: "info",
	},

	// Configuration options for tests that use SSH to connect to an external machine.
	externalNodeUsername: {
		envVarName:   externalNodeUsername,
		helpText:     "The SSH username to use for the external node.",
		defaultValue: "ubuntu",
	},
	externalNodeSSHKey: {
		envVarName:   externalNodeSSHKey,
		helpText:     "The absolute path to the SSH key to connect to the external node.",
		defaultValue: "",
	},
	externalNodeIP: {
		envVarName:   externalNodeIP,
		helpText:     "The IP address of the external node.",
		defaultValue: "",
	},
}

func RemoteClusterKubeconfig() string {
	return allConfigOptions[remoteKubeConfig].actualValue
}

func ExtNodeUsername() string {
	return allConfigOptions[externalNodeUsername].actualValue
}

func ExtNodeSSHKey() string {
	return allConfigOptions[externalNodeIP].actualValue
}

func ExtNodeIP() string {
	return allConfigOptions[externalNodeIP].actualValue
}

func init() {
	// Load defaults and env variables
	for _, c := range allConfigOptions {
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
	for _, c := range allConfigOptions {
		if ev, exists := os.LookupEnv(c.envVarName); exists && ev != "" {
			c.actualValue = os.ExpandEnv(ev)
		} else {
			c.actualValue = os.ExpandEnv(c.defaultValue)
		}
	}
}

func RegisterFlags(flags *flag.FlagSet) {
	// Register each of the defined config options as a flag.
	for _, c := range allConfigOptions {
		flags.StringVar(&c.cmdLineValue, c.cliName(), "", c.helpText)
	}
}

func AfterReadingAllFlags() {
	// Make sure any supplied command line args override defaults and env variables
	for _, c := range allConfigOptions {
		if c.cmdLineValue != "" {
			c.actualValue = os.ExpandEnv(c.cmdLineValue)
		}
	}
	// Set logrus log level based on the LOG_LEVEL environment variable or command line flag.
	lvl := allConfigOptions[logLevel].actualValue
	if l, err := logrus.ParseLevel(lvl); lvl != "" && err != nil {
		logrus.Fatalf("Failed to parse LOG_LEVEL: %v", err)
	} else if lvl == "" {
		logrus.SetLevel(logrus.InfoLevel)
	} else {
		logrus.SetLevel(l)
	}

	// And log out the values of all config options.
	logrus.Infof("Running tests with the following configuration:")
	for _, c := range allConfigOptions {
		if c.actualValue != "" {
			logrus.Infof("%s => %s", c.envVarName, c.actualValue)
		}
	}
}
