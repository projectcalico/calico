// Copyright (c) 2022 Tigera, Inc. All rights reserved.
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
	"flag"
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
	"github.com/projectcalico/calico/pod2daemon/csidriver/driver"
)

func main() {
	// Set the log output to stdout to prevent some components from interpretting logs as errors (e.g. fluentd).
	log.SetOutput(os.Stdout)
	// Install a hook that adds file/line no information
	log.AddHook(&logutils.ContextHook{})
	// Set up log formatting to reference this component.
	log.SetFormatter(&logutils.Formatter{Component: "csi-driver"})
	// Set the preliminary log level
	log.SetLevel(log.WarnLevel)

	// Read out the configurable settings
	logLevel := flag.String("loglevel", "", "Log level for the driver to report on")
	endpoint := flag.String("endpoint", "", "location of the unix domain socket the Kubelet communicates with the CSI plugin on")
	nodeId := flag.String("nodeid", "", "Node ID unique to the node")
	flag.Parse()

	// Parse and inspect the configuration
	config, err := driver.RetrieveConfig()
	if err != nil {
		log.Fatal(err)
	}

	// Overwrite the log level from the flag if given
	if *logLevel != "" {
		config.LogLevel = *logLevel
	}

	// Set the log level from the configuration
	level, err := log.ParseLevel(config.LogLevel)
	if err != nil {
		log.Fatalf("Could not parse the log level: %v", err)
	}
	log.SetLevel(level)

	// Overwrite the node ID given from the flag
	config.NodeID = *nodeId

	// Overwrite the endpoint given from the flag if given
	if *endpoint != "" {
		config.Endpoint = *endpoint
	}

	// Instantiate driver and run
	d := driver.NewDriver(config)
	if err := d.Run(); err != nil {
		log.Fatal(err)
	}
}
