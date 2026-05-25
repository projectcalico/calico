// Copyright (c) 2022-2026 Tigera, Inc. All rights reserved.
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

package csi

import (
	"os"

	"github.com/projectcalico/calico/lib/std/log"
	"github.com/projectcalico/calico/pod2daemon/csidriver/driver"
)

// Config holds the CLI-provided configuration for the CSI driver.
type Config struct {
	LogLevel string
	Endpoint string
	NodeID   string
}

// Run starts the CSI driver. It loads configuration from the standard config file,
// applies any overrides from cfg, and blocks serving gRPC.
func Run(cfg Config) {
	log.SetOutput(os.Stdout)
	log.SetComponent("csi-driver")
	log.SetLevel(log.WarnLevel)

	driverCfg, err := driver.RetrieveConfig()
	if err != nil {
		log.WithError(err).Fatal("Failed to retrieve CSI driver config")
	}

	if cfg.LogLevel != "" {
		driverCfg.LogLevel = cfg.LogLevel
	}

	level, err := log.ParseLevel(driverCfg.LogLevel)
	if err != nil {
		log.WithError(err).WithField("logLevel", driverCfg.LogLevel).Fatal("Could not parse the log level")
	}
	log.SetLevel(level)

	driverCfg.NodeID = cfg.NodeID

	if cfg.Endpoint != "" {
		driverCfg.Endpoint = cfg.Endpoint
	}

	d := driver.NewDriver(driverCfg)
	if err := d.Run(); err != nil {
		log.WithError(err).Fatal("CSI driver failed")
	}
}
