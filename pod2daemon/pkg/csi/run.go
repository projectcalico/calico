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

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
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
	logrus.SetOutput(os.Stdout)
	logutils.ConfigureFormatter("csi-driver")
	logrus.SetLevel(logrus.WarnLevel)

	driverCfg, err := driver.RetrieveConfig()
	if err != nil {
		logrus.WithError(err).Fatal("Failed to retrieve CSI driver config")
	}

	if cfg.LogLevel != "" {
		driverCfg.LogLevel = cfg.LogLevel
	}

	level, err := logrus.ParseLevel(driverCfg.LogLevel)
	if err != nil {
		logrus.WithError(err).Fatalf("Could not parse the log level")
	}
	logrus.SetLevel(level)

	driverCfg.NodeID = cfg.NodeID

	if cfg.Endpoint != "" {
		driverCfg.Endpoint = cfg.Endpoint
	}

	d := driver.NewDriver(driverCfg)
	if err := d.Run(); err != nil {
		logrus.WithError(err).Fatal("CSI driver failed")
	}
}
