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

// Run starts the CSI driver. It loads configuration from the standard config file,
// applies any overrides from the provided parameters, and blocks serving gRPC.
func Run(logLevel, endpoint, nodeID string) {
	logrus.SetOutput(os.Stdout)
	logutils.ConfigureFormatter("csi-driver")
	logrus.SetLevel(logrus.WarnLevel)

	config, err := driver.RetrieveConfig()
	if err != nil {
		logrus.WithError(err).Fatal("Failed to retrieve CSI driver config")
	}

	if logLevel != "" {
		config.LogLevel = logLevel
	}

	level, err := logrus.ParseLevel(config.LogLevel)
	if err != nil {
		logrus.WithError(err).Fatalf("Could not parse the log level")
	}
	logrus.SetLevel(level)

	config.NodeID = nodeID

	if endpoint != "" {
		config.Endpoint = endpoint
	}

	d := driver.NewDriver(config)
	if err := d.Run(); err != nil {
		logrus.WithError(err).Fatal("CSI driver failed")
	}
}
