// Copyright (c) 2025 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package utils

import (
	"os"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
)

// ConfigureLogging configures the logging framework. The logging level that will
// be used is passed in as a parameter. Otherwise, it will default to WARN
// The output will be set to STDOUT and the format is TextFormat
func ConfigureLogging(logLevel string) {
	// Install a hook that adds file/line number information.
	logutils.ConfigureFormatter("goldmane")
	logrus.SetOutput(os.Stdout)

	// Override with desired log level
	level, err := logrus.ParseLevel(logLevel)
	if err != nil {
		logrus.Error("Invalid logging level passed in. Will use default level set to WARN")
		// Setting default to WARN
		level = logrus.WarnLevel
	}

	logrus.SetLevel(level)
}
