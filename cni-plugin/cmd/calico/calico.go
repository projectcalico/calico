// Copyright (c) 2018,2020 Tigera, Inc. All rights reserved.

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
	"os"
	"path/filepath"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/cni-plugin/pkg/install"
	"github.com/projectcalico/calico/cni-plugin/pkg/ipamplugin"
	"github.com/projectcalico/calico/cni-plugin/pkg/plugin"
)

// VERSION is filled out during the build process (using git describe output)
var VERSION string

func main() {
	// Use the name of the binary to determine which routine to run.
	_, filename := filepath.Split(os.Args[0])
	switch filename {
	case "calico", "calico.exe":
		plugin.Main(VERSION)
	case "calico-ipam", "calico-ipam.exe":
		ipamplugin.Main(VERSION)
	case "install":
		err := install.Install()
		if err != nil {
			logrus.WithError(err).Fatal("Error installing CNI plugin")
		}
	default:
		panic("Unknown binary name: " + filename)
	}
}
