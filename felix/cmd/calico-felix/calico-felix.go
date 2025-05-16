// Copyright (c) 2017-2025 Tigera, Inc. All rights reserved.
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
	docopt "github.com/docopt/docopt-go"

	"github.com/projectcalico/calico/felix/daemon"
	"github.com/projectcalico/calico/lib/std/log"
	"github.com/projectcalico/calico/pkg/buildinfo"
)

const usage = `Felix, the Calico per-host daemon.

Usage:
  calico-felix [options]

Options:
  -c --config-file=<filename>  Config file to load [default: /etc/calico/felix.cfg].
  --version                    Print the version and exit.
`

// main is the entry point to the calico-felix binary.
func main() {
	// Parse command-line args.
	version := "Version:            " + buildinfo.Version + "\n" +
		"Full git commit ID: " + buildinfo.GitRevision + "\n" +
		"Build date:         " + buildinfo.BuildDate + "\n"
	arguments, err := docopt.ParseArgs(usage, nil, version)
	if err != nil {
		println(usage)
		log.Fatalf("Failed to parse usage, exiting: %v", err)
	}
	configFile := arguments["--config-file"].(string)

	// Execute felix.
	daemon.Run(configFile, buildinfo.Version, buildinfo.GitRevision, buildinfo.BuildDate)
}
