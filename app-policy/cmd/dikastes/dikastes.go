// Copyright (c) 2018-2026 Tigera, Inc. All rights reserved.

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
	"github.com/docopt/docopt-go"
	logrus "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/app-policy/pkg/dikastes"
	"github.com/projectcalico/calico/pkg/buildinfo"
)

const usage = `Dikastes - the decider.

Usage:
  dikastes server [options]
  dikastes client <namespace> <account> [--method <method>] [options]

Options:
  <namespace>            Service account namespace.
  <account>              Service account name.
  -h --help              Show this screen.
  -l --listen <port>     Unix domain socket path [default: /var/run/dikastes/dikastes.sock]
  -d --dial <target>     Target to dial. [default: localhost:50051]
  --debug                Log at Debug level.`

func main() {
	arguments, err := docopt.ParseArgs(usage, nil, buildinfo.Version)
	if err != nil {
		println(usage)
		return
	}
	if arguments["--debug"].(bool) {
		logrus.SetLevel(logrus.DebugLevel)
	}
	if arguments["server"].(bool) {
		filePath := arguments["--listen"].(string)
		dial := arguments["--dial"].(string)
		dikastes.RunServer(filePath, dial)
	} else if arguments["client"].(bool) {
		dial := arguments["--dial"].(string)
		namespace := arguments["<namespace>"].(string)
		account := arguments["<account>"].(string)
		method := ""
		if arguments["--method"].(bool) {
			method = arguments["<method>"].(string)
		}
		dikastes.RunClient(dial, namespace, account, method)
	}
}
