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

package main

import (
	"flag"

	"github.com/projectcalico/calico/pod2daemon/pkg/csi"
)

func main() {
	logLevel := flag.String("loglevel", "", "Log level for the driver to report on")
	endpoint := flag.String("endpoint", "", "location of the unix domain socket the Kubelet communicates with the CSI plugin on")
	nodeID := flag.String("nodeid", "", "Node ID unique to the node")
	flag.Parse()

	csi.Run(*logLevel, *endpoint, *nodeID)
}
