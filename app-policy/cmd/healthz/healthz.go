// Copyright (c) 2019-2026 Tigera, Inc. All rights reserved.

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
	"fmt"
	"os"

	"github.com/projectcalico/calico/app-policy/pkg/healthz"
)

func main() {
	var dialPath string
	flag.StringVar(&dialPath, "dialPath", healthz.DefaultDialPath, "Path to health check gRPC service")
	flag.Parse()

	if len(flag.Args()) == 0 {
		fmt.Fprintf(os.Stderr, "Usage: %s (liveness|readiness)\n", os.Args[0])
		os.Exit(1)
	}

	healthz.Run(dialPath, flag.Arg(0))
}
