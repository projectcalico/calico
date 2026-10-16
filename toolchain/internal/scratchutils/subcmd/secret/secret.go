// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

// Package secret materializes a mounted-secret env var to a file, the Go form of
// cc-utils' createLocalSecret. Usage: secret NAME PATH.
package secret

import (
	"fmt"
	"os"

	"github.com/projectcalico/calico/toolchain/internal/scratchutils/util"
)

// Run executes the secret subcommand and returns its exit code.
func Run() int {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: secret <ENV_VAR_NAME> <DEST_PATH>")
		return 2
	}
	found, err := util.LocalSecret(os.Args[1], os.Args[2])
	if err != nil {
		fmt.Fprintf(os.Stderr, "secret: %v\n", err)
		return 1
	}
	if !found {
		fmt.Printf("secret %s not created (env var not set)\n", os.Args[1])
		return 0
	}
	fmt.Printf("created %s\n", os.Args[2])
	return 0
}
