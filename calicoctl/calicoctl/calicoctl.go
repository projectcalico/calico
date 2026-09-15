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
	"fmt"
	"os"

	"github.com/projectcalico/calico/calicoctl/calicoctl/commands"
	"github.com/projectcalico/calico/calicoctl/calicoctl/util"
)

func main() {
	cmd := commands.NewCommand()
	// Use the invocation name (calicoctl, or kubectl-calico when run as a
	// kubectl plugin) as the root command name in help output.
	name, _ := util.NameAndDescription()
	cmd.Use = name

	if err := cmd.Execute(); err != nil {
		// NewCommand sets SilenceErrors and wraps every RunE with MassageError,
		// so the returned error is already user-facing; print it without a prefix.
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
