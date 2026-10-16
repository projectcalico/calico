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

// Command scratch-utils bundles the CI VM helpers into one binary dispatched by
// subcommand -- one image, different args, not four binaries:
//
//	scratch-utils createvm                       create the CI GCE VM (config from env)
//	scratch-utils deletevm                       delete it by name, best-effort
//	scratch-utils secret <ENV_VAR> <DEST_PATH>   env var -> file
//	scratch-utils runonvm [flags] <script>       run a script on the VM over SSH
//
// No gcloud or bash dependency, so it runs from a distroless image. The ENTRYPOINT
// is this binary, so a pod passes the subcommand as an ARGUMENT -- `args:
// [createvm]`; a bare `command: [createvm]` replaces the entrypoint and fails.
package main

import (
	"fmt"
	"os"

	"github.com/projectcalico/calico/toolchain/internal/scratchutils/subcmd/createvm"
	"github.com/projectcalico/calico/toolchain/internal/scratchutils/subcmd/deletevm"
	"github.com/projectcalico/calico/toolchain/internal/scratchutils/subcmd/runonvm"
	"github.com/projectcalico/calico/toolchain/internal/scratchutils/subcmd/secret"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	sub := os.Args[1]
	// Each subcommand then sees its own args as os.Args[1:].
	os.Args = append([]string{os.Args[0] + " " + sub}, os.Args[2:]...)

	switch sub {
	case "createvm":
		os.Exit(createvm.Run())
	case "deletevm":
		os.Exit(deletevm.Run())
	case "secret":
		os.Exit(secret.Run())
	case "runonvm":
		os.Exit(runonvm.Run())
	default:
		fmt.Fprintf(os.Stderr, "scratch-utils: unknown subcommand %q\n", sub)
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: scratch-utils <createvm|deletevm|secret|runonvm> [args]")
}
