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

// cilanes explains why an e2e lane runs or drops each spec, without writing
// anything. Run `cilanes explain` for its usage.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/projectcalico/calico/e2e/pkg/cilanes"
)

const usage = "usage: cilanes explain [-repo-root dir] [-binary path] <lane> [spec]"

func main() {
	if len(os.Args) < 2 || os.Args[1] != "explain" {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}

	flags := flag.NewFlagSet("explain", flag.ExitOnError)
	repoRoot := flags.String("repo-root", ".", "path to the repository root")
	binary := flags.String("binary", "e2e/bin/k8s/e2e.test", "e2e test binary, relative to the repo root")
	flags.Usage = func() {
		fmt.Fprintln(os.Stderr, usage)
		flags.PrintDefaults()
	}
	if err := flags.Parse(os.Args[2:]); err != nil {
		os.Exit(2)
	}
	if flags.NArg() < 1 || flags.NArg() > 2 {
		flags.Usage()
		os.Exit(2)
	}

	spec := ""
	if flags.NArg() == 2 {
		spec = flags.Arg(1)
	}
	if err := explain(*repoRoot, *binary, flags.Arg(0), spec); err != nil {
		fmt.Fprintln(os.Stderr, "cilanes:", err)
		os.Exit(1)
	}
}

// explain audits the lane the query names and prints the result.
func explain(repoRoot, binary, query, spec string) error {
	lanes, err := cilanes.Load(repoRoot)
	if err != nil {
		return err
	}
	name, lane, err := cilanes.FindLane(lanes, query)
	if err != nil {
		return err
	}

	binary, err = filepath.Abs(filepath.Join(repoRoot, binary))
	if err != nil {
		return err
	}
	audit, err := cilanes.AuditLane(binary, repoRoot, lane)
	if err != nil {
		return err
	}
	fmt.Print(cilanes.Explain(name, lane, audit, spec))
	return nil
}
