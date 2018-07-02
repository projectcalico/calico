// Copyright (c) 2017 Tigera, Inc. All rights reserved.
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
	"fmt"
	"os"
	"time"

	"github.com/projectcalico/kube-controllers/pkg/status"
)

// VERSION is filled out during the build process (using git describe output)
var VERSION string

// main is the main entry point into the anx controller.
func main() {

	// If `-v` is passed, display the version and exit.
	// Use a new flag set so as not to conflict with existing libraries which use "flag"
	flagSet := flag.NewFlagSet("check-status", flag.ExitOnError)
	version := flagSet.Bool("v", false, "Display version")
	file := flagSet.String("f", status.DefaultStatusFile, "File to read with status information")
	checkReady := flagSet.Bool("r", false, "Check readiness")
	err := flagSet.Parse(os.Args[1:])
	if err != nil {
		fmt.Println("Failed to parse flags")
		os.Exit(1)
	}
	if *version {
		fmt.Println(VERSION)
		os.Exit(0)
	}

	// Read the status file
	if *checkReady {
		var st *status.Status
		var err error
		// Try reading the status file up to 3 times.
		for i := 0; i < 3; i++ {
			st, err = status.ReadStatusFile(*file)
			if err != nil {
				time.Sleep(1 * time.Second)
				continue
			}
			break
		}
		if err != nil {
			fmt.Printf("Failed to read status file %s: %v\n", *file, err)
			os.Exit(1)
		}

		// Check if all components are ready
		if st.GetReadiness() {
			fmt.Println("Ready")
			os.Exit(0)
		}

		// If not ready, log the components that are not ready
		fmt.Println(st.GetNotReadyConditions())
		os.Exit(1)
	}

	fmt.Println("No command specified to check-status")
	os.Exit(1)
}
