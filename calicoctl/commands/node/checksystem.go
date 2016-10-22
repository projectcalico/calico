// Copyright (c) 2016 Tigera, Inc. All rights reserved.

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

package node

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strings"

	docopt "github.com/docopt/docopt-go"
	goversion "github.com/mcuadros/go-version"
)

// The minimum allowed linux kernel version is 2.6.24, which introduced network
// namespaces and veth pairs.
const minKernelVersion = "2.6.24"

// Required kernel modules to run Calico
var requiredModules = []string{"xt_set", "ip6_tables"}

// Checksystem checks host system for compatible versions
func Checksystem(args []string) error {
	doc := `Usage: 
  calicoctl node checksystem

Options:
  -h --help                 Show this screen.

Description:
  Check the compatibility of this compute host to run a Calico node instance.`

	// Note: This call is ignoring the error because error check happens at the level above
	// i.e at `node.go` before it calls `node.Status`. This call is just so help message gets
	// printed for this option
	_, _ = docopt.Parse(doc, args, true, "", false, false)

	// Make sure the command is run with super user priviladges
	if os.Getuid() != 0 {
		fmt.Println("Need super user privilages: Operation not permitted")
		os.Exit(1)
	}

	systemOk := true

	fmt.Print("Checking kernel version...\n")
	err := checkKernelVersion()
	if err != nil {
		systemOk = false
	}

	fmt.Print("Checking kernel modules...\n")
	err = checkKernelModules()
	if err != nil {
		systemOk = false
	}

	// If any of the checks fail, print a message and exit
	if !systemOk {
		fmt.Printf("%-20s\t\t\t%s", "System doesn't meet one or more minimum systems requirements to run Calico", "FAIL\n")
		os.Exit(1)
	}

	fmt.Printf("%-20s\t\t\t%s", "System meets minimum system requirements to run Calico!", "OK\n")

	return nil
}

// checkKernelVersion checks for minimum required kernel version
func checkKernelVersion() error {
	kernelVersion, err := exec.Command("uname", "-r").Output()
	if err != nil {
		log.Println(err)
	}

	// To strip the trailing `\n`
	kernelVersionStr := strings.TrimSpace(string(kernelVersion))

	// Print the version for the command output
	fmt.Printf("\t\t%-20s", kernelVersionStr)

	// Goversion normalizes the versions and compares them returns `true` if
	// running version is >= minimum version
	if !goversion.CompareNormalized(kernelVersionStr, minKernelVersion, ">=") {

		// Prints "FAIL" if current version is not >= minimum required version
		fmt.Printf("\t\t\t\t\tFAIL\n")
		log.Printf("Minimum kernel version to run Calico is %s. Detected kernel version: %s", minKernelVersion, string(kernelVersion))
		return errors.New("Kernel version mismatch")
	}

	// Prints "OK" if current version is >= minimum required version
	fmt.Printf("\t\t\t\t\tOK\n")

	return nil
}

// checkKernelModules checks for all the required kernel modules in the system
func checkKernelModules() error {

	kernelVersion, err := exec.Command("uname", "-r").Output()
	if err != nil {
		log.Println(err)
	}

	// To strip the trailing `\n`
	kernelVersionStr := strings.TrimSpace(string(kernelVersion))

	// File path to Loadable kernel modules
	modulesLoadablePath := fmt.Sprintf("/lib/modules/%s/modules.dep", kernelVersionStr)

	// File path to Builtin kernel modules
	modulesBuiltinPath := fmt.Sprintf("/lib/modules/%s/modules.builtin", kernelVersionStr)

	// Keep track of modules that are not found
	modulesNotFound := []string{}

	// Execute lsmod and cache the result
	lsmodOut, err := exec.Command("lsmod").Output()
	if err != nil {
		log.Println(err)
	}

	// Go through all the required modules and check Loadable and Builtin in order
	for _, v := range requiredModules {
		err = checkModule(modulesLoadablePath, v, kernelVersionStr)

		// Check Builtin modules if not found in Loadable
		if err != nil {
			err = checkModule(modulesBuiltinPath, v, kernelVersionStr)

			// Check if it's in lsmod, if not found in Builtin either
			if err != nil {

				regex, err := regexp.Compile(v)
				if err != nil {
					log.Fatalf("Error: %v\n", err)
				}

				if !regex.MatchString(string(lsmodOut)) {
					log.Printf("WARNING: Unable to detect the %s module as Loaded/Builtin module or lsmod\n", v)
					modulesNotFound = append(modulesNotFound, v)
					fmt.Printf("\t\t%-20s%s", v, "\t\t\t\t\tFAIL\n")
				} else {
					fmt.Printf("\t\t%-20s%s", v, "\t\t\t\t\tOK\n")
				}
			} else {
				fmt.Printf("\t\t%-20s%s", v, "\t\t\t\t\tOK\n")
			}
		} else {
			fmt.Printf("\t\t%-20s%s", v, "\t\t\t\t\tOK\n")
		}
	}

	// If there are still any modules not found then return an error
	if len(modulesNotFound) > 0 {

		// ip6_tables is not a required module for ipv4 setups, so just print
		// a warning instead of failing the system check
		if len(modulesNotFound) == 1 && modulesNotFound[0] == "ip6_tables" {
			fmt.Printf("WARNING: IPv6 will be unavailable as ip6_tables kernel module is not found\n")
			return nil
		}
		return errors.New("One of more kernel modules missing")
	}

	return nil
}

// checkModule is a utility function used by `checkKernelModules`
// it opens the file provided and checks if the module passed in
// as an argument exists for the provided kernelVersion
func checkModule(filename, module, kernelVersion string) error {

	regex, err := regexp.Compile(fmt.Sprintf("\\/%s.ko", module))
	if err != nil {
		log.Fatalf("Error: %v\n", err)
	}

	fh, err := os.Open(filename)
	if err != nil {
		log.Fatalf("Error: %v\n", err)
	}

	f := bufio.NewReader(fh)
	defer fh.Close()

	// Make a byte buffer to read lines
	buf := make([]byte, 1024)

	for {

		// Ignoring second output (isPrefix) since it's not necessory
		buf, _, err = f.ReadLine()
		if err != nil {

			// EOF without a match
			return errors.New("Module not found")
		}

		if regex.MatchString(string(buf)) {
			return nil
		}
	}

}
