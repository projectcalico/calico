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
	"os"
	"os/exec"
	"regexp"
	"strings"

	docopt "github.com/docopt/docopt-go"
	goversion "github.com/mcuadros/go-version"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/calicoctl/calicoctl/util"
)

// The minimum allowed linux kernel version is 2.6.24, which introduced network
// namespaces and veth pairs.
const minKernelVersion = "2.6.24"

// Required kernel modules to run Calico are saved in a two dimensional map variable.
// Keys are used to search in `lsmod` results or `modules.dep` and `modules.builtin` files.
// Values are used to search the the `kernel config` or `ip_tables_matches` file.
var requiredModules = map[string]string{
	"ip_set":               "CONFIG_IP_SET",
	"ip6_tables":           "CONFIG_IP6_NF_IPTABLES",
	"ip_tables":            "CONFIG_IP_NF_IPTABLES",
	"ipt_ipvs":             "CONFIG_NETFILTER_XT_MATCH_IPVS",
	"vfio-pci":             "CONFIG_VFIO",
	"xt_bpf":               "CONFIG_BPF",
	"ipt_REJECT":           "CONFIG_NFT_REJECT",
	"ipt_rpfilter":         "CONFIG_IP_NF_MATCH_RPFILTER",
	"xt_rpfilter":          "CONFIG_IP_NF_MATCH_RPFILTER",
	"ipt_set":              "CONFIG_NET_EMATCH_IPSET",
	"nf_conntrack_netlink": "CONFIG_NF_CT_NETLINK",
	"xt_addrtype":          "CONFIG_NETFILTER_XT_MATCH_ADDRTYPE",
	"xt_conntrack":         "CONFIG_NETFILTER_XT_MATCH_CONNTRACK",
	"xt_icmp":              "icmp",
	"xt_icmp6":             "icmp",
	"xt_mark":              "CONFIG_IP_NF_TARGET_MARK",
	"xt_multiport":         "CONFIG_IP_NF_MATCH_MULTIPORT",
	"xt_set":               "CONFIG_NETFILTER_XT_SET",
	"xt_u32":               "CONFIG_NETFILTER_XT_MATCH_U32"}

// Variable to override bootfile location.
var overrideBootFile = ""

// Checksystem checks host system for compatible versions
func Checksystem(args []string) error {
	doc := `Usage:
  <BINARY_NAME> node checksystem [--kernel-config=<kernel-config>] [--allow-version-mismatch]

Options:
  -h --help                             Show this screen.
  -f --kernel-config=<kernel-config>    Override the Kernel config file location.
                                        Expected format is plain text.
                                        default search locations:
                                          "/usr/src/linux/.config",
                                          "/boot/config-kernelVersion,
                                          "/usr/src/linux-kernelVersion/.config",
                                          "/usr/src/linux-headers-kernelVersion/.config",
                                          "/lib/modules/kernelVersion/build/.config"
     --allow-version-mismatch           Allow client and cluster versions mismatch.

Description:
  Check the compatibility of this compute host to run a Calico node instance.
`
	// Replace all instances of BINARY_NAME with the name of the binary.
	name, _ := util.NameAndDescription()
	doc = strings.ReplaceAll(doc, "<BINARY_NAME>", name)

	parsedArgs, err := docopt.ParseArgs(doc, args, "")
	if err != nil {
		return fmt.Errorf("Invalid option: 'calicoctl %s'. Use flag '--help' to read about a specific subcommand.", strings.Join(args, " "))
	}
	if len(parsedArgs) == 0 {
		return nil
	}

	// Note: Intentionally not check version mismatch for this command

	if parsedArgs["--kernel-config"] != nil {
		overrideBootFile = parsedArgs["--kernel-config"].(string)
	}
	// Make sure the command is run with super user privileges
	enforceRoot()

	systemOk := true

	fmt.Print("Checking kernel version...\n")
	err = checkKernelVersion()
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
		return fmt.Errorf("System doesn't meet one or more minimum systems requirements to run Calico")
	}

	fmt.Printf("System meets minimum system requirements to run Calico!\n")

	return nil
}

// checkKernelVersion checks for minimum required kernel version
func checkKernelVersion() error {
	kernelVersion, err := exec.Command("uname", "-r").Output()
	if err != nil {
		printResult("", "FAIL")
		fmt.Printf("Error executing command: %s\n", err)
		return err
	}

	// To strip the trailing `\n`
	kernelVersionStr := strings.TrimSpace(string(kernelVersion))

	// Goversion normalizes the versions and compares them returns `true` if
	// running version is >= minimum version
	if !goversion.CompareNormalized(kernelVersionStr, minKernelVersion, ">=") {

		// Prints "FAIL" if current version is not >= minimum required version
		printResult(kernelVersionStr, "FAIL")
		fmt.Printf("Minimum kernel version to run Calico is %s. Detected kernel version: %s", minKernelVersion, string(kernelVersion))
		return errors.New("Kernel version mismatch")
	}

	// Prints "OK" if current version is >= minimum required version
	printResult(kernelVersionStr, "OK")

	return nil
}

// checkKernelModules checks for all the required kernel modules in the system
func checkKernelModules() error {

	kernelVersion, err := exec.Command("uname", "-r").Output()
	if err != nil {
		fmt.Printf("Error executing command: %s\n", err)
		return err
	}

	// To strip the trailing `\n`
	kernelVersionStr := strings.TrimSpace(string(kernelVersion))

	// File path to Loadable kernel modules
	modulesLoadablePath := fmt.Sprintf("/lib/modules/%s/modules.dep", kernelVersionStr)

	// File path to Builtin kernel modules
	modulesBuiltinPath := fmt.Sprintf("/lib/modules/%s/modules.builtin", kernelVersionStr)

	// File path to module configs in boot time
	modulesBootPath := findBootFile(kernelVersionStr)

	// File path for loaded iptables modules
	modulesLoadedIPtables := "/proc/net/ip_tables_matches"

	// Keep track of modules that are not found
	modulesNotFound := []string{}

	// Execute lsmod and cache the result
	lsmodOut, err := exec.Command("lsmod").Output()
	if err != nil {
		fmt.Printf("Error executing command: %s\n", err)
		return err
	}

	// Go through all the required modules and check Loadable and Builtin in order
	for v, i := range requiredModules {
		err = checkModule(modulesLoadablePath, v, kernelVersionStr, "\\/%s.ko")

		// Check Builtin modules if not found in Loadable
		if err != nil {
			err = checkModule(modulesBuiltinPath, v, kernelVersionStr, "\\/%s.ko")

			// Check if it's in lsmod, if not found in Builtin either
			if err != nil {

				regex, err := regexp.Compile(v)
				if err != nil {
					log.Errorf("Error: %v\n", err)
					return err
				}

				if regex.MatchString(string(lsmodOut)) {
					printResult(v, "OK")
				} else if modulesBootPath != "" && checkModule(modulesBootPath, i, kernelVersionStr, "^%s=.") == nil {
					printResult(v, "OK")
					// Since `xt_icmp` and `xt_icmp6` are not available in most distros anymore as a last resort
					// this `if` condition will check currently loaded modules in iptables using `ip_tables_matches` file.
				} else if checkModule(modulesLoadedIPtables, i, kernelVersionStr, "^%s$") == nil {
					printResult(v, "OK")
				} else {
					fmt.Printf("WARNING: Unable to detect the %s module as Loaded/Builtin module or lsmod\n", v)
					modulesNotFound = append(modulesNotFound, v)
					printResult(v, "FAIL")
				}
			} else {
				printResult(v, "OK")
			}
		} else {
			printResult(v, "OK")
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
func checkModule(filename, module, kernelVersion string, pattern string) error {

	regex, err := regexp.Compile(fmt.Sprintf(pattern, module))
	if err != nil {
		log.Errorf("Error: %v\n", err)
		return err
	}

	fh, err := os.Open(filename)
	if err != nil {
		log.Errorf("Error: %v\n", err)
		return err
	}

	f := bufio.NewReader(fh)
	defer fh.Close()

	for {
		// Ignoring second output (isPrefix) since it's not necessory
		buf, _, err := f.ReadLine()
		if err != nil {
			// EOF without a match
			return errors.New("Module not found")
		}

		if regex.MatchString(string(buf)) {
			return nil
		}
	}
}

func findBootFile(kernelVersion string) string {
	// If user has provided an override kernelconfig file skip default locations.
	if overrideBootFile != "" {
		return overrideBootFile
	}

	// default locations that we will look for kernelconfig file.
	possibilePaths := []string{
		"/usr/src/linux/.config",
		"/boot/config-" + kernelVersion,
		"/usr/src/linux-" + kernelVersion + "/.config",
		"/usr/src/linux-headers-" + kernelVersion + "/.config",
		"/lib/modules/" + kernelVersion + "/build/.config"}

	for _, v := range possibilePaths {
		_, err := os.Stat(v)
		if err == nil {
			return v
		}
	}
	// If no config file is present, send an empty string.
	return ""
}

func printResult(val, result string) {
	fmt.Printf("\t\t%-20s\t\t\t\t\t%s\n", val, result)
}
