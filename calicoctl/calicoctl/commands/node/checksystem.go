// Copyright (c) 2016-2026 Tigera, Inc. All rights reserved.

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
	"path/filepath"
	"regexp"
	"strings"

	goversion "github.com/mcuadros/go-version"
	log "github.com/sirupsen/logrus"
)

// The minimum allowed linux kernel version is 2.6.24, which introduced network
// namespaces and veth pairs.
const minKernelVersion = "2.6.24"

// moduleCheck describes how to detect a kernel feature Calico may need.
//
// Name is the historical module name shown to the user.
// ConfigOptions are CONFIG_* symbols looked up in the kernel .config (any match is OK).
// IPTMatches are tokens looked up in /proc/net/ip_tables_matches (any match is OK).
// Alternatives are other module names that provide the same feature (e.g. xt_set for ipt_set).
// Optional modules only produce a WARNING when missing and do not fail the check.
type moduleCheck struct {
	Name          string
	ConfigOptions []string
	IPTMatches    []string
	Alternatives  []string
	Optional      bool
	SkipModProbe  bool // feature is not a real loadable module on modern kernels
}

// requiredModules is the list of kernel features checked by `calicoctl node checksystem`.
// Stale xt_icmp/xt_icmp6 module names are replaced with iptables-match / kconfig probes.
// ipt_set is treated as satisfied by xt_set (the modern equivalent).
var requiredModules = []moduleCheck{
	{Name: "ip_set", ConfigOptions: []string{"CONFIG_IP_SET"}},
	{Name: "ip6_tables", ConfigOptions: []string{"CONFIG_IP6_NF_IPTABLES"}, Optional: true},
	{Name: "ip_tables", ConfigOptions: []string{"CONFIG_IP_NF_IPTABLES"}},
	{Name: "ipt_ipvs", ConfigOptions: []string{"CONFIG_NETFILTER_XT_MATCH_IPVS"}, Alternatives: []string{"xt_ipvs"}},
	{Name: "vfio-pci", ConfigOptions: []string{"CONFIG_VFIO", "CONFIG_VFIO_PCI"}, Alternatives: []string{"vfio_pci"}},
	{Name: "xt_bpf", ConfigOptions: []string{"CONFIG_BPF", "CONFIG_NETFILTER_XT_MATCH_BPF"}, Optional: true},
	{Name: "ipt_REJECT", ConfigOptions: []string{"CONFIG_IP_NF_TARGET_REJECT", "CONFIG_NFT_REJECT", "CONFIG_NETFILTER_XT_TARGET_REJECT"}, Alternatives: []string{"xt_REJECT"}},
	{Name: "ipt_rpfilter", ConfigOptions: []string{"CONFIG_IP_NF_MATCH_RPFILTER"}, Alternatives: []string{"xt_rpfilter"}},
	{Name: "xt_rpfilter", ConfigOptions: []string{"CONFIG_IP_NF_MATCH_RPFILTER", "CONFIG_IP6_NF_MATCH_RPFILTER", "CONFIG_NETFILTER_XT_MATCH_RPFILTER"}, Alternatives: []string{"ipt_rpfilter"}},
	// ipt_set is obsolete on modern kernels; xt_set provides the same match.
	{Name: "ipt_set", ConfigOptions: []string{"CONFIG_NETFILTER_XT_SET", "CONFIG_IP_SET"}, Alternatives: []string{"xt_set"}},
	{Name: "nf_conntrack_netlink", ConfigOptions: []string{"CONFIG_NF_CT_NETLINK"}},
	{Name: "xt_addrtype", ConfigOptions: []string{"CONFIG_NETFILTER_XT_MATCH_ADDRTYPE"}},
	{Name: "xt_conntrack", ConfigOptions: []string{"CONFIG_NETFILTER_XT_MATCH_CONNTRACK"}},
	// xt_icmp / xt_icmp6 are not shipped as standalone modules on modern distros;
	// the icmp match is built into iptables or provided via kconfig.
	{
		Name:          "xt_icmp",
		ConfigOptions: []string{"CONFIG_IP_NF_MATCH_ICMP", "CONFIG_NETFILTER_XT_MATCH_ICMP"},
		IPTMatches:    []string{"icmp"},
		SkipModProbe:  true,
	},
	{
		Name:          "xt_icmp6",
		ConfigOptions: []string{"CONFIG_IP6_NF_MATCH_IPV6HEADER", "CONFIG_IP6_NF_MATCH_ICMP6", "CONFIG_NETFILTER_XT_MATCH_ICMP"},
		IPTMatches:    []string{"icmp6", "icmpv6", "ipv6header"},
		SkipModProbe:  true,
		Optional:      true, // IPv4-only clusters do not need icmp6
	},
	{Name: "xt_mark", ConfigOptions: []string{"CONFIG_NETFILTER_XT_MARK", "CONFIG_IP_NF_TARGET_MARK", "CONFIG_NETFILTER_XT_TARGET_MARK"}},
	{Name: "xt_multiport", ConfigOptions: []string{"CONFIG_NETFILTER_XT_MATCH_MULTIPORT", "CONFIG_IP_NF_MATCH_MULTIPORT"}},
	{Name: "xt_set", ConfigOptions: []string{"CONFIG_NETFILTER_XT_SET"}, Alternatives: []string{"ipt_set"}},
	// xt_u32 is not required for standard Calico operation.
	{Name: "xt_u32", ConfigOptions: []string{"CONFIG_NETFILTER_XT_MATCH_U32"}, Optional: true},
}

// Variable to override bootfile location.
var overrideBootFile = ""

// Checksystem checks host system for compatible versions. A non-empty
// kernelConfig overrides the kernel config file search location.
func Checksystem(kernelConfig string) error {
	if kernelConfig != "" {
		overrideBootFile = kernelConfig
	}
	// Make sure the command is run with super user privileges
	enforceRoot()

	systemOk := true

	fmt.Print("Checking kernel version...\n")
	if err := checkKernelVersion(); err != nil {
		systemOk = false
	}

	fmt.Print("Checking kernel modules...\n")
	if err := checkKernelModules(); err != nil {
		systemOk = false
	}

	// If any of the checks fail, print a message and exit
	if !systemOk {
		return fmt.Errorf("system doesn't meet one or more minimum systems requirements to run Calico")
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
		return errors.New("kernel version mismatch")
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
	lsmodStr := string(lsmodOut)

	// Go through all the required modules and check Loadable and Builtin in order
	for _, mod := range requiredModules {
		if moduleAvailable(mod, modulesLoadablePath, modulesBuiltinPath, modulesBootPath, modulesLoadedIPtables, lsmodStr) {
			printResult(mod.Name, "OK")
			continue
		}

		if mod.Optional {
			fmt.Printf("WARNING: Unable to detect optional module/feature %s; continuing\n", mod.Name)
			printResult(mod.Name, "SKIP")
			continue
		}

		fmt.Printf("WARNING: Unable to detect the %s module as Loaded/Builtin module or lsmod\n", mod.Name)
		modulesNotFound = append(modulesNotFound, mod.Name)
		printResult(mod.Name, "FAIL")
	}

	// If there are still any modules not found then return an error
	if len(modulesNotFound) > 0 {
		return errors.New("one of more kernel modules missing")
	}

	return nil
}

// moduleAvailable reports whether a required kernel feature is present.
func moduleAvailable(mod moduleCheck, loadablePath, builtinPath, bootPath, iptMatchesPath, lsmodOut string) bool {
	candidates := []string{mod.Name}
	candidates = append(candidates, mod.Alternatives...)

	for _, name := range candidates {
		// /sys/module/<name> exists for both loaded and built-in modules.
		if modulePresentInSysfs(name) {
			return true
		}

		// modules.dep may list .ko, .ko.gz, .ko.xz, .ko.zst
		if checkModuleFile(loadablePath, name) == nil {
			return true
		}

		// modules.builtin uses the same basenames without compression suffixes.
		if checkModuleFile(builtinPath, name) == nil {
			return true
		}

		// lsmod uses underscores; accept hyphen/underscore variants.
		if lsmodHasModule(lsmodOut, name) {
			return true
		}
	}

	// Kernel .config options (built-in =y or module =m).
	if bootPath != "" {
		for _, cfg := range mod.ConfigOptions {
			if cfg == "" {
				continue
			}
			if checkModule(bootPath, cfg, "", "^%s=[ym]") == nil {
				return true
			}
		}
	}

	// Loaded iptables match names (useful for icmp which is not a standalone module).
	for _, match := range mod.IPTMatches {
		if checkModule(iptMatchesPath, match, "", "^%s$") == nil {
			return true
		}
	}

	return false
}

func modulePresentInSysfs(name string) bool {
	// sysfs uses underscores
	sysName := strings.ReplaceAll(name, "-", "_")
	if _, err := os.Stat(filepath.Join("/sys/module", sysName)); err == nil {
		return true
	}
	return false
}

func lsmodHasModule(lsmodOut, name string) bool {
	// Match module name as a whole field at the start of a line (lsmod format).
	for _, candidate := range []string{name, strings.ReplaceAll(name, "-", "_"), strings.ReplaceAll(name, "_", "-")} {
		re, err := regexp.Compile(`(?m)^` + regexp.QuoteMeta(candidate) + `\s`)
		if err != nil {
			continue
		}
		if re.MatchString(lsmodOut) {
			return true
		}
	}
	return false
}

// checkModuleFile looks for a module basename in modules.dep / modules.builtin,
// accepting compressed object suffixes used by modern distros.
func checkModuleFile(filename, module string) error {
	// Match /module.ko or /module.ko.gz etc. anywhere on the line.
	pattern := `/` + regexp.QuoteMeta(module) + `\.ko(\.(gz|xz|zst|bz2))?`
	re, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}

	fh, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer func() { _ = fh.Close() }()

	scanner := bufio.NewScanner(fh)
	// modules.dep lines can be long
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		if re.MatchString(scanner.Text()) {
			return nil
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return errors.New("module not found")
}

// checkModule is a utility function used by `checkKernelModules`
// it opens the file provided and checks if the module passed in
// as an argument exists for the provided kernelVersion
func checkModule(filename, module, kernelVersion string, pattern string) error {
	regex, err := regexp.Compile(fmt.Sprintf(pattern, regexp.QuoteMeta(module)))
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
	defer func() { _ = fh.Close() }()

	for {
		// Ignoring second output (isPrefix) since it's not necessary
		buf, _, err := f.ReadLine()
		if err != nil {
			// EOF without a match
			return errors.New("module not found")
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
		"/lib/modules/" + kernelVersion + "/build/.config",
	}

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
