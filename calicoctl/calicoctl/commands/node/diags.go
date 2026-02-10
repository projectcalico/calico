// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.

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
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/docopt/docopt-go"
	log "github.com/sirupsen/logrus"
	shutil "github.com/termie/go-shutil"

	"github.com/projectcalico/calico/calicoctl/calicoctl/util"
)

// containerRuntime represents a detected container runtime
type containerRuntime int

const (
	runtimeUnknown containerRuntime = iota
	runtimeDocker
	runtimeContainerd
	runtimeCRIO
)

// diagCmd is a struct to hold a command, cmd info and filename to run diagnostic on
type diagCmd struct {
	info     string
	cmd      string
	filename string
}

// detectContainerRuntime detects which container runtime is available on the system
func detectContainerRuntime() containerRuntime {
	// Check for crictl first (most common for Kubernetes with containerd)
	if _, err := exec.LookPath("crictl"); err == nil {
		log.Debug("Detected crictl (containerd/CRI-O)")
		return runtimeCRIO
	}

	// Check for ctr (containerd native CLI)
	if _, err := exec.LookPath("ctr"); err == nil {
		log.Debug("Detected ctr (containerd)")
		return runtimeContainerd
	}

	// Check for docker
	if _, err := exec.LookPath("docker"); err == nil {
		log.Debug("Detected docker")
		return runtimeDocker
	}

	log.Debug("No container runtime detected")
	return runtimeUnknown
}

// getIPSetCommand returns the appropriate command to run ipset in a container based on detected runtime
func getIPSetCommand(runtime containerRuntime) string {
	switch runtime {
	case runtimeDocker:
		return "docker run --rm --privileged --net=host calico/node ipset list"
	case runtimeCRIO:
		// crictl doesn't support running one-off commands, so we try to exec into a running calico-node pod
		// This command attempts to find and exec into the calico-node container
		return "crictl exec $(crictl ps --name calico-node -q | head -1) ipset list"
	case runtimeContainerd:
		// ctr can exec into running containers in the k8s.io namespace
		return "ctr -n k8s.io task exec --exec-id diag-ipset $(ctr -n k8s.io c ls -q | grep calico-node | head -1) ipset list"
	default:
		return ""
	}
}

// Diags function collects diagnostic information and logs
func Diags(args []string) error {
	var err error
	doc := `Usage:
  <BINARY_NAME> node diags [--log-dir=<LOG_DIR>] [--allow-version-mismatch]

Options:
  -h --help                    Show this screen.
     --log-dir=<LOG_DIR>       The directory containing Calico logs.
                               [default: /var/log/calico]
     --allow-version-mismatch  Allow client and cluster versions mismatch.

Description:
  This command is used to gather diagnostic information from a Calico node.
  This is usually used when trying to diagnose an issue that may be related to
  your Calico network.

  This command must be run on the specific Calico node that you are gathering
  diagnostics for.
`
	// Replace all instances of BINARY_NAME with the name of the binary.
	name, _ := util.NameAndDescription()
	doc = strings.ReplaceAll(doc, "<BINARY_NAME>", name)

	arguments, err := docopt.ParseArgs(doc, args, "")
	if err != nil {
		return fmt.Errorf("invalid option: 'calicoctl %s'. Use flag '--help' to read about a specific subcommand", strings.Join(args, " "))
	}
	if len(arguments) == 0 {
		return nil
	}

	// Note: Intentionally not check version mismatch for this command

	return runDiags(arguments["--log-dir"].(string))
}

// runDiags takes logDir and runs a sequence of commands to collect diagnostics
func runDiags(logDir string) error {
	// Detect container runtime early
	runtime := detectContainerRuntime()

	// Note: in for the cmd field in this struct, it  can't handle args quoted with space in it
	// For example, you can't add cmd "do this", since after the `strings.Fields` it will become `"do` and `this"`
	cmds := []diagCmd{
		{"", "date", "date"},
		{"", "hostname", "hostname"},
		{"Dumping routes (IPv4)", "ip -4 route", "ipv4_route"},
		{"Dumping routes (IPv6)", "ip -6 route", "ipv6_route"},
		{"Dumping interface info (IPv4)", "ip -4 addr", "ipv4_addr"},
		{"Dumping interface info (IPv6)", "ip -6 addr", "ipv6_addr"},
		{"Dumping nftables", "nft -n -a list ruleset", "nft_ruleset"},
		{"Dumping iptables (IPv4)", "iptables-save -c", "ipv4_tables"},
		{"Dumping iptables (IPv6)", "ip6tables-save -c", "ipv6_tables"},
		{"Dumping ipsets", "ipset list", "ipsets"},
		{"Copying journal for calico-node.service", "journalctl -u calico-node.service --no-pager", "journalctl_calico_node"},
		{"Dumping felix stats", "pkill -SIGUSR1 felix", ""},
	}

	// Add container ipset command only if a runtime is detected
	ipsetCmd := getIPSetCommand(runtime)
	if ipsetCmd != "" {
		// Insert after "Dumping ipsets" command
		cmds = append(cmds, diagCmd{
			"Dumping ipsets (container)", ipsetCmd, "ipset_container",
		})
	}

	// Make sure the command is run with super user privileges
	enforceRoot()

	fmt.Println("Collecting diagnostics")

	// Create a temp directory in /tmp
	tmpDir, err := os.MkdirTemp("", "calico")
	if err != nil {
		return fmt.Errorf("error creating temp directory to dump logs: %v", err)
	}

	fmt.Println("Using temp dir:", tmpDir)
	err = os.Chdir(tmpDir)
	if err != nil {
		return fmt.Errorf("error changing directory to temp directory to dump logs: %v", err)
	}

	err = os.MkdirAll("diagnostics", os.ModeDir)
	if err != nil {
		return fmt.Errorf("error creating diagnostics directory: %v", err)
	}
	diagsTmpDir := filepath.Join(tmpDir, "diagnostics")

	netstatCmd := diagCmd{
		info:     "Dumping netstat",
		cmd:      "netstat -a -n",
		filename: "netstat",
	}

	ssCmd := diagCmd{
		info:     "Dumping ss",
		cmd:      "ss -a -n",
		filename: "ss",
	}
	// sometimes socket information is not collected as netstat tool
	// is obsolete and removed in Ubuntu and other distros. so when
	// "netstat -a -n " fails, we should use "ss -a -n" instead of it
	if _, err := exec.LookPath(netstatCmd.filename); err == nil {
		cmds = append(cmds, netstatCmd)
	} else {
		cmds = append(cmds, ssCmd)
	}

	for _, v := range cmds {
		_ = writeDiags(v, diagsTmpDir)
	}

	tmpLogDir := filepath.Join(diagsTmpDir, "logs")

	// Check if the logDir provided/default exists and is a directory
	fileInfo, err := os.Stat(logDir)
	if err != nil {
		fmt.Printf("Error copying log files: %v\n", err)
	} else if fileInfo.IsDir() {
		fmt.Println("Copying Calico logs")
		err = shutil.CopyTree(logDir, tmpLogDir, nil)
		if err != nil {
			fmt.Printf("Error copying log files: %v\n", err)
		}
	} else {
		fmt.Printf("No logs found in %s; skipping log copying", logDir)
	}

	// Try to copy logs from containers for hosted installs.
	getNodeContainerLogs(tmpLogDir, runtime)

	// Get the current time and create a tar.gz file with the timestamp in the name
	tarFile := fmt.Sprintf("diags-%s.tar.gz", time.Now().Format("20060102_150405"))

	// Have to use shell to compress the file because Go archive/tar can't handle
	// some header metadata longer than a certain length (Ref: https://github.com/golang/go/issues/12436)
	err = exec.Command("tar", "-zcvf", tarFile, "diagnostics").Run()
	if err != nil {
		fmt.Printf("Error compressing the diagnostics: %v\n", err)
	}

	tarFilePath := filepath.Join(tmpDir, tarFile)

	fmt.Printf("\nDiags saved to %s\n", tarFilePath)
	fmt.Println("If required, you can upload the diagnostics bundle to a file sharing service.")

	return nil
}

// getNodeContainerLogs will attempt to grab logs for any "calico" named containers for hosted installs.
func getNodeContainerLogs(logDir string, runtime containerRuntime) {
	err := os.MkdirAll(logDir, os.ModeDir)
	if err != nil {
		fmt.Printf("Error creating log directory: %v\n", err)
		return
	}

	var result []byte
	var containers string

	switch runtime {
	case runtimeDocker:
		// Get a list of Calico containers running on this Node.
		result, err = exec.Command("docker", "ps", "-a", "--filter", "name=calico", "--format", "{{.Names}}: {{.CreatedAt}}").CombinedOutput()
		if err != nil {
			fmt.Printf("Could not run docker command: %s\n", string(result))
			return
		}
		containers = string(result)

	case runtimeCRIO:
		// Use crictl to get container list
		result, err = exec.Command("crictl", "ps", "-a", "--name", "calico").CombinedOutput()
		if err != nil {
			fmt.Printf("Could not run crictl command: %s\n", string(result))
			return
		}
		containers = string(result)

	case runtimeContainerd:
		// Use ctr to get container list
		result, err = exec.Command("ctr", "-n", "k8s.io", "containers", "list").CombinedOutput()
		if err != nil {
			fmt.Printf("Could not run ctr command: %s\n", string(result))
			return
		}
		// Filter for calico containers
		lines := strings.Split(string(result), "\n")
		var calicoContainers []string
		for _, line := range lines {
			if strings.Contains(line, "calico") {
				calicoContainers = append(calicoContainers, line)
			}
		}
		containers = strings.Join(calicoContainers, "\n")

	default:
		log.Debug("No supported container runtime found for log collection")
		return
	}

	// No Calico containers found.
	if containers == "" {
		log.Debug("Did not find any Calico containers")
		return
	}

	// Remove any containers that have "k8s_POD" in them.
	re := regexp.MustCompile("(?m)[\r\n]+^.*k8s_POD.*$")
	containers = re.ReplaceAllString(containers, "")

	fmt.Println("Copying logs from Calico containers")
	err = os.WriteFile(logDir+"/"+"container_creation_time", []byte(containers), 0o666)
	if err != nil {
		fmt.Printf("Could not save output of container list command to container_creation_time: %s\n", err)
	}

	// Grab the log for each container based on runtime
	getContainerLogs(logDir, containers, runtime)
}

// getContainerLogs retrieves logs for each container based on the runtime
func getContainerLogs(logDir, containers string, runtime containerRuntime) {
	scanner := bufio.NewScanner(strings.NewReader(containers))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		var name string
		var logCmd *exec.Cmd

		switch runtime {
		case runtimeDocker:
			name = strings.Split(line, ":")[0]
			logCmd = exec.Command("docker", "logs", name)

		case runtimeCRIO:
			// crictl output format: CONTAINER ID IMAGE CREATED STATE NAME
			fields := strings.Fields(line)
			if len(fields) < 5 {
				continue
			}
			containerID := fields[0]
			name = fields[4] // Container name is typically the 5th field
			logCmd = exec.Command("crictl", "logs", containerID)

		case runtimeContainerd:
			// ctr output format: CONTAINER IMAGE RUNTIME
			fields := strings.Fields(line)
			if len(fields) < 1 {
				continue
			}
			containerID := fields[0]
			name = containerID
			// Note: ctr doesn't have a direct 'logs' command for container logs
			// Skip log collection for containerd without CRI as logs are not easily accessible
			log.Debugf("Skipping log collection for container %s: ctr doesn't support direct log retrieval", name)
			continue

		default:
			continue
		}

		log.Debugf("Getting logs for container %s", name)
		cLog, err := logCmd.CombinedOutput()
		if err != nil {
			fmt.Printf("Could not pull log for container %s: %s\n", name, err)
			continue
		}
		err = os.WriteFile(logDir+"/"+name+".log", cLog, 0o666)
		if err != nil {
			fmt.Printf("Failed to write log for container %s to file: %s\n", name, err)
		}
	}
}

// writeDiags executes the diagnostic commands and outputs the result in the file
// with the filename and directory passed as arguments
func writeDiags(cmds diagCmd, dir string) error {
	if cmds.info != "" {
		fmt.Println(cmds.info)
	}

	parts := strings.Fields(cmds.cmd)

	var content []byte
	var err error

	// Check if command contains shell features like $(...) or |
	// If so, execute via shell
	if strings.Contains(cmds.cmd, "$(") || strings.Contains(cmds.cmd, "|") {
		content, err = exec.Command("sh", "-c", cmds.cmd).CombinedOutput()
	} else {
		content, err = exec.Command(parts[0], parts[1:]...).CombinedOutput()
	}

	if err != nil {
		fmt.Printf("Failed to run command: %s\nError: %s\n", cmds.cmd, string(content))
		return err
	}

	// This is for the commands we want to run but don't want to save the output
	// or for commands that don't produce any output to stdout
	if cmds.filename == "" {
		return nil
	}

	fp := filepath.Join(dir, cmds.filename)
	if err := os.WriteFile(fp, content, 0o666); err != nil {
		log.Errorf("Error writing diags to file: %s\n", err)
	}
	return nil
}
