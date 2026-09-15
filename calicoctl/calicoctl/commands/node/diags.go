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
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	shutil "github.com/termie/go-shutil"
)

// diagCmd is a struct to hold a command, cmd info and filename to run diagnostic on
type diagCmd struct {
	info     string
	cmd      string
	filename string
}

// containerRuntimes is the preference order for tooling that can run or inspect
// containers on a node. Modern Kubernetes nodes typically only have crictl
// (containerd/CRI-O); docker-based installs still have docker.
var containerRuntimes = []string{"docker", "nerdctl", "crictl"}

// Diags gathers diagnostic information and logs from a Calico node, reading
// logs from logDir.
func Diags(logDir string) error {
	return runDiags(logDir)
}

// runDiags takes logDir and runs a sequence of commands to collect diagnostics
func runDiags(logDir string) error {
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

	// Prefer host `ipset list`, then also try via a container runtime so the
	// dump still works when the host lacks the ipset binary (common on k8s
	// nodes that only have containerd/CRI-O tooling).
	if ipsetCmd, err := containerIpsetCmd(); err == nil {
		cmds = append(cmds, diagCmd{"Dumping ipsets (container)", ipsetCmd, "ipset_container"})
	} else {
		fmt.Printf("Skipping container ipset dump: %v\n", err)
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
	getNodeContainerLogs(tmpLogDir)

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

// findContainerRuntime returns the first supported container CLI found in PATH.
// lookPath is injected so unit tests can simulate different environments.
func findContainerRuntime(lookPath func(string) (string, error)) string {
	if lookPath == nil {
		lookPath = exec.LookPath
	}
	for _, name := range containerRuntimes {
		if _, err := lookPath(name); err == nil {
			return name
		}
	}
	return ""
}

// containerIpsetCmd builds a command that runs `ipset list` in a privileged
// calico/node context. Docker and nerdctl start an ephemeral container; crictl
// execs into the already-running calico-node (which is privileged + host net).
func containerIpsetCmd() (string, error) {
	return containerIpsetCmdFor(findContainerRuntime(nil), crictlFindContainer)
}

// containerIpsetCmdFor is the testable core of containerIpsetCmd.
func containerIpsetCmdFor(runtime string, findCrictlContainer func(name string) (string, error)) (string, error) {
	switch runtime {
	case "docker", "nerdctl":
		return runtime + " run --rm --privileged --net=host calico/node ipset list", nil
	case "crictl":
		id, err := findCrictlContainer("calico-node")
		if err != nil {
			return "", fmt.Errorf("crictl: %w", err)
		}
		return "crictl exec " + id + " ipset list", nil
	default:
		return "", fmt.Errorf("no supported container runtime found in PATH (tried %s)", strings.Join(containerRuntimes, ", "))
	}
}

// crictlFindContainer returns the first container ID whose name matches name.
func crictlFindContainer(name string) (string, error) {
	// Prefer running containers, then fall back to -a.
	for _, args := range [][]string{
		{"ps", "--name", name, "-q"},
		{"ps", "-a", "--name", name, "-q"},
	} {
		out, err := exec.Command("crictl", args...).CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("crictl %s failed: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		}
		ids := strings.Fields(string(out))
		if len(ids) > 0 {
			return ids[0], nil
		}
	}
	return "", fmt.Errorf("no container matching %q found", name)
}

// getNodeContainerLogs will attempt to grab logs for any "calico" named containers for hosted installs.
func getNodeContainerLogs(logDir string) {
	err := os.MkdirAll(logDir, os.ModeDir)
	if err != nil {
		fmt.Printf("Error creating log directory: %v\n", err)
		return
	}

	runtime := findContainerRuntime(nil)
	switch runtime {
	case "docker", "nerdctl":
		getDockerStyleContainerLogs(runtime, logDir)
	case "crictl":
		getCrictlContainerLogs(logDir)
	default:
		fmt.Printf("Could not collect container logs: no container runtime found (tried %s)\n", strings.Join(containerRuntimes, ", "))
	}
}

// getDockerStyleContainerLogs copies logs using docker or nerdctl (compatible CLIs).
func getDockerStyleContainerLogs(cli, logDir string) {
	// Get a list of Calico containers running on this Node.
	result, err := exec.Command(cli, "ps", "-a", "--filter", "name=calico", "--format", "{{.Names}}: {{.CreatedAt}}").CombinedOutput()
	if err != nil {
		fmt.Printf("Could not run %s command: %s\n", cli, string(result))
		return
	}

	// No Calico containers found.
	if string(result) == "" {
		log.Debug("Did not find any Calico containers")
		return
	}

	// Remove any containers that have "k8s_POD" in them.
	re := regexp.MustCompile("(?m)[\r\n]+^.*k8s_POD.*$")
	containers := re.ReplaceAllString(string(result), "")

	fmt.Printf("Copying logs from Calico containers (%s)\n", cli)
	err = os.WriteFile(logDir+"/"+"container_creation_time", []byte(containers), 0o666)
	if err != nil {
		fmt.Printf("Could not save output of `%s ps` command to container_creation_time: %s\n", cli, err)
	}

	// Grab the log for each container and write it as <containerName>.log.
	scanner := bufio.NewScanner(strings.NewReader(containers))
	for scanner.Scan() {
		name := strings.Split(scanner.Text(), ":")[0]
		log.Debugf("Getting logs for container %s", name)
		cLog, err := exec.Command(cli, "logs", name).CombinedOutput()
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

// getCrictlContainerLogs copies logs for calico containers via crictl (containerd/CRI-O).
func getCrictlContainerLogs(logDir string) {
	// --name does a substring match on the container name (e.g. calico-node).
	idsOut, err := exec.Command("crictl", "ps", "-a", "--name", "calico", "-q").CombinedOutput()
	if err != nil {
		fmt.Printf("Could not run crictl command: %s\n", strings.TrimSpace(string(idsOut)))
		return
	}
	ids := strings.Fields(string(idsOut))
	if len(ids) == 0 {
		log.Debug("Did not find any Calico containers via crictl")
		return
	}

	fmt.Println("Copying logs from Calico containers (crictl)")
	if err := os.WriteFile(logDir+"/container_creation_time", []byte(strings.Join(ids, "\n")+"\n"), 0o666); err != nil {
		fmt.Printf("Could not save container list to container_creation_time: %s\n", err)
	}

	for _, id := range ids {
		log.Debugf("Getting logs for container %s", id)
		cLog, err := exec.Command("crictl", "logs", id).CombinedOutput()
		if err != nil {
			fmt.Printf("Could not pull log for container %s: %s\n", id, err)
			continue
		}
		if err := os.WriteFile(logDir+"/"+id+".log", cLog, 0o666); err != nil {
			fmt.Printf("Failed to write log for container %s to file: %s\n", id, err)
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

	content, err := exec.Command(parts[0], parts[1:]...).CombinedOutput()
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
