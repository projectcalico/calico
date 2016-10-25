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
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/docopt/docopt-go"
	shutil "github.com/termie/go-shutil"
)

// diagCmd is a struct to hold a command, cmd info and filename to run diagnostic on
type diagCmd struct {
	info     string
	cmd      string
	filename string
}

// Diags function collects diagnostic information and logs
func Diags(args []string) error {
	var err error
	doc := `Usage:
  calicoctl node diags [--log-dir=<LOG_DIR>]

Options:
  -h --help               Show this screen.
     --log-dir=<LOG_DIR>  The directory containing Calico logs [default: /var/log/calico]

Description:
  Create a diagnostics bundle for the Calico node instance running on this compute host.`

	arguments, err := docopt.Parse(doc, args, true, "", false, false)
	if err != nil {
		return err
	}
	if len(arguments) == 0 {
		return nil
	}

	runDiags(arguments["--log-dir"].(string))

	return nil
}

// runDiags takes logDir and runs a sequence of commands to collect diagnostics
func runDiags(logDir string) {

	// Note: in for the cmd field in this struct, it  can't handle args quoted with space in it
	// For example, you can't add cmd "do this", since after the `strings.Fields` it will become `"do` and `this"`
	cmds := []diagCmd{
		{"", "date", "date"},
		{"", "hostname", "hostname"},
		{"Dumping netstat", "netstat --all --numeric", "netstat"},
		{"Dumping routes (IPv4)", "ip -4 route", "ipv4_route"},
		{"Dumping routes (IPv6)", "ip -6 route", "ipv6_route"},
		{"Dumping interface info (IPv4)", "ip -4 addr", "ipv4_addr"},
		{"Dumping interface info (IPv6)", "ip -6 addr", "ipv6_addr"},
		{"Dumping iptables (IPv4)", "iptables-save", "ipv4_tables"},
		{"Dumping iptables (IPv6)", "ip6tables-save", "ipv6_tables"},
		{"Dumping ipsets", "ipset list", "ipsets"},
		{"Dumping ipsets (container)", "docker run --privileged --net=host calico/node ipset list", "ipset_container"},
		{"Copying journal for calico-node.service", "journalctl -u calico-node.service --no-pager", "journalctl_calico_node"},
		{"Dumping felix stats", "pkill -SIGUSR1 felix", ""},
	}

	// Make sure the command is run with super user priviladges
	if os.Getuid() != 0 {
		fmt.Println("Need super user privilages: Operation not permitted")
		os.Exit(1)
	}

	fmt.Println("Collecting diagnostics")

	// Create a temp directory in /tmp
	tmpDir, err := ioutil.TempDir("", "calico")
	if err != nil {
		log.Fatalf("Error creating temp directory to dump logs: %v\n", err)
	}

	fmt.Println("Using temp dir:", tmpDir)
	err = os.Chdir(tmpDir)
	if err != nil {
		log.Fatalf("Error changing directory to temp directory to dump logs: %v\n", err)
	}

	os.Mkdir("diagnostics", os.ModeDir)
	diagsTmpDir := filepath.Join(tmpDir, "diagnostics")

	for _, v := range cmds {
		writeDiags(v, diagsTmpDir)
	}

	tmpLogDir := filepath.Join(diagsTmpDir, "logs")

	// Check if the logDir provided/default exists and is a directory
	fileInfo, err := os.Stat(logDir)
	if err != nil {
		log.Printf("Error copying log files: %v\n", err)
	} else if fileInfo.IsDir() {
		fmt.Println("Copying Calico logs")
		err = shutil.CopyTree(logDir, tmpLogDir, nil)
		if err != nil {
			log.Fatalf("Error copying log files: %v\n", err)
		}
	} else {
		fmt.Printf("No logs found in %s; skipping log copying", logDir)
	}

	// Get the current time and create a tar.gz file with the timestamp in the name
	tarFile := fmt.Sprintf("diags-%s.tar.gz", time.Now().Format("20060102_150405"))

	// Have to use shell to compress the file because Go archive/tar can't handle
	// some header metadata longer than a certain length (Ref: https://github.com/golang/go/issues/12436)
	err = exec.Command("tar", "-zcvf", tarFile, "diagnostics").Run()
	if err != nil {
		log.Printf("Error compressing the diagnostics: %v\n", err)
	}

	tarFilePath := filepath.Join(tmpDir, tarFile)

	fmt.Printf("\nDiags saved to %s\n", tarFilePath)
	fmt.Printf(`If required, you can upload the diagnostics bundle to a file sharing service 
such as transfer.sh using curl or similar.  For example:

    curl --upload-file %s https://transfer.sh/%s`, tarFilePath, tarFilePath)
	fmt.Println()

}

// writeDiags executes the dignostic commans and outputs the result in the file
// with the filename and directory passed as arguments
func writeDiags(cmds diagCmd, dir string) {

	if cmds.info != "" {
		fmt.Println(cmds.info)
	}

	// This is for the commands we want to run but don't want to save the output
	// or for commands that don't produce any output to stdout
	if cmds.filename == "" {
		return
	}

	parts := strings.Fields(cmds.cmd)

	command := exec.Command(parts[0], parts[1:]...)

	content, err := command.Output()
	if err != nil {
		log.Println(err)
	}

	fp := filepath.Join(dir, cmds.filename)
	if err := ioutil.WriteFile(fp, content, 0666); err != nil {
		log.Fatal(err)
	}
}
