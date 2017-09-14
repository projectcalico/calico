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

package workload

import (
	"bufio"
	"fmt"
	"io"
	"io/ioutil"
	"os/exec"
	"strings"

	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/types"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/felix/fv/containers"
	"github.com/projectcalico/libcalico-go/lib/api"
	"github.com/projectcalico/libcalico-go/lib/client"
	"github.com/projectcalico/libcalico-go/lib/net"
)

type Workload struct {
	C                *containers.Container
	Name             string
	InterfaceName    string
	IP               string
	Ports            string
	runCmd           *exec.Cmd
	outPipe          io.ReadCloser
	errPipe          io.ReadCloser
	namespacePath    string
	WorkloadEndpoint *api.WorkloadEndpoint
}

var workloadIdx = 0

func (w *Workload) Stop() {
	if w == nil {
		log.Info("Stop no-op because nil workload")
	} else {
		log.WithField("workload", w).Info("Stop")
		outputBytes, err := exec.Command("docker", "exec", w.C.Name,
			"cat",
			fmt.Sprintf("/tmp/%v", w.Name)).CombinedOutput()
		Expect(err).NotTo(HaveOccurred())
		pid := strings.TrimSpace(string(outputBytes))
		err = exec.Command("docker", "exec", w.C.Name, "kill", pid).Run()
		Expect(err).NotTo(HaveOccurred())
		w.runCmd.Process.Wait()
		wOut, err := ioutil.ReadAll(w.outPipe)
		Expect(err).NotTo(HaveOccurred())
		wErr, err := ioutil.ReadAll(w.errPipe)
		Expect(err).NotTo(HaveOccurred())
		log.WithFields(log.Fields{
			"workload": w,
			"stdout":   string(wOut),
			"stderr":   string(wErr)}).Info("Workload now stopped")
	}
}

func Run(c *containers.Container, name, interfaceName, ip, ports string) (w *Workload) {

	// Build unique workload name and struct.
	workloadIdx++
	w = &Workload{
		C:             c,
		Name:          fmt.Sprintf("%s-idx%v", name, workloadIdx),
		InterfaceName: interfaceName,
		IP:            ip,
		Ports:         ports,
	}

	// Ensure that the host has the 'test-workload' binary.
	w.C.EnsureBinary("test-workload")

	// Start the workload.
	log.WithField("workload", w).Info("About to run workload")
	w.runCmd = exec.Command("docker", "exec", w.C.Name,
		"sh", "-c",
		fmt.Sprintf("echo $$ > /tmp/%v; exec /test-workload %v %v %v",
			w.Name,
			w.InterfaceName,
			w.IP,
			w.Ports))
	var err error
	w.outPipe, err = w.runCmd.StdoutPipe()
	Expect(err).NotTo(HaveOccurred())
	w.errPipe, err = w.runCmd.StderrPipe()
	Expect(err).NotTo(HaveOccurred())
	err = w.runCmd.Start()
	Expect(err).NotTo(HaveOccurred())

	// Read the workload's namespace path, which it writes to its standard output.
	stdoutReader := bufio.NewReader(w.outPipe)
	stderrReader := bufio.NewReader(w.errPipe)
	namespacePath, err := stdoutReader.ReadString('\n')
	Expect(err).NotTo(HaveOccurred())
	w.namespacePath = strings.TrimSpace(namespacePath)

	go func() {
		for {
			line, err := stderrReader.ReadString('\n')
			if err != nil {
				log.WithError(err).Info("End of workload stderr")
				return
			}
			log.Infof("Workload %s stderr: %s", name, strings.TrimSpace(string(line)))
		}
	}()
	go func() {
		for {
			line, err := stdoutReader.ReadString('\n')
			if err != nil {
				log.WithError(err).Info("End of workload stdout")
				return
			}
			log.Infof("Workload %s stdout: %s", name, strings.TrimSpace(string(line)))
		}
	}()

	log.WithField("workload", w).Info("Workload now running")

	wep := api.NewWorkloadEndpoint()
	wep.Metadata.Name = w.Name
	wep.Metadata.Workload = w.Name
	wep.Metadata.Orchestrator = "felixfv"
	wep.Metadata.Node = w.C.Hostname
	wep.Metadata.Labels = map[string]string{"name": w.Name}
	wep.Spec.IPNetworks = []net.IPNet{net.MustParseNetwork(w.IP + "/32")}
	wep.Spec.InterfaceName = w.InterfaceName
	wep.Spec.Profiles = []string{"default"}
	w.WorkloadEndpoint = wep

	return
}

func (w *Workload) Configure(client *client.Client) {
	_, err := client.WorkloadEndpoints().Apply(w.WorkloadEndpoint)
	Expect(err).NotTo(HaveOccurred())
}

func (w *Workload) NameSelector() string {
	return "name=='" + w.Name + "'"
}

func (w *Workload) CanConnectTo(ip, port string) bool {

	// Ensure that the host has the 'test-connection' binary.
	w.C.EnsureBinary("test-connection")

	// Run 'test-connection' to the target.
	connectionCmd := exec.Command("docker", "exec", w.C.Name,
		"/test-connection", w.namespacePath, ip, port)
	outPipe, err := connectionCmd.StdoutPipe()
	Expect(err).NotTo(HaveOccurred())
	errPipe, err := connectionCmd.StderrPipe()
	Expect(err).NotTo(HaveOccurred())
	err = connectionCmd.Start()
	Expect(err).NotTo(HaveOccurred())

	wOut, err := ioutil.ReadAll(outPipe)
	Expect(err).NotTo(HaveOccurred())
	wErr, err := ioutil.ReadAll(errPipe)
	Expect(err).NotTo(HaveOccurred())
	err = connectionCmd.Wait()

	log.WithFields(log.Fields{
		"stdout": string(wOut),
		"stderr": string(wErr)}).WithError(err).Info("Connection test")

	return err == nil
}

func HaveConnectivityToPort(target *Workload, port uint16) types.GomegaMatcher {
	return &connectivityMatcher{target.IP, fmt.Sprintf("%d", port), fmt.Sprintf("%s on port %d", target.Name, port)}
}

func HaveConnectivityTo(target *Workload) types.GomegaMatcher {
	if strings.Contains(target.Ports, ",") {
		panic("HaveConnectivityTo only supports a single port")
	}
	return &connectivityMatcher{target.IP, target.Ports, target.Name}
}

type connectivityMatcher struct {
	ip, port, targetName string
}

func (m *connectivityMatcher) Match(actual interface{}) (success bool, err error) {
	w := actual.(*Workload)
	success = w.CanConnectTo(m.ip, m.port)
	return
}

func (m *connectivityMatcher) FailureMessage(actual interface{}) (message string) {
	w := actual.(*Workload)
	message = fmt.Sprintf("Expected %v\n\t%+v\nto have connectivity to %v\n\t%v:%v\nbut it doesn't", w.Name, w, m.targetName, m.ip, m.port)
	return
}

func (m *connectivityMatcher) NegatedFailureMessage(actual interface{}) (message string) {
	w := actual.(*Workload)
	message = fmt.Sprintf("Expected %v\n\t%+v\nnot to have connectivity to %v\n\t%v:%v\nbut it does", w.Name, w, m.targetName, m.ip, m.port)
	return
}
