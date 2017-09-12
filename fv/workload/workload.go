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
	"github.com/projectcalico/felix/fv/containers"
	"github.com/projectcalico/libcalico-go/lib/api"
	"github.com/projectcalico/libcalico-go/lib/client"
	"github.com/projectcalico/libcalico-go/lib/net"
	log "github.com/sirupsen/logrus"
)

type Workload struct {
	C             *containers.Container
	Name          string
	InterfaceName string
	IP            string
	Port          string
	runCmd        *exec.Cmd
	outPipe       io.ReadCloser
	errPipe       io.ReadCloser
	namespacePath string
}

var workloadIdx = 0

func (w *Workload) Stop() {
	if w == nil {
		log.Info("Stop no-op because nil workload")
	} else if w.runCmd == nil {
		log.WithField("workload", w).Info("Stop no-op because workload is not running")
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

func Run(c *containers.Container, interfaceName, ip, port string) (w *Workload) {

	// Build unique workload name and struct.
	workloadIdx++
	w = &Workload{
		C:             c,
		Name:          fmt.Sprintf("w%v", workloadIdx),
		InterfaceName: interfaceName,
		IP:            ip,
		Port:          port,
	}

	// Ensure that the host has the 'test-workload' binary.
	w.C.EnsureBinary("test-workload")

	// Start the workload.
	log.WithField("workload", w).Info("About to run workload")
	runCmd := exec.Command("docker", "exec", w.C.Name,
		"sh", "-c",
		fmt.Sprintf("echo $$ > /tmp/%v; exec /test-workload %v %v %v",
			w.Name,
			w.InterfaceName,
			w.IP,
			w.Port))
	var err error
	w.outPipe, err = runCmd.StdoutPipe()
	Expect(err).NotTo(HaveOccurred())
	w.errPipe, err = runCmd.StderrPipe()
	Expect(err).NotTo(HaveOccurred())
	err = runCmd.Start()
	Expect(err).NotTo(HaveOccurred())

	// Read the workload's namespace path, which it writes to its standard output.
	namespacePath, err := bufio.NewReader(w.outPipe).ReadString('\n')
	Expect(err).NotTo(HaveOccurred())
	w.namespacePath = strings.TrimSpace(namespacePath)

	log.WithField("workload", w).Info("Workload now running")

	return
}

func (w *Workload) Configure(client *client.Client) {
	wep := api.NewWorkloadEndpoint()
	wep.Metadata.Name = w.Name
	wep.Metadata.Workload = w.Name
	wep.Metadata.Orchestrator = "felixfv"
	wep.Metadata.Node = w.C.Hostname
	wep.Metadata.Labels = map[string]string{"name": w.Name}
	wep.Spec.IPNetworks = []net.IPNet{net.MustParseNetwork(w.IP + "/32")}
	wep.Spec.InterfaceName = w.InterfaceName
	wep.Spec.Profiles = []string{"default"}
	_, err := client.WorkloadEndpoints().Create(wep)
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

func HaveConnectivityTo(target *Workload) types.GomegaMatcher {
	return &connectivityMatcher{target.IP, target.Port}
}

type connectivityMatcher struct {
	ip, port string
}

func (m *connectivityMatcher) Match(actual interface{}) (success bool, err error) {
	w := actual.(*Workload)
	success = w.CanConnectTo(m.ip, m.port)
	return
}

func (m *connectivityMatcher) FailureMessage(actual interface{}) (message string) {
	w := actual.(*Workload)
	message = fmt.Sprintf("Expected %v to have connectivity to %v:%v, but it doesn't", w, m.ip, m.port)
	return
}

func (m *connectivityMatcher) NegatedFailureMessage(actual interface{}) (message string) {
	w := actual.(*Workload)
	message = fmt.Sprintf("Expected %v not to have connectivity to %v:%v, but it does", w, m.ip, m.port)
	return
}
