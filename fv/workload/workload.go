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
	"sync"

	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/types"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/felix/fv/containers"
	"github.com/projectcalico/felix/fv/utils"
	api "github.com/projectcalico/libcalico-go/lib/apis/v3"
	client "github.com/projectcalico/libcalico-go/lib/clientv3"
)

type Workload struct {
	C                *containers.Container
	Name             string
	InterfaceName    string
	IP               string
	Ports            string
	DefaultPort      string
	runCmd           *exec.Cmd
	outPipe          io.ReadCloser
	errPipe          io.ReadCloser
	namespacePath    string
	WorkloadEndpoint *api.WorkloadEndpoint
	Protocol         string // "tcp" or "udp"
}

var workloadIdx = 0

func (w *Workload) Stop() {
	if w == nil {
		log.Info("Stop no-op because nil workload")
	} else {
		log.WithField("workload", w).Info("Stop")
		outputBytes, err := utils.Command("docker", "exec", w.C.Name,
			"cat", fmt.Sprintf("/tmp/%v", w.Name)).CombinedOutput()
		Expect(err).NotTo(HaveOccurred())
		pid := strings.TrimSpace(string(outputBytes))
		err = utils.Command("docker", "exec", w.C.Name, "kill", pid).Run()
		Expect(err).NotTo(HaveOccurred())
		w.runCmd.Process.Wait()
		log.WithField("workload", w).Info("Workload now stopped")
	}
}

func Run(c *containers.Container, name, interfaceName, ip, ports string, protocol string) (w *Workload) {

	// Build unique workload name and struct.
	workloadIdx++
	w = &Workload{
		C:             c,
		Name:          fmt.Sprintf("%s-idx%v", name, workloadIdx),
		InterfaceName: interfaceName,
		IP:            ip,
		Ports:         ports,
		Protocol:      protocol,
	}

	// Ensure that the host has the 'test-workload' binary.
	w.C.EnsureBinary("test-workload")

	// Start the workload.
	log.WithField("workload", w).Info("About to run workload")
	var udpArg string
	if protocol == "udp" {
		udpArg = "--udp"
	}
	w.runCmd = utils.Command("docker", "exec", w.C.Name,
		"sh", "-c",
		fmt.Sprintf("echo $$ > /tmp/%v; exec /test-workload %v %v %v %v",
			w.Name,
			udpArg,
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
	wep.Labels = map[string]string{"name": w.Name}
	wep.Spec.Node = w.C.Hostname
	wep.Spec.Orchestrator = "felixfv"
	wep.Spec.Workload = w.Name
	wep.Spec.Endpoint = w.Name
	wep.Spec.IPNetworks = []string{w.IP + "/32"}
	wep.Spec.InterfaceName = w.InterfaceName
	wep.Spec.Profiles = []string{"default"}
	w.WorkloadEndpoint = wep

	return
}

func (w *Workload) IPNet() string {
	return w.IP + "/32"
}

func (w *Workload) Configure(client client.Interface) {
	wep := w.WorkloadEndpoint
	wep.Namespace = "fv"
	_, err := client.WorkloadEndpoints().Create(utils.Ctx, w.WorkloadEndpoint, utils.NoOptions)
	Expect(err).NotTo(HaveOccurred())
}

func (w *Workload) NameSelector() string {
	return "name=='" + w.Name + "'"
}

func (w *Workload) SourceName() string {
	return w.Name
}

func (w *Workload) CanConnectTo(ip, port, protocol string) bool {
	anyPort := Port{
		Workload: w,
	}
	return anyPort.CanConnectTo(ip, port, protocol)
}

func (w *Workload) Port(port uint16) *Port {
	return &Port{
		Workload: w,
		Port:     port,
	}
}

type Port struct {
	*Workload
	Port uint16
}

func (w *Port) SourceName() string {
	if w.Port == 0 {
		return w.Name
	}
	return fmt.Sprintf("%s:%d", w.Name, w.Port)
}

func (p *Port) CanConnectTo(ip, port, protocol string) bool {

	// Ensure that the host has the 'test-connection' binary.
	p.C.EnsureBinary("test-connection")

	if protocol == "udp" {
		// If this is a retry then we may have stale conntrack entries and we don't want those
		// to influence the connectivity check.  Only an issue for UDP due to the lack of a
		// sequence number.
		p.C.ExecMayFail("conntrack", "-D", "-p", "udp", "-s", p.Workload.IP, "-d", ip)
	}

	// Run 'test-connection' to the target.
	args := []string{
		"exec", p.C.Name, "/test-connection", p.namespacePath, ip, port, "--protocol=" + protocol,
	}
	if p.Port != 0 {
		// If we are using a particular source port, fill it in.
		args = append(args, fmt.Sprintf("--source-port=%d", p.Port))
	}
	connectionCmd := utils.Command("docker", args...)
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

// ToMatcher implements the connectionTarget interface, allowing this port to be used as
// target.
func (p *Port) ToMatcher(explicitPort ...uint16) *connectivityMatcher {
	if p.Port == 0 {
		return p.Workload.ToMatcher(explicitPort...)
	}
	return &connectivityMatcher{
		ip:         p.Workload.IP,
		port:       fmt.Sprint(p.Port),
		targetName: fmt.Sprintf("%s on port %d", p.Workload.Name, p.Port),
	}
}

type connectionTarget interface {
	ToMatcher(explicitPort ...uint16) *connectivityMatcher
}

type IP string // Just so we can define methods on it...

func (s IP) ToMatcher(explicitPort ...uint16) *connectivityMatcher {
	if len(explicitPort) != 1 {
		panic("Explicit port needed with IP as a connectivity target")
	}
	port := fmt.Sprintf("%d", explicitPort[0])
	return &connectivityMatcher{
		ip:         string(s),
		port:       port,
		targetName: string(s) + ":" + port,
		protocol:   "tcp",
	}
}

func (w *Workload) ToMatcher(explicitPort ...uint16) *connectivityMatcher {
	var port string
	if len(explicitPort) == 1 {
		port = fmt.Sprintf("%d", explicitPort[0])
	} else if w.DefaultPort != "" {
		port = w.DefaultPort
	} else if !strings.Contains(w.Ports, ",") {
		port = w.Ports
	} else {
		panic("Explicit port needed for workload with multiple ports")
	}
	return &connectivityMatcher{
		ip:         w.IP,
		port:       port,
		targetName: fmt.Sprintf("%s on port %s", w.Name, port),
		protocol:   "tcp",
	}
}

func HaveConnectivityTo(target connectionTarget, explicitPort ...uint16) types.GomegaMatcher {
	return target.ToMatcher(explicitPort...)
}

type connectivityMatcher struct {
	ip, port, targetName, protocol string
}

type connectionSource interface {
	CanConnectTo(ip, port, protocol string) bool
	SourceName() string
}

func (m *connectivityMatcher) Match(actual interface{}) (success bool, err error) {
	success = actual.(connectionSource).CanConnectTo(m.ip, m.port, m.protocol)
	return
}

func (m *connectivityMatcher) FailureMessage(actual interface{}) (message string) {
	src := actual.(connectionSource)
	message = fmt.Sprintf("Expected %v\n\t%+v\nto have connectivity to %v\n\t%v:%v\nbut it does not", src.SourceName(), src, m.targetName, m.ip, m.port)
	return
}

func (m *connectivityMatcher) NegatedFailureMessage(actual interface{}) (message string) {
	src := actual.(connectionSource)
	message = fmt.Sprintf("Expected %v\n\t%+v\nnot to have connectivity to %v\n\t%v:%v\nbut it does", src.SourceName(), src, m.targetName, m.ip, m.port)
	return
}

type expectation struct {
	from     connectionSource     // Workload or Container
	to       *connectivityMatcher // Workload or IP, + port
	expected bool
}

// ConnectivityChecker records a set of connectivity expectations and supports calculating the
// actual state of the connectivity between the given workloads.  It is expected to be used like so:
//
//     var cc = &workload.ConnectivityChecker{}
//     cc.ExpectNone(w[2], w[0], 1234)
//     cc.ExpectSome(w[1], w[0], 5678)
//     Eventually(cc.ActualConnectivity, "10s", "100ms").Should(Equal(cc.ExpectedConnectivity()))
//
// Note that the ActualConnectivity method is passed to Eventually as a function pointer to allow
// Ginkgo to re-evaluate the result as needed.
type ConnectivityChecker struct {
	ReverseDirection bool
	Protocol         string // "tcp" or "udp"
	expectations     []expectation
}

func (c *ConnectivityChecker) ExpectSome(from connectionSource, to connectionTarget, explicitPort ...uint16) {
	if c.ReverseDirection {
		from, to = to.(connectionSource), from.(connectionTarget)
	}
	c.expectations = append(c.expectations, expectation{from, to.ToMatcher(explicitPort...), true})
}

func (c *ConnectivityChecker) ExpectNone(from connectionSource, to connectionTarget, explicitPort ...uint16) {
	if c.ReverseDirection {
		from, to = to.(connectionSource), from.(connectionTarget)
	}
	c.expectations = append(c.expectations, expectation{from, to.ToMatcher(explicitPort...), false})
}

func (c *ConnectivityChecker) ResetExpectations() {
	c.expectations = nil
}

// ActualConnectivity calculates the current connectivity for all the expected paths.  One string is
// returned for each expectation, in the order they were recorded.  The strings are intended to be
// human readable, and they are in the same order and format as those returned by
// ExpectedConnectivity().
func (c *ConnectivityChecker) ActualConnectivity() []string {
	var wg sync.WaitGroup
	result := make([]string, len(c.expectations))
	for i, exp := range c.expectations {
		wg.Add(1)
		go func(i int, exp expectation) {
			defer wg.Done()
			p := "tcp"
			if c.Protocol != "" {
				p = c.Protocol
			}
			hasConnectivity := exp.from.CanConnectTo(exp.to.ip, exp.to.port, p)
			result[i] = fmt.Sprintf("%s -> %s = %v", exp.from.SourceName(), exp.to.targetName, hasConnectivity)
		}(i, exp)
	}
	wg.Wait()
	log.Debug("Connectivity", result)
	return result
}

// ExpectedConnectivity returns one string per recorded expection in order, encoding the expected
// connectivity in the same format used by ActualConnectivity().
func (c *ConnectivityChecker) ExpectedConnectivity() []string {
	result := make([]string, len(c.expectations))
	for i, exp := range c.expectations {
		result[i] = fmt.Sprintf("%s -> %s = %v", exp.from.SourceName(), exp.to.targetName, exp.expected)
	}
	return result
}
