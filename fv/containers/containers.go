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

package containers

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/felix/fv/utils"
	api "github.com/projectcalico/libcalico-go/lib/apis/v3"
	client "github.com/projectcalico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/libcalico-go/lib/options"
	"github.com/projectcalico/libcalico-go/lib/set"
)

type Container struct {
	Name     string
	IP       string
	Hostname string
	runCmd   *exec.Cmd

	mutex    sync.Mutex
	binaries set.Set
}

var containerIdx = 0

func (c *Container) Stop() {
	if c == nil {
		log.Info("Stop no-op because nil container")
	} else if c.runCmd == nil {
		log.WithField("container", c).Info("Stop no-op because container is not running")
	} else {
		log.WithField("container", c).Info("Stop")
		c.runCmd.Process.Signal(os.Interrupt)
		c.WaitNotRunning(60 * time.Second)
	}
}

type RunOpts struct {
	AutoRemove bool
}

func Run(namePrefix string, opts RunOpts, args ...string) (c *Container) {

	// Build unique container name and struct.
	containerIdx++
	c = &Container{Name: fmt.Sprintf("%v-%d-%d-felixfv", namePrefix, os.Getpid(), containerIdx)}

	// Prep command to run the container.
	log.WithField("container", c).Info("About to run container")
	runArgs := []string{"run", "--name", c.Name, "--hostname", c.Name}

	if opts.AutoRemove {
		runArgs = append(runArgs, "--rm")
	}

	// Add remaining args
	runArgs = append(runArgs, args...)

	c.runCmd = utils.Command("docker", runArgs...)

	// Get the command's output pipes, so we can merge those into the test's own logging.
	stdout, err := c.runCmd.StdoutPipe()
	Expect(err).NotTo(HaveOccurred())
	stderr, err := c.runCmd.StderrPipe()
	Expect(err).NotTo(HaveOccurred())

	// Start the container running.
	err = c.runCmd.Start()
	Expect(err).NotTo(HaveOccurred())

	// Merge container's output into our own logging.
	go copyOutputToLog(c.Name, "stdout", stdout)
	go copyOutputToLog(c.Name, "stderr", stderr)

	// Note: it might take a long time for the container to start running, e.g. if the image
	// needs to be downloaded.
	c.WaitUntilRunning()

	// Fill in rest of container struct.
	c.IP = c.GetIP()
	c.Hostname = c.GetHostname()
	c.binaries = set.New()
	log.WithField("container", c).Info("Container now running")
	return
}

// Start executes "docker start" on a container. Useful when used after Stop()
// to restart a container.
func (c *Container) Start() {
	c.runCmd = utils.Command("docker", "start", "--attach", c.Name)

	stdout, err := c.runCmd.StdoutPipe()
	Expect(err).NotTo(HaveOccurred())
	stderr, err := c.runCmd.StderrPipe()
	Expect(err).NotTo(HaveOccurred())

	// Start the container running.
	err = c.runCmd.Start()
	Expect(err).NotTo(HaveOccurred())

	// Merge container's output into our own logging.
	go copyOutputToLog(c.Name, "stdout", stdout)
	go copyOutputToLog(c.Name, "stderr", stderr)

	c.WaitUntilRunning()

	log.WithField("container", c).Info("Container now running")
}

// Remove deletes a container. Should be manually called after a non-auto-removed container
// is stopped.
func (c *Container) Remove() {
	c.runCmd = utils.Command("docker", "rm", "-f", c.Name)
	err := c.runCmd.Start()
	Expect(err).NotTo(HaveOccurred())

	log.WithField("container", c).Info("Removed container.")
}

func copyOutputToLog(name string, streamName string, stream io.Reader) {
	scanner := bufio.NewScanner(stream)
	for scanner.Scan() {
		log.Info(name, "[", streamName, "] ", scanner.Text())
	}
	logCxt := log.WithFields(log.Fields{
		"name":   name,
		"stream": stream,
	})
	if scanner.Err() != nil {
		logCxt.WithError(scanner.Err()).Warn("Error reading container stream")
	}
	logCxt.Info("Stream finished")
}

func (c *Container) DockerInspect(format string) string {
	inspectCmd := utils.Command("docker", "inspect",
		"--format="+format,
		c.Name,
	)
	outputBytes, err := inspectCmd.CombinedOutput()
	Expect(err).NotTo(HaveOccurred())
	return string(outputBytes)
}

func (c *Container) GetIP() string {
	output := c.DockerInspect("{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}")
	return strings.TrimSpace(output)
}

func (c *Container) GetHostname() string {
	output := c.DockerInspect("{{.Config.Hostname}}")
	return strings.TrimSpace(output)
}

func (c *Container) GetPIDs(processName string) []int {
	out, err := c.ExecOutput("pgrep", fmt.Sprintf("^%s$", processName))
	Expect(err).NotTo(HaveOccurred())
	Expect(out).NotTo(BeEmpty())
	var pids []int
	for _, line := range strings.Split(out, "\n") {
		if line == "" {
			continue
		}
		pid, err := strconv.Atoi(line)
		Expect(err).NotTo(HaveOccurred())
		pids = append(pids, pid)
	}
	return pids
}

func (c *Container) WaitUntilRunning() {
	log.Info("Wait for container to be listed in docker ps")

	// Set up so we detect if container startup fails.
	stoppedChan := make(chan struct{})
	go func() {
		defer close(stoppedChan)
		err := c.runCmd.Wait()
		log.WithError(err).WithField("name", c.Name).Info("Container stopped")
		c.mutex.Lock()
		defer c.mutex.Unlock()
		c.runCmd = nil
	}()

	for {
		Expect(stoppedChan).NotTo(BeClosed())

		cmd := utils.Command("docker", "ps")
		out, err := cmd.CombinedOutput()
		Expect(err).NotTo(HaveOccurred())
		if strings.Contains(string(out), c.Name) {
			break
		}
		time.Sleep(1000 * time.Millisecond)
	}
}

func (c *Container) Stopped() bool {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.runCmd == nil
}

func (c *Container) ListedInDockerPS() bool {
	cmd := utils.Command("docker", "ps")
	out, err := cmd.CombinedOutput()
	Expect(err).NotTo(HaveOccurred())
	return strings.Contains(string(out), c.Name)
}

func (c *Container) WaitNotRunning(timeout time.Duration) {
	log.Info("Wait for container not to be listed in docker ps")
	start := time.Now()
	for {
		if !c.ListedInDockerPS() {
			break
		}
		if time.Since(start) > timeout {
			log.Panic("Timed out waiting for container not to be listed.")
		}
		time.Sleep(1000 * time.Millisecond)
	}
}

func (c *Container) EnsureBinary(name string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if !c.binaries.Contains(name) {
		utils.Command("docker", "cp", "../bin/"+name, c.Name+":/"+name).Run()
		c.binaries.Add(name)
	}
}

func (c *Container) CopyFileIntoContainer(hostPath, containerPath string) error {
	cmd := utils.Command("docker", "cp", hostPath, c.Name+":"+containerPath)
	return cmd.Run()
}

func (c *Container) Exec(cmd ...string) {
	log.WithField("container", c.Name).WithField("command", cmd).Info("Running command")
	arg := []string{"exec", c.Name}
	arg = append(arg, cmd...)
	utils.Run("docker", arg...)
}

func (c *Container) ExecMayFail(cmd ...string) error {
	arg := []string{"exec", c.Name}
	arg = append(arg, cmd...)
	return utils.RunMayFail("docker", arg...)
}

func (c *Container) ExecOutput(args ...string) (string, error) {
	arg := []string{"exec", c.Name}
	arg = append(arg, args...)
	cmd := exec.Command("docker", arg...)
	out, err := cmd.Output()
	if err != nil {
		if out == nil {
			return "", err
		}
		return string(out), err
	}
	return string(out), nil
}

func (c *Container) SourceName() string {
	return c.Name
}

func (c *Container) CanConnectTo(ip, port, protocol string) bool {

	// Ensure that the container has the 'test-connection' binary.
	c.EnsureBinary("test-connection")

	// Run 'test-connection' to the target.
	connectionCmd := utils.Command("docker", "exec", c.Name,
		"/test-connection", "--protocol="+protocol, "-", ip, port)
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

func RunEtcd() *Container {
	log.Info("Starting etcd")
	return Run("etcd",
		RunOpts{AutoRemove: true},
		"--privileged", // So that we can add routes inside the etcd container,
		// when using the etcd container to model an external client connecting
		// into the cluster.
		utils.Config.EtcdImage,
		"etcd",
		"--advertise-client-urls", "http://127.0.0.1:2379",
		"--listen-client-urls", "http://0.0.0.0:2379")
}

func RunFelix(etcdIP string) *Container {
	log.Info("Starting felix")
	return Run("felix",
		RunOpts{AutoRemove: true},
		"--privileged",
		"-e", "CALICO_DATASTORE_TYPE=etcdv3",
		"-e", "CALICO_ETCD_ENDPOINTS=http://"+etcdIP+":2379",
		"-e", "FELIX_LOGSEVERITYSCREEN=debug",
		"-e", "FELIX_DATASTORETYPE=etcdv3",
		"-e", "FELIX_PROMETHEUSMETRICSENABLED=true",
		"-e", "FELIX_USAGEREPORTINGENABLED=false",
		"-e", "FELIX_IPV6SUPPORT=false",
		"calico/felix:latest")
}

// StartSingleNodeEtcdTopology starts an etcd container and a single Felix container; it initialises
// the datastore and installs a Node resource for the Felix node.
func StartSingleNodeEtcdTopology() (felix, etcd *Container, calicoClient client.Interface) {
	felixes, etcd, calicoClient := StartNNodeEtcdTopology(1)
	felix = felixes[0]
	return
}

// StartTwoNodeEtcdTopology starts an etcd container and a pair of Felix hosts connected
// with IPIP.
//
// - Configures an IPAM pool for 10.65.0.0/16 (so that Felix programs the all-IPAM blocks IP set)
//   but (for simplicity) we don't actually use IPAM to assign IPs.
// - Configures routes between the two "hosts", giving each host 10.65.x.0/24, where x is the
//   index in the returned array.  When creating workloads, use IPs from the relevant block.
// - Configures the Tunnel IP as 10.65.x.1
func StartTwoNodeEtcdTopology() (felixes []*Container, etcd *Container, client client.Interface) {
	return StartNNodeEtcdTopology(2)
}

// StartNNodeEtcdTopology starts an etcd container and a set of Felix hosts.  If n > 1, sets
// up IPIP, otherwise this is skipped.
//
// - Configures an IPAM pool for 10.65.0.0/16 (so that Felix programs the all-IPAM blocks IP set)
//   but (for simplicity) we don't actually use IPAM to assign IPs.
// - Configures routes between the hosts, giving each host 10.65.x.0/24, where x is the
//   index in the returned array.  When creating workloads, use IPs from the relevant block.
// - Configures the Tunnel IP for each host as 10.65.x.1.
func StartNNodeEtcdTopology(n int) (felixes []*Container, etcd *Container, client client.Interface) {
	log.Infof("Starting a %d-node etcd topology.", n)
	success := false
	var err error
	defer func() {
		if !success {
			log.WithError(err).Error("Failed to start topology, tearing down containers")
			for _, felix := range felixes {
				felix.Stop()
			}
			etcd.Stop()
		}
	}()

	// First start etcd.
	etcd = RunEtcd()

	// Connect to etcd.
	client = utils.GetEtcdClient(etcd.IP)
	mustInitDatastore(client)

	if n > 1 {
		Eventually(func() error {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			ipPool := api.NewIPPool()
			ipPool.Name = "test-pool"
			ipPool.Spec.CIDR = "10.65.0.0/16"
			ipPool.Spec.IPIPMode = api.IPIPModeAlways
			_, err = client.IPPools().Create(ctx, ipPool, options.SetOptions{})
			return err
		}).ShouldNot(HaveOccurred())
	}

	for i := 0; i < n; i++ {
		// Then start Felix and create a node for it.
		felix := RunFelix(etcd.IP)

		felixNode := api.NewNode()
		felixNode.Name = felix.Hostname
		if n > 1 {
			felixNode.Spec.BGP = &api.NodeBGPSpec{
				IPv4Address:        felix.IP,
				IPv4IPIPTunnelAddr: fmt.Sprintf("10.65.%d.1", i),
			}
		}
		Eventually(func() error {
			_, err = client.Nodes().Create(utils.Ctx, felixNode, utils.NoOptions)
			if err != nil {
				log.WithError(err).Warn("Failed to create node")
			}
			return err
		}, "10s", "500ms").ShouldNot(HaveOccurred())

		felixes = append(felixes, felix)
	}

	// Set up routes between the hosts, note: we're not using IPAM here but we set up similar
	// CIDR-based routes.
	for i, iFelix := range felixes {
		for j, jFelix := range felixes {
			if i == j {
				continue
			}

			jBlock := fmt.Sprintf("10.65.%d.0/24", j)
			err := iFelix.ExecMayFail("ip", "route", "add", jBlock, "via", jFelix.IP, "dev", "tunl0", "onlink")
			Expect(err).ToNot(HaveOccurred())
		}
	}
	success = true
	return
}

func mustInitDatastore(client client.Interface) {
	Eventually(func() error {
		log.Info("Initializing the datastore...")
		ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
		err := client.EnsureInitialized(
			ctx,
			"test-version",
			"felix-fv",
		)
		log.WithError(err).Info("EnsureInitialized result")
		return err
	}).ShouldNot(HaveOccurred())
}
