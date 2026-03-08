// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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

package conncheck

import (
	"context"
	"fmt"
	"maps"
	"strings"
	"sync"
	"time"

	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/ginkgo/v2"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubernetes/test/e2e/framework"
	"k8s.io/kubernetes/test/e2e/framework/kubectl"
	e2epod "k8s.io/kubernetes/test/e2e/framework/pod"
	e2eoutput "k8s.io/kubernetes/test/e2e/framework/pod/output"

	"github.com/projectcalico/calico/e2e/pkg/utils"
	"github.com/projectcalico/calico/e2e/pkg/utils/client"
	"github.com/projectcalico/calico/e2e/pkg/utils/images"
	"github.com/projectcalico/calico/e2e/pkg/utils/remotecluster"
	"github.com/projectcalico/calico/e2e/pkg/utils/windows"
)

const (
	roleLabel  = "e2e.projectcalico.org/role"
	roleClient = "client"
	roleServer = "server"
)

type connectionTester struct {
	f            *framework.Framework
	servers      map[string]*Server
	clients      map[string]*Client
	expectations map[string]*Expectation
	deployed     bool
}

type ConnectionTester interface {
	// Methods for setup and teardown.
	AddClient(client *Client)
	AddServer(server *Server)
	Deploy()
	Stop()

	// Methods for one-shot execution.
	ExpectSuccess(client *Client, targets ...Target)
	ExpectFailure(client *Client, targets ...Target)
	Execute()
	ResetExpectations()

	// Methods for continuous execution.
	ExpectContinuously(client *Client, targets ...Target) Checkpointer
}

// Checkpointer provides a way to checkpoint continuous connection tests at specific points in time
// during a test to verify that all connections are as expected up to that point.
type Checkpointer interface {
	ExpectSuccess(msg string)
	ExpectFailure(msg string)
	Stop()
}

var _ ConnectionTester = &connectionTester{}

func NewConnectionTester(f *framework.Framework) ConnectionTester {
	return &connectionTester{
		f:            f,
		clients:      make(map[string]*Client),
		servers:      make(map[string]*Server),
		expectations: make(map[string]*Expectation),
	}
}

func (c *connectionTester) ResetExpectations() {
	if err := c.expectationsTested(); err != nil {
		framework.Fail(fmt.Sprintf("ResetExpectations() called before all expectations were tested: %v", err), 1)
	}
	c.expectations = make(map[string]*Expectation)
}

func (c *connectionTester) Deploy() {
	framework.ExpectNoErrorWithOffset(1, c.deploy())
}

func (c *connectionTester) deploy() error {
	// For each client and server, deploy a long lived pod.
	for _, client := range c.clients {
		if client.pod != nil {
			// Pod was already deployed. Skip it, and only deploy new pods.
			continue
		}
		By(fmt.Sprintf("Deploying client pod %s/%s", client.namespace.Name, client.name))
		pod, err := createClientPod(c.f, client.namespace, client.name, client.labels, client.composedCustomizer())
		if err != nil {
			return err
		}
		client.pod = pod
	}
	for _, server := range c.servers {
		if server.pod != nil {
			// Pod was already deployed. Skip it, and only deploy new pods.
			continue
		}
		By(fmt.Sprintf("Deploying server pod %s/%s", server.namespace.Name, server.name))
		pod, svc := CreateServerPodAndServiceX(
			c.f,
			server.namespace,
			server.name,
			server.ports,
			server.labels,
			server.composedPodCustomizer(),
			server.composedSvcCustomizer(),
			server.autoCreateSvc,
		)
		server.pod = pod
		server.service = svc
	}

	// Wait for all pods to be running.
	By("Waiting for all pods in the connection checker to be running")
	timeout := 1 * time.Minute
	if windows.ClusterIsWindows() {
		// Windows images are very large (sometimes 2GB+), so this needs a considerably
		// longer timeout in order to allow them to be pulled
		timeout = 15 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	for _, client := range c.clients {
		err := e2epod.WaitTimeoutForPodRunningInNamespace(ctx, c.f.ClientSet, client.pod.Name, client.pod.Namespace, timeout)
		if err != nil {
			return err
		}
		// Update the client pod object with the actual pod spec. i.e Spec.NodeName etc.
		p, err := c.f.ClientSet.CoreV1().Pods(client.namespace.Name).Get(ctx, client.pod.Name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		client.pod = p
	}
	for _, server := range c.servers {
		err := e2epod.WaitTimeoutForPodRunningInNamespace(ctx, c.f.ClientSet, server.pod.Name, server.pod.Namespace, timeout)
		if err != nil {
			return err
		}

		// Update the server pod object with the actual pod IP.
		p, err := c.f.ClientSet.CoreV1().Pods(server.namespace.Name).Get(ctx, server.pod.Name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		server.pod = p
	}
	c.deployed = true
	return nil
}

func (c *connectionTester) Stop() {
	framework.ExpectNoErrorWithOffset(1, c.stop())
}

func (c *connectionTester) stop() error {
	By("Tearing down the connection tester")

	// Delete all of the pods.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	for _, client := range c.clients {
		By(fmt.Sprintf("Deleting client pod %s", client.pod.Name))
		err := c.f.ClientSet.CoreV1().Pods(client.namespace.Name).Delete(ctx, client.pod.Name, metav1.DeleteOptions{})
		if err != nil {
			return err
		}
	}

	for _, server := range c.servers {
		By(fmt.Sprintf("Deleting server pod %s", server.pod.Name))
		err := c.f.ClientSet.CoreV1().Pods(server.namespace.Name).Delete(ctx, server.pod.Name, metav1.DeleteOptions{})
		if err != nil {
			return err
		}
		if server.service != nil {
			By(fmt.Sprintf("Deleting server service %s", server.service.Name))
			err = c.f.ClientSet.CoreV1().Services(server.namespace.Name).Delete(ctx, server.service.Name, metav1.DeleteOptions{})
			if err != nil {
				return err
			}
		}
	}

	// Wait for pods to be deleted.
	for _, client := range c.clients {
		By(fmt.Sprintf("Waiting for client pod %s to be deleted", client.pod.Name))
		if err := e2epod.WaitForPodNotFoundInNamespace(ctx, c.f.ClientSet, client.pod.Name, client.pod.Namespace, 1*time.Minute); err != nil {
			return err
		}
	}
	for _, server := range c.servers {
		By(fmt.Sprintf("Waiting for server pod %s to be deleted", server.pod.Name))
		if err := e2epod.WaitForPodNotFoundInNamespace(ctx, c.f.ClientSet, server.pod.Name, server.pod.Namespace, 1*time.Minute); err != nil {
			return err
		}
	}

	return c.expectationsTested()
}

func (c *connectionTester) expectationsTested() error {
	for _, exp := range c.expectations {
		if !exp.executed {
			return fmt.Errorf("expected connection %s was not executed. Did you call Execute()?", exp.Description)
		}
	}
	return nil
}

func (c *connectionTester) AddClient(client *Client) {
	if client.namespace == nil {
		framework.Failf("Client %s has no namespace", client.name)
	}
	if _, ok := c.clients[client.ID()]; ok {
		framework.Failf("Client with ID %s already exists", client.ID())
	}
	c.clients[client.ID()] = client
}

func (c *connectionTester) AddServer(server *Server) {
	if server.namespace == nil {
		framework.Failf("Server %s has no namespace", server.name)
	}
	if _, ok := c.servers[server.ID()]; ok {
		framework.Failf("Server with ID %s already exists", server.ID())
	}
	c.servers[server.ID()] = server
}

type Expectation struct {
	Client         *v1.Pod
	Target         Target
	Description    string
	ExpectedResult ResultStatus

	// Track whether or not we have executed this expectation.
	// This is helpful for spotting test bugs where we forget to execute.
	executed bool
}

func (e *Expectation) String() string {
	// An Expectation is defined by:
	// - Client name and namespace.
	// - The target name (and if applicable, namespace).
	// - The type of connection, e.g., ClusterIP/ICMP.
	return fmt.Sprintf("Client=%s/%s; Server=%s; Type=%s",
		e.Client.Namespace,
		e.Client.Name,
		e.Target.String(),
		e.Target.AccessType(),
	)
}

func (c *connectionTester) ExpectSuccess(client *Client, targets ...Target) {
	for _, target := range targets {
		c.expectSuccess(client, target)
	}
}

func (c *connectionTester) expectSuccess(client *Client, target Target) {
	if c.clients[client.ID()] == nil {
		framework.Fail(fmt.Sprintf("Test bug: client %s not registered with connection tester. AddClient()?", client.ID()), 2)
	}
	if c.clients[client.ID()].pod == nil {
		framework.Fail(fmt.Sprintf("Client %s has no running pod. Did you Deploy()?", client.ID()), 2)
	}

	// Prevent duplication expectations. This is a common mistake when writing tests.
	e := &Expectation{
		Client:         c.clients[client.ID()].pod,
		Target:         target,
		Description:    fmt.Sprintf("%s -> %s", client.name, target.String()),
		ExpectedResult: Success,
	}
	if c.expectations[e.String()] != nil {
		// Protect against tests accidentally calling ExpectX with the same values
		// multiple times, which is indicative of a test bug.
		framework.Fail(fmt.Sprintf("Test bug: duplicate expectation: %s", e.String()), 2)
	}
	c.expectations[e.String()] = e
}

// ExpectContinuously starts continuous connection tests from the given client to the given targets.
// It returns a Checkpointer that can be used to checkpoint and verify the results at specific points in time.
// Callers must call Stop() on the returned Checkpointer when done.
func (c *connectionTester) ExpectContinuously(client *Client, targets ...Target) Checkpointer {
	checkpointer := &checkpointer{
		results: make(chan connectionResult, 1000),
		done:    make(chan struct{}),
		client:  client,
		targets: targets,
		tester:  c,
	}
	checkpointer.start()
	return checkpointer
}

func (c *connectionTester) ExpectFailure(client *Client, targets ...Target) {
	for _, target := range targets {
		c.expectFailure(client, target)
	}
}

func (c *connectionTester) expectFailure(client *Client, target Target) {
	if c.clients[client.ID()] == nil {
		framework.Fail(fmt.Sprintf("Test bug: client %s not registered with connection tester. AddClient()?", client.ID()), 2)
	}
	if c.clients[client.ID()].pod == nil {
		framework.Fail(fmt.Sprintf("Client %s has no running pod. Did you Deploy()?", client.ID()), 2)
	}

	// Prevent duplication expectations. This is a common mistake when writing tests.
	e := &Expectation{
		Client:         c.clients[client.ID()].pod,
		Target:         target,
		Description:    fmt.Sprintf("%s -> %s", client.name, target.String()),
		ExpectedResult: Failure,
	}
	if c.expectations[e.String()] != nil {
		framework.Fail(fmt.Sprintf("Test bug: duplicate expectation: %s", e.String()), 2)
	}
	c.expectations[e.String()] = e
}

// TestConnections tests one or more connections in parallel. It will fail the test if any of the connections fail.
func (c *connectionTester) Execute() {
	if !c.deployed {
		framework.Fail("Execute() called before Deploy()", 1)
	}
	By(fmt.Sprintf("Testing %d connections in parallel", len(c.expectations)))

	// Channel to collect results.
	resultChan := make(chan connectionResult, len(c.expectations))

	// Context to control overall timeout for all connections. After it times out, we'll forcefully
	// terminate any remaining connections. This avoids deadlocking the test waiting for results if
	// something goes wrong.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Launch all of the connections in parallel. We'll wait for them all to finish at the end and report on success / failure.
	for _, expectation := range c.expectations {
		go c.runConnection(ctx, expectation, resultChan)
	}

	// Wait for all of the connections to finish.
	var results []connectionResult
	var failed bool
	for range c.expectations {
		result := <-resultChan
		results = append(results, result)
		if result.Failed() {
			failed = true
			logDiagsForConnection(c.f, result)
		}
	}

	// Only close the result channel after all connections have finished to avoid
	// connection goroutines attempting to write to a closed channel.
	close(resultChan)

	// If we had any errors, log out the per-test diags and then fail the test.
	if failed {
		logDiagsForNamespace(c.f, c.f.Namespace)
		msg := buildFailureMessage(results)
		framework.Fail(msg, 1)
	}
}

func (c *connectionTester) runConnection(ctx context.Context, exp *Expectation, results chan<- connectionResult) {
	// Exec into the client pod and try to connect to the server.
	cmd := c.command(exp.Target)

	logCtx := logrus.WithFields(logrus.Fields{
		"cmd":      cmd,
		"client":   fmt.Sprintf("%s/%s", exp.Client.Namespace, exp.Client.Name),
		"target":   exp.Target.String(),
		"expected": exp.ExpectedResult,
	})

	// First attempt.
	out, result, err := c.execCommandInPod(exp.Client, cmd)
	if err != nil {
		logCtx.WithError(err).Warn("Connection attempt returned an error")
	}

	// Retry until the context expires if we didn't get the expected result. This helps to avoid flakes due to transient issues.
	// We don't want to retry too many times, as that could mask real issues and slow down tests. However, we know that
	// especially on CPU constrained environments such as CI, there can be a delay between making changes (e.g., applying a NetworkPolicy) and
	// those changes taking effect. So a short retry loop is helpful.

loop:
	for err != nil || result != exp.ExpectedResult {
		select {
		case <-ctx.Done():
			break loop
		default:
			// Not timed out yet.
		}

		logCtx.WithFields(logrus.Fields{
			"output": out,
			"err":    err,
			"actual": result,
		}).Warn("Connection attempt did not get expected result. Retrying...")

		time.Sleep(1 * time.Second)

		out, result, err = c.execCommandInPod(exp.Client, cmd)
		if err != nil {
			logCtx.WithError(err).Warn("Connection attempt returned an error")
		}
	}

	logCtx.WithFields(logrus.Fields{
		"output": out,
		"err":    err,
		"actual": result,
	}).Debug("Final connection attempt result")

	exp.executed = true
	results <- connectionResult{
		clientPod: exp.Client,
		target:    exp.Target,
		expected:  exp.ExpectedResult,
		actual:    result,
		err:       err,
	}
}

// Connect runs a one-shot connection attempt from the client pod to the given target, and returns the output of the command.
func (c *connectionTester) Connect(client *Client, target Target) (string, error) {
	if c.clients[client.ID()] == nil {
		return "", fmt.Errorf("test bug: client %s not registered with connection tester. AddClient()?", client.ID())
	}
	if c.clients[client.ID()].pod == nil {
		return "", fmt.Errorf("Client %s has no running pod. Did you Deploy()?", client.ID())
	}

	cmd := c.command(target)
	out, _, err := c.execCommandInPod(c.clients[client.ID()].pod, cmd)
	return out, err
}

func (c *connectionTester) execCommandInPod(pod *v1.Pod, cmd string) (string, ResultStatus, error) {
	var out string
	var err error

	// Ensure the kubectl command executes in the remote cluster if required. Remote framework objects do not control
	// how kubeconfigs are resolved by the kubectl command, so we must use this wrapper. See NewDefaultFrameworkForRemoteCluster.
	remotecluster.RemoteFrameworkAwareExec(c.f, func() {
		if windows.ClusterIsWindows() {
			out, err = ExecInPod(pod, "powershell.exe", "-Command", cmd)
		} else {
			out, err = ExecInPod(pod, "sh", "-c", cmd)
		}
	})
	result := Success
	if err != nil {
		result = Failure
	}

	return out, result, err
}

func (c *connectionTester) command(t Target) string {
	var cmd string

	if windows.ClusterIsWindows() {
		// Windows.
		switch t.GetProtocol() {
		case TCP:
			cmd = fmt.Sprintf("Invoke-WebRequest %s -UseBasicParsing -TimeoutSec 5 -DisableKeepAlive -ErrorAction Stop | Out-Null", t.Destination())
		case ICMP:
			cmd = fmt.Sprintf("Test-Connection -Count 5 -ComputerName %s", t.Destination())
		default:
			framework.Failf("Unsupported protocol %s", t.GetProtocol())
		}
	} else {
		// Linux.
		switch t.GetProtocol() {
		case TCP:
			cmd = fmt.Sprintf("wget -qO- -T 5 %s", t.Destination())
		case ICMP:
			cmd = fmt.Sprintf("ping -c 5 %s", t.Destination())
		case HTTP:
			cmdArgs := []string{"curl", "--connect-timeout", "5", "--verbose", "--fail"}
			req := t.HTTPParams()
			cmdArgs = append(cmdArgs, "--request", req.Method)
			for _, header := range req.Headers {
				cmdArgs = append(cmdArgs, "--header", fmt.Sprintf("'%s'", header))
			}
			cmdArgs = append(cmdArgs, fmt.Sprintf("'http://%s%s'", t.Destination(), req.Path))
			cmd = strings.Join(cmdArgs, " ")
		default:
			framework.Failf("Unsupported protocol %s", t.GetProtocol())
		}
	}
	return cmd
}

type ResultStatus string

const (
	Success ResultStatus = "SUCCESS"
	Failure ResultStatus = "FAILURE"
)

func NewConnectionResult(exp, act ResultStatus, c v1.Pod, t Target, err error) connectionResult {
	return connectionResult{
		expected:  exp,
		actual:    act,
		clientPod: &c,
		target:    t,
		err:       err,
	}
}

type connectionResult struct {
	clientPod *v1.Pod
	target    Target
	expected  ResultStatus
	actual    ResultStatus
	err       error
}

func (r *connectionResult) Failed() bool {
	return r.expected != r.actual
}

func buildFailureMessage(results []connectionResult) string {
	// Builed an error message.
	var msg strings.Builder
	msg.WriteString("One or more connection tests failed:\n")

	// Add expected results.
	for _, res := range results {
		exp := res.expected
		actual := res.actual
		status := "   OK"
		if exp != actual {
			status = "ERROR"
		}
		msg.WriteString(fmt.Sprintf(
			"\n%s: %s/%s -> %s (%s, %s, %s); Expected=%s, Actual=%s",
			status,
			res.clientPod.Namespace, res.clientPod.Name,
			res.target.String(),
			res.target.Destination(),
			res.target.GetProtocol(),
			res.target.AccessType(),
			exp,
			actual,
		))
	}
	msg.WriteString("\n")
	return msg.String()
}

// createClientPod creates a long lived pod that sleeps, and can be used to execute connection tests as a client.
func createClientPod(f *framework.Framework, namespace *v1.Namespace, baseName string, labels map[string]string, customizer func(pod *v1.Pod)) (*v1.Pod, error) {
	var image string
	var args []string
	var command []string
	nodeselector := map[string]string{}

	// Randomize pod names to avoid clashes with previous tests.
	podName := utils.GenerateRandomName(baseName)

	if windows.ClusterIsWindows() {
		image = images.WindowsClientImage()
		command = []string{"powershell.exe"}
		args = []string{"Start-Sleep", "3600"}
		nodeselector["kubernetes.io/os"] = "windows"
	} else {
		image = images.Alpine
		command = []string{"/bin/sleep"}
		args = []string{"3600"}
		nodeselector["kubernetes.io/os"] = "linux"
	}

	// Merge the base labels with the pod name label.
	mergedLabels := make(map[string]string)
	maps.Copy(mergedLabels, labels)
	mergedLabels["pod-name"] = baseName
	mergedLabels[roleLabel] = roleClient

	// Create the pod.
	zero := int64(0)
	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:   podName,
			Labels: mergedLabels,
		},
		Spec: v1.PodSpec{
			RestartPolicy:                 v1.RestartPolicyNever,
			NodeSelector:                  nodeselector,
			TerminationGracePeriodSeconds: &zero,
			Containers: []v1.Container{
				{
					Name:            "client-container",
					Image:           image,
					Command:         command,
					Args:            args,
					ImagePullPolicy: v1.PullIfNotPresent,
				},
			},
			Tolerations: []v1.Toleration{
				v1.Toleration{
					Key:      "kubernetes.io/arch",
					Operator: v1.TolerationOpEqual,
					Value:    "arm64",
					Effect:   v1.TaintEffectNoSchedule,
				},
			},
		},
	}
	if customizer != nil {
		customizer(pod)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return f.ClientSet.CoreV1().Pods(namespace.Name).Create(ctx, pod, metav1.CreateOptions{})
}

func logDiagsForConnection(f *framework.Framework, res connectionResult) {
	By(fmt.Sprintf("Collecting diagnostics for connection %s -> %s", res.clientPod.Name, res.target.Destination()))

	logrus.WithError(res.err).WithFields(logrus.Fields{
		"from":   fmt.Sprintf("%s/%s", res.clientPod.Namespace, res.clientPod.Name),
		"to":     res.target.Destination(),
		"ns":     res.clientPod.Namespace,
		"expect": res.expected,
	}).Error("Error running connection test")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	logs, err := e2epod.GetPodLogs(ctx, f.ClientSet, res.clientPod.Namespace, res.clientPod.Name, fmt.Sprintf("%s-container", res.clientPod.Name))
	if err != nil {
		logrus.WithError(err).Error("Error getting container logs")
	}
	logrus.Infof("[DIAGS] Pod %s/%s logs:\n%s", res.clientPod.Namespace, res.clientPod.Name, logs)
	prevLogs, err := e2epod.GetPreviousPodLogs(ctx, f.ClientSet, res.clientPod.Namespace, res.clientPod.Name, fmt.Sprintf("%s-container", res.clientPod.Name))
	if err != nil {
		logrus.WithError(err).Error("Error getting prev container logs")
	}
	logrus.Infof("[DIAGS] Pod %s/%s logs (previous):\n%s", res.clientPod.Namespace, res.clientPod.Name, prevLogs)

	// Get Pod Describe output.
	podDesc, err := kubectl.RunKubectl(res.clientPod.Namespace, "describe", "pod", res.clientPod.Name)
	if err != nil {
		logrus.WithError(err).Error("Error getting pod description")
	}
	logrus.Infof("[DIAGS] Pod %s/%s describe:\n%s", res.clientPod.Namespace, res.clientPod.Name, podDesc)
}

func logDiagsForNamespace(f *framework.Framework, ns *v1.Namespace) {
	// Collect current NetworkPolicies applied in the test namespace.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	policies, err := f.ClientSet.NetworkingV1().NetworkPolicies(f.Namespace.Name).List(ctx, metav1.ListOptions{})
	if err != nil {
		logrus.WithError(err).Infof("error getting current NetworkPolicies for %s namespace", f.Namespace.Name)
	}
	logrus.Infof("[DIAGS] NetworkPolicies:\n\t%v", policies.Items)

	if f.Namespace.Name != ns.Name {
		// If the pod namespace is different from the test namespace, collect the NetworkPolicies for the pod namespace as well.
		ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		policies, err := f.ClientSet.NetworkingV1().NetworkPolicies(ns.Name).List(ctx, metav1.ListOptions{})
		if err != nil {
			logrus.WithError(err).Infof("error getting current NetworkPolicies for %s namespace", ns.Name)
		}
		logrus.Infof("[DIAGS] NetworkPolicies (pod NS):\n\t%v", policies.Items)
	}

	// Collect Calico network policies and heps.
	nps := &v3.NetworkPolicyList{}
	gnps := &v3.GlobalNetworkPolicyList{}
	heps := &v3.HostEndpointList{}
	logrus.Infof("Current test namespace is %s, but will get policies for all", f.Namespace.Name)

	cli, err := client.New(f.ClientConfig())
	if err != nil {
		logrus.WithError(err).Info("error getting calico client")
	} else {
		err = cli.List(ctx, nps)
		if err != nil {
			logrus.WithError(err).Info("error getting current Calico NetworkPolicies")
		}
		err = cli.List(ctx, gnps)
		if err != nil {
			logrus.WithError(err).Info("error getting current Calico GlobalNetworkPolicies")
		}
		err = cli.List(ctx, heps)
		if err != nil {
			logrus.WithError(err).Info("error getting current Calico HEPs")
		}
	}
	logrus.Infof("[DIAGS] Calico NetworkPolicies:\n\t%v", nps.Items)
	logrus.Infof("[DIAGS] Calico GlobalNetworkPolicies:\n\t%v", gnps.Items)
	logrus.Infof("[DIAGS] Calico HostEndpoints:\n\t%v", heps.Items)

	// Collect the list of pods running in the test namespace.
	ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	podsInNS, err := e2epod.GetPodsInNamespace(ctx, f.ClientSet, ns.Name, map[string]string{})
	if err != nil {
		logrus.WithError(err).Infof("error getting pods for %s namespace", f.Namespace.Name)
	}
	logrus.Infof("[DIAGS] Pods in namespace %s:", ns.Name)
	for _, p := range podsInNS {
		logrus.Infof("Namespace: %s, Pod: %s, Status: %s", ns.Name, p.Name, p.Status.String())
	}

	// Dump debug information for the test namespace.
	e2eoutput.DumpDebugInfo(context.Background(), f.ClientSet, f.Namespace.Name)
}

// ExecInPod executes a kubectl command in a pod. Returns the response as a string, or an error upon failure.
func ExecInPod(pod *v1.Pod, sh, opt, cmd string) (string, error) {
	args := []string{"exec", pod.Name, "--", sh, opt, cmd}
	return kubectl.NewKubectlCommand(pod.Namespace, args...).
		WithTimeout(time.After(10 * time.Second)).
		Exec()
}

// checkpointer implements the Checkpointer interface.
// It runs continuous connection checks in the background, and allows
// the test to checkpoint and verify the results at specific points in time.
type checkpointer struct {
	results               chan connectionResult
	done                  chan struct{}
	client                *Client
	targets               []Target
	routinesDone          sync.WaitGroup
	expectationInProgress sync.WaitGroup
	requestsInProgress    sync.WaitGroup
	tester                *connectionTester
}

func (c *checkpointer) Stop() {
	close(c.done)
	c.routinesDone.Wait()
	close(c.results)
}

func (c *checkpointer) ExpectSuccess(reason string) {
	c.expect(reason, false)
}

func (c *checkpointer) ExpectFailure(reason string) {
	c.expect(reason, true)
}

func (c *checkpointer) start() {
	// Start goroutines running continuous checks for each target.
	for _, target := range c.targets {
		c.routinesDone.Add(1)

		go func(t Target) {
			for {
				select {
				case <-c.done:
					// Stop the goroutine, and mark it as done.
					c.routinesDone.Done()
					return
				default:
				}

				// Block if we are currently performing an expectation check.
				c.expectationInProgress.Wait()

				c.requestsInProgress.Add(1)
				_, result, err := c.tester.execCommandInPod(c.tester.clients[c.client.ID()].pod, c.tester.command(t))
				if err != nil {
					logrus.WithError(err).Warn("Continuous connection attempt returned an error")
				}

				c.results <- connectionResult{
					clientPod: c.tester.clients[c.client.ID()].pod,
					target:    t,
					expected:  Success,
					actual:    result,
					err:       err,
				}
				c.requestsInProgress.Done()
				time.Sleep(10 * time.Millisecond)
			}
		}(target)
	}
}

func (c *checkpointer) expect(reason string, expectFailure bool) {
	By(fmt.Sprintf("Checking continuous connection results %s", reason))

	checkResult := func(res connectionResult) string {
		if !expectFailure && res.Failed() {
			return fmt.Sprintf("Continuous connection check failure %s\n\n%s", reason, buildFailureMessage([]connectionResult{res}))
		} else if expectFailure && !res.Failed() {
			return fmt.Sprintf("Continuous connection check unexpectedly succeeded %s\n\n%s", reason, buildFailureMessage([]connectionResult{res}))
		}
		return ""
	}

	// Wait for at least one result to be available.
	select {
	case res := <-c.results:
		if msg := checkResult(res); msg != "" {
			framework.Fail(msg, 2)
		}
	case <-time.After(10 * time.Second):
		framework.Fail("Timeout waiting for continuous connection results", 2)
	}

	// Block new connection attempts, and wait for any in-progress attempts to complete before
	// draining the results channel. This ensures we have a consistent view of all connection attempts
	// up to this point in time, and prevents possible races where new attempts are started while we are
	// checking results.
	c.expectationInProgress.Add(1)
	defer c.expectationInProgress.Done()

	// Wait for any in-progress requests to complete.
	c.requestsInProgress.Wait()

	// Drain the results channel and log any failures.
	for {
		select {
		case res := <-c.results:
			if msg := checkResult(res); msg != "" {
				framework.Fail(msg, 2)
			}
		default:
			// No more results to process.
			return
		}
	}
}
