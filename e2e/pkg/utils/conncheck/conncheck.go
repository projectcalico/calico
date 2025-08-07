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
	"math/rand"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubernetes/test/e2e/framework"
	"k8s.io/kubernetes/test/e2e/framework/kubectl"
	e2epod "k8s.io/kubernetes/test/e2e/framework/pod"
	e2eoutput "k8s.io/kubernetes/test/e2e/framework/pod/output"

	"github.com/projectcalico/calico/e2e/pkg/utils/client"
	"github.com/projectcalico/calico/e2e/pkg/utils/images"
	"github.com/projectcalico/calico/e2e/pkg/utils/remotecluster"
	"github.com/projectcalico/calico/e2e/pkg/utils/windows"
)

const (
	maxNameLength          = 63
	randomLength           = 5
	maxGeneratedNameLength = maxNameLength - randomLength
)

type connectionTester struct {
	f            *framework.Framework
	servers      map[string]*Server
	clients      map[string]*Client
	expectations map[string]*Expectation
	deployed     bool
}

type ConnectionTester interface {
	AddClient(client *Client)
	AddServer(server *Server)
	Deploy()
	ExpectSuccess(client *Client, targets ...Target)
	ExpectFailure(client *Client, targets ...Target)
	Execute()
	ResetExpectations()
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
		pod, err := createClientPod(c.f, client.namespace, client.name, client.labels, client.customizer)
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
			server.podCustomizer,
			server.svcCustomizer,
		)
		server.pod = pod
		server.service = svc
	}

	// Wait for all pods to be running.
	By("Waiting for all pods in the connection checker to be running")
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()
	for _, client := range c.clients {
		err := e2epod.WaitTimeoutForPodRunningInNamespace(ctx, c.f.ClientSet, client.pod.Name, client.pod.Namespace, 1*time.Minute)
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
		err := e2epod.WaitTimeoutForPodRunningInNamespace(ctx, c.f.ClientSet, server.pod.Name, server.pod.Namespace, 1*time.Minute)
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
		By(fmt.Sprintf("Deleting server pod %s and service %s", server.pod.Name, server.service.Name))
		err := c.f.ClientSet.CoreV1().Pods(server.namespace.Name).Delete(ctx, server.pod.Name, metav1.DeleteOptions{})
		if err != nil {
			return err
		}
		err = c.f.ClientSet.CoreV1().Services(server.namespace.Name).Delete(ctx, server.service.Name, metav1.DeleteOptions{})
		if err != nil {
			return err
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
			return fmt.Errorf("Expected connection %s was not executed. Did you call Execute()?", exp.Description)
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
	resultChan := make(chan connectionResult, len(c.expectations))

	// Launch all of the connections in parallel. We'll wait for them all to finish at the end and report on success / failure.
	for _, expectation := range c.expectations {
		go c.runConnection(expectation, resultChan)
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

	// If we had any errors, log out the per-test diags and then fail the test.
	if failed {
		logDiagsForNamespace(c.f, c.f.Namespace)
		msg := buildFailureMessage(results)
		framework.Fail(msg, 1)
	}
}

func (c *connectionTester) runConnection(exp *Expectation, results chan<- connectionResult) {
	// Exec into the client pod and try to connect to the server.
	cmd := c.command(exp.Target)

	var out string
	var err error
	// Ensure the kubectl command executes in the remote cluster if required. Remote framework objects do not control
	// how kubeconfigs are resolved by the kubectl command, so we must use this wrapper. See NewDefaultFrameworkForRemoteCluster.
	remotecluster.RemoteFrameworkAwareExec(c.f, func() {
		if windows.ClusterIsWindows() {
			out, err = ExecInPod(exp.Client, "powershell.exe", "-Command", cmd)
		} else {
			out, err = ExecInPod(exp.Client, "sh", "-c", cmd)
		}
	})
	logrus.WithFields(logrus.Fields{
		"output": out,
		"cmd":    cmd,
		"err":    err,
	}).Debug("Output from connection attempt.")
	result := Success
	if err != nil {
		result = Failure
	}

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
		return "", fmt.Errorf("Test bug: client %s not registered with connection tester. AddClient()?", client.ID())
	}
	if c.clients[client.ID()].pod == nil {
		return "", fmt.Errorf("Client %s has no running pod. Did you Deploy()?", client.ID())
	}

	cmd := c.command(target)
	var out string
	var err error

	// Ensure the kubectl command executes in the remote cluster if required. Remote framework objects do not control
	// how kubeconfigs are resolved by the kubectl command, so we must use this wrapper. See NewDefaultFrameworkForRemoteCluster.
	remotecluster.RemoteFrameworkAwareExec(c.f, func() {
		if windows.ClusterIsWindows() {
			out, err = ExecInPod(c.clients[client.ID()].pod, "powershell.exe", "-Command", cmd)
		} else {
			out, err = ExecInPod(c.clients[client.ID()].pod, "sh", "-c", cmd)
		}
	})
	return out, err
}

func (c *connectionTester) command(t Target) string {
	var cmd string

	if windows.ClusterIsWindows() {
		// Windows.
		switch t.GetProtocol() {
		case TCP:
			cmd = fmt.Sprintf("$sb={Invoke-WebRequest %s -UseBasicParsing -TimeoutSec 3 -DisableKeepAlive}; "+
				"For ($i=0; $i -lt 5; $i++) { sleep 5; "+
				"try {& $sb} catch { echo failed loop $i ; continue }; exit 0 ; }; exit 1", t.Destination())
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
	msg := "One or more connection tests failed:\n"

	// Add expected results.
	for _, res := range results {
		exp := res.expected
		actual := res.actual
		status := "   OK"
		if exp != actual {
			status = "ERROR"
		}
		msg += fmt.Sprintf(
			"\n%s: %s/%s -> %s (%s, %s, %s); Expected=%s, Actual=%s",
			status,
			res.clientPod.Namespace, res.clientPod.Name,
			res.target.String(),
			res.target.Destination(),
			res.target.GetProtocol(),
			res.target.AccessType(),
			exp,
			actual,
		)
	}
	msg += "\n"
	return msg
}

// createClientPod creates a long lived pod that sleeps, and can be used to execute connection tests as a client.
func createClientPod(f *framework.Framework, namespace *v1.Namespace, baseName string, labels map[string]string, customizer func(pod *v1.Pod)) (*v1.Pod, error) {
	var image string
	var args []string
	var command []string
	nodeselector := map[string]string{}
	pullPolicy := v1.PullAlways

	// Randomize pod names to avoid clashes with previous tests.
	podName := GenerateRandomName(baseName)

	if windows.ClusterIsWindows() {
		image = images.WindowsClientImage()
		command = []string{"powershell.exe"}
		args = []string{"Start-Sleep", "600"}
		nodeselector["kubernetes.io/os"] = "windows"
		pullPolicy = v1.PullIfNotPresent
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
					ImagePullPolicy: pullPolicy,
				},
			},
			Tolerations: []v1.Toleration{
				corev1.Toleration{
					Key:      "kubernetes.io/arch",
					Operator: corev1.TolerationOpEqual,
					Value:    "arm64",
					Effect:   corev1.TaintEffectNoSchedule,
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

	// // Collect/log Calico diags.
	// err = calico.LogCalicoDiagsForPodNode(f, res.clientPod.Namespace, res.clientPod.Name)
	// if err != nil {
	// 	logrus.WithError(err).Error("Error getting Calico diags")
	// }
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

func GenerateRandomName(base string) string {
	if len(base) > maxGeneratedNameLength {
		base = base[:maxGeneratedNameLength]
	}
	return fmt.Sprintf("%s-%s", base, randomString(randomLength))
}

func randomString(length int) string {
	// Generate a random string of the specified length.
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

// ExecInPod executes a kubectl command in a pod. Returns the response as a string, or an error upon failure.
func ExecInPod(pod *v1.Pod, sh, opt, cmd string) (string, error) {
	return kubectl.RunKubectl(pod.Namespace, "exec", pod.Name, "--", sh, opt, cmd)
}
