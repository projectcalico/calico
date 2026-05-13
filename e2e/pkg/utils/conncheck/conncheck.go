// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.
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
	"net"
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
	roleLabel             = "e2e.projectcalico.org/role"
	roleClient            = "client"
	roleServer            = "server"
	defaultExecuteTimeout = 30 * time.Second
)

type connectionTester struct {
	f              *framework.Framework
	servers        map[string]Server
	clients        map[string]Client
	expectations   map[string]*Expectation
	deployed       bool
	executeTimeout time.Duration
}

type ConnectionTester interface {
	AddClient(client Client)
	AddServer(server Server)
	Deploy()
	Stop()
	StopClient(client Client)

	ExpectSuccess(client Client, targets ...Target)
	ExpectFailure(client Client, targets ...Target)
	Execute()
	ResetExpectations()
	WithTimeout(d time.Duration)

	ExpectContinuously(client Client, targets ...Target) Checkpointer

	// Connect runs a one-shot probe and returns its output, without
	// recording success/failure expectations.
	Connect(client Client, target Target) (string, error)

	// Encryption verification. The client must have NET_RAW and NET_ADMIN
	// (use WithCapture()).
	ExpectEncrypted(client Client, target Target)
	ExpectPlaintext(client Client, target Target)
}

// Checkpointer asserts on results captured by a continuous probe.
type Checkpointer interface {
	ExpectSuccess(msg string)
	ExpectFailure(msg string)
	// ExpectNoDisruption asserts that the captured probe results have no
	// disruption gap beyond what the supplied options allow. At least one
	// of WithMaxGap / WithMaxConsecutiveLoss must be provided; there is
	// no default tolerance.
	ExpectNoDisruption(msg string, opts ...DisruptionOption)
	Stop()
}

var _ ConnectionTester = &connectionTester{}

func NewConnectionTester(f *framework.Framework) ConnectionTester {
	return &connectionTester{
		f:            f,
		clients:      make(map[string]Client),
		servers:      make(map[string]Server),
		expectations: make(map[string]*Expectation),
	}
}

func (c *connectionTester) ResetExpectations() {
	if err := c.expectationsTested(); err != nil {
		framework.Fail(fmt.Sprintf("ResetExpectations() called before all expectations were tested: %v", err), 1)
	}
	c.expectations = make(map[string]*Expectation)
	c.executeTimeout = 0
}

// WithTimeout sets the timeout for the next Execute() call. Useful when a
// connectivity check needs more time, e.g. waiting for Windows HNS policy
// programming.
func (c *connectionTester) WithTimeout(d time.Duration) {
	c.executeTimeout = d
}

func (c *connectionTester) Deploy() {
	framework.ExpectNoErrorWithOffset(1, c.deploy())
}

func (c *connectionTester) deploy() error {
	timeout := podReadyTimeout(nil)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	for _, cl := range c.clients {
		By(fmt.Sprintf("Deploying client %s", cl.ID()))
		if err := cl.Deploy(ctx, c.f); err != nil {
			return err
		}
	}
	for _, srv := range c.servers {
		By(fmt.Sprintf("Deploying server %s", srv.ID()))
		if err := srv.Deploy(ctx, c.f); err != nil {
			return err
		}
	}

	By("Waiting for all clients and servers to be ready")
	for _, cl := range c.clients {
		if err := cl.WaitReady(ctx, c.f); err != nil {
			return err
		}
	}
	for _, srv := range c.servers {
		if err := srv.WaitReady(ctx, c.f); err != nil {
			return err
		}
	}
	c.deployed = true
	return nil
}

func (c *connectionTester) Stop() {
	framework.ExpectNoErrorWithOffset(1, c.stop())
}

func (c *connectionTester) stop() error {
	By("Tearing down the connection tester")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	for _, cl := range c.clients {
		By(fmt.Sprintf("Cleaning up client %s", cl.ID()))
		if err := cl.Cleanup(ctx, c.f); err != nil {
			return err
		}
	}
	for _, srv := range c.servers {
		By(fmt.Sprintf("Cleaning up server %s", srv.ID()))
		if err := srv.Cleanup(ctx, c.f); err != nil {
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

func (c *connectionTester) AddClient(cl Client) {
	if _, ok := c.clients[cl.ID()]; ok {
		framework.Failf("Client with ID %s already exists", cl.ID())
	}
	c.clients[cl.ID()] = cl
}

func (c *connectionTester) StopClient(cl Client) {
	framework.ExpectNoErrorWithOffset(1, c.stopClient(cl))
}

func (c *connectionTester) stopClient(cl Client) error {
	id := cl.ID()
	if _, ok := c.clients[id]; !ok {
		return fmt.Errorf("client %s not found", id)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()
	if err := c.clients[id].Cleanup(ctx, c.f); err != nil {
		return err
	}
	delete(c.clients, id)
	return nil
}

func (c *connectionTester) AddServer(srv Server) {
	if _, ok := c.servers[srv.ID()]; ok {
		framework.Failf("Server with ID %s already exists", srv.ID())
	}
	c.servers[srv.ID()] = srv
}

type Expectation struct {
	Client         Client
	Target         Target
	Description    string
	ExpectedResult ResultStatus

	executed bool
}

func (e *Expectation) String() string {
	return fmt.Sprintf("Client=%s; Server=%s; Type=%s",
		e.Client.ID(),
		e.Target.String(),
		e.Target.AccessType(),
	)
}

func (c *connectionTester) ExpectSuccess(cl Client, targets ...Target) {
	for _, target := range targets {
		c.expectSuccess(cl, target)
	}
}

func (c *connectionTester) expectSuccess(cl Client, target Target) {
	if c.clients[cl.ID()] == nil {
		framework.Fail(fmt.Sprintf("Test bug: client %s not registered with connection tester. AddClient()?", cl.ID()), 2)
	}
	e := &Expectation{
		Client:         cl,
		Target:         target,
		Description:    fmt.Sprintf("%s -> %s", cl.Name(), target.String()),
		ExpectedResult: Success,
	}
	if c.expectations[e.String()] != nil {
		framework.Fail(fmt.Sprintf("Test bug: duplicate expectation: %s", e.String()), 2)
	}
	c.expectations[e.String()] = e
}

// ExpectContinuously starts continuous probes from cl to targets. Callers must
// call Stop() on the returned Checkpointer when done.
func (c *connectionTester) ExpectContinuously(cl Client, targets ...Target) Checkpointer {
	cp := &checkpointer{
		results: make(chan connectionResult, 1000),
		done:    make(chan struct{}),
		client:  cl,
		targets: targets,
		tester:  c,
	}
	cp.start()
	return cp
}

func (c *connectionTester) ExpectFailure(cl Client, targets ...Target) {
	for _, target := range targets {
		c.expectFailure(cl, target)
	}
}

func (c *connectionTester) expectFailure(cl Client, target Target) {
	if c.clients[cl.ID()] == nil {
		framework.Fail(fmt.Sprintf("Test bug: client %s not registered with connection tester. AddClient()?", cl.ID()), 2)
	}
	e := &Expectation{
		Client:         cl,
		Target:         target,
		Description:    fmt.Sprintf("%s -> %s", cl.Name(), target.String()),
		ExpectedResult: Failure,
	}
	if c.expectations[e.String()] != nil {
		framework.Fail(fmt.Sprintf("Test bug: duplicate expectation: %s", e.String()), 2)
	}
	c.expectations[e.String()] = e
}

func (c *connectionTester) Execute() {
	if !c.deployed {
		framework.Fail("Execute() called before Deploy()", 1)
	}
	By(fmt.Sprintf("Testing %d connections in parallel", len(c.expectations)))

	resultChan := make(chan connectionResult, len(c.expectations))

	timeout := c.executeTimeout
	if timeout == 0 {
		timeout = defaultExecuteTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	for _, expectation := range c.expectations {
		go c.runConnection(ctx, expectation, resultChan)
	}

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
	close(resultChan)

	if failed {
		logDiagsForNamespace(c.f, c.f.Namespace)
		framework.Fail(buildFailureMessage(results), 1)
	}
}

func (c *connectionTester) runConnection(ctx context.Context, exp *Expectation, results chan<- connectionResult) {
	cmd := c.command(exp.Target)

	logCtx := logrus.WithFields(logrus.Fields{
		"cmd":      cmd,
		"client":   exp.Client.ID(),
		"target":   exp.Target.String(),
		"expected": exp.ExpectedResult,
	})

	out, result, err := c.execCommand(exp.Client, cmd)
	if err != nil {
		logCtx.WithError(err).Warn("Connection attempt returned an error")
	}

	// Retry on mismatch until the context expires. Avoids flakes during
	// short windows after policy/route changes propagate.
loop:
	for result != exp.ExpectedResult {
		select {
		case <-ctx.Done():
			break loop
		default:
		}

		logCtx.WithFields(logrus.Fields{
			"output": out,
			"err":    err,
			"actual": result,
		}).Warn("Connection attempt did not get expected result. Retrying...")

		time.Sleep(1 * time.Second)

		out, result, err = c.execCommand(exp.Client, cmd)
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
		client:     exp.Client,
		target:     exp.Target,
		expected:   exp.ExpectedResult,
		actual:     result,
		err:        err,
		recordedAt: time.Now(),
	}
}

// Connect runs a one-shot probe from the client to target and returns the output.
func (c *connectionTester) Connect(cl Client, target Target) (string, error) {
	if c.clients[cl.ID()] == nil {
		return "", fmt.Errorf("test bug: client %s not registered with connection tester. AddClient()?", cl.ID())
	}
	cmd := c.command(target)
	out, _, err := c.execCommand(cl, cmd)
	return out, err
}

func (c *connectionTester) execCommand(cl Client, cmd string) (string, ResultStatus, error) {
	var out string
	var err error

	// Wrap kubectl calls so they pick up the remote cluster kubeconfig when
	// the framework is configured for one. See NewDefaultFrameworkForRemoteCluster.
	remotecluster.RemoteFrameworkAwareExec(c.f, func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		out, err = cl.Exec(ctx, cmd)
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
		switch t.GetProtocol() {
		case TCP:
			cmd = fmt.Sprintf("Invoke-WebRequest %s -UseBasicParsing -TimeoutSec 5 -DisableKeepAlive -ErrorAction Stop | Out-Null", t.Destination())
		case ICMP:
			cmd = fmt.Sprintf("Test-Connection -Count 5 -ComputerName %s", t.Destination())
		default:
			framework.Failf("Unsupported protocol %s", t.GetProtocol())
		}
	} else {
		switch t.GetProtocol() {
		case TCP:
			cmd = fmt.Sprintf("wget -qO- -T 5 http://%s", t.Destination())
		case ICMP:
			cmd = fmt.Sprintf("ping -c 5 %s", t.Destination())
		case HTTP:
			cmdArgs := []string{"curl", "-s", "--connect-timeout", "5", "--fail"}
			req := t.HTTPParams()
			cmdArgs = append(cmdArgs, "--request", req.Method)
			for _, header := range req.Headers {
				cmdArgs = append(cmdArgs, "--header", fmt.Sprintf("'%s'", header))
			}
			if req.Body != "" {
				cmdArgs = append(cmdArgs, "-d", fmt.Sprintf("'%s'", req.Body))
			}
			cmdArgs = append(cmdArgs, fmt.Sprintf("'http://%s%s'", t.Destination(), req.Path))
			cmd = strings.Join(cmdArgs, " ")
		case UDP:
			req := t.HTTPParams()
			host, port, err := net.SplitHostPort(t.Destination())
			if err != nil {
				framework.Failf("UDP target must have a port: %v", err)
			}
			if strings.Contains(host, ":") {
				cmd = fmt.Sprintf("echo '%s' | nc -6 -u -w1 %s %s", req.Body, host, port)
			} else {
				cmd = fmt.Sprintf("echo '%s' | nc -u -w1 %s %s", req.Body, host, port)
			}
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

type connectionResult struct {
	client     Client
	target     Target
	expected   ResultStatus
	actual     ResultStatus
	err        error
	recordedAt time.Time
}

func (r *connectionResult) Failed() bool {
	return r.expected != r.actual
}

// clientLabel returns a printable identifier for the client, falling back to
// the interface ID when there's no pod.
func (r *connectionResult) clientLabel() string {
	if r.client == nil {
		return "<nil>"
	}
	return r.client.ID()
}

func buildFailureMessage(results []connectionResult) string {
	var msg strings.Builder
	msg.WriteString("One or more connection tests failed:\n")

	for _, res := range results {
		exp := res.expected
		actual := res.actual
		status := "   OK"
		if exp != actual {
			status = "ERROR"
		}
		msg.WriteString(fmt.Sprintf(
			"\n%s: %s -> %s (%s, %s, %s); Expected=%s, Actual=%s",
			status,
			res.clientLabel(),
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

// CreateClientPod creates a long-lived sleep pod usable as a connection-test client.
func CreateClientPod(f *framework.Framework, namespace *v1.Namespace, baseName string, labels map[string]string, customizer func(pod *v1.Pod)) (*v1.Pod, error) {
	var image string
	var args []string
	var command []string
	nodeselector := map[string]string{}

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

	mergedLabels := make(map[string]string)
	maps.Copy(mergedLabels, labels)
	mergedLabels["pod-name"] = baseName
	mergedLabels[roleLabel] = roleClient

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
				{
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
	pod := res.client.Pod()
	if pod == nil {
		logrus.WithError(res.err).WithFields(logrus.Fields{
			"from":   res.clientLabel(),
			"to":     res.target.Destination(),
			"expect": res.expected,
		}).Error("Error running connection test (no pod for client)")
		return
	}
	By(fmt.Sprintf("Collecting diagnostics for connection %s -> %s", pod.Name, res.target.Destination()))

	logrus.WithError(res.err).WithFields(logrus.Fields{
		"from":   fmt.Sprintf("%s/%s", pod.Namespace, pod.Name),
		"to":     res.target.Destination(),
		"ns":     pod.Namespace,
		"expect": res.expected,
	}).Error("Error running connection test")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	container := ""
	if len(pod.Spec.Containers) > 0 {
		container = pod.Spec.Containers[0].Name
	}
	logs, err := e2epod.GetPodLogs(ctx, f.ClientSet, pod.Namespace, pod.Name, container)
	if err != nil {
		logrus.WithError(err).Error("Error getting container logs")
	}
	logrus.Infof("[DIAGS] Pod %s/%s logs:\n%s", pod.Namespace, pod.Name, logs)
	prevLogs, err := e2epod.GetPreviousPodLogs(ctx, f.ClientSet, pod.Namespace, pod.Name, container)
	if err != nil {
		logrus.WithError(err).Error("Error getting prev container logs")
	}
	logrus.Infof("[DIAGS] Pod %s/%s logs (previous):\n%s", pod.Namespace, pod.Name, prevLogs)

	podDesc, err := kubectl.RunKubectl(pod.Namespace, "describe", "pod", pod.Name)
	if err != nil {
		logrus.WithError(err).Error("Error getting pod description")
	}
	logrus.Infof("[DIAGS] Pod %s/%s describe:\n%s", pod.Namespace, pod.Name, podDesc)
}

func logDiagsForNamespace(f *framework.Framework, ns *v1.Namespace) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	policies, err := f.ClientSet.NetworkingV1().NetworkPolicies(f.Namespace.Name).List(ctx, metav1.ListOptions{})
	if err != nil {
		logrus.WithError(err).Infof("error getting current NetworkPolicies for %s namespace", f.Namespace.Name)
	}
	logrus.Infof("[DIAGS] NetworkPolicies:\n\t%v", policies.Items)

	if f.Namespace.Name != ns.Name {
		ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		policies, err := f.ClientSet.NetworkingV1().NetworkPolicies(ns.Name).List(ctx, metav1.ListOptions{})
		if err != nil {
			logrus.WithError(err).Infof("error getting current NetworkPolicies for %s namespace", ns.Name)
		}
		logrus.Infof("[DIAGS] NetworkPolicies (pod NS):\n\t%v", policies.Items)
	}

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

	e2eoutput.DumpDebugInfo(context.Background(), f.ClientSet, f.Namespace.Name)
}

// ExecInPod runs a kubectl exec against pod and returns the output.
func ExecInPod(pod *v1.Pod, sh, opt, cmd string) (string, error) {
	args := []string{"exec", pod.Name, "--", sh, opt, cmd}
	return kubectl.NewKubectlCommand(pod.Namespace, args...).
		WithTimeout(time.After(10 * time.Second)).
		Exec()
}

// checkpointer runs continuous connection probes in the background and lets
// the test assert results at specific points in time.
type checkpointer struct {
	results               chan connectionResult
	done                  chan struct{}
	client                Client
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
	for _, target := range c.targets {
		c.routinesDone.Add(1)

		go func(t Target) {
			for {
				select {
				case <-c.done:
					c.routinesDone.Done()
					return
				default:
				}

				c.expectationInProgress.Wait()

				c.requestsInProgress.Add(1)
				started := time.Now()
				_, result, err := c.tester.execCommand(c.client, c.tester.command(t))
				if err != nil {
					logrus.WithError(err).Warn("Continuous connection attempt returned an error")
				}

				c.results <- connectionResult{
					client:     c.client,
					target:     t,
					expected:   Success,
					actual:     result,
					err:        err,
					recordedAt: started,
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

	select {
	case res := <-c.results:
		if msg := checkResult(res); msg != "" {
			framework.Fail(msg, 2)
		}
	case <-time.After(10 * time.Second):
		framework.Fail("Timeout waiting for continuous connection results", 2)
	}

	// Block new probe attempts and drain the channel for a consistent view.
	c.expectationInProgress.Add(1)
	defer c.expectationInProgress.Done()
	c.requestsInProgress.Wait()

	for {
		select {
		case res := <-c.results:
			if msg := checkResult(res); msg != "" {
				framework.Fail(msg, 2)
			}
		default:
			return
		}
	}
}

// disruptionConfig captures user-supplied tolerance for ExpectNoDisruption.
// Either or both bounds may be set. A zero bound means that bound is not enforced.
type disruptionConfig struct {
	maxGap             time.Duration
	maxConsecutiveLoss int
	gapSet             bool
	lossSet            bool
}

// DisruptionOption tunes ExpectNoDisruption's tolerance.
type DisruptionOption func(*disruptionConfig)

// WithMaxGap fails the assertion if any two consecutive probes (per target)
// are recorded more than d apart.
func WithMaxGap(d time.Duration) DisruptionOption {
	return func(c *disruptionConfig) {
		c.maxGap = d
		c.gapSet = true
	}
}

// WithMaxConsecutiveLoss fails the assertion if any target sees more than n
// consecutive failed probes.
func WithMaxConsecutiveLoss(n int) DisruptionOption {
	return func(c *disruptionConfig) {
		c.maxConsecutiveLoss = n
		c.lossSet = true
	}
}

func (c *checkpointer) ExpectNoDisruption(reason string, opts ...DisruptionOption) {
	cfg := &disruptionConfig{}
	for _, opt := range opts {
		opt(cfg)
	}
	if !cfg.gapSet && !cfg.lossSet {
		framework.Fail("ExpectNoDisruption: must set WithMaxGap and/or WithMaxConsecutiveLoss", 2)
	}

	By(fmt.Sprintf("Checking continuous connection disruption %s", reason))

	// Block new probe attempts and drain everything captured so far.
	c.expectationInProgress.Add(1)
	defer c.expectationInProgress.Done()
	c.requestsInProgress.Wait()

	// Group results by target so per-target gap/loss is meaningful.
	byTarget := map[string][]connectionResult{}
	keys := []string{}
	for {
		select {
		case res := <-c.results:
			k := res.target.String()
			if _, ok := byTarget[k]; !ok {
				keys = append(keys, k)
			}
			byTarget[k] = append(byTarget[k], res)
			continue
		default:
		}
		break
	}

	if len(keys) == 0 {
		framework.Fail(fmt.Sprintf("ExpectNoDisruption %s: no probe results captured. Did probes start?", reason), 2)
	}

	var problems []string
	for _, k := range keys {
		series := byTarget[k]
		if len(series) == 0 {
			problems = append(problems, fmt.Sprintf("target %s: no probe results captured", k))
			continue
		}
		if cfg.lossSet {
			consec := 0
			worst := 0
			for _, r := range series {
				if r.actual != Success {
					consec++
					if consec > worst {
						worst = consec
					}
				} else {
					consec = 0
				}
			}
			if worst > cfg.maxConsecutiveLoss {
				problems = append(problems, fmt.Sprintf("target %s: %d consecutive failed probes (max allowed %d)", k, worst, cfg.maxConsecutiveLoss))
			}
		}
		if cfg.gapSet && len(series) > 1 {
			var worst time.Duration
			for i := 1; i < len(series); i++ {
				gap := series[i].recordedAt.Sub(series[i-1].recordedAt)
				if gap > worst {
					worst = gap
				}
			}
			if worst > cfg.maxGap {
				problems = append(problems, fmt.Sprintf("target %s: max inter-probe gap %s exceeds bound %s", k, worst, cfg.maxGap))
			}
		}
	}

	if len(problems) > 0 {
		framework.Fail(fmt.Sprintf("ExpectNoDisruption %s:\n  %s", reason, strings.Join(problems, "\n  ")), 2)
	}
}
