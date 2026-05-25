// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

// Package k8stutils is the Go port of node/tests/k8st/utils and test_base.py.
// It provides shell-out helpers for kubectl/calicoctl/docker plus typed
// client-go helpers for the cases where typed CRUD is cleaner than
// shelling out.
package k8stutils

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// RouterImage is the BIRD image used to stand up external BGP routers in
// tests. Overridable via $ROUTER_IMAGE to match utils.py.
var RouterImage = envOr("ROUTER_IMAGE", "calico/bird:latest")

// NginxImage is the nginx image used by tests that need a simple HTTP
// backend. Overridable via $NGINX_IMAGE to match utils.py.
var NginxImage = envOr("NGINX_IMAGE", "nginx:1")

// ipv6Map maps each kind node name to its static IPv6 address. Kubernetes
// does not yet expose an IPv6 field on Node, so the value here must match
// the assignment in tests/k8st/deploy_resources_on_kind_cluster.sh.
var ipv6Map = map[string]string{
	"kind-control-plane": "2001:20::8",
	"kind-worker":        "2001:20::1",
	"kind-worker2":       "2001:20::2",
	"kind-worker3":       "2001:20::3",
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// ----------------------------------------------------------------------------
// Shell-out helpers.

// RunOptions controls Run/Kubectl/Calicoctl behaviour. Mirrors the keyword
// arguments on utils.py:run. Zero value = defaults (log on failure, fail
// the test on non-zero exit, return stdout).
type RunOptions struct {
	// AllowFail makes a non-zero exit return (with a non-nil error)
	// instead of fatally failing the test.
	AllowFail bool
	// ReturnErr makes a failing Run return stderr in the output string.
	ReturnErr bool
	// SuppressErrLog skips the "Failure output:" log line on non-zero
	// exit. Useful in diag-collection paths where we don't want to
	// log-spam the failures we expect.
	SuppressErrLog bool
	// Timeout sends SIGTERM to the child after the given duration.
	Timeout time.Duration
}

// Run executes a shell command using `sh -c` and returns stdout (or stderr
// if opts.ReturnErr is set and the command failed). The command runs
// synchronously; non-zero exits return an error unless AllowFail is set.
func Run(t testing.TB, command string, opts ...RunOptions) (string, error) {
	t.Helper()
	o := mergeRunOptions(opts)

	t.Logf("[%s] %s", time.Now().Format(time.RFC3339), command)

	ctx := context.Background()
	var cancel context.CancelFunc
	if o.Timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, o.Timeout)
		defer cancel()
	}

	cmd := exec.CommandContext(ctx, "sh", "-c", command)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	out := stdout.String()
	errOut := stderr.String()
	t.Logf("Out:\n%s", out)
	t.Logf("Err:\n%s", errOut)

	if err != nil {
		if !o.SuppressErrLog {
			t.Logf("Failure output:\n%s\nerr:\n%s", out, errOut)
		}
		if !o.AllowFail {
			return out, fmt.Errorf("command %q failed: %w (stderr: %s)", command, err, errOut)
		}
		if o.ReturnErr {
			return errOut, err
		}
		return out, err
	}
	return out, nil
}

// MustRun is Run that calls t.Fatalf on any error.
func MustRun(t testing.TB, command string, opts ...RunOptions) string {
	t.Helper()
	out, err := Run(t, command, opts...)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	return out
}

// Kubectl is Run("kubectl " + args). It mirrors utils.py:kubectl: when
// timeout is non-zero, the command is wrapped in `timeout -s <sec>` so the
// elapsed Kubernetes-side deadline matches the Python helper exactly.
func Kubectl(t testing.TB, args string, opts ...RunOptions) (string, error) {
	t.Helper()
	o := mergeRunOptions(opts)
	cmd := "kubectl " + args
	if o.Timeout > 0 {
		// Use the external `timeout` binary so the kubectl process itself
		// receives SIGTERM at exactly the requested wall-clock deadline
		// (some kubectl subcommands ignore Go context cancellation).
		// utils.py:kubectl uses `timeout -s %d kubectl`, which is a latent
		// bug — `-s` is the signal to send, not the duration — but it
		// never fires there because no Python test passes a timeout. The
		// correct invocation is `timeout <DURATION> kubectl ...`.
		secs := int(o.Timeout.Seconds())
		if secs < 1 {
			secs = 1
		}
		cmd = fmt.Sprintf("timeout %d kubectl %s", secs, args)
		o.Timeout = 0
	}
	return Run(t, cmd, o)
}

// MustKubectl is Kubectl that calls t.Fatalf on any error.
func MustKubectl(t testing.TB, args string, opts ...RunOptions) string {
	t.Helper()
	out, err := Kubectl(t, args, opts...)
	if err != nil {
		t.Fatalf("kubectl %s failed: %v", args, err)
	}
	return out
}

// Calicoctl shells out to `calico ctl --allow-version-mismatch <args>`.
func Calicoctl(t testing.TB, args string, opts ...RunOptions) (string, error) {
	t.Helper()
	return Run(t, "calico ctl --allow-version-mismatch "+args, opts...)
}

// MustCalicoctl is Calicoctl that calls t.Fatalf on any error.
func MustCalicoctl(t testing.TB, args string, opts ...RunOptions) string {
	t.Helper()
	out, err := Calicoctl(t, args, opts...)
	if err != nil {
		t.Fatalf("calicoctl %s failed: %v", args, err)
	}
	return out
}

func mergeRunOptions(opts []RunOptions) RunOptions {
	if len(opts) == 0 {
		return RunOptions{}
	}
	return opts[0]
}

// ----------------------------------------------------------------------------
// Retry.

// RetryUntilSuccess invokes fn until it returns nil or the timeout
// elapses. It uses exponential backoff starting at 0.5s and capped at 10s,
// mirroring utils.py:retry_until_success. The time taken by fn counts
// toward the wall-clock deadline so the overall budget is predictable.
//
// Returns the last error from fn on timeout, or nil on success.
func RetryUntilSuccess(t testing.TB, timeout time.Duration, fn func() error) error {
	t.Helper()
	if timeout <= 0 {
		timeout = 90 * time.Second
	}
	start := time.Now()
	deadline := start.Add(timeout)
	backoff := 500 * time.Millisecond
	const maxBackoff = 10 * time.Second
	attempts := 0

	var lastErr error
	for {
		attempts++
		err := fn()
		if err == nil {
			elapsed := time.Since(start)
			if elapsed > timeout/2 {
				t.Logf("retry succeeded but used %s of %s budget (%d attempts)", elapsed, timeout, attempts)
			}
			return nil
		}
		lastErr = err
		now := time.Now()
		if !now.Before(deadline) {
			return fmt.Errorf("retry did not succeed within %s (%d attempts): %w", timeout, attempts, lastErr)
		}
		remaining := deadline.Sub(now)
		sleep := backoff
		if sleep > remaining {
			sleep = remaining
		}
		if sleep > maxBackoff {
			sleep = maxBackoff
		}
		t.Logf("retry attempt %d hit error, sleeping %s (%s remaining): %v", attempts, sleep, remaining, err)
		time.Sleep(sleep)
		backoff = time.Duration(float64(backoff) * 1.5)
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

// ----------------------------------------------------------------------------
// Kubernetes client + node discovery.

var (
	clientOnce sync.Once
	clientSet  *kubernetes.Clientset
	clientErr  error
)

// K8sClient returns a singleton clientset loaded from $KUBECONFIG (or the
// default loading rules if unset). Mirrors test_base.py:k8s_client.
func K8sClient(t testing.TB) *kubernetes.Clientset {
	t.Helper()
	clientOnce.Do(func() {
		loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
		if kc := os.Getenv("KUBECONFIG"); kc != "" {
			loadingRules.ExplicitPath = kc
		}
		cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
			loadingRules, &clientcmd.ConfigOverrides{}).ClientConfig()
		if err != nil {
			clientErr = err
			return
		}
		clientSet, clientErr = kubernetes.NewForConfig(cfg)
	})
	if clientErr != nil {
		t.Fatalf("could not build Kubernetes client: %v", clientErr)
	}
	return clientSet
}

// NodeInfo returns (nodes, IPv4s, IPv6s). The first entry is the control-plane
// node; entries 1..3 are workers in their kubectl listing order. The IPv6
// slice is filled from ipv6Map. Mirrors utils.py:node_info.
func NodeInfo(t testing.TB) (nodes, ips, ip6s []string) {
	t.Helper()
	cs := K8sClient(t)

	// Control plane first.
	cp, err := cs.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{
		LabelSelector: "node-role.kubernetes.io/control-plane",
	})
	if err != nil {
		t.Fatalf("listing control-plane nodes: %v", err)
	}
	if len(cp.Items) == 0 {
		t.Fatalf("no control-plane node found")
	}
	master := cp.Items[0]
	nodes = append(nodes, master.Name)
	ips = append(ips, nodeAddress(master))
	ip6s = append(ip6s, ipv6Map[master.Name])

	// Workers.
	wk, err := cs.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{
		LabelSelector: "!node-role.kubernetes.io/control-plane",
	})
	if err != nil {
		t.Fatalf("listing worker nodes: %v", err)
	}
	for i := 0; i < 3 && i < len(wk.Items); i++ {
		n := wk.Items[i]
		nodes = append(nodes, n.Name)
		ips = append(ips, nodeAddress(n))
		ip6s = append(ip6s, ipv6Map[n.Name])
	}
	return
}

func nodeAddress(n corev1.Node) string {
	// Mirror utils.py which reads addresses[0].address.
	if len(n.Status.Addresses) == 0 {
		return ""
	}
	return n.Status.Addresses[0].Address
}

// CalicoNodePodName returns the calico-node pod scheduled on the given kind
// node. Mirrors utils.py:calico_node_pod_name.
func CalicoNodePodName(t testing.TB, nodeName string) string {
	t.Helper()
	out, err := Kubectl(t, fmt.Sprintf(
		"get po -n calico-system -l k8s-app=calico-node "+
			"--field-selector spec.nodeName=%s "+
			"-o jsonpath='{.items[0].metadata.name}'", nodeName))
	if err != nil {
		t.Fatalf("looking up calico-node pod on %s: %v", nodeName, err)
	}
	return strings.TrimSpace(out)
}

// ExecInCalicoNode runs the given command inside the calico-node pod
// scheduled on nodeName. Mirrors utils.py:exec_in_calico_node.
func ExecInCalicoNode(t testing.TB, nodeName, command string, opts ...RunOptions) (string, error) {
	t.Helper()
	pod, err := lookupCalicoNodePod(t, nodeName)
	if err != nil {
		return "", err
	}
	return Kubectl(t, fmt.Sprintf("exec -n calico-system %s -- %s", pod, command), opts...)
}

// MustExecInCalicoNode is ExecInCalicoNode that fails the test on error.
func MustExecInCalicoNode(t testing.TB, nodeName, command string, opts ...RunOptions) string {
	t.Helper()
	out, err := ExecInCalicoNode(t, nodeName, command, opts...)
	if err != nil {
		t.Fatalf("exec in calico-node on %s (%q): %v", nodeName, command, err)
	}
	return out
}

func lookupCalicoNodePod(t testing.TB, nodeName string) (string, error) {
	t.Helper()
	// Mirror utils.py which scrapes wide output. The kubectl jsonpath form
	// is cleaner and avoids the ambiguity of grepping pod names.
	out, err := Kubectl(t, fmt.Sprintf(
		"-n calico-system get pods -l k8s-app=calico-node "+
			"--field-selector spec.nodeName=%s "+
			"-o jsonpath='{.items[0].metadata.name}'", nodeName))
	if err != nil {
		return "", err
	}
	name := strings.TrimSpace(out)
	if name == "" {
		return "", fmt.Errorf("no calico-node pod found on node %s", nodeName)
	}
	return name, nil
}

// ----------------------------------------------------------------------------
// Diags.

// CollectDiagsOnFailure registers a t.Cleanup that prints diagnostics if the
// test (or any of its parents) failed. It mirrors utils.py:DiagsCollector,
// which is used as a context manager around test bodies.
//
// Usage:
//
//	func TestSomething(t *testing.T) {
//	    defer k8stutils.CollectDiagsOnFailure(t)()
//	    ...
//	}
//
// The returned func is intentionally a no-op so it can be used with defer
// or ignored; the actual diag dump runs from t.Cleanup.
func CollectDiagsOnFailure(t testing.TB) func() {
	t.Helper()
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		dumpDiags(t)
	})
	return func() {}
}

func dumpDiags(t testing.TB) {
	t.Helper()
	t.Logf("===================================================")
	t.Logf("============= COLLECTING DIAGS FOR TEST ===========")
	t.Logf("===================================================")
	// All these calls allow failure: diag collection must never mask the
	// real test failure.
	allow := RunOptions{AllowFail: true, SuppressErrLog: true}
	_, _ = Kubectl(t, "version", allow)
	_, _ = Kubectl(t, "get deployments,pods,svc,endpoints --all-namespaces -o wide", allow)
	for _, resource := range []string{"node", "bgpconfig", "bgppeer", "gnp", "felixconfig"} {
		_, _ = Calicoctl(t, "get "+resource+" -o yaml", allow)
	}
	nodes, _, _ := NodeInfo(t)
	for _, node := range nodes {
		_, _ = Run(t, "docker exec "+node+" ip r", allow)
		_, _ = Run(t, "docker exec "+node+" ip -6 r", allow)
	}
	_, _ = Kubectl(t, "logs -n calico-system -l k8s-app=calico-node", allow)
	printConfdTemplates(t, nodes)
	t.Logf("===================================================")
	t.Logf("============= COLLECTED DIAGS FOR TEST ============")
	t.Logf("===================================================")
}

func printConfdTemplates(t testing.TB, nodes []string) {
	t.Helper()
	allow := RunOptions{AllowFail: true, SuppressErrLog: true}
	for _, node := range nodes {
		pod, err := lookupCalicoNodePod(t, node)
		if err != nil || pod == "" {
			continue
		}
		for _, f := range []string{
			"bird.cfg", "bird_aggr.cfg", "bird_ipam.cfg",
			"bird6.cfg", "bird6_aggr.cfg", "bird6_ipam.cfg",
		} {
			_, _ = Kubectl(t, fmt.Sprintf(
				"exec -n calico-system %s -- cat /etc/calico/confd/config/%s",
				pod, f), allow)
		}
	}
}

// ----------------------------------------------------------------------------
// Pod-status assertions.

// CheckPodStatus fails the test if any pod in the namespace is not in the
// Running phase. Mirrors test_base.py:check_pod_status.
func CheckPodStatus(t testing.TB, namespace string) {
	t.Helper()
	cs := K8sClient(t)
	pods, err := cs.CoreV1().Pods(namespace).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		t.Fatalf("listing pods in %s: %v", namespace, err)
	}
	for _, p := range pods.Items {
		t.Logf("%s\t%s\t%s", p.Name, p.Namespace, p.Status.Phase)
		if p.Status.Phase != corev1.PodRunning {
			// Surface describe output to help debug.
			_, _ = Kubectl(t, fmt.Sprintf("describe po %s -n %s", p.Name, p.Namespace),
				RunOptions{AllowFail: true})
			t.Fatalf("pod %s/%s is in phase %s, expected Running",
				p.Namespace, p.Name, p.Status.Phase)
		}
	}
}

// ----------------------------------------------------------------------------
// Errors.

// ErrTimeout is returned by RetryUntilSuccess on deadline expiry. It's a
// convenience for callers that want to distinguish timeouts from other
// errors; RetryUntilSuccess wraps it via fmt.Errorf.
var ErrTimeout = errors.New("retry timeout")
