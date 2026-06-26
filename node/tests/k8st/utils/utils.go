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

// Package utils is the Go port of node/tests/k8st/utils and test_base.py.
// All Kubernetes interaction goes through native client-go (typed CRUD,
// SPDY exec, log streaming); shell-out helpers remain only for docker and
// calicoctl, which have no Go client equivalent here.
package utils

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
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/remotecommand"
	"k8s.io/utils/ptr"
)

// RouterImage is the BIRD image used to stand up external BGP routers in
// tests. Overridable via $ROUTER_IMAGE to match utils.py.
var RouterImage = envOr("ROUTER_IMAGE", "calico/bird:latest")

// Agnhost is Kubernetes' swiss-army e2e image. Used via `netexec` for
// multi-protocol servers (HTTP/UDP/SCTP on one pod) and via other
// subcommands for common test helpers.
const Agnhost = "registry.k8s.io/e2e-test-images/agnhost:2.47"

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

// RunOptions controls Run/Calicoctl/ExecInPod behaviour. Mirrors the
// keyword arguments on utils.py:run. Zero value = defaults (log on
// failure, fail the test on non-zero exit, return stdout).
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
	restConfig *rest.Config
	clientErr  error
)

// K8sClient returns a singleton clientset loaded from $KUBECONFIG (or the
// default loading rules if unset). Mirrors test_base.py:k8s_client.
func K8sClient(t testing.TB) *kubernetes.Clientset {
	t.Helper()
	initK8sClient(t)
	return clientSet
}

// K8sRestConfig returns the rest.Config behind K8sClient. Needed by the
// SPDY executor in ExecInPod.
func K8sRestConfig(t testing.TB) *rest.Config {
	t.Helper()
	initK8sClient(t)
	return restConfig
}

func initK8sClient(t testing.TB) {
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
		restConfig = cfg
		clientSet, clientErr = kubernetes.NewForConfig(cfg)
	})
	if clientErr != nil {
		t.Fatalf("could not build Kubernetes client: %v", clientErr)
	}
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
	pod, err := lookupCalicoNodePod(t, nodeName)
	if err != nil {
		t.Fatalf("looking up calico-node pod on %s: %v", nodeName, err)
	}
	return pod.Name
}

// ExecInCalicoNode runs the given command inside the calico-node pod
// scheduled on nodeName. Mirrors utils.py:exec_in_calico_node.
func ExecInCalicoNode(t testing.TB, nodeName, command string, opts ...RunOptions) (string, error) {
	t.Helper()
	pod, err := lookupCalicoNodePod(t, nodeName)
	if err != nil {
		return "", err
	}
	return execInPod(t, pod, command, opts...)
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

func lookupCalicoNodePod(t testing.TB, nodeName string) (*corev1.Pod, error) {
	t.Helper()
	cs := K8sClient(t)
	pods, err := cs.CoreV1().Pods("calico-system").List(context.Background(), metav1.ListOptions{
		LabelSelector: "k8s-app=calico-node",
		FieldSelector: fields.OneTermEqualSelector("spec.nodeName", nodeName).String(),
	})
	if err != nil {
		return nil, err
	}
	if len(pods.Items) == 0 {
		return nil, fmt.Errorf("no calico-node pod found on node %s", nodeName)
	}
	return &pods.Items[0], nil
}

// ExecInPod runs the given space-separated command inside the named pod
// (first container) over a native SPDY exec session — the client-go
// equivalent of `kubectl exec`. The remote process's stdout is returned;
// a non-zero remote exit surfaces as a non-nil error, following the same
// RunOptions semantics as Run.
func ExecInPod(t testing.TB, namespace, podName, command string, opts ...RunOptions) (string, error) {
	t.Helper()
	cs := K8sClient(t)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*1)
	defer cancel()

	pod, err := cs.CoreV1().Pods(namespace).Get(ctx, podName, metav1.GetOptions{})
	if err != nil {
		return "", err
	}
	return execInPod(t, pod, command, opts...)
}

func execInPod(t testing.TB, pod *corev1.Pod, command string, opts ...RunOptions) (string, error) {
	t.Helper()
	// Match `kubectl exec -- <command>` after shell word splitting: the Python
	// helper passed the command unquoted, so plain whitespace splitting is the
	// semantic it relied on.
	return streamInPod(t, pod, strings.Fields(command), "", opts...)
}

// ExecInPodStdin runs an explicit argv inside the named pod's first container,
// feeding stdin to the remote process. Used for tools like scapy that read a
// script from standard input — where the `kubectl exec -- <whitespace-split>`
// semantics of ExecInPod cannot express the input.
func ExecInPodStdin(t testing.TB, namespace, podName, stdin string, command []string, opts ...RunOptions) (string, error) {
	t.Helper()
	cs := K8sClient(t)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*1)
	defer cancel()

	pod, err := cs.CoreV1().Pods(namespace).Get(ctx, podName, metav1.GetOptions{})
	if err != nil {
		return "", err
	}
	return streamInPod(t, pod, command, stdin, opts...)
}

// streamInPod runs command (already split into argv) inside the pod's first
// container over a native SPDY exec session, optionally feeding stdin to the
// remote process. It follows the same RunOptions semantics as Run.
func streamInPod(t testing.TB, pod *corev1.Pod, command []string, stdin string, opts ...RunOptions) (string, error) {
	t.Helper()
	o := mergeRunOptions(opts)

	t.Logf("[%s] exec in %s/%s: %v", time.Now().Format(time.RFC3339), pod.Namespace, pod.Name, command)

	ctx := context.Background()
	var cancel context.CancelFunc
	if o.Timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, o.Timeout)
		defer cancel()
	}

	// Pick the first container explicitly: PodExecOptions requires a
	// container name when the pod has more than one and no default-container
	// annotation.
	if len(pod.Spec.Containers) == 0 {
		return "", fmt.Errorf("pod %s/%s has no containers", pod.Namespace, pod.Name)
	}
	container := pod.Spec.Containers[0].Name

	cs := K8sClient(t)
	req := cs.CoreV1().RESTClient().
		Post().
		Resource("pods").
		Name(pod.Name).
		Namespace(pod.Namespace).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: container,
			Command:   command,
			Stdin:     stdin != "",
			Stdout:    true,
			Stderr:    true,
		}, scheme.ParameterCodec)

	executor, err := remotecommand.NewSPDYExecutor(K8sRestConfig(t), "POST", req.URL())
	if err != nil {
		return "", fmt.Errorf("building SPDY executor: %w", err)
	}

	streamOpts := remotecommand.StreamOptions{}
	var stdout, stderr strings.Builder
	streamOpts.Stdout = &stdout
	streamOpts.Stderr = &stderr
	if stdin != "" {
		streamOpts.Stdin = strings.NewReader(stdin)
	}

	err = executor.StreamWithContext(ctx, streamOpts)
	out := stdout.String()
	errOut := stderr.String()
	t.Logf("Out:\n%s", out)
	t.Logf("Err:\n%s", errOut)

	if err != nil {
		if !o.SuppressErrLog {
			t.Logf("Failure output:\n%s\nerr:\n%s", out, errOut)
		}
		if !o.AllowFail {
			return out, fmt.Errorf("exec %v in pod %s/%s failed: %w (stderr: %s)",
				command, pod.Namespace, pod.Name, err, errOut)
		}
		if o.ReturnErr {
			return errOut, err
		}
		return out, err
	}
	return out, nil
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
//	    defer utils.CollectDiagsOnFailure(t)()
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
	logServerVersion(t)
	logClusterSnapshot(t)
	for _, resource := range []string{"node", "bgpconfig", "bgppeer", "gnp", "felixconfig"} {
		_, _ = Calicoctl(t, "get "+resource+" -o yaml", allow)
	}
	nodes, _, _ := NodeInfo(t)
	for _, node := range nodes {
		_, _ = Run(t, "docker exec "+node+" ip r", allow)
		_, _ = Run(t, "docker exec "+node+" ip -6 r", allow)
	}
	logCalicoNodeLogs(t)
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
		if err != nil {
			continue
		}
		for _, f := range []string{
			"bird.cfg", "bird_aggr.cfg", "bird_ipam.cfg",
			"bird6.cfg", "bird6_aggr.cfg", "bird6_ipam.cfg",
		} {
			_, _ = execInPod(t, pod, "cat /etc/calico/confd/config/"+f, allow)
		}
	}
}

// logServerVersion logs the Kubernetes server version (the client-go
// replacement for `kubectl version` in the diags dump).
func logServerVersion(t testing.TB) {
	t.Helper()
	v, err := K8sClient(t).Discovery().ServerVersion()
	if err != nil {
		t.Logf("could not fetch server version: %v", err)
		return
	}
	t.Logf("Kubernetes server version: %s", v.GitVersion)
}

// logClusterSnapshot logs a one-line summary of every deployment, pod,
// service and endpoints object across all namespaces — the client-go
// replacement for `kubectl get deployments,pods,svc,endpoints
// --all-namespaces -o wide` in the diags dump.
func logClusterSnapshot(t testing.TB) {
	t.Helper()
	cs := K8sClient(t)
	ctx := context.Background()

	if deps, err := cs.AppsV1().Deployments(metav1.NamespaceAll).List(ctx, metav1.ListOptions{}); err != nil {
		t.Logf("could not list deployments: %v", err)
	} else {
		for _, d := range deps.Items {
			t.Logf("deployment %s/%s: %d/%d replicas ready", d.Namespace, d.Name,
				d.Status.ReadyReplicas, d.Status.Replicas)
		}
	}

	if pods, err := cs.CoreV1().Pods(metav1.NamespaceAll).List(ctx, metav1.ListOptions{}); err != nil {
		t.Logf("could not list pods: %v", err)
	} else {
		for _, p := range pods.Items {
			t.Logf("pod %s/%s: phase=%s ip=%s node=%s", p.Namespace, p.Name,
				p.Status.Phase, p.Status.PodIP, p.Spec.NodeName)
		}
	}

	if svcs, err := cs.CoreV1().Services(metav1.NamespaceAll).List(ctx, metav1.ListOptions{}); err != nil {
		t.Logf("could not list services: %v", err)
	} else {
		for _, s := range svcs.Items {
			t.Logf("service %s/%s: type=%s clusterIPs=%v externalIPs=%v", s.Namespace, s.Name,
				s.Spec.Type, s.Spec.ClusterIPs, s.Spec.ExternalIPs)
		}
	}

	if eps, err := cs.CoreV1().Endpoints(metav1.NamespaceAll).List(ctx, metav1.ListOptions{}); err != nil {
		t.Logf("could not list endpoints: %v", err)
	} else {
		for _, e := range eps.Items {
			t.Logf("endpoints %s/%s: %v", e.Namespace, e.Name, e.Subsets)
		}
	}
}

// logCalicoNodeLogs logs the tail of every calico-node pod's logs — the
// client-go replacement for `kubectl logs -n calico-system -l
// k8s-app=calico-node` in the diags dump.
func logCalicoNodeLogs(t testing.TB) {
	t.Helper()
	cs := K8sClient(t)
	ctx := context.Background()
	pods, err := cs.CoreV1().Pods("calico-system").List(ctx, metav1.ListOptions{
		LabelSelector: "k8s-app=calico-node",
	})
	if err != nil {
		t.Logf("could not list calico-node pods for logs: %v", err)
		return
	}
	for _, p := range pods.Items {
		// Bound the tail so a long-running soak doesn't dump megabytes per
		// pod into the test log. (kubectl's selector form defaulted to 10
		// lines per pod; 100 gives more context at still-reasonable cost.)
		raw, err := cs.CoreV1().Pods(p.Namespace).GetLogs(p.Name, &corev1.PodLogOptions{
			TailLines: ptr.To(int64(100)),
		}).Do(ctx).Raw()
		if err != nil {
			t.Logf("could not fetch logs for %s/%s: %v", p.Namespace, p.Name, err)
			continue
		}
		t.Logf("logs for %s/%s:\n%s", p.Namespace, p.Name, raw)
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
			// Surface conditions, container statuses and events to help
			// debug (the client-go replacement for `kubectl describe po`).
			logPodDebug(t, &p)
			t.Fatalf("pod %s/%s is in phase %s, expected Running",
				p.Namespace, p.Name, p.Status.Phase)
		}
	}
}

// logPodDebug logs the pod's conditions, container statuses and events.
func logPodDebug(t testing.TB, pod *corev1.Pod) {
	t.Helper()
	for _, c := range pod.Status.Conditions {
		t.Logf("pod %s/%s condition %s=%s reason=%q message=%q",
			pod.Namespace, pod.Name, c.Type, c.Status, c.Reason, c.Message)
	}
	for _, c := range pod.Status.ContainerStatuses {
		t.Logf("pod %s/%s container %s: ready=%v restarts=%d state=%+v",
			pod.Namespace, pod.Name, c.Name, c.Ready, c.RestartCount, c.State)
	}
	events, err := K8sClient(t).CoreV1().Events(pod.Namespace).List(context.Background(), metav1.ListOptions{
		FieldSelector: fields.AndSelectors(
			fields.OneTermEqualSelector("involvedObject.name", pod.Name),
			fields.OneTermEqualSelector("involvedObject.namespace", pod.Namespace),
		).String(),
	})
	if err != nil {
		t.Logf("could not list events for pod %s/%s: %v", pod.Namespace, pod.Name, err)
		return
	}
	for _, e := range events.Items {
		t.Logf("pod %s/%s event %s %s: %s", pod.Namespace, pod.Name, e.Type, e.Reason, e.Message)
	}
}

// ----------------------------------------------------------------------------
// Pod lifecycle helpers (the client-go equivalents of `kubectl wait` and
// `kubectl delete po`).

// PodNames returns the names of the pods in namespace matching the given
// label and field selectors (either may be empty).
func PodNames(t testing.TB, namespace, labelSelector, fieldSelector string) ([]string, error) {
	t.Helper()
	pods, err := K8sClient(t).CoreV1().Pods(namespace).List(context.Background(), metav1.ListOptions{
		LabelSelector: labelSelector,
		FieldSelector: fieldSelector,
	})
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(pods.Items))
	for _, p := range pods.Items {
		names = append(names, p.Name)
	}
	return names, nil
}

// WaitForPodsReady blocks until every pod in the namespace matching
// labelSelector (empty = all pods) has a Ready condition of True, fatally
// failing the test on timeout. The client-go equivalent of
// `kubectl wait --for=condition=Ready pods`.
func WaitForPodsReady(t testing.TB, namespace, labelSelector string, timeout time.Duration) {
	t.Helper()
	cs := K8sClient(t)
	err := RetryUntilSuccess(t, timeout, func() error {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		pods, err := cs.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
			LabelSelector: labelSelector,
		})
		if err != nil {
			return err
		}
		if len(pods.Items) == 0 {
			return fmt.Errorf("no pods found in namespace %s", namespace)
		}
		for _, p := range pods.Items {
			if !podIsReady(&p) {
				return fmt.Errorf("pod %s/%s is not ready", p.Namespace, p.Name)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("pods in %s did not become ready within %s: %v", namespace, timeout, err)
	}
}

// WaitForPodReady blocks until the named pod has a Ready condition of
// True, fatally failing the test on timeout.
func WaitForPodReady(t testing.TB, namespace, name string, timeout time.Duration) {
	t.Helper()
	cs := K8sClient(t)
	err := RetryUntilSuccess(t, timeout, func() error {
		pod, err := cs.CoreV1().Pods(namespace).Get(context.Background(), name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		if !podIsReady(pod) {
			return fmt.Errorf("pod %s/%s is not ready", namespace, name)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("pod %s/%s did not become ready within %s: %v", namespace, name, timeout, err)
	}
}

func podIsReady(pod *corev1.Pod) bool {
	for _, c := range pod.Status.Conditions {
		if c.Type == corev1.PodReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

// DeletePodAndWait deletes the named pod and blocks until it is fully gone
// from the API, fatally failing the test on timeout. Waiting matters: the
// graceful-restart tests look up the replacement pod by IP, and the old
// terminating pod would match the same selector. (kubectl delete waits for
// finalization by default; client-go Delete returns immediately.)
func DeletePodAndWait(t testing.TB, namespace, name string, timeout time.Duration) {
	t.Helper()
	cs := K8sClient(t)
	err := cs.CoreV1().Pods(namespace).Delete(context.Background(), name, metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		t.Fatalf("deleting pod %s/%s: %v", namespace, name, err)
	}
	err = RetryUntilSuccess(t, timeout, func() error {
		_, err := cs.CoreV1().Pods(namespace).Get(context.Background(), name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return nil
		}
		if err != nil {
			return err
		}
		return fmt.Errorf("pod %s/%s still exists", namespace, name)
	})
	if err != nil {
		t.Fatalf("pod %s/%s was not deleted within %s: %v", namespace, name, timeout, err)
	}
}

// ----------------------------------------------------------------------------
// Errors.

// ErrTimeout is returned by RetryUntilSuccess on deadline expiry. It's a
// convenience for callers that want to distinguish timeouts from other
// errors; RetryUntilSuccess wraps it via fmt.Errorf.
var ErrTimeout = errors.New("retry timeout")
