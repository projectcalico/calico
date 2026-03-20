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

package iperfcheck

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"time"

	"github.com/onsi/ginkgo/v2"
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubernetes/test/e2e/framework"
	e2ekubectl "k8s.io/kubernetes/test/e2e/framework/kubectl"
	e2epod "k8s.io/kubernetes/test/e2e/framework/pod"

	"github.com/projectcalico/calico/e2e/pkg/utils"
	"github.com/projectcalico/calico/e2e/pkg/utils/images"
)

const (
	roleLabel = "e2e.projectcalico.org/role"
	roleIperf = "iperf"

	defaultPort          = 5201
	defaultDuration      = 10
	defaultOmitSeconds   = 5
	defaultRetries       = 3
	defaultRetryInterval = 5 * time.Second
	defaultExecTimeout   = 60 * time.Second
)

// Peer represents an iperf3 endpoint. Any peer can act as server or client
// for a given measurement. Pods run `sleep infinity` and iperf3 commands
// are executed on demand via kubectl exec.
type Peer struct {
	name       string
	namespace  *v1.Namespace
	labels     map[string]string
	nodeName   string
	pod        *v1.Pod
	customizer func(*v1.Pod)
}

// PeerOption configures a Peer.
type PeerOption func(*Peer)

// WithNodeName pins the peer pod to the given node.
func WithNodeName(nodeName string) PeerOption {
	return func(p *Peer) {
		p.nodeName = nodeName
	}
}

// WithPeerLabels sets additional labels on the peer pod.
func WithPeerLabels(labels map[string]string) PeerOption {
	return func(p *Peer) {
		p.labels = labels
	}
}

// WithPeerCustomizer sets a function to customize the pod spec before creation.
func WithPeerCustomizer(fn func(*v1.Pod)) PeerOption {
	return func(p *Peer) {
		p.customizer = fn
	}
}

// NewPeer creates a new iperf3 peer.
func NewPeer(name string, ns *v1.Namespace, opts ...PeerOption) *Peer {
	if ns == nil {
		framework.Failf("Namespace is required for peer %s", name)
	}
	p := &Peer{
		name:      name,
		namespace: ns,
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// Name returns the peer's base name.
func (p *Peer) Name() string {
	return p.name
}

// Pod returns the peer's running pod. Fails the test if the pod is not deployed.
func (p *Peer) Pod() *v1.Pod {
	if p.pod == nil {
		framework.Failf("No pod is running for peer %s/%s", p.namespace.Name, p.name)
	}
	return p.pod
}

// Result holds parsed iperf3 bandwidth measurements.
type Result struct {
	// AverageRate is the average throughput in bits/sec from end.sum_received.
	AverageRate float64
	// PeakRate is the throughput of the first interval in bits/sec.
	PeakRate float64
}

// IperfTester manages iperf3 peers and executes bandwidth measurements.
type IperfTester struct {
	f     *framework.Framework
	peers map[string]*Peer
}

// NewIperfTester creates a new IperfTester.
func NewIperfTester(f *framework.Framework) *IperfTester {
	return &IperfTester{
		f:     f,
		peers: make(map[string]*Peer),
	}
}

// AddPeer registers a peer with the tester.
func (t *IperfTester) AddPeer(peer *Peer) {
	if _, ok := t.peers[peer.name]; ok {
		framework.Failf("Peer %s already registered", peer.name)
	}
	t.peers[peer.name] = peer
}

// RemovePeer deletes a specific peer's pod and deregisters it from the tester.
func (t *IperfTester) RemovePeer(name string) {
	peer, ok := t.peers[name]
	if !ok {
		framework.Failf("Peer %s not registered", name)
	}

	if peer.pod != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
		defer cancel()
		ginkgo.By(fmt.Sprintf("Deleting iperf peer pod %s", peer.pod.Name))
		err := t.f.ClientSet.CoreV1().Pods(peer.namespace.Name).Delete(ctx, peer.pod.Name, metav1.DeleteOptions{})
		framework.ExpectNoError(err, "failed to delete iperf peer pod %s", peer.pod.Name)

		err = e2epod.WaitForPodNotFoundInNamespace(ctx, t.f.ClientSet, peer.pod.Name, peer.namespace.Name, 1*time.Minute)
		framework.ExpectNoError(err, "timed out waiting for peer pod %s deletion", peer.pod.Name)
	}

	delete(t.peers, name)
}

// Deploy creates pods for all registered peers that don't have one yet, then
// waits for them to reach Running state.
func (t *IperfTester) Deploy() {
	for _, peer := range t.peers {
		if peer.pod != nil {
			continue
		}
		ginkgo.By(fmt.Sprintf("Deploying iperf peer pod %s/%s", peer.namespace.Name, peer.name))
		pod, err := createPeerPod(t.f, peer)
		framework.ExpectNoError(err, "failed to create iperf peer pod %s", peer.name)
		peer.pod = pod
	}

	// Wait for all pods to be running.
	ginkgo.By("Waiting for all iperf peer pods to be running")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	for _, peer := range t.peers {
		err := e2epod.WaitTimeoutForPodRunningInNamespace(ctx, t.f.ClientSet, peer.pod.Name, peer.pod.Namespace, 2*time.Minute)
		framework.ExpectNoError(err, "iperf peer pod %s did not reach Running state", peer.pod.Name)

		// Refresh pod to get assigned IP, node name, etc.
		p, err := t.f.ClientSet.CoreV1().Pods(peer.namespace.Name).Get(ctx, peer.pod.Name, metav1.GetOptions{})
		framework.ExpectNoError(err, "failed to get iperf peer pod %s", peer.pod.Name)
		peer.pod = p
	}
}

// Stop deletes all peer pods and waits for them to be gone.
func (t *IperfTester) Stop() {
	ginkgo.By("Tearing down iperf tester")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	for _, peer := range t.peers {
		if peer.pod == nil {
			continue
		}
		ginkgo.By(fmt.Sprintf("Deleting iperf peer pod %s", peer.pod.Name))
		err := t.f.ClientSet.CoreV1().Pods(peer.namespace.Name).Delete(ctx, peer.pod.Name, metav1.DeleteOptions{})
		if err != nil {
			framework.Logf("WARNING: failed to delete iperf peer pod %s: %v", peer.pod.Name, err)
		}
	}

	for _, peer := range t.peers {
		if peer.pod == nil {
			continue
		}
		ginkgo.By(fmt.Sprintf("Waiting for iperf peer pod %s to be deleted", peer.pod.Name))
		if err := e2epod.WaitForPodNotFoundInNamespace(ctx, t.f.ClientSet, peer.pod.Name, peer.namespace.Name, 1*time.Minute); err != nil {
			framework.Logf("WARNING: timed out waiting for peer pod %s deletion: %v", peer.pod.Name, err)
		}
	}
}

// measureConfig holds options for a single bandwidth measurement.
type measureConfig struct {
	reverse         bool
	duration        int
	omitSeconds     int
	retries         int
	retryInterval   time.Duration
	port            int
	udp             bool
	packetLength    int
	targetBandwidth string
}

// MeasureOption configures a bandwidth measurement.
type MeasureOption func(*measureConfig)

// WithReverse enables the -R flag so the server sends data to the client.
// This is used for testing ingress bandwidth limits.
func WithReverse() MeasureOption {
	return func(c *measureConfig) {
		c.reverse = true
	}
}

// WithDuration sets the iperf3 test duration in seconds (-t flag).
func WithDuration(d int) MeasureOption {
	return func(c *measureConfig) {
		c.duration = d
	}
}

// WithOmitSeconds sets the number of seconds to omit from the start (-O flag).
func WithOmitSeconds(n int) MeasureOption {
	return func(c *measureConfig) {
		c.omitSeconds = n
	}
}

// WithRetries sets the number of retry attempts and interval between them.
func WithRetries(n int, interval time.Duration) MeasureOption {
	return func(c *measureConfig) {
		c.retries = n
		c.retryInterval = interval
	}
}

// WithPort overrides the default iperf3 port (5201).
func WithPort(port int) MeasureOption {
	return func(c *measureConfig) {
		c.port = port
	}
}

// WithUDP enables UDP mode (-u flag) for the iperf3 client.
func WithUDP() MeasureOption {
	return func(c *measureConfig) {
		c.udp = true
	}
}

// WithPacketLength sets the UDP packet size in bytes (-l flag).
func WithPacketLength(n int) MeasureOption {
	return func(c *measureConfig) {
		c.packetLength = n
	}
}

// WithTargetBandwidth sets the target send bandwidth (-b flag), e.g. "100M".
func WithTargetBandwidth(bw string) MeasureOption {
	return func(c *measureConfig) {
		c.targetBandwidth = bw
	}
}

// MeasureBandwidth runs an iperf3 test from the client peer to the server peer.
// It starts a one-shot iperf3 server on the server peer, then runs the client.
func (t *IperfTester) MeasureBandwidth(client, server *Peer, opts ...MeasureOption) (*Result, error) {
	cfg := &measureConfig{
		duration:      defaultDuration,
		omitSeconds:   defaultOmitSeconds,
		retries:       defaultRetries,
		retryInterval: defaultRetryInterval,
		port:          defaultPort,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	if client.pod == nil {
		return nil, fmt.Errorf("client peer %s has no running pod", client.name)
	}
	if server.pod == nil {
		return nil, fmt.Errorf("server peer %s has no running pod", server.name)
	}

	serverIP := server.pod.Status.PodIP
	if serverIP == "" {
		return nil, fmt.Errorf("server peer %s has no pod IP", server.name)
	}

	var lastErr error
	for attempt := range cfg.retries {
		logrus.Infof("iperf3 attempt %d of %d", attempt+1, cfg.retries)

		// Kill any leftover iperf3 server from a previous failed attempt before
		// starting a new one, otherwise the port will already be in use.
		killCmd := fmt.Sprintf("pkill -f 'iperf3.*-p %d' 2>/dev/null; sleep 0.5", cfg.port)
		_, _ = execInPod(server.pod, 5*time.Second, "sh", "-c", killCmd)

		// Start a one-shot iperf3 server in daemon mode.
		serverCmd := fmt.Sprintf("iperf3 -s -1 -D -p %d", cfg.port)
		_, err := execInPod(server.pod, defaultExecTimeout, "sh", "-c", serverCmd)
		if err != nil {
			lastErr = fmt.Errorf("failed to start iperf3 server: %w", err)
			logrus.WithError(lastErr).Warn("iperf3 server start failed, retrying")
			time.Sleep(cfg.retryInterval)
			continue
		}

		// Wait for the server daemon to start listening before running the client.
		// The iperf3 image is minimal (no ss/netstat), so check /proc/net/tcp
		// and /proc/net/tcp6 for the listening port in hex. iperf3 typically
		// binds on IPv6 with dual-stack, so both files need to be checked.
		portHex := fmt.Sprintf("%04X", cfg.port)
		waitCmd := fmt.Sprintf(
			"for i in $(seq 1 10); do "+
				"(grep -q ':%s .* 0A' /proc/net/tcp 2>/dev/null || grep -q ':%s .* 0A' /proc/net/tcp6 2>/dev/null) && exit 0; "+
				"sleep 0.5; done; exit 1",
			portHex, portHex,
		)
		_, err = execInPod(server.pod, 10*time.Second, "sh", "-c", waitCmd)
		if err != nil {
			lastErr = fmt.Errorf("iperf3 server not listening on port %d: %w", cfg.port, err)
			logrus.WithError(lastErr).Warn("iperf3 server readiness check failed, retrying")
			time.Sleep(cfg.retryInterval)
			continue
		}

		// Run the iperf3 client. Use --connect-timeout so a failed TCP control
		// connection fails fast instead of burning the full exec timeout.
		clientCmd := fmt.Sprintf("iperf3 -c %s -p %d -t %d -O %d -J --connect-timeout 5000",
			serverIP, cfg.port, cfg.duration, cfg.omitSeconds)
		if cfg.reverse {
			clientCmd += " -R"
		}
		if cfg.udp {
			clientCmd += " -u"
			if cfg.packetLength > 0 {
				clientCmd += fmt.Sprintf(" -l %d", cfg.packetLength)
			}
			if cfg.targetBandwidth != "" {
				clientCmd += fmt.Sprintf(" -b %s", cfg.targetBandwidth)
			}
		}

		// Timeout = duration + omit + buffer.
		timeout := time.Duration(cfg.duration+cfg.omitSeconds+15) * time.Second
		out, err := execInPod(client.pod, timeout, "sh", "-c", clientCmd)
		if err != nil {
			lastErr = fmt.Errorf("iperf3 client exec failed: %w", err)
			logrus.WithError(lastErr).Warn("iperf3 attempt failed, retrying")
			time.Sleep(cfg.retryInterval)
			continue
		}

		result, err := parseIperf3JSON(out)
		if err != nil || result.AverageRate == 0 {
			lastErr = fmt.Errorf("iperf3 parse failed: %w", err)
			logrus.WithError(lastErr).Warn("iperf3 parse failed, retrying")
			time.Sleep(cfg.retryInterval)
			continue
		}

		return result, nil
	}

	return nil, fmt.Errorf("iperf3 failed after %d retries: %w", cfg.retries, lastErr)
}

// createPeerPod creates an iperf3 peer pod that sleeps until exec'd into.
func createPeerPod(f *framework.Framework, peer *Peer) (*v1.Pod, error) {
	podName := utils.GenerateRandomName(peer.name)

	mergedLabels := make(map[string]string)
	maps.Copy(mergedLabels, peer.labels)
	mergedLabels["pod-name"] = peer.name
	mergedLabels[roleLabel] = roleIperf

	zero := int64(0)
	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:   podName,
			Labels: mergedLabels,
		},
		Spec: v1.PodSpec{
			RestartPolicy:                 v1.RestartPolicyNever,
			NodeSelector:                  map[string]string{"kubernetes.io/os": "linux"},
			TerminationGracePeriodSeconds: &zero,
			Containers: []v1.Container{
				{
					Name:            "iperf3",
					Image:           images.Iperf3,
					Command:         []string{"/bin/sh", "-c", "sleep infinity"},
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

	if peer.nodeName != "" {
		pod.Spec.NodeName = peer.nodeName
	}
	if peer.customizer != nil {
		peer.customizer(pod)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return f.ClientSet.CoreV1().Pods(peer.namespace.Name).Create(ctx, pod, metav1.CreateOptions{})
}

// execInPod runs a command in a pod with the given timeout.
func execInPod(pod *v1.Pod, timeout time.Duration, command ...string) (string, error) {
	args := append([]string{"exec", pod.Name, "-n", pod.Namespace, "--"}, command...)
	return e2ekubectl.NewKubectlCommand(pod.Namespace, args...).
		WithTimeout(time.After(timeout)).
		Exec()
}

// iperf3Result is a minimal struct for parsing iperf3 JSON output.
type iperf3Result struct {
	Intervals []struct {
		Sum struct {
			BitsPerSecond float64 `json:"bits_per_second"`
		} `json:"sum"`
	} `json:"intervals"`
	End struct {
		SumReceived struct {
			BitsPerSecond float64 `json:"bits_per_second"`
		} `json:"sum_received"`
		// Sum is used by UDP results (iperf3 reports under "sum" rather than "sum_received" for UDP).
		Sum struct {
			BitsPerSecond float64 `json:"bits_per_second"`
		} `json:"sum"`
	} `json:"end"`
}

// parseIperf3JSON parses iperf3 JSON output and returns a Result.
func parseIperf3JSON(output string) (*Result, error) {
	var raw iperf3Result
	if err := json.Unmarshal([]byte(output), &raw); err != nil {
		return nil, fmt.Errorf("failed to parse iperf3 JSON: %w", err)
	}

	avgRate := raw.End.SumReceived.BitsPerSecond
	if avgRate == 0 {
		// UDP results report under "sum" rather than "sum_received".
		avgRate = raw.End.Sum.BitsPerSecond
	}

	result := &Result{
		AverageRate: avgRate,
	}
	if len(raw.Intervals) > 0 {
		result.PeakRate = raw.Intervals[0].Sum.BitsPerSecond
	}

	logrus.Infof("iperf3 result: rate=%.0f bps, peakRate=%.0f bps", result.AverageRate, result.PeakRate)
	return result, nil
}
