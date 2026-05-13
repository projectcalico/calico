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

package conncheck

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/remotecommand"
	"k8s.io/kubernetes/test/e2e/framework"
)

const defaultStreamMaxBytes = 1 << 20

// StreamSource is the transport-specific bottom half of a stream probe.
// Implementations: PodSource (in-cluster SPDY exec), externalnode.ContainerSource
// (SSH + docker on an external host).
type StreamSource interface {
	// Start launches command and writes its merged stdout/stderr to w. Any
	// async transport error after Start returns goes to errSink. Single-use.
	Start(ctx context.Context, command []string, w io.Writer, errSink func(error)) error
	// Stop terminates the command. Idempotent.
	Stop() error
}

type streamConfig struct {
	command  []string
	maxBytes int
}

// StreamOption configures the streaming probe at construction.
type StreamOption func(*streamConfig) error

// WithStreamCommand sets the command argv the source will run. Required.
func WithStreamCommand(argv ...string) StreamOption {
	return func(c *streamConfig) error {
		if len(argv) == 0 {
			return fmt.Errorf("WithStreamCommand: argv is empty")
		}
		c.command = argv
		return nil
	}
}

// WithStreamMaxBytes caps the in-memory line buffer. Oldest lines and events
// are dropped on overflow. Default 1 MiB.
func WithStreamMaxBytes(n int) StreamOption {
	return func(c *streamConfig) error {
		if n <= 0 {
			return fmt.Errorf("WithStreamMaxBytes: n must be > 0")
		}
		c.maxBytes = n
		return nil
	}
}

type streamDisruptionConfig struct {
	maxGap time.Duration
	gapSet bool
}

// StreamDisruptionOption tunes StreamCheckpointer.ExpectNoDisruption.
// Distinct from DisruptionOption: stream "gap" is interval-between-line-arrivals,
// not interval-between-probe-attempts.
type StreamDisruptionOption func(*streamDisruptionConfig)

// WithStreamMaxGap fails ExpectNoDisruption if two consecutive captured lines
// arrived more than d apart. Only meaningful for known-cadence producers like
// `ping -i 0.2`; raw `nc` cadence is dominated by traffic, not connectivity.
func WithStreamMaxGap(d time.Duration) StreamDisruptionOption {
	return func(c *streamDisruptionConfig) {
		c.maxGap = d
		c.gapSet = true
	}
}

// StreamCheckpointer runs a long-lived command via a StreamSource and asserts
// on the cadence of its output. One newline-terminated record = one event,
// timestamped at arrival. Separate from Checkpointer (discrete probes) by design.
type StreamCheckpointer interface {
	// Stop terminates the source and drains. Returns the terminal error
	// (also sticky in Err). Idempotent.
	Stop() error
	// Err returns the first non-EOF stream error, or nil. Sticky.
	Err() error
	// NumLines is the count of captured records. Allocation-free.
	NumLines() int
	// Events returns line-arrival timestamps, the primary input for gap analysis.
	Events() []time.Time
	// Lines returns the captured records (debug aid).
	Lines() []string
	// ExpectNoDisruption fails if inter-line gap analysis exceeds the
	// supplied bounds. WithStreamMaxGap is required.
	ExpectNoDisruption(opts ...StreamDisruptionOption)
}

// streamCheckpointer is the unexported impl of StreamCheckpointer.
type streamCheckpointer struct {
	name   string
	source StreamSource
	cfg    streamConfig

	mu         sync.Mutex
	events     []time.Time
	lines      []string
	pending    []byte
	err        error
	overflowed bool // true once the byte cap had to drop pending wholesale

	stopOnce sync.Once
	stopDone chan struct{} // closed when Stop has finished tearing down
	stopErr  error         // terminal error from Stop (sticky into err)
}

// StartStream builds a StreamCheckpointer and starts source. WithStreamCommand
// is required. Single-use; caller must Stop (typically via DeferCleanup).
// Invalid args or a failed Start fail the test via framework.Failf.
func StartStream(ctx context.Context, name string, source StreamSource, opts ...StreamOption) StreamCheckpointer {
	if name == "" {
		framework.Failf("StartStream: name is required")
	}
	if source == nil {
		framework.Failf("StartStream: source is required")
	}
	cp := &streamCheckpointer{
		name:     name,
		source:   source,
		cfg:      streamConfig{maxBytes: defaultStreamMaxBytes},
		stopDone: make(chan struct{}),
	}
	for _, opt := range opts {
		if err := opt(&cp.cfg); err != nil {
			framework.Failf("StartStream %q: option error: %v", name, err)
		}
	}
	if len(cp.cfg.command) == 0 {
		framework.Failf("StartStream %q: WithStreamCommand is required", name)
	}
	if err := source.Start(ctx, cp.cfg.command, &streamWriter{cp: cp}, cp.setErr); err != nil {
		framework.Failf("StartStream %q: source.Start: %v", name, err)
	}
	return cp
}

// Stop tears down the source exactly once; concurrent callers block on the
// same teardown. Deferred close of stopDone keeps a panic in source.Stop from
// stranding them.
func (p *streamCheckpointer) Stop() error {
	p.stopOnce.Do(func() {
		defer close(p.stopDone)
		err := p.source.Stop()
		// Drop any trailing un-terminated chunk: no newline = no event.
		p.mu.Lock()
		p.pending = nil
		if err != nil && p.err == nil {
			p.err = err
		}
		p.stopErr = p.err
		p.mu.Unlock()
	})
	<-p.stopDone
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.stopErr
}

func (p *streamCheckpointer) Err() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.err
}

func (p *streamCheckpointer) NumLines() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.lines)
}

func (p *streamCheckpointer) Events() []time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]time.Time, len(p.events))
	copy(out, p.events)
	return out
}

func (p *streamCheckpointer) Lines() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]string, len(p.lines))
	copy(out, p.lines)
	return out
}

func (p *streamCheckpointer) ExpectNoDisruption(opts ...StreamDisruptionOption) {
	cfg := &streamDisruptionConfig{}
	for _, opt := range opts {
		opt(cfg)
	}
	if !cfg.gapSet {
		framework.Fail(fmt.Sprintf("StreamCheckpointer %q: ExpectNoDisruption requires WithStreamMaxGap", p.name), 2)
	}

	// Surface transport errors before doing gap math.
	if err := p.Err(); err != nil {
		framework.Failf("StreamCheckpointer %q: stream error: %v", p.name, err)
	}

	p.mu.Lock()
	overflowed := p.overflowed
	p.mu.Unlock()
	if overflowed {
		framework.Failf("StreamCheckpointer %q: byte cap overflowed; gap analysis would be unreliable. Raise WithStreamMaxBytes or reduce probe verbosity.", p.name)
	}

	events := p.Events()
	if len(events) == 0 {
		framework.Failf("StreamCheckpointer %q: no events captured", p.name)
	}
	if len(events) < 2 {
		framework.Failf("StreamCheckpointer %q: only %d event(s) captured; need >=2 for gap analysis", p.name, len(events))
	}
	var worst time.Duration
	for i := 1; i < len(events); i++ {
		gap := events[i].Sub(events[i-1])
		if gap > worst {
			worst = gap
		}
	}
	if worst > cfg.maxGap {
		framework.Failf("StreamCheckpointer %q: max inter-line gap %v exceeds bound %v (events=%d)",
			p.name, worst, cfg.maxGap, len(events))
	}
}

// setErr records a stream error if one isn't already set. Called by sources
// that detect a transport-level error and want to surface it via Err().
func (p *streamCheckpointer) setErr(err error) {
	if err == nil {
		return
	}
	p.mu.Lock()
	if p.err == nil {
		p.err = err
	}
	p.mu.Unlock()
}

// streamWriter splits source output on newlines and timestamps each record
// at the split (not at Write entry) so multi-line writes don't bias gaps.
type streamWriter struct {
	cp *streamCheckpointer
}

func (w *streamWriter) Write(b []byte) (int, error) {
	p := w.cp
	p.mu.Lock()
	defer p.mu.Unlock()

	p.pending = append(p.pending, b...)
	for {
		nl := bytes.IndexByte(p.pending, '\n')
		if nl < 0 {
			break
		}
		ts := time.Now()
		line := bytes.TrimSuffix(p.pending[:nl], []byte{'\r'})
		p.lines = append(p.lines, string(line))
		p.events = append(p.events, ts)
		p.pending = p.pending[nl+1:]
	}

	// Byte cap: drop oldest line+event pairs; if pending still exceeds the
	// cap, drop pending wholesale and mark overflow. Truncating pending
	// would manufacture a fake line on the next newline; ExpectNoDisruption
	// refuses overflowed streams instead.
	size := len(p.pending)
	for _, l := range p.lines {
		size += len(l) + 1
	}
	for size > p.cfg.maxBytes && len(p.lines) > 0 {
		dropped := p.lines[0]
		p.lines = p.lines[1:]
		p.events = p.events[1:]
		size -= len(dropped) + 1
	}
	if size > p.cfg.maxBytes {
		p.pending = nil
		p.overflowed = true
	}

	return len(b), nil
}

// WaitForCadence blocks until cp has captured at least n lines, or fails the
// test (framework.Failf) on ctx cancel, the 'within' budget, or stream error.
func WaitForCadence(ctx context.Context, cp StreamCheckpointer, n int, within time.Duration) {
	deadline := time.Now().Add(within)
	for {
		if err := cp.Err(); err != nil {
			framework.Failf("WaitForCadence: stream error: %v", err)
		}
		if cp.NumLines() >= n {
			return
		}
		if time.Now().After(deadline) {
			framework.Failf("WaitForCadence: expected %d lines within %v, got %d", n, within, cp.NumLines())
		}
		select {
		case <-ctx.Done():
			framework.Failf("WaitForCadence: context cancelled while waiting for %d lines (have %d): %v", n, cp.NumLines(), ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// PodSource is a StreamSource that runs the command in a Kubernetes pod via
// SPDY exec. Termination uses the stdin-EOF wrapper (see streamWrapper in
// pod_exec.go).
type PodSource struct {
	f         *framework.Framework
	client    Client
	container string

	mu       sync.Mutex
	stdinW   io.WriteCloser
	doneCh   chan struct{}
	stopping bool // true once Stop() has been called; suppresses expected SIGTERM rc=143 exit
}

// NewPodSource builds a PodSource for the given conncheck Client. The pod's
// first container is used unless overridden with WithPodContainer.
func NewPodSource(f *framework.Framework, client Client) *PodSource {
	if f == nil {
		framework.Failf("NewPodSource: framework is required")
	}
	if client == nil {
		framework.Failf("NewPodSource: client is required")
	}
	return &PodSource{f: f, client: client}
}

// WithPodContainer sets the container name to exec in. Defaults to the first
// container in the client's pod.
func (s *PodSource) WithPodContainer(name string) *PodSource {
	s.container = name
	return s
}

// Start launches the command via SPDY exec. Output writes to w.
// errSink, if non-nil, receives any mid-stream SPDY error.
func (s *PodSource) Start(ctx context.Context, command []string, w io.Writer, errSink func(error)) error {
	pod := s.client.Pod()
	container := s.container
	if container == "" && len(pod.Spec.Containers) > 0 {
		container = pod.Spec.Containers[0].Name
	}

	// "/bin/sh -c <wrapper> -- <user-argv>...": the "--" is consumed as $0,
	// user argv expands as "$@" in the wrapper.
	cmd := append([]string{"/bin/sh", "-c", streamWrapper, "--"}, command...)

	req := s.f.ClientSet.CoreV1().RESTClient().
		Post().
		Resource("pods").
		Name(pod.Name).
		Namespace(pod.Namespace).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: container,
			Command:   cmd,
			Stdin:     true,
			Stdout:    true,
			Stderr:    true,
			TTY:       false,
		}, scheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(s.f.ClientConfig(), "POST", req.URL())
	if err != nil {
		return fmt.Errorf("PodSource: build executor: %w", err)
	}

	stdinR, stdinW := io.Pipe()
	doneCh := make(chan struct{})

	s.mu.Lock()
	s.stdinW = stdinW
	s.doneCh = doneCh
	s.mu.Unlock()

	go func() {
		defer close(doneCh)
		streamErr := exec.StreamWithContext(ctx, remotecommand.StreamOptions{
			Stdin:  stdinR,
			Stdout: w,
			Stderr: w,
		})
		// Suppress the wrapper's expected rc=143 after Stop closes stdin;
		// errors seen before stopping is set are real.
		s.mu.Lock()
		stopping := s.stopping
		s.mu.Unlock()
		if streamErr != nil && !errors.Is(streamErr, io.EOF) && !stopping && errSink != nil {
			errSink(streamErr)
		}
	}()

	return nil
}

// Stop closes the SPDY stdin (wrapper's reaper SIGTERMs the child) and waits
// for the executor.
func (s *PodSource) Stop() error {
	s.mu.Lock()
	s.stopping = true
	w := s.stdinW
	done := s.doneCh
	s.stdinW = nil
	s.mu.Unlock()

	if w != nil {
		_ = w.Close()
	}
	if done != nil {
		<-done
	}
	return nil
}
