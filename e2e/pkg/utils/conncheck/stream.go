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

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/remotecommand"
	"k8s.io/kubernetes/test/e2e/framework"
)

const defaultStreamMaxBytes = 1 << 20

// StreamSource abstracts the transport-specific bottom half of a StreamProbe:
// how the command is launched and where its combined stdout/stderr is read.
// Implementations: conncheck.PodSource (in-cluster SPDY exec),
// externalnode.ContainerSource (SSH + docker on an external host).
type StreamSource interface {
	// Start launches the command. Output bytes are written to w by the
	// implementation, possibly asynchronously. Returns when the command is
	// launched (or fails to launch). Single-use: Start may be called once
	// per source instance.
	Start(ctx context.Context, command []string, w io.Writer) error
	// Stop terminates the command. Idempotent.
	Stop() error
}

type streamConfig struct {
	command  []string
	maxBytes int
}

type StreamOption func(*streamConfig) error

func WithStreamCommand(argv ...string) StreamOption {
	return func(c *streamConfig) error {
		if len(argv) == 0 {
			return fmt.Errorf("WithStreamCommand: argv is empty")
		}
		c.command = argv
		return nil
	}
}

func WithStreamMaxBytes(n int) StreamOption {
	return func(c *streamConfig) error {
		if n <= 0 {
			return fmt.Errorf("WithStreamMaxBytes: n must be > 0")
		}
		c.maxBytes = n
		return nil
	}
}

// StreamProbe runs a long-lived command via a StreamSource and captures its
// stdout (merged with stderr) into an in-memory line buffer. The buffer is
// capped; oldest lines are dropped on overflow. Single-use.
type StreamProbe struct {
	name   string
	source StreamSource
	cfg    streamConfig

	mu      sync.Mutex
	lines   []string
	pending []byte
	started bool
	stopped bool
	err     error
}

// NewStreamProbe builds a StreamProbe. WithStreamCommand is required.
// Fails (via framework.Failf) on bad input to match the conncheck package
// convention (see NewClient, NewServer, NewTarget).
func NewStreamProbe(name string, source StreamSource, opts ...StreamOption) *StreamProbe {
	if name == "" {
		framework.Failf("NewStreamProbe: name is required")
	}
	if source == nil {
		framework.Failf("NewStreamProbe: source is required")
	}
	p := &StreamProbe{
		name:   name,
		source: source,
		cfg:    streamConfig{maxBytes: defaultStreamMaxBytes},
	}
	for _, opt := range opts {
		if err := opt(&p.cfg); err != nil {
			framework.Failf("NewStreamProbe %q: option error: %v", name, err)
		}
	}
	if len(p.cfg.command) == 0 {
		framework.Failf("NewStreamProbe %q: WithStreamCommand is required", name)
	}
	return p
}

// Start launches the underlying command via the source. The probe is
// single-use: calling Start twice (or after Stop) returns an error.
func (p *StreamProbe) Start(ctx context.Context) error {
	p.mu.Lock()
	if p.started {
		p.mu.Unlock()
		return fmt.Errorf("StreamProbe %q: already started", p.name)
	}
	if p.stopped {
		p.mu.Unlock()
		return fmt.Errorf("StreamProbe %q: stopped, single-use", p.name)
	}
	p.started = true
	p.mu.Unlock()

	return p.source.Start(ctx, p.cfg.command, &streamWriter{probe: p})
}

// Stop terminates the underlying source. Idempotent. After Stop, Lines() and
// Err() reflect the final captured state.
func (p *StreamProbe) Stop() error {
	p.mu.Lock()
	if p.stopped {
		p.mu.Unlock()
		return nil
	}
	p.stopped = true
	p.mu.Unlock()

	err := p.source.Stop()

	// Flush any trailing un-terminated bytes as a final line.
	p.mu.Lock()
	if len(p.pending) > 0 {
		p.lines = append(p.lines, string(p.pending))
		p.pending = nil
	}
	p.mu.Unlock()

	return err
}

// Lines returns a snapshot of newline-delimited records captured so far.
func (p *StreamProbe) Lines() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]string, len(p.lines))
	copy(out, p.lines)
	return out
}

// NumLines returns the count of newline-delimited records captured so far.
// Cheaper than Lines() in tight polling loops (no slice copy).
func (p *StreamProbe) NumLines() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.lines)
}

// Err returns the first non-EOF stream error reported by the source, or nil.
func (p *StreamProbe) Err() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.err
}

// setErr records a stream error if one isn't already set. Called by sources
// that detect a transport-level error and want to surface it via Err().
func (p *StreamProbe) setErr(err error) {
	if err == nil {
		return
	}
	p.mu.Lock()
	if p.err == nil {
		p.err = err
	}
	p.mu.Unlock()
}

// streamWriter is the io.Writer wired to the source's output. It splits on
// newlines into lines and enforces the byte cap by dropping the oldest line(s).
type streamWriter struct {
	probe *StreamProbe
}

func (w *streamWriter) Write(b []byte) (int, error) {
	p := w.probe
	p.mu.Lock()
	defer p.mu.Unlock()

	p.pending = append(p.pending, b...)
	for {
		nl := bytes.IndexByte(p.pending, '\n')
		if nl < 0 {
			break
		}
		line := bytes.TrimSuffix(p.pending[:nl], []byte{'\r'})
		p.lines = append(p.lines, string(line))
		p.pending = p.pending[nl+1:]
	}

	// Cap: drop oldest lines first; if pending alone still exceeds cap,
	// head-truncate pending. Invariant: bufferedSize() <= maxBytes (best
	// effort; a single Write larger than maxBytes is clipped after split).
	size := len(p.pending)
	for _, l := range p.lines {
		size += len(l) + 1
	}
	for size > p.cfg.maxBytes && len(p.lines) > 0 {
		dropped := p.lines[0]
		p.lines = p.lines[1:]
		size -= len(dropped) + 1
	}
	if size > p.cfg.maxBytes && len(p.pending) > p.cfg.maxBytes {
		drop := len(p.pending) - p.cfg.maxBytes
		p.pending = p.pending[drop:]
	}

	return len(b), nil
}

// streamWrapper is /bin/sh -c body that wraps the user command. Closing the
// SPDY stdin from outside causes the reaper subshell to read EOF and SIGTERM
// the child. This is the only reliable way to terminate a remote process via
// SPDY exec since signals are not forwarded.
//
// `exec 3<&0` saves the wrapper's stdin to fd 3 BEFORE any backgrounding,
// because non-interactive shells redirect backgrounded subshell stdin to
// /dev/null (the reaper would otherwise read /dev/null and fire instantly).
// The child gets /dev/null stdin; busybox nc tolerates this by continuing to
// read the socket until EOF (or our SIGTERM).
const streamWrapper = `exec 3<&0
"$@" </dev/null &
child=$!
( cat <&3 >/dev/null ; kill -TERM "$child" 2>/dev/null || true ) &
reaper=$!
wait "$child"
rc=$?
kill -TERM "$reaper" 2>/dev/null || true
exit "$rc"
`

// PodSource is a StreamSource that runs the command in a Kubernetes pod via
// SPDY exec. Termination uses the stdin-EOF wrapper (see streamWrapper).
type PodSource struct {
	f         *framework.Framework
	client    *Client
	container string

	mu       sync.Mutex
	stdinW   io.WriteCloser
	doneCh   chan struct{}
	probe    *StreamProbe // for setErr; set on Start binding via streamWriter's parent
	stopping bool         // true once Stop() has been called; suppresses expected SIGTERM exit
}

// NewPodSource builds a PodSource for the given conncheck Client. The
// pod's first container is used unless overridden with WithPodContainer.
func NewPodSource(f *framework.Framework, client *Client) *PodSource {
	if f == nil {
		framework.Failf("NewPodSource: framework is required")
	}
	if client == nil {
		framework.Failf("NewPodSource: client is required")
	}
	return &PodSource{f: f, client: client}
}

// WithPodContainer sets the container name to exec in. Defaults to the
// first container in the client's pod.
func (s *PodSource) WithPodContainer(name string) *PodSource {
	s.container = name
	return s
}

// Start launches the command via SPDY exec. Output writes to w.
func (s *PodSource) Start(ctx context.Context, command []string, w io.Writer) error {
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
	// Stash the streamWriter's parent probe so we can surface errors.
	if sw, ok := w.(*streamWriter); ok {
		s.probe = sw.probe
	}
	s.mu.Unlock()

	go func() {
		defer close(doneCh)
		streamErr := exec.StreamWithContext(ctx, remotecommand.StreamOptions{
			Stdin:  stdinR,
			Stdout: w,
			Stderr: w,
		})
		// Suppress the non-zero exit the wrapper produces when Stop closes
		// stdin (the reaper SIGTERMs the child, so wait returns rc=143 and
		// the wrapper propagates it). Errors before Stop are real.
		s.mu.Lock()
		stopping := s.stopping
		s.mu.Unlock()
		if streamErr != nil && !errors.Is(streamErr, io.EOF) && !stopping {
			if s.probe != nil {
				s.probe.setErr(streamErr)
			}
		}
	}()

	return nil
}

// Stop closes the SPDY stdin (which triggers the wrapper's reaper to SIGTERM
// the child) and waits for the executor to return.
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
