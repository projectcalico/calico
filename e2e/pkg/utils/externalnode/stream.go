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

package externalnode

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// ContainerSource implements conncheck.StreamSource by running a command in a
// docker container on the external node and polling `docker logs` for output.
// Use with conncheck.StartStream.
type ContainerSource struct {
	client       *Client
	container    string
	image        string
	runFlags     []string
	pollInterval time.Duration

	mu      sync.Mutex
	started bool
	stopped bool
	stopCh  chan struct{}
	doneCh  chan struct{}
	seen    int // bytes already forwarded; only touched by poller goroutine
}

// NewContainerSource builds a ContainerSource. container is the docker
// container name on the external host, image is the container image, runFlags
// are extra `docker run` flags (e.g. "--network", "host"). The command itself
// is supplied by StartStream at Start time.
//
// Shell-quoting contract: the command tokens passed via WithStreamCommand are
// space-joined and re-executed under `sh -c` over SSH, NOT auto-quoted. For a
// simple argv like `[]string{"nc", "10.0.0.1", "9999"}` no quoting is needed.
// For a multi-token shell command (pipes, redirects, variable expansion),
// pass it as a single token with literal single quotes, e.g.
//
//	WithStreamCommand("sh", "-c", "'sleep 999 | nc 10.0.0.1 9999'")
//
// so the outer `sh -c` sees one quoted argument and runs it as a sub-shell.
func NewContainerSource(client *Client, container, image string, runFlags ...string) *ContainerSource {
	if client == nil {
		panic("NewContainerSource: client is required")
	}
	if container == "" {
		panic("NewContainerSource: container is required")
	}
	if image == "" {
		panic("NewContainerSource: image is required")
	}
	return &ContainerSource{
		client:       client,
		container:    container,
		image:        image,
		runFlags:     runFlags,
		pollInterval: 1 * time.Second,
	}
}

// WithPollInterval sets the docker-logs polling cadence (default 1s).
func (s *ContainerSource) WithPollInterval(d time.Duration) *ContainerSource {
	s.pollInterval = d
	return s
}

// Start launches `docker run -d <runFlags> --name <container> <image> <command>`
// and starts a goroutine that periodically polls `docker logs` and writes new
// bytes to w. Implements conncheck.StreamSource.
//
// errSink is currently unused: docker-logs polling never propagates errors
// up the stack (a missing/dying container shows up as a long gap in the
// captured event stream, which ExpectNoDisruption detects).
func (s *ContainerSource) Start(ctx context.Context, command []string, w io.Writer, errSink func(error)) error {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return fmt.Errorf("ContainerSource %q: already started", s.container)
	}
	if s.stopped {
		s.mu.Unlock()
		return fmt.Errorf("ContainerSource %q: stopped, single-use", s.container)
	}
	s.started = true
	s.mu.Unlock()

	_ = s.client.RemoveContainer(s.container)

	flags := append([]string{"-d"}, s.runFlags...)
	if _, err := s.client.RunContainer(s.container, s.image, flags, command...); err != nil {
		return fmt.Errorf("ContainerSource %q: run: %w", s.container, err)
	}

	// docker run -d returns 0 even if the embedded command crashes immediately
	// (bad binary, syntax error, target unreachable). Verify the container is
	// running. Fail fast if inspect reports the container is not running
	// (it already exited); only retry while inspect itself errors (transient
	// SSH failure during the 15s window).
	deadline := time.Now().Add(15 * time.Second)
	for {
		running, err := s.client.IsContainerRunning(s.container)
		if err == nil && running {
			break
		}
		if err == nil && !running {
			logs, _ := s.client.ContainerLogs(s.container)
			_ = s.client.RemoveContainer(s.container)
			return fmt.Errorf("ContainerSource %q: container exited before stream could start (logs: %q)", s.container, logs)
		}
		if time.Now().After(deadline) {
			_ = s.client.RemoveContainer(s.container)
			return fmt.Errorf("ContainerSource %q: container readiness check timed out: %w", s.container, err)
		}
		select {
		case <-ctx.Done():
			_ = s.client.RemoveContainer(s.container)
			return fmt.Errorf("ContainerSource %q: %w", s.container, ctx.Err())
		case <-time.After(500 * time.Millisecond):
		}
	}

	stopCh := make(chan struct{})
	doneCh := make(chan struct{})
	s.mu.Lock()
	s.stopCh = stopCh
	s.doneCh = doneCh
	s.mu.Unlock()

	go func() {
		defer close(doneCh)
		ticker := time.NewTicker(s.pollInterval)
		defer ticker.Stop()
		for {
			select {
			case <-stopCh:
				s.poll(w)
				return
			case <-ctx.Done():
				s.poll(w)
				return
			case <-ticker.C:
				s.poll(w)
			}
		}
	}()

	return nil
}

// poll fetches the container's logs and forwards any bytes beyond what was
// already seen.
func (s *ContainerSource) poll(w io.Writer) {
	out, err := s.client.ContainerLogs(s.container)
	if err != nil {
		logrus.Debugf("ContainerSource %s: docker logs failed: %v", s.container, err)
		return
	}
	if len(out) > s.seen {
		_, _ = w.Write([]byte(out[s.seen:]))
		s.seen = len(out)
	}
}

// Stop signals the polling goroutine to exit, waits for it (which includes a
// final poll), then removes the container. Idempotent.
func (s *ContainerSource) Stop() error {
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return nil
	}
	s.stopped = true
	stopCh := s.stopCh
	doneCh := s.doneCh
	s.mu.Unlock()

	if stopCh != nil {
		close(stopCh)
	}
	if doneCh != nil {
		<-doneCh
	}
	return s.client.RemoveContainer(s.container)
}
