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
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"

	v1 "k8s.io/api/core/v1"
	"k8s.io/kubernetes/test/e2e/framework"

	"github.com/projectcalico/calico/e2e/pkg/utils/externalnode"
)

// ExternalNodeClient runs probes over SSH on a host outside the cluster.
type ExternalNodeClient struct {
	name string
	node *externalnode.Client
}

// NewExternalNodeClient wraps an externalnode.Client as a conncheck.Client.
func NewExternalNodeClient(name string, node *externalnode.Client) Client {
	if name == "" {
		framework.Fail("NewExternalNodeClient: name is required", 1)
	}
	if node == nil {
		framework.Fail("NewExternalNodeClient: node is required", 1)
	}
	return &ExternalNodeClient{name: name, node: node}
}

func (c *ExternalNodeClient) ID() string {
	return "external/" + c.name
}

func (c *ExternalNodeClient) Name() string {
	return c.name
}

func (c *ExternalNodeClient) Namespace() *v1.Namespace {
	return nil
}

func (c *ExternalNodeClient) Pod() *v1.Pod {
	return nil
}

func (c *ExternalNodeClient) Deploy(_ context.Context, _ *framework.Framework) error {
	return nil
}

func (c *ExternalNodeClient) Cleanup(_ context.Context, _ *framework.Framework) error {
	return nil
}

func (c *ExternalNodeClient) WaitReady(_ context.Context, _ *framework.Framework) error {
	return nil
}

func (c *ExternalNodeClient) Exec(_ context.Context, cmd string) (string, error) {
	return c.node.Exec("sh", "-c", cmd)
}

// ExecStream runs cmd via a long-lived ssh and streams its merged output to w.
// The returned stop function kills the ssh process and waits for it.
func (c *ExternalNodeClient) ExecStream(ctx context.Context, cmd []string, w io.Writer) (func() error, error) {
	dest := fmt.Sprintf("%s@%s", c.node.SSHUser(), c.node.SSHIP())
	args := []string{
		"-o", "ConnectTimeout=5",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "StrictHostKeyChecking=no",
		"-i", c.node.SSHKeyPath(),
		dest,
		"--",
		strings.Join(cmd, " "),
	}
	sshCmd := exec.CommandContext(ctx, "ssh", args...)
	sshCmd.Stdout = w
	sshCmd.Stderr = w
	if err := sshCmd.Start(); err != nil {
		return nil, fmt.Errorf("ExternalNodeClient: ssh start: %w", err)
	}

	var (
		mu      sync.Mutex
		stopped bool
	)
	waitCh := make(chan error, 1)
	go func() { waitCh <- sshCmd.Wait() }()

	stop := func() error {
		mu.Lock()
		if stopped {
			mu.Unlock()
			return nil
		}
		stopped = true
		mu.Unlock()
		if sshCmd.Process != nil {
			_ = sshCmd.Process.Kill()
		}
		<-waitCh
		return nil
	}
	return stop, nil
}
