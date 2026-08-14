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

package cri

import (
	"context"
	"fmt"
	"strings"
	"time"

	securejoin "github.com/cyphar/filepath-securejoin"
	internalapi "k8s.io/cri-api/pkg/apis"
	criv1 "k8s.io/cri-api/pkg/apis/runtime/v1"
	remote "k8s.io/cri-client/pkg"
)

// hostRootPrefix is the prefix used to reach host-filesystem paths from
// inside the calico-node container. The operator bind-mounts the host's
// /proc into calico-node at /host/proc, so /host/proc/1/root is host
// PID-1's root — i.e. the host's mount namespace — regardless of which
// PID namespace calico-node runs in (this does NOT depend on
// hostPID=true). The CRI socket lives on the host, but calico-node
// doesn't bind-mount it; routing through /host/proc/1/root walks the
// host's mount namespace, so connect() finds the socket inode the same
// way an on-host caller would.  Overridable for tests.
var hostRootPrefix = "/host/proc/1/root"

// connectTimeout is how long we wait for the initial CRI gRPC handshake.
const connectTimeout = 10 * time.Second

// Client is a thin wrapper over kubelet's CRI runtime client. It
// looks up the pod sandbox for a given pod UID and derives the host
// path to its network namespace, for callers that need to resolve a
// pod's netns without depending on the CNI's per-pod state.
type Client struct {
	runtime    internalapi.RuntimeService
	socketPath string
}

// New opens a CRI gRPC connection to the local container runtime at
// socketPath.  socketPath is a host-absolute path (typically
// /run/containerd/containerd.sock or /var/run/crio/crio.sock); we
// rewrite it to go through /host/proc/1/root so the dial finds the
// socket in the host's mount namespace.
//
// Returns an error if the runtime can't be reached.
func New(socketPath string) (*Client, error) {
	if socketPath == "" {
		return nil, fmt.Errorf("empty CRI socket path")
	}
	endpoint := "unix://" + viaHostRoot(socketPath)
	// tp=nil (no tracing), useStreaming=false (we only issue unary
	// List/Status RPCs, never Exec/Attach/PortForward).
	svc, err := remote.NewRemoteRuntimeServiceBuilder().
		WithEndpoint(endpoint).
		WithConnectionTimeout(connectTimeout).
		WithTracerProvider(nil).
		WithUseStreaming(false).
		Build(context.Background())
	if err != nil {
		return nil, fmt.Errorf("NewRemoteRuntimeService(%s): %w", endpoint, err)
	}
	return &Client{runtime: svc, socketPath: socketPath}, nil
}

// SocketPath returns the (host-absolute) socket path this client is
// configured for, for diagnostic logging.
func (c *Client) SocketPath() string {
	if c == nil {
		return ""
	}
	return c.socketPath
}

// NetnsPathForPodUID asks the local container runtime for the pod
// sandbox identified by the given Kubernetes pod UID, and returns the
// host-absolute path to its network namespace
// (/proc/<sandbox-pid>/ns/net).
//
// Returns an error if the runtime can't be reached, no sandbox matches
// the UID, or the sandbox has no derivable PID. Any of these is treated
// as "CRI couldn't help" by the caller; the legacy resolver runs next.
func (c *Client) NetnsPathForPodUID(ctx context.Context, podUID string) (string, error) {
	if c == nil || c.runtime == nil {
		return "", fmt.Errorf("nil CRI client")
	}
	if podUID == "" {
		return "", fmt.Errorf("empty pod UID")
	}

	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	items, err := c.runtime.ListPodSandbox(ctx, &criv1.PodSandboxFilter{
		LabelSelector: map[string]string{
			// kubelet stamps this label on every sandbox it creates.
			"io.kubernetes.pod.uid": podUID,
		},
		State: &criv1.PodSandboxStateValue{
			State: criv1.PodSandboxState_SANDBOX_READY,
		},
	})
	if err != nil {
		return "", fmt.Errorf("ListPodSandbox(uid=%s): %w", podUID, err)
	}
	if len(items) == 0 {
		return "", fmt.Errorf("no ready sandbox for pod uid %s", podUID)
	}

	// verbose=true is required to populate Info, which is where
	// containerd / CRI-O publish the sandbox PID.
	sandboxID := items[0].Id
	status, err := c.runtime.PodSandboxStatus(ctx, sandboxID, true)
	if err != nil {
		return "", fmt.Errorf("PodSandboxStatus(%s): %w", sandboxID, err)
	}
	pid, ok := pidFromInfo(status.Info)
	if !ok {
		return "", fmt.Errorf("sandbox %s: no pid in runtime info", sandboxID)
	}
	return fmt.Sprintf("/proc/%d/ns/net", pid), nil
}

// pidFromInfo extracts the sandbox PID from the runtime-info JSON blob
// that containerd / CRI-O ship in PodSandboxStatusResponse.Info["info"].
// We only need a single integer field, so we don't pull in a full JSON
// parser — a small scanner is enough.
func pidFromInfo(info map[string]string) (int, bool) {
	blob, ok := info["info"]
	if !ok {
		return 0, false
	}
	const key = `"pid":`
	idx := strings.Index(blob, key)
	if idx < 0 {
		return 0, false
	}
	idx += len(key)
	for idx < len(blob) && (blob[idx] == ' ' || blob[idx] == '\t') {
		idx++
	}
	pid := 0
	digits := 0
	for idx < len(blob) && blob[idx] >= '0' && blob[idx] <= '9' {
		pid = pid*10 + int(blob[idx]-'0')
		idx++
		digits++
	}
	if digits == 0 {
		return 0, false
	}
	return pid, true
}

// viaHostRoot translates a host-filesystem absolute path into one
// reachable from inside calico-node via the bind-mounted host /proc
// at /host/proc (host PID-1's root). Non-absolute or already-prefixed
// paths pass through.
//
// Symlinks along the path are resolved against the host's view (via
// /host/proc/1/root) using SecureJoin — otherwise an absolute symlink
// target like /var/run -> /run would be re-rooted at the container's
// "/" by the kernel's path walker and the dial would miss the real
// socket. If SecureJoin errors (e.g. a broken intermediate symlink),
// fall back to the naive prefix so the caller still gets a chance to
// open the path.
func viaHostRoot(p string) string {
	if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, hostRootPrefix+"/") || p == hostRootPrefix {
		return p
	}
	resolved, err := securejoin.SecureJoin(hostRootPrefix, p)
	if err != nil {
		return hostRootPrefix + p
	}
	return resolved
}
