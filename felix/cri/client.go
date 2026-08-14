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
	"path/filepath"
	"strconv"
	"strings"
	"time"

	securejoin "github.com/cyphar/filepath-securejoin"
	internalapi "k8s.io/cri-api/pkg/apis"
	criv1 "k8s.io/cri-api/pkg/apis/runtime/v1"
	remote "k8s.io/cri-client/pkg"
)

// hostMountRoot returns the path, from inside calico-node, of the host
// mount namespace's root: PID-1's root within the procfs at procRoot.
// In production procRoot is the operator's host-procfs bind-mount, so
// this is /host/proc/1/root; with procRoot=/proc (calico-node in the host
// PID namespace) it is /proc/1/root. Either way it walks host PID-1's
// mount namespace, so connect()/open() finds a host inode the same way an
// on-host caller would (this does NOT depend on hostPID=true). The CRI
// socket lives on the host and calico-node doesn't bind-mount it, so it is
// reached this way.
func hostMountRoot(procRoot string) string {
	return filepath.Join(procRoot, "1", "root")
}

// connectTimeout is how long we wait for the initial CRI gRPC handshake.
const connectTimeout = 10 * time.Second

// Client is a thin wrapper over kubelet's CRI runtime client. It
// looks up the pod sandbox for a given pod UID and derives the host
// path to its network namespace, for callers that need to resolve a
// pod's netns without depending on the CNI's per-pod state.
type Client struct {
	runtime    internalapi.RuntimeService
	socketPath string
	procRoot   string
}

// New opens a CRI gRPC connection to the local container runtime at
// socketPath.  socketPath is a host-absolute path (typically
// /run/containerd/containerd.sock or /var/run/crio/crio.sock); we
// rewrite it to go through /host/proc/1/root so the dial finds the
// socket in the host's mount namespace.
//
// procRoot is the procfs the sandbox PID lives in (/proc when Felix
// shares the host PID namespace, else the operator's host-procfs
// bind-mount); NetnsPathForPodUID builds its result under it.
//
// Returns an error if the runtime can't be reached.
func New(procRoot, socketPath string) (*Client, error) {
	if socketPath == "" {
		return nil, fmt.Errorf("empty CRI socket path")
	}
	endpoint := "unix://" + viaHostRoot(procRoot, socketPath)
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
	return &Client{runtime: svc, socketPath: socketPath, procRoot: procRoot}, nil
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
// path to its network namespace (<procRoot>/<sandbox-pid>/ns/net),
// directly openable because the sandbox PID lives in procRoot's procfs.
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
	return filepath.Join(c.procRoot, strconv.Itoa(pid), "ns", "net"), nil
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
// reachable from inside calico-node via host PID-1's root in procRoot's
// procfs (hostMountRoot). Non-absolute or already-prefixed paths pass
// through.
//
// Symlinks along the path are resolved against the host's view (via
// hostMountRoot) using SecureJoin — otherwise an absolute symlink
// target like /var/run -> /run would be re-rooted at the container's
// "/" by the kernel's path walker and the dial would miss the real
// socket. If SecureJoin errors (e.g. a broken intermediate symlink),
// fall back to the naive prefix so the caller still gets a chance to
// open the path.
func viaHostRoot(procRoot, p string) string {
	root := hostMountRoot(procRoot)
	if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, root+"/") || p == root {
		return p
	}
	resolved, err := securejoin.SecureJoin(root, p)
	if err != nil {
		return root + p
	}
	return resolved
}
