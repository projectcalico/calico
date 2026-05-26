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
	"fmt"
	"os"

	securejoin "github.com/cyphar/filepath-securejoin"
)

// wellKnownSocketPaths is a small fixed list of host-absolute paths
// where Kubernetes container runtimes commonly publish their CRI
// gRPC sockets. DetectSocketPath probes them in order and returns
// the first one that exists.
//
// Order matters: containerd first (by far the most common), then
// CRI-O, then distro-specific layouts (k3s, RKE2, microk8s). We
// deliberately do NOT list /var/run/* duplicates here — the probe
// resolves /var/run -> /run via SecureJoin against /host/proc/1/root,
// so /run/* covers both layouts.
var wellKnownSocketPaths = []string{
	"/run/containerd/containerd.sock",
	"/run/crio/crio.sock",
	"/run/k3s/containerd/containerd.sock",
	"/run/rke2/containerd/containerd.sock",
	"/var/snap/microk8s/common/run/containerd.sock",
	"/run/dockershim.sock",
}

// DetectSocketPath probes a short list of well-known CRI socket
// paths and returns the first one present on the host filesystem.
//
// Paths are resolved through hostRootPrefix (/host/proc/1/root in
// production) with SecureJoin, so symlinks like /var/run -> /run are
// followed against the host's view rather than the container's, even
// though calico-node does not bind-mount the runtime socket dir.
//
// Returns an error if none of the well-known paths exist.
func DetectSocketPath() (string, error) {
	for _, p := range wellKnownSocketPaths {
		probe, err := securejoin.SecureJoin(hostRootPrefix, p)
		if err != nil {
			continue
		}
		if _, err := os.Stat(probe); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("no CRI socket found at any well-known path (containerd, CRI-O, k3s, RKE2, microk8s, dockershim)")
}
