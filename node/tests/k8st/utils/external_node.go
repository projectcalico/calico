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

package utils

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// ----------------------------------------------------------------------------
// External BGP node.
//
// The BGP advertisement tests peer the cluster with a standalone BIRD router
// running in a docker container on the kind network. These helpers are the Go
// port of utils.py:start_external_node_with_bgp and the get_routes / curl
// helpers in test_base.py, all of which shell out to docker.

// ExternalNodeName is the docker container name of the external BGP router that
// the advertisement tests peer with. Matches the Python "kube-node-extra".
const ExternalNodeName = "kube-node-extra"

// StartExternalNodeWithBGP launches a privileged BIRD router container on the
// kind network and (optionally) installs a peer config, returning the
// container's IP address on the kind network. It is the Go port of
// utils.py:start_external_node_with_bgp (IPv4 path only — the v6 path is added
// when the v6 advertisement test is ported). Any failure fatally fails the
// test.
func StartExternalNodeWithBGP(t testing.TB, name, birdPeerConfig string) string {
	t.Helper()

	// Check how much disk space we have (matches the Python diag).
	_, _ = Run(t, "df -h", RunOptions{AllowFail: true})

	// Setup external node: privileged so it can program routes.
	MustRun(t, fmt.Sprintf("docker run -d --privileged --net=kind --name %s %s", name, RouterImage))

	// The image may still be downloading, so retry until the container runs.
	err := RetryUntilSuccess(t, 60*time.Second, func() error {
		_, err := Run(t, "docker exec "+name+" df -h", RunOptions{AllowFail: true, SuppressErrLog: true})
		return err
	})
	if err != nil {
		t.Fatalf("external node %s did not start within 60s: %v", name, err)
	}

	// Install curl and iproute2.
	MustRun(t, "docker exec "+name+" apk add --no-cache curl iproute2")

	// Set ECMP hash algorithm to L4 for proper load balancing between nodes.
	MustRun(t, "docker exec "+name+" sysctl -w net.ipv4.fib_multipath_hash_policy=1")

	// Add "merge paths on" to the BIRD config so ECMP routes are installed.
	MustRun(t, "docker exec "+name+" sed -i '/protocol kernel {/a merge paths on;' /etc/bird.conf")
	MustRun(t, "docker exec "+name+" sed -i '/protocol kernel {/a merge paths on;' /etc/bird6.conf")

	birdyIP := strings.TrimSpace(MustRun(t, fmt.Sprintf(
		"docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' %s", name)))

	if birdPeerConfig != "" {
		// Install the desired peer config, substituting the container's own IP
		// for the "ip@local" placeholder used in the BIRD templates.
		peerConf := strings.ReplaceAll(birdPeerConfig, "ip@local", birdyIP)
		f, err := os.CreateTemp("", "peers-*.conf")
		if err != nil {
			t.Fatalf("creating temp peers.conf: %v", err)
		}
		defer os.Remove(f.Name())
		if _, err := f.WriteString(peerConf); err != nil {
			t.Fatalf("writing temp peers.conf: %v", err)
		}
		if err := f.Close(); err != nil {
			t.Fatalf("closing temp peers.conf: %v", err)
		}
		MustRun(t, fmt.Sprintf("docker cp %s %s:/etc/bird/peers.conf", f.Name(), name))
		MustRun(t, "docker exec "+name+" birdcl configure")
	}

	return birdyIP
}

// RemoveExternalNode best-effort removes the external BGP router container. Safe
// to call in cleanup; it never fails the test.
func RemoveExternalNode(t testing.TB, name string) {
	t.Helper()
	_, _ = Run(t, "docker rm -f "+name, RunOptions{AllowFail: true, SuppressErrLog: true})
}

// ExternalNodeRoutes returns the IPv4 routing table of the external BGP node, as
// produced by `ip r`. It is the Go port of test_base.py:get_routes.
func ExternalNodeRoutes(t testing.TB) string {
	t.Helper()
	return MustRun(t, "docker exec "+ExternalNodeName+" ip r")
}

// Curl runs `curl` from the external BGP node against the given host. An IPv6
// literal is wrapped in brackets. It is the Go port of utils.py:curl.
func Curl(t testing.TB, hostname string) (string, error) {
	t.Helper()
	if strings.Contains(hostname, ":") {
		hostname = "[" + hostname + "]"
	}
	return Run(t, fmt.Sprintf("docker exec %s curl --connect-timeout 2 -m 3 %s", ExternalNodeName, hostname))
}
