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
// helpers, all of which shell out to docker.

// ExternalNodeName is the docker container name of the external BGP router that
// the advertisement tests peer with. Matches the Python "kube-node-extra".
const ExternalNodeName = "kube-node-extra"

// StartExternalNodeWithBGP launches a privileged BIRD router container on the
// kind docker network and configures it as a BGP peer. Exactly one of
// birdPeerConfig / bird6PeerConfig should be set, selecting IPv4 or IPv6
// peering; the literal "ip@local" in the config is replaced with the router's
// own source address. Returns that source address (the "birdy" IP).
func StartExternalNodeWithBGP(t testing.TB, name, birdPeerConfig, bird6PeerConfig string) string {
	t.Helper()

	// Log available disk space (diagnostic parity with the Python helper).
	_, _ = Run(t, "df -h", RunOptions{AllowFail: true})

	// Start the router in privileged mode so it can program routes.
	MustRun(t, fmt.Sprintf("docker run -d --privileged --net=kind --name %s %s", name, RouterImage))

	// The image may still be downloading; retry until the container responds.
	if err := RetryUntilSuccess(t, time.Minute, func() error {
		_, err := Run(t, fmt.Sprintf("docker exec %s df -h", name), RunOptions{AllowFail: true, SuppressErrLog: true})
		return err
	}); err != nil {
		t.Fatalf("external node %s did not come up: %v", name, err)
	}

	// Install curl and iproute2.
	MustRun(t, fmt.Sprintf("docker exec %s apk add --no-cache curl iproute2", name))

	// Set ECMP hash algorithm to L4 for proper load balancing between nodes.
	MustRun(t, fmt.Sprintf("docker exec %s sysctl -w net.ipv4.fib_multipath_hash_policy=1", name))

	// Add "merge paths on" to the BIRD kernel protocols.
	MustRun(t, fmt.Sprintf("docker exec %s sed -i '/protocol kernel {/a merge paths on;' /etc/bird.conf", name))
	MustRun(t, fmt.Sprintf("docker exec %s sed -i '/protocol kernel {/a merge paths on;' /etc/bird6.conf", name))

	var birdyIP string
	switch {
	case birdPeerConfig != "":
		out := MustRun(t, fmt.Sprintf("docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' %s", name))
		birdyIP = strings.TrimSpace(out)
		installExternalPeerConfig(t, name, "/etc/bird/peers.conf", strings.ReplaceAll(birdPeerConfig, "ip@local", birdyIP))
		MustRun(t, fmt.Sprintf("docker exec %s birdcl configure", name))
	case bird6PeerConfig != "":
		birdyIP = "2001:20::20"
		MustRun(t, fmt.Sprintf("docker exec %s sysctl -w net.ipv6.conf.all.disable_ipv6=0", name))
		MustRun(t, fmt.Sprintf("docker exec %s sysctl -w net.ipv6.conf.all.forwarding=1", name))
		// Best-effort: older kernels (e.g. Semaphore v2) lack the IPv6
		// multipath hash setting, and we don't test IPv6 ECMP in detail.
		_, _ = Run(t, fmt.Sprintf("docker exec %s sysctl -w net.ipv6.fib_multipath_hash_policy=1", name), RunOptions{AllowFail: true})
		MustRun(t, fmt.Sprintf("docker exec %s ip -6 a a %s/64 dev eth0", name, birdyIP))
		installExternalPeerConfig(t, name, "/etc/bird6/peers.conf", strings.ReplaceAll(bird6PeerConfig, "ip@local", birdyIP))
		MustRun(t, fmt.Sprintf("docker exec %s birdcl6 configure", name))
	}
	return birdyIP
}

// installExternalPeerConfig writes the given BIRD peer config to destPath
// inside the named container via a heredoc piped into `docker exec -i`.
func installExternalPeerConfig(t testing.TB, name, destPath, config string) {
	t.Helper()
	MustRun(t, fmt.Sprintf("cat <<'PEEREOF' | docker exec -i %s sh -c 'cat > %s'\n%s\nPEEREOF\n", name, destPath, config))
}

// RemoveExternalNode best-effort removes the external BGP router container. Safe
// to call in cleanup; it never fails the test.
func RemoveExternalNode(t testing.TB, name string) {
	t.Helper()
	_, _ = Run(t, "docker rm -f "+name, RunOptions{AllowFail: true, SuppressErrLog: true})
}

// ExternalNodeRoutes returns the IPv4 routing table of the external BGP node, as
// produced by `ip r`.
func ExternalNodeRoutes(t testing.TB) string {
	t.Helper()
	return MustRun(t, "docker exec "+ExternalNodeName+" ip r")
}

// Curl runs `curl` from the external BGP node against the given host. An IPv6
// literal is wrapped in brackets.
func Curl(t testing.TB, hostname string) (string, error) {
	t.Helper()
	if strings.Contains(hostname, ":") {
		hostname = "[" + hostname + "]"
	}
	return Run(t, fmt.Sprintf("docker exec %s curl --connect-timeout 2 -m 3 %s", ExternalNodeName, hostname))
}
