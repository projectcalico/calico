// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.
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

package images

import (
	"os"

	"k8s.io/kubernetes/test/e2e/framework"
)

const (
	// Alpine provides a minimal POSIX shell environment (sh, wget, nc, ping,
	// sleep). Used for client pods that need to run shell scripts or standard
	// CLI tools; Agnhost is distroless and doesn't ship a shell.
	Alpine = "docker.io/alpine:3"

	// Porter is Calico's multi-protocol TCP/UDP test server. Used as the
	// server image on Windows nodes, since Agnhost has no Windows binary.
	Porter = "calico/porter"

	// TestWebserver is a minimal HTTP server from the K8s e2e image set. Used
	// as the default Linux server in conncheck when tests don't need any of
	// Agnhost's extra endpoints (/clientip, /dial, UDP echo, etc.).
	TestWebserver = "gcr.io/kubernetes-e2e-test-images/test-webserver:1.0"

	// Agnhost is Kubernetes' swiss-army e2e image. Used via `netexec` for
	// multi-protocol servers (HTTP/UDP/SCTP on one pod) and via other
	// subcommands for common test helpers. Version is pinned; bump deliberately.
	Agnhost = "registry.k8s.io/e2e-test-images/agnhost:2.47"

	// RapidClient is a Tigera-built HTTP client that reuses a fixed source port
	// across rapid sequential connections. Needed for Maglev tests where the
	// load-balancer hash depends on source port staying the same; curl, wget,
	// and agnhost don't expose source-port control.
	RapidClient = "quay.io/tigeradev/rapidclient"

	// Iperf3 is a TCP/UDP bandwidth generator, used by iperfcheck for throughput
	// tests. No upstream K8s test image provides iperf3.
	Iperf3 = "docker.io/networkstatic/iperf3:latest"

	// Socat is an alpine+socat container, used for ad-hoc UDP listeners and
	// protocol proxying that agnhost's fixed handlers can't express (e.g. raw
	// UDP echo without the "echo " prefix, or a listener on a non-default port).
	Socat = "docker.io/alpine/socat:1.8.0.1"

	// Netshoot is a network troubleshooting image (curl, tcpdump, nc, ping,
	// iproute2). Used when tests need raw network tools the default client
	// images don't ship, most notably tcpdump for packet capture in the
	// wireguard and encap tests.
	Netshoot = "docker.io/nicolaka/netshoot:v0.13"

	// EchoServer is an alias for Agnhost, used as a convention indicator.
	// Use with `netexec --http-port=PORT` args. Hit /clientip for source IP.
	EchoServer = Agnhost

	// PacketSizeServer is an HTTP/UDP server for tests that need controlled
	// payload sizes (e.g. MTU boundary, fragmentation, encap overhead).
	// Endpoints, all on the same port (default 5000):
	//   - GET /length/<N>: response body is exactly N bytes.
	//   - POST /post: echoes the request body.
	//   - UDP: echoes received datagrams (socat-backed, 10KB buffer).
	// Source: tigera/k8s-e2e/images/flask.
	PacketSizeServer = "calico/k8s-e2e-dataplane-server:stable"

	// KubeVirtUbuntu is a containerDisk image with Ubuntu 20.04 used as the
	// guest OS for KubeVirt VM-based e2e tests. Pinned by digest so test runs
	// don't drift if the upstream :latest tag is repushed; bump deliberately.
	KubeVirtUbuntu = "mcas/kubevirt-ubuntu-20.04@sha256:35158058769932812d8ec3ba76985b6f3b02ba288e33a22c77445a7b7f8b3e30"

	// CalicoBIRD is the Calico BIRD 1.x build used as the BGP daemon on the
	// external TOR node in the KubeVirt eBGP live-migration test. Pinned to a
	// known-good Calico build; bump deliberately if BIRD behaviour changes.
	CalicoBIRD = "calico/bird:v0.3.3-211-g9111ec3c"
)

// Get client image and powershell command based on windows OS version
func WindowsClientImage() string {
	opsys := os.Getenv("WINDOWS_OS")
	if opsys == "" {
		framework.Failf("WINDOWS_OS env not specified. Please set env properly")
		return ""
	}
	switch opsys {
	case "1809", "1909", "1903", "2004", "20H2":
		return "mcr.microsoft.com/windows/servercore:" + opsys
	case "2022":
		// For 2022, servercore uses "ltsc2022" and does not have the image tag
		// "2022" (unlike previous Windows versions).
		return "mcr.microsoft.com/windows/servercore:ltsc2022"
	default:
		framework.Failf("Windows OS version currently not supported: %s", opsys)
	}
	return ""
}
