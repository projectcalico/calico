// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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
	Alpine        = "docker.io/alpine:3"
	Porter        = "calico/porter"
	TestWebserver = "gcr.io/kubernetes-e2e-test-images/test-webserver:1.0"
	Agnhost       = "registry.k8s.io/e2e-test-images/agnhost:2.47"
	RapidClient   = "quay.io/tigeradev/rapidclient"
	Iperf3        = "docker.io/networkstatic/iperf3:latest"
	Netutils      = "calico/k8s-e2e-netutils:stable"
	Socat         = "docker.io/alpine/socat:1.8.0.1"
	Netshoot      = "docker.io/nicolaka/netshoot:v0.13"

	// EchoServer is an alias for Agnhost, used as a convention indicator.
	EchoServer = Agnhost

	// PacketSizeServer is an HTTP/UDP server for tests that need controlled
	// payload sizes (e.g. MTU boundary, fragmentation, encap overhead).
	PacketSizeServer = "calico/k8s-e2e-dataplane-server:stable"

	// KubeVirtUbuntu: Ubuntu 20.04 containerDisk for KubeVirt VM e2e tests.
	KubeVirtUbuntu = "mcas/kubevirt-ubuntu-20.04@sha256:35158058769932812d8ec3ba76985b6f3b02ba288e33a22c77445a7b7f8b3e30"

	// CalicoBIRD: Calico BIRD 1.x. Keep in sync with BIRD_VERSION in metadata.mk.
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
