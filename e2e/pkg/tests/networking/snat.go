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

package networking

import (
	"fmt"
	"strings"
	"time"

	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"

	"github.com/projectcalico/calico/e2e/pkg/utils/conncheck"
	"github.com/projectcalico/calico/e2e/pkg/utils/images"
)

// connectionResult represents the expected outcome of a connectivity check,
// including SNAT behavior.
type connectionResult string

const (
	unreachable     connectionResult = "unreachable"
	reachableNoSNAT connectionResult = "reachable-no-snat"
	reachableSNAT   connectionResult = "reachable-snat"
)

// checkConnection verifies connectivity from client to target and checks SNAT
// behavior. The target must be an HTTP target pointing to an agnhost netexec
// /clientip endpoint (created via WithHTTP("GET", "/clientip", nil)).
// Uses ct.Connect() for all connectivity — never bypasses conncheck.
func checkConnection(ct conncheck.ConnectionTester, client conncheck.Client, target conncheck.Target, expected connectionResult) {
	logrus.WithFields(logrus.Fields{
		"client":   client.Name(),
		"target":   target.String(),
		"expected": expected,
	}).Info("Checking connection")

	var lastErr error
	Eventually(func() error {
		out, err := ct.Connect(client, target)
		if expected == unreachable {
			if err != nil {
				return nil
			}
			return fmt.Errorf("expected connection to be unreachable, but it succeeded: %s", out)
		}

		if err != nil {
			lastErr = err
			return fmt.Errorf("expected connection to succeed, but it failed: %w", err)
		}

		if expected == reachableSNAT {
			return nil
		}

		// expected == reachableNoSNAT: verify source IP was preserved.
		clientIP := client.Pod().Status.PodIP
		if client.Pod().Spec.HostNetwork {
			// Host-networked pods may use any local IP as the source, so
			// we can't reliably check for SNAT.
			return nil
		}

		sourceIP := parseClientAddress(out)
		if sourceIP == "" {
			return fmt.Errorf("could not parse client IP from /clientip response: %q", out)
		}
		if sourceIP != clientIP {
			return fmt.Errorf("SNAT detected: server saw source %s, expected client IP %s", sourceIP, clientIP)
		}
		return nil
	}, 30*time.Second, 1*time.Second).Should(Succeed(),
		"connection check failed (last err: %v)", lastErr)
}

// withCurlClient swaps the conncheck client pod to Netshoot, which has curl
// and nc. Required when using HTTP protocol targets since the default
// TestWebserver client image only has wget.
func withCurlClient(pod *v1.Pod) {
	for i := range pod.Spec.Containers {
		pod.Spec.Containers[i].Image = images.Netshoot
		pod.Spec.Containers[i].Command = []string{"sleep", "3600"}
		pod.Spec.Containers[i].Args = nil
	}
}

// parseClientAddress extracts the client IP from an agnhost /clientip response.
// The response format is "IP:port" (e.g., "10.244.0.5:34860" or "[::1]:34860").
func parseClientAddress(response string) string {
	response = strings.TrimSpace(response)
	if response == "" {
		return ""
	}

	// Handle IPv6 format: [::1]:port
	if strings.HasPrefix(response, "[") {
		idx := strings.LastIndex(response, "]:")
		if idx >= 0 {
			return response[1:idx]
		}
		return ""
	}

	// Handle IPv4 format: 10.0.0.1:port
	idx := strings.LastIndex(response, ":")
	if idx >= 0 {
		return response[:idx]
	}
	return response
}
