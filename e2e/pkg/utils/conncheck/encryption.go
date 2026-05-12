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
	"fmt"
	"strings"
	"time"

	gomega "github.com/onsi/gomega"
)

// ExpectEncrypted verifies that TCP traffic from the client to the target is encrypted.
// It uses tcpdump to capture packets and asserts that no plaintext HTTP patterns are visible.
// The client pod must have NET_RAW and NET_ADMIN capabilities (use WithCapture() client option).
func (c *connectionTester) ExpectEncrypted(client Client, target Target) {
	c.verifyEncryption(client, target, true)
}

// ExpectPlaintext verifies that TCP traffic from the client to the target is NOT encrypted.
// It uses tcpdump to capture packets and asserts that plaintext HTTP patterns are visible.
// The client pod must have NET_RAW and NET_ADMIN capabilities (use WithCapture() client option).
func (c *connectionTester) ExpectPlaintext(client Client, target Target) {
	c.verifyEncryption(client, target, false)
}

// TODO: Hook encryption verification into the Execute() parallel loop so that multiple
// encryption checks can run concurrently alongside connectivity checks. Currently these
// run serially per client/target pair.
func (c *connectionTester) verifyEncryption(client Client, target Target, expectEncrypted bool) {
	pod := client.Pod()
	dest := target.Destination()

	gomega.Eventually(func() error {
		output, err := ExecInPod(pod, "sh", "-c", captureCommand(dest))
		if err != nil {
			return fmt.Errorf("tcpdump exec failed: %w", err)
		}
		return checkEncryption(output, expectEncrypted)
	}).WithTimeout(60*time.Second).WithPolling(10*time.Second).Should(
		gomega.Succeed(),
		encryptionMessage(expectEncrypted),
	)
}

func captureCommand(destination string) string {
	return fmt.Sprintf(
		"tcpdump -Ai eth0 -c 20 2>&1 & TCPDUMP_PID=$!; "+
			"sleep 2; "+
			"wget -q -O /dev/null http://%s/ 2>&1; "+
			"sleep 2; "+
			"kill $TCPDUMP_PID 2>/dev/null; "+
			"wait $TCPDUMP_PID 2>/dev/null",
		destination,
	)
}

var plaintextPatterns = []string{"GET / HTTP", "HTTP/1.0", "HTTP/1.1"}

func checkEncryption(output string, expectEncrypted bool) error {
	hasPlaintext := false
	for _, pattern := range plaintextPatterns {
		if strings.Contains(output, pattern) {
			hasPlaintext = true
			break
		}
	}

	if expectEncrypted && hasPlaintext {
		return fmt.Errorf("traffic appears unencrypted: found plaintext HTTP in tcpdump output")
	}
	if !expectEncrypted && !hasPlaintext {
		return fmt.Errorf("traffic appears encrypted: no plaintext HTTP visible in tcpdump output")
	}
	return nil
}

func encryptionMessage(expectEncrypted bool) string {
	if expectEncrypted {
		return "Traffic should be encrypted (no plaintext HTTP visible in tcpdump)"
	}
	return "Traffic should be unencrypted (plaintext HTTP visible in tcpdump)"
}
