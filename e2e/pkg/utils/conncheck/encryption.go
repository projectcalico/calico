// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package conncheck

import (
	"fmt"
	"strings"
	"time"

	gomega "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	"k8s.io/kubernetes/test/e2e/framework/kubectl"
)

// ExpectEncrypted verifies that TCP traffic from the client to the target is encrypted.
// It uses tcpdump to capture packets and asserts that no plaintext HTTP patterns are visible.
// The client pod must have NET_RAW and NET_ADMIN capabilities (use WithCapture() client option).
func (c *connectionTester) ExpectEncrypted(client *Client, target Target) {
	c.verifyEncryption(client, target, true)
}

// ExpectPlaintext verifies that TCP traffic from the client to the target is NOT encrypted.
// It uses tcpdump to capture packets and asserts that plaintext HTTP patterns are visible.
// The client pod must have NET_RAW and NET_ADMIN capabilities (use WithCapture() client option).
func (c *connectionTester) ExpectPlaintext(client *Client, target Target) {
	c.verifyEncryption(client, target, false)
}

// verifyEncryption captures traffic with tcpdump while sending an HTTP request, then checks
// for plaintext HTTP patterns in the capture output.
func (c *connectionTester) verifyEncryption(client *Client, target Target, expectEncrypted bool) {
	pod := client.Pod()
	dest := target.Destination()

	gomega.Eventually(func() error {
		output, err := execInPodWithTimeout(pod, captureCommand(dest), 15*time.Second)
		if err != nil {
			return fmt.Errorf("tcpdump exec failed: %w", err)
		}
		return checkEncryption(output, expectEncrypted)
	}).WithTimeout(60*time.Second).WithPolling(10*time.Second).Should(
		gomega.Succeed(),
		encryptionMessage(expectEncrypted),
	)
}

// captureCommand builds a shell command that runs tcpdump in the background, sends an HTTP
// request to the destination, then collects the capture output. The tcpdump PID is tracked
// explicitly to avoid zombie processes.
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

// plaintextPatterns are HTTP patterns that indicate unencrypted traffic in a tcpdump capture.
var plaintextPatterns = []string{
	"GET / HTTP",
	"HTTP/1.0",
	"HTTP/1.1",
}

// checkEncryption inspects tcpdump output for plaintext HTTP patterns.
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

// execInPodWithTimeout executes a command in a pod with a custom timeout.
func execInPodWithTimeout(pod *v1.Pod, cmd string, timeout time.Duration) (string, error) {
	args := []string{"exec", pod.Name, "--", "sh", "-c", cmd}
	return kubectl.NewKubectlCommand(pod.Namespace, args...).
		WithTimeout(time.After(timeout)).
		Exec()
}
