/*
Copyright (c) 2026 Tigera, Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"syscall"
	"time"
)

func init() { registerMode(clientMode{}) }

// clientMode is the default mode: a simple HTTP client that forces source-port
// reuse (SO_REUSEADDR, keep-alives disabled) so each call is a fresh TCP
// connection from a fixed source port. Used to test Maglev consistent hashing
// and load-balancer behaviour.
type clientMode struct{}

func (clientMode) Name() string { return "client" }

func (clientMode) Run(args []string) error {
	// ContinueOnError so a parse error or missing required flag is returned to
	// main (which maps it to a non-zero exit) rather than calling os.Exit here.
	// This honours the Mode.Run contract, matches server mode, and keeps the
	// mode unit-testable.
	fs := flag.NewFlagSet("client", flag.ContinueOnError)
	var (
		targetURL  = fs.String("url", "", "Target URL to send request to (required)")
		sourcePort = fs.Int("port", 12345, "Source port to use for connection")
		timeout    = fs.Duration("timeout", 30*time.Second, "Request timeout")
		verbose    = fs.Bool("v", false, "Verbose logging")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *targetURL == "" {
		return fmt.Errorf("-url is required")
	}

	if *verbose {
		log.Printf("Sending request to: %s", *targetURL)
		log.Printf("Using source port: %d", *sourcePort)
		log.Printf("Timeout: %v", *timeout)
	}

	client := createRapidClient(*sourcePort, *timeout)

	// Send a single request.
	resp, err := client.Get(*targetURL)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if *verbose {
		fmt.Printf("Status: %s\n", resp.Status)
		fmt.Printf("Response: %s", string(body))
	} else {
		// Just print the raw response body.
		fmt.Print(string(body))
	}
	return nil
}

// createRapidClient creates an HTTP client configured for rapid connections with
// source port reuse.
func createRapidClient(sourcePort int, timeout time.Duration) *http.Client {
	// 1. Create a custom dialer function.
	dialer := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 0, // Disable keep-alive to force new connections.
		// Control function to set socket options before connection.
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				// Set SO_REUSEADDR to allow reusing the port more quickly.
				err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
				if err != nil {
					log.Printf("Warning: Failed to set SO_REUSEADDR: %v", err)
				}
			})
		},
	}

	// 2. Define the local address and port to use for every outgoing connection.
	localAddr := &net.TCPAddr{
		IP:   net.IPv4zero, // Bind to all local IPv4 addresses.
		Port: sourcePort,   // Use the specified source port.
	}
	dialer.LocalAddr = localAddr

	// 3. Create an HTTP client that uses the custom dialer.
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext:           dialer.DialContext,
			DisableKeepAlives:     true,             // Force new connections.
			MaxIdleConnsPerHost:   0,                // No connection pooling.
			IdleConnTimeout:       1 * time.Second,  // Short idle timeout.
			TLSHandshakeTimeout:   10 * time.Second, // TLS timeout.
			ExpectContinueTimeout: 1 * time.Second,  // Expect 100-continue timeout.
		},
	}

	return client
}
