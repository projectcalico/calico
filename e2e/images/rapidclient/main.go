/*
Copyright (c) 2025 Tigera, Inc. All rights reserved.

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
	"os"
	"syscall"
	"time"
)

func main() {
	// Command line flags
	var (
		targetURL  = flag.String("url", "", "Target URL to send request to (required)")
		sourcePort = flag.Int("port", 12345, "Source port to use for connection")
		timeout    = flag.Duration("timeout", 30*time.Second, "Request timeout")
		verbose    = flag.Bool("v", false, "Verbose logging")
	)
	flag.Parse()

	if *targetURL == "" {
		fmt.Fprintf(os.Stderr, "Error: -url is required\n")
		flag.Usage()
		os.Exit(1)
	}

	if *verbose {
		log.Printf("Sending request to: %s", *targetURL)
		log.Printf("Using source port: %d", *sourcePort)
		log.Printf("Timeout: %v", *timeout)
	}

	client := createRapidClient(*sourcePort, *timeout)

	// Send a single request
	resp, err := client.Get(*targetURL)
	if err != nil {
		log.Fatalf("Request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Read and print the response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Failed to read response: %v", err)
	}

	if *verbose {
		fmt.Printf("Status: %s\n", resp.Status)
		fmt.Printf("Response: %s", string(body))
	} else {
		// Just print the raw response body
		fmt.Print(string(body))
	}
}

// createRapidClient creates an HTTP client configured for rapid connections with source port reuse
func createRapidClient(sourcePort int, timeout time.Duration) *http.Client {
	// 1. Create a custom dialer function
	dialer := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 0, // Disable keep-alive to force new connections
		// Control function to set socket options before connection
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				// Set SO_REUSEADDR to allow reusing the port more quickly
				err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
				if err != nil {
					log.Printf("Warning: Failed to set SO_REUSEADDR: %v", err)
				}
			})
		},
	}

	// 2. Define the local address and port to use for every outgoing connection
	localAddr := &net.TCPAddr{
		IP:   net.IPv4zero, // Bind to all local IPv4 addresses
		Port: sourcePort,   // Use the specified source port
	}
	dialer.LocalAddr = localAddr

	// 3. Create an HTTP client that uses the custom dialer
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext:           dialer.DialContext,
			DisableKeepAlives:     true,             // Force new connections
			MaxIdleConnsPerHost:   0,                // No connection pooling
			IdleConnTimeout:       1 * time.Second,  // Short idle timeout
			TLSHandshakeTimeout:   10 * time.Second, // TLS timeout
			ExpectContinueTimeout: 1 * time.Second,  // Expect 100-continue timeout
		},
	}

	return client
}
