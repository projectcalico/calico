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

package tunnel_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/guardian/pkg/tunnel"
	"github.com/projectcalico/calico/guardian/test/utils"
)

// handleConnection accepts a connection from the listener, sets up a yamux session,
// reads a message from the client, and writes a response. Errors are reported via
// errCh rather than calling Expect() (which would panic from a non-test goroutine).
// doneCh is closed when the function completes all its work.
func handleConnection(t *testing.T, listener net.Listener, errCh chan<- error, doneCh chan<- struct{}) {
	defer close(doneCh)

	conn, err := listener.Accept()
	if err != nil {
		errCh <- fmt.Errorf("Accept: %v", err)
		return
	}
	defer func() { _ = conn.Close() }()
	t.Log("Accepted connection from client")

	session, err := yamux.Server(conn, nil)
	if err != nil {
		errCh <- fmt.Errorf("yamux.Server: %v", err)
		return
	}
	defer func() { _ = session.Close() }()

	stream, err := session.Accept()
	if err != nil {
		errCh <- fmt.Errorf("session.Accept: %v", err)
		return
	}
	defer func() { _ = stream.Close() }()

	buf := make([]byte, 1024)
	n, err := stream.Read(buf)
	if err != nil {
		errCh <- fmt.Errorf("stream.Read: %v", err)
		return
	}
	request := string(buf[:n])
	t.Logf("Server received: %s", request)
	if request != "Hello from client" {
		errCh <- fmt.Errorf("unexpected request: %q", request)
		return
	}

	_, err = stream.Write([]byte("Hello from server"))
	if err != nil {
		errCh <- fmt.Errorf("stream.Write: %v", err)
		return
	}
}

func TestDial(t *testing.T) {
	t.Run("Dial Plain TCP", func(t *testing.T) {
		setupTest(t)

		listener, err := net.Listen("tcp", "localhost:0")
		Expect(err).NotTo(HaveOccurred())
		defer func() { _ = listener.Close() }()

		errCh := make(chan error, 1)
		doneCh := make(chan struct{})
		go handleConnection(t, listener, errCh, doneCh)

		dialer, err := tunnel.NewTLSSessionDialer(listener.Addr().String(), nil)
		Expect(err).NotTo(HaveOccurred())

		assertExpectations(t, dialer, doneCh)

		select {
		case err := <-errCh:
			t.Fatalf("handleConnection error: %v", err)
		default:
		}
	})

	t.Run("Dial TLS", func(t *testing.T) {
		setupTest(t)

		tmpDir := os.TempDir()

		serverCrt, serverKey := utils.CreateKeyCertPair(tmpDir)
		defer func() { _ = serverCrt.Close() }()
		defer func() { _ = serverKey.Close() }()

		cert, err := tls.LoadX509KeyPair(serverCrt.Name(), serverKey.Name())
		if err != nil {
			t.Fatalf("Failed to load server certificate and key: %v", err)
		}

		// Bind to 127.0.0.1:0 (not localhost:0) to avoid IPv6 issues with the cert SANs.
		listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
		Expect(err).NotTo(HaveOccurred())
		defer func() { _ = listener.Close() }()

		errCh := make(chan error, 1)
		doneCh := make(chan struct{})
		go handleConnection(t, listener, errCh, doneCh)

		certPool := x509.NewCertPool()
		caCert, err := os.ReadFile(serverCrt.Name())
		Expect(err).NotTo(HaveOccurred())
		certPool.AppendCertsFromPEM(caCert)

		dialer, err := tunnel.NewTLSSessionDialer(listener.Addr().String(), &tls.Config{
			RootCAs: certPool,
		})
		Expect(err).NotTo(HaveOccurred())
		assertExpectations(t, dialer, doneCh)

		select {
		case err := <-errCh:
			t.Fatalf("handleConnection error: %v", err)
		default:
		}
	})
}

func assertExpectations(t *testing.T, dialer tunnel.SessionDialer, serverDone <-chan struct{}) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	session, err := dialer.Dial(ctx)
	Expect(err).NotTo(HaveOccurred())
	Expect(session).ToNot(BeNil())

	conn, err := session.Open()
	Expect(err).NotTo(HaveOccurred())
	Expect(conn).NotTo(BeNil())

	_, err = conn.Write([]byte("Hello from client"))
	Expect(err).NotTo(HaveOccurred())

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	Expect(err).NotTo(HaveOccurred())
	Expect(string(buf[:n])).To(Equal("Hello from server"))

	// Wait for the server goroutine to finish its Write before closing the session,
	// otherwise the server's Write races with session.Close().
	<-serverDone

	err = session.Close()
	Expect(err).NotTo(HaveOccurred())

	err = conn.Close()
	Expect(err).NotTo(HaveOccurred())
}
