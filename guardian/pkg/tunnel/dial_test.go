package tunnel_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/guardian/pkg/tunnel"
	"github.com/projectcalico/calico/guardian/test/utils"
)

func handleConnection(t *testing.T, listener net.Listener) {
	conn, err := listener.Accept()
	Expect(err).NotTo(HaveOccurred())
	Expect(conn).NotTo(BeNil())
	defer func() { _ = conn.Close() }()
	t.Log("Accepted connection from client")

	// Create a yamux server session
	session, err := yamux.Server(conn, nil)
	Expect(err).NotTo(HaveOccurred())
	defer func() { _ = session.Close() }()

	stream, err := session.Accept()
	Expect(err).NotTo(HaveOccurred())
	defer func() { _ = stream.Close() }()

	buf := make([]byte, 1024)
	n, err := stream.Read(buf)
	Expect(err).ShouldNot(HaveOccurred())
	request := string(buf[:n])
	t.Logf("Server received: %s", request)
	Expect(request).To(Equal("Hello from client"))

	_, err = stream.Write([]byte("Hello from server"))
	Expect(err).ShouldNot(HaveOccurred())
}

func TestDial(t *testing.T) {
	setupTest(t)
	address := "localhost:8080"

	t.Run("Dial Plain TCP", func(t *testing.T) {
		listener, err := net.Listen("tcp", address)
		Expect(err).NotTo(HaveOccurred())
		defer func() { _ = listener.Close() }()

		go func() {
			handleConnection(t, listener)
		}()

		dialer, err := tunnel.NewTLSSessionDialer(address, nil)
		Expect(err).NotTo(HaveOccurred())

		assertExpectations(t, dialer)
	})

	t.Run("Dial TLS", func(t *testing.T) {
		tmpDir := os.TempDir()

		serverCrt, serverKey := utils.CreateKeyCertPair(tmpDir)
		defer func() { _ = serverCrt.Close() }()
		defer func() { _ = serverKey.Close() }()

		cert, err := tls.LoadX509KeyPair(serverCrt.Name(), serverKey.Name())
		if err != nil {
			t.Fatalf("Failed to load server certificate and key: %v", err)
		}

		listener, err := tls.Listen("tcp", address, &tls.Config{Certificates: []tls.Certificate{cert}})
		Expect(err).NotTo(HaveOccurred())
		defer func() { _ = listener.Close() }()

		go func() {
			handleConnection(t, listener)
		}()

		// Load the server's certificate
		certPool := x509.NewCertPool()
		caCert, err := os.ReadFile(serverCrt.Name())
		Expect(err).NotTo(HaveOccurred())
		certPool.AppendCertsFromPEM(caCert)

		dialer, err := tunnel.NewTLSSessionDialer(address, &tls.Config{
			RootCAs: certPool,
		})
		Expect(err).NotTo(HaveOccurred())
		assertExpectations(t, dialer)
	})
}

func assertExpectations(t *testing.T, dialer tunnel.SessionDialer) {
	// Dial the server
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	session, err := dialer.Dial(ctx)
	Expect(err).NotTo(HaveOccurred())

	Expect(session).ToNot(BeNil())

	// Open a connection in the session
	conn, err := session.Open()
	Expect(err).NotTo(HaveOccurred())
	Expect(conn).NotTo(BeNil())

	// Send a request through the connection
	_, err = conn.Write([]byte("Hello from client"))
	Expect(err).NotTo(HaveOccurred())

	// Read the response from the server
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	Expect(err).NotTo(HaveOccurred())
	Expect(string(buf[:n])).To(Equal("Hello from server"))

	// Close the session
	err = session.Close()
	Expect(err).NotTo(HaveOccurred())

	err = conn.Close()
	Expect(err).NotTo(HaveOccurred())
}
