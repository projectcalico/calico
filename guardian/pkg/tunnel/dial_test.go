package tunnel_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/guardian/pkg/tunnel"
)

func handleConnection(t *testing.T, conn net.Conn, listener net.Listener) {
	conn, err := listener.Accept()
	Expect(err).NotTo(HaveOccurred())
	Expect(conn).NotTo(BeNil())
	defer conn.Close()
	t.Log("Accepted connection from client")

	// Create a yamux server session
	session, err := yamux.Server(conn, nil)
	Expect(err).NotTo(HaveOccurred())
	defer session.Close()

	stream, err := session.Accept()
	Expect(err).NotTo(HaveOccurred())
	defer stream.Close()

	buf := make([]byte, 1024)
	n, err := stream.Read(buf)
	Expect(err).ShouldNot(HaveOccurred())
	request := string(buf[:n])
	t.Logf("Server received: %s", request)
	Expect(request).To(Equal("Hello from client"))

	_, err = stream.Write([]byte("Hello from server"))
	Expect(err).ShouldNot(HaveOccurred())
}

func TestDialPlainTCP(t *testing.T) {
	setupTest(t)

	address := "localhost:8080"
	listener, err := net.Listen("tcp", address)
	Expect(err).NotTo(HaveOccurred())
	defer listener.Close()

	go func() {
		handleConnection(t, nil, listener)
	}()

	dialer, err := tunnel.NewTLSSessionDialer(address, nil)
	Expect(err).NotTo(HaveOccurred())

	assertExpectations(t, dialer)

}

func TestDialTLS(t *testing.T) {
	setupTest(t)

	address := "localhost:8081"

	servercrt, err := filepath.Abs("../../test/tmp/server.crt")
	Expect(err).NotTo(HaveOccurred())

	serverKey, err := filepath.Abs("../../test/tmp/server.key")
	Expect(err).NotTo(HaveOccurred())

	cert, err := tls.LoadX509KeyPair(servercrt, serverKey)
	if err != nil {
		t.Fatalf("Failed to load server certificate and key: %v", err)
	}

	listener, err := tls.Listen("tcp", address, &tls.Config{Certificates: []tls.Certificate{cert}})
	Expect(err).NotTo(HaveOccurred())
	defer listener.Close()

	go func() {
		handleConnection(t, nil, listener)
	}()

	// Load the server's certificate
	certPool := x509.NewCertPool()
	caCert, err := os.ReadFile(servercrt)
	Expect(err).NotTo(HaveOccurred())
	certPool.AppendCertsFromPEM(caCert)

	dialer, err := tunnel.NewTLSSessionDialer(address, &tls.Config{
		RootCAs: certPool,
	})
	Expect(err).NotTo(HaveOccurred())
	assertExpectations(t, dialer)
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
