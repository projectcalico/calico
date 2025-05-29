package fv_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"github.com/hashicorp/yamux"
	"net"
	"net/http"
	"os"
	"time"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/lib/std/cryptoutils"
)

func createKeyCertPair(dir, certFileName, keyFileName string) (string, string) {
	certPEM, keyPEM, err := cryptoutils.GenerateSelfSignedCert(
		cryptoutils.WithDNSNames("localhost"),
		cryptoutils.WithExtKeyUsages(x509.ExtKeyUsageAny))
	Expect(err).ShouldNot(HaveOccurred())

	certFile, err := os.Create(dir + "/" + certFileName)
	Expect(err).ShouldNot(HaveOccurred())
	defer certFile.Close()

	keyFile, err := os.Create(dir + "/" + keyFileName)
	Expect(err).ShouldNot(HaveOccurred())
	defer keyFile.Close()

	_, err = certFile.Write(certPEM)
	Expect(err).ShouldNot(HaveOccurred())
	_, err = keyFile.Write(keyPEM)
	Expect(err).ShouldNot(HaveOccurred())

	return certFile.Name(), keyFile.Name()
}

type upstreamServer struct {
	close                  chan struct{}
	mux                    *yamux.Session
	connectionRequestCount int
	rejectConnections      bool
}

func newUpstreamServer(addr string, tlsCfg *tls.Config) *upstreamServer {
	listener, err := net.Listen("tcp", addr)
	Expect(err).ShouldNot(HaveOccurred())
	listener = tls.NewListener(listener, tlsCfg)

	srv := &upstreamServer{
		close: make(chan struct{}),
	}

	// Use a different go routine to accept connections so we don't block getting mux connections while waiting to accept.
	connCh := make(chan net.Conn)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			srv.connectionRequestCount++
			if srv.rejectConnections {
				_ = conn.Close()
			} else {
				connCh <- conn
			}
		}
	}()

	go func() {
		defer func() {
			if srv.mux != nil {
				_ = srv.mux.Close()
			}
		}()
		for {
			select {
			case <-srv.close:
				_ = listener.Close()
				return
			case conn := <-connCh:
				if srv.mux != nil && !srv.mux.IsClosed() {
					continue
				}
				cfg := yamux.DefaultConfig()
				cfg.ConnectionWriteTimeout = 5 * time.Minute
				cfg.AcceptBacklog = 1000
				cfg.EnableKeepAlive = true
				cfg.KeepAliveInterval = 10000

				if tlsConn, ok := conn.(*tls.Conn); ok {
					if !tlsConn.ConnectionState().HandshakeComplete {
						if err := tlsConn.Handshake(); err != nil {
							_ = conn.Close()
						}
						certs := tlsConn.ConnectionState().PeerCertificates
						_ = certs
					}
				}

				srv.mux, err = yamux.Server(conn, cfg)

				// We never expect an error here, so something is wrong with the test if we get an error.
				if err != nil {
					panic(err)
				}
			}
		}
	}()

	return srv
}

func (srv *upstreamServer) waitConnection(ctx context.Context) {
	for srv.mux == nil || srv.mux.IsClosed() {
		time.Sleep(500 * time.Millisecond)
		if ctx.Err() != nil {
			panic(ctx.Err())
		}
	}
}

func (srv *upstreamServer) SendRequest(ctx context.Context, req *http.Request) (*http.Response, error) {
	srv.waitConnection(ctx)

	conn, err := srv.mux.Open()
	Expect(err).ShouldNot(HaveOccurred())

	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2"},
	})

	// We never expect an error here, so something is wrong with the test if we get an error.
	if err := tlsConn.Handshake(); err != nil {
		return nil, err
	}

	http2Conn, err := http2Transport.NewClientConn(tlsConn)
	Expect(err).ShouldNot(HaveOccurred())

	return http2Conn.RoundTrip(req)
}

func (srv *upstreamServer) Close() {
	close(srv.close)
}
