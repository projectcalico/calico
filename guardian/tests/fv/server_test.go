package fv_test

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"time"

	"github.com/hashicorp/yamux"
)

type ServerSideSessionListener struct {
	listener net.Listener
}

func NewServerSideSessionListener(addr string, tlsCfg *tls.Config) (*ServerSideSessionListener, error) {
	listener, err := tls.Listen("tcp", addr, tlsCfg)
	if err != nil {
		return nil, err
	}
	return &ServerSideSessionListener{
		listener: listener,
	}, nil
}

type ServerSideSession struct {
	session *yamux.Session

	id          string
	fingerprint string
	certificate *x509.Certificate
}

func (ss *ServerSideSession) Addr() net.Addr {
	return ss.session.Addr()
}

func (ss *ServerSideSession) Open() (net.Conn, error) {
	return ss.session.Open()
}

func (ss *ServerSideSession) Accept() (net.Conn, error) {
	return ss.session.Accept()
}

func (ss *ServerSideSession) Close() error {
	return ss.session.Close()
}

func (mg *ServerSideSessionListener) Listen() (<-chan *ServerSideSession, error) {
	ch := make(chan *ServerSideSession, 100)
	go func() {
		defer close(ch)
		for {
			conn, err := mg.listener.Accept()
			if err != nil {
				return
			}

			cfg := yamux.DefaultConfig()
			cfg.ConnectionWriteTimeout = 5 * time.Minute
			cfg.AcceptBacklog = 1000
			cfg.EnableKeepAlive = true
			cfg.KeepAliveInterval = 10000

			ss := &ServerSideSession{}
			if tlsConn, ok := conn.(*tls.Conn); ok {
				if !tlsConn.ConnectionState().HandshakeComplete {
					if err := tlsConn.Handshake(); err != nil {
						// TODO log error
						// If the handshake failed then close the connection (if it wasn't already done).
						_ = conn.Close()
						continue
					}
					if len(tlsConn.ConnectionState().PeerCertificates) == 0 {
						// Close the connection if there are no peer certificates as we require mtls.
						_ = conn.Close()
					}

					ss.certificate = tlsConn.ConnectionState().PeerCertificates[0]
					ss.fingerprint = generateFingerprint(ss.certificate)
					ss.id = ss.certificate.Subject.CommonName

					// TODO Verify ID.
				}
			} else {
				// Don't accept non tls connections.
				_ = conn.Close()
				continue
			}

			session, err := yamux.Server(conn, cfg)
			// If an error is returned, then the config is invalid. Since this is a static configuration, it means this
			// will never succeed and is a developer error.
			if err != nil {
				panic(err)
			}

			ch <- &ServerSideSession{session: session}
		}
	}()

	return ch, nil
}

func (mg *ServerSideSessionListener) Close() {
	_ = mg.listener.Close()
}

// GenerateFingerprint returns the sha256 hash for a x509 certificate printed as a hex number
func generateFingerprint(certificate *x509.Certificate) string {
	fingerprint := fmt.Sprintf("%x", sha256.Sum256(certificate.Raw))
	return fingerprint
}
