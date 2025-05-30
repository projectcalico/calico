package bimux

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/hashicorp/yamux"

	"github.com/projectcalico/calico/lib/std/chanutil"
)

type SessionListener[T any] interface {
	Listen(ctx context.Context) (<-chan *ServerSession[T], error)
	WaitForShutdown() <-chan struct{}
}

type ConnectionAuthenticator[T any] interface {
	Authenticate(net.Conn) (*T, error)
}

type sessionListener[T any] struct {
	addr   string
	tlsCfg *tls.Config

	connVerifier ConnectionAuthenticator[T]

	shutdownCh chan struct{}
}

func NewDefaultSessionListener(addr string, tlsCfg *tls.Config) (SessionListener[any], error) {
	return NewSessionListener[any](addr, tlsCfg, nil)
}

func NewSessionListener[T any](addr string, tlsCfg *tls.Config, verifier ConnectionAuthenticator[T]) (SessionListener[T], error) {
	tlsCfg.InsecureSkipVerify = true
	return &sessionListener[T]{
		addr:         addr,
		tlsCfg:       tlsCfg,
		connVerifier: verifier,
		shutdownCh:   make(chan struct{}),
	}, nil
}

func (mg *sessionListener[T]) Listen(ctx context.Context) (<-chan *ServerSession[T], error) {
	sessionChan := make(chan *ServerSession[T], 100)
	go func() {
		defer close(sessionChan)
		defer close(mg.shutdownCh)

		listener, err := tls.Listen("tcp", mg.addr, mg.tlsCfg)
		if err != nil {
			log.WithError(err).Error("Failed to listen for session.")
			return
		}

		go func() {
			select {
			case <-ctx.Done():
				log.Debugf("Context finished.")
			case <-mg.shutdownCh:
				log.Debugf("Shutdown signaled.")
			}

			_ = listener.Close()
		}()

		for {
			conn, err := listener.Accept()
			if err != nil {
				log.WithError(err).Debug("Failed to accept connection.")
				return
			}

			cfg := yamux.DefaultConfig()
			cfg.ConnectionWriteTimeout = 5 * time.Minute
			cfg.AcceptBacklog = 1000
			cfg.EnableKeepAlive = true
			cfg.KeepAliveInterval = 10000

			var identity *T
			if mg.connVerifier != nil {
				identity, err = mg.connVerifier.Authenticate(conn)
				if err != nil {
					log.WithError(err).Debugf("Terminating connection, verification failed.")
					_ = conn.Close()
					continue
				}
			}

			mux, err := yamux.Server(conn, cfg)
			// If an error is returned, then the config is invalid. Since this is a static configuration, it means this
			// will never succeed and is a developer error.
			if err != nil {
				panic(err)
			}

			err = chanutil.Write(ctx, sessionChan, newServerSideSession(mux, identity))
			if err != nil {
				log.WithError(err).Debugf("Failed to write to session channel")
				return
			}
		}
	}()

	return sessionChan, nil
}

func (mg *sessionListener[T]) WaitForShutdown() <-chan struct{} {
	return mg.shutdownCh
}
