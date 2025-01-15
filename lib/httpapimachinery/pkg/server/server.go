package server

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"
	
	"github.com/projectcalico/calico/lib/httpapimachinery/pkg/handler"
)

// HTTPServer is the interface that most, if not all, our http servers need to implement. It allows for starting tls /
// non tls servers, and waiting for the server too shutdown.
type HTTPServer interface {
	ListenAndServeTLS(context.Context) error
	ListenAndServe(context.Context) error
	WaitForShutdown() error
}

type httpServer struct {
	srv         *http.Server
	tlsConfig   *tls.Config
	addr        string
	shutdownCtx context.Context
	serverErrs  chan error
}

type Router interface {
	RegisterAPIs([]handler.API, ...handler.MiddlewareFunc) http.Handler
}

func NewHTTPServer(router Router, apis []handler.API, options ...Option) (HTTPServer, error) {
	srv := &httpServer{
		srv:        &http.Server{},
		serverErrs: make(chan error, 1),
	}

	for _, option := range options {
		if err := option(srv); err != nil {
			return nil, err
		}
	}

	srv.srv.Addr = srv.addr
	srv.srv.TLSConfig = srv.tlsConfig
	srv.srv.Handler = router.RegisterAPIs(apis)

	return srv, nil
}

func (s *httpServer) ListenAndServeTLS(ctx context.Context) error {
	s.shutdownCtx = ctx

	addr := s.srv.Addr
	if addr == "" {
		addr = ":https"
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	go func() {
		defer ln.Close()
		defer close(s.serverErrs)

		s.serverErrs <- s.srv.ServeTLS(ln, "", "")
	}()

	return nil
}

func (s *httpServer) ListenAndServe(ctx context.Context) error {
	addr := s.srv.Addr
	if addr == "" {
		addr = ":https"
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	s.shutdownCtx = ctx
	go func() {
		defer ln.Close()
		defer close(s.serverErrs)

		s.serverErrs <- s.srv.Serve(ln)
	}()

	return nil
}

func (s *httpServer) WaitForShutdown() error {
	var err error
	select {
	case <-s.shutdownCtx.Done():
		log.Info("Received shutdown signal, shutting server down.")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		err = s.srv.Shutdown(ctx)
	case err = <-s.serverErrs:
	}
	return err
}
