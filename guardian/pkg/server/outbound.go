package server

import (
	"context"
	"fmt"
	"net"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/guardian/pkg/bimux"
	"github.com/projectcalico/calico/guardian/pkg/conn"
	"github.com/projectcalico/calico/lib/std/chanutil"
)

// OutboundProxyServer is an interface for a server that proxies connections from within the cluster to outside the cluster.
type OutboundProxyServer interface {
	ListenAndProxy(ctx context.Context) error
	WaitForShutdown() <-chan struct{}
}

type outboundProxyServer struct {
	listenPort string
	listenHost string

	bimuxMgr bimux.SessionPool

	shutdownCh chan struct{}
}

func NewOutboundProxyServer(sessionManager bimux.SessionPool, opts ...OutboundProxyServerOption) (OutboundProxyServer, error) {
	srv := &outboundProxyServer{
		listenPort: "8080",
		bimuxMgr:   sessionManager,
		shutdownCh: make(chan struct{}),
	}
	for _, o := range opts {
		if err := o(srv); err != nil {
			return nil, fmt.Errorf("applying option failed: %w", err)
		}
	}
	return srv, nil
}

func (srv *outboundProxyServer) ListenAndProxy(ctx context.Context) error {
	defer close(srv.shutdownCh)

	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%s", srv.listenHost, srv.listenPort))
	if err != nil {
		return fmt.Errorf("failed to listen on %s:%s: %w", srv.listenHost, srv.listenPort, err)
	}

	defer listener.Close()

	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	for {
		// TODO Consider throttling the number of connections this accepts.
		srcConn, err := listener.Accept()
		if err != nil {
			logrus.WithError(err).Debugf("failed to accept connection, closing listener.")
			return nil
		}
		logrus.Debugf("Accepted connection from %s", srcConn.RemoteAddr())

		chRsp, err := chanutil.Read(ctx, srv.bimuxMgr.Get())
		if err != nil {
			// Either the channel is closed or the context is cancelled. Either way, this is an intentional shutdown.
			return nil
		}

		if chRsp.Err != nil {
			return fmt.Errorf("failed to get session: %w", chRsp.Err)
		}

		dstConn, err := chRsp.Value.Open()
		if err != nil {
			if err := srcConn.Close(); err != nil {
				logrus.WithError(err).Error("failed to close source connection")
			}

			logrus.WithError(err).Error("failed to open connection to the tunnel")
			continue
		}

		go conn.Forward(srcConn, dstConn)
	}
}

func (srv *outboundProxyServer) WaitForShutdown() <-chan struct{} {
	return srv.shutdownCh
}
