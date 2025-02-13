// Copyright (c) 2020-2022 Tigera, Inc. All rights reserved.

// Package tunnel defines an authenticated tunnel API, that allows creating byte
// pipes in both directions, initiated from either side of the tunnel.
package tunnel

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/pkg/errors"
	"github.com/projectcalico/calico/guardian/pkg/chanutil"
	"github.com/sirupsen/logrus"
)

const (
	defaultKeepAlive         = true
	defaultKeepAliveInterval = 100 * time.Millisecond
	defaultSessionBacklog    = 1000
	tunnelNetwork            = "voltron-tunnel"
)

type Session interface {
	Open() (net.Conn, error)
	Accept() (net.Conn, error)
	Addr() net.Addr
	Close() error
}

type Tunnel interface {
	Connect(context.Context) error
	Open(context.Context) (net.Conn, error)
	Listener(context.Context) (net.Listener, error)
}

type ObjectWithErr[Obj any] struct {
	Obj Obj
	Err error
}

func newObjectWithErr[Obj any](obj Obj, err error) ObjectWithErr[Obj] {
	return ObjectWithErr[Obj]{Obj: obj, Err: err}
}

// Tunnel represents either side of the tunnel that allows waiting for,
// accepting and initiating creation of new BytePipes.
type tunnel struct {
	tlsConfig *tls.Config

	keepAliveEnable   bool
	keepAliveInterval time.Duration

	openConnService    chanutil.Service[any, net.Conn]
	getListenerService chanutil.Service[any, net.Listener]
	acceptConnService  chanutil.Service[any, net.Conn]
	getAddrService     chanutil.Service[any, net.Addr]

	sessionCreator func() (Session, error)

	connectOnce sync.Once

	dialing     bool
	dialer      Dialer
	session     Session
	sessionChan chan ObjectWithErr[Session]
}

func NewTunnel(dialer Dialer, opts ...Option) (Tunnel, error) {
	return newTunnel(dialer, opts...)
}

func newTunnel(dialer Dialer, opts ...Option) (*tunnel, error) {
	t := &tunnel{
		keepAliveEnable:    defaultKeepAlive,
		keepAliveInterval:  defaultKeepAliveInterval,
		dialer:             dialer,
		openConnService:    chanutil.NewService[any, net.Conn](0),
		getListenerService: chanutil.NewService[any, net.Listener](0),
		acceptConnService:  chanutil.NewService[any, net.Conn](0),
		getAddrService:     chanutil.NewService[any, net.Addr](0),
		sessionChan:        make(chan ObjectWithErr[Session]),
	}
	t.sessionCreator = t.defaultSessionCreator

	for _, o := range opts {
		if err := o(t); err != nil {
			return nil, errors.WithMessage(err, "applying option failed")
		}
	}

	return t, nil
}

// Connect connects to the other side of the tunnel. The Tunnel cannot be used before this function is called, otherwise
// it will panic.
func (t *tunnel) Connect(ctx context.Context) error {
	// TODO consider adding the context to the service loop so that if this is called multiple times it's not actually shut
	// TODO down if one context is closed?
	var err error
	t.connectOnce.Do(func() {
		t.session, err = t.sessionCreator()
		if err != nil {
			logrus.WithError(err).Error("Failed to open initial connection.")
			return
		}
		go t.startServiceLoop(ctx)
	})
	return err
}

func (t *tunnel) startServiceLoop(ctx context.Context) {
	defer t.openConnService.Close()
	defer t.getListenerService.Close()
	defer t.acceptConnService.Close()
	defer t.getAddrService.Close()
	defer close(t.sessionChan)

	openConnReqs := chanutil.NewRequestsHandler(func(any) (net.Conn, error) { return t.session.Open() })
	getListenerReqs := chanutil.NewRequestsHandler(func(any) (net.Listener, error) {
		return newListener(t), nil
	})
	acceptConnReqs := chanutil.NewRequestsHandler(func(any) (net.Conn, error) { return t.session.Accept() })
	getAddrReqs := chanutil.NewRequestsHandler(func(any) (net.Addr, error) {
		return newTunnelAddress(t.session.Addr().String()), nil
	})
	requestHandlers := []interface {
		Handle() error
		ReturnError(error)
	}{openConnReqs, acceptConnReqs, getListenerReqs, getAddrReqs}

	var fatalErr error
	defer func() {
		if t.session != nil {
			if err := t.session.Close(); err != nil {
				logrus.WithError(err).Error("Failed to close mux.")
			}
		}

		// Return an error for all open requests.
		if fatalErr != nil {
			for _, hdlr := range requestHandlers {
				hdlr.ReturnError(fatalErr)
			}
			return
		}
	}()

	for {
		select {
		case req := <-t.openConnService.Listen():
			openConnReqs.Add(req)
		case req := <-t.getListenerService.Listen():
			getListenerReqs.Add(req)
		case req := <-t.acceptConnService.Listen():
			acceptConnReqs.Add(req)
		case req := <-t.getAddrService.Listen():
			getAddrReqs.Add(req)
		case req := <-t.sessionChan:
			if req.Err != nil {
				fatalErr = req.Err
				return
			}
			t.session = req.Obj
			t.dialing = false
		case <-ctx.Done():
			return
		}

		// If we're dialing to acquire the session then continue since be can't handle any of the outstanding requests.
		if t.dialing {
			continue
		}

		for _, hdlr := range requestHandlers {
			if err := hdlr.Handle(); err != nil {
				if err != io.EOF {
					fatalErr = err
					return
				}

				t.reCreateSession()
			}
		}
	}
}

func (t *tunnel) reCreateSession() {
	if !t.dialing {
		t.dialing = true
		go func() {
			mux, err := t.sessionCreator()
			t.sessionChan <- newObjectWithErr(mux, err)
		}()
	}
}

func (t *tunnel) defaultSessionCreator() (Session, error) {
	config := yamux.DefaultConfig()
	config.AcceptBacklog = defaultSessionBacklog
	config.EnableKeepAlive = t.keepAliveEnable
	config.KeepAliveInterval = t.keepAliveInterval
	config.LogOutput = &logrusWriter{logrus.WithField("component", "tunnel-yamux")}

	conn, err := t.dialer.dial()
	if err != nil {
		return nil, fmt.Errorf("failed to dial to the other side of the tunnel: %w", err)
	}

	mux, err := yamux.Client(conn, config)
	if err != nil {
		return nil, fmt.Errorf("failed creating muxer: %s", err)
	}

	return mux, nil
}

func (t *tunnel) Listener(ctx context.Context) (net.Listener, error) {
	return t.getListenerService.Send(ctx, nil)
}

func (t *tunnel) accept() (net.Conn, error) {
	return t.acceptConnService.Send(context.Background(), nil)
}

// Addr returns the address of this tunnel sides endpoint.
func (t *tunnel) addr(ctx context.Context) (net.Addr, error) {
	return t.getAddrService.Send(ctx, nil)
}

// Open opens a new net.Conn to the other side of the tunnel. Returns when
func (t *tunnel) Open(ctx context.Context) (net.Conn, error) {
	return t.openConnService.Send(ctx, nil)
}

func newTunnelAddress(addr string) net.Addr {
	return tunnelAddress{addr: addr}
}

type tunnelAddress struct {
	addr string
}

func (a tunnelAddress) Network() string {
	return tunnelNetwork
}

func (a tunnelAddress) String() string {
	return a.addr
}

// listener implements the net.Listener interface and is used by the Manager to allow components to listen for connections
// over the tunnel
type listener struct {
	tunnel *tunnel
}

func newListener(tunnel *tunnel) *listener {
	return &listener{tunnel: tunnel}
}

// Accept waits for a connection to be opened from the other side of the connection and returns it.
func (l *listener) Accept() (net.Conn, error) {
	return l.tunnel.accept()
}

// Close closes the listener. A closed listener cannot be used again
func (l *listener) Close() error {
	return nil
}

func (l *listener) Addr() net.Addr {
	// TODO I'm wondering if we should instead set this when we create the listener...
	a, err := l.tunnel.addr(context.Background())
	if err != nil {
		return nil
	}
	return a
}
