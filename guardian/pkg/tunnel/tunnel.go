// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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

// Package tunnel defines an authenticated tunnel API, that allows creating byte
// pipes in both directions, initiated from either side of the tunnel.
package tunnel

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"sync"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/guardian/pkg/chanutil"
)

const (
	tunnelNetwork = "voltron-tunnel"
)

type Tunnel interface {
	Connect(context.Context) error
	Open(context.Context) (net.Conn, error)
	Listener(context.Context) (net.Listener, error)
	WaitForClose() <-chan struct{}
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

	openConnService    chanutil.Service[any, net.Conn]
	getListenerService chanutil.Service[any, net.Listener]
	acceptConnService  chanutil.Service[any, net.Conn]
	getAddrService     chanutil.Service[any, net.Addr]

	connectOnce sync.Once

	dialing     bool
	dialer      SessionDialer
	session     Session
	sessionChan chan ObjectWithErr[Session]

	closed chan struct{}
}

func (t *tunnel) WaitForClose() <-chan struct{} {
	return t.closed
}

func NewTunnel(dialer SessionDialer, opts ...Option) (Tunnel, error) {
	return newTunnel(dialer, opts...)
}

func newTunnel(dialer SessionDialer, opts ...Option) (*tunnel, error) {
	t := &tunnel{
		dialer:             dialer,
		openConnService:    chanutil.NewService[any, net.Conn](0),
		getListenerService: chanutil.NewService[any, net.Listener](0),
		acceptConnService:  chanutil.NewService[any, net.Conn](0),
		getAddrService:     chanutil.NewService[any, net.Addr](0),
		sessionChan:        make(chan ObjectWithErr[Session]),
		closed:             make(chan struct{}),
	}

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
		t.session, err = t.dialer.Dial()
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
		Close()
	}{openConnReqs, acceptConnReqs, getListenerReqs, getAddrReqs}

	var fatalErr error
	defer func() {
		defer close(t.closed)
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
			logrus.Info("Skipping handling of requests while waiting for session to be established.")
			continue
		}

		logrus.Info("Handling requests.")
		for _, hdlr := range requestHandlers {
			if err := hdlr.Handle(); err != nil {
				if err != io.EOF {
					logrus.WithError(err).Error("Failed to handle request, closing tunnel permanently.")
					fatalErr = err
					return
				}

				logrus.Info("Session was closed, recreating it.")
				t.reCreateSession()
			}
		}
	}
}

func (t *tunnel) reCreateSession() {
	if !t.dialing {
		t.dialing = true
		go func() {
			mux, err := t.dialer.Dial()
			t.sessionChan <- newObjectWithErr(mux, err)
		}()
	}
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
