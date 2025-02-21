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

package tunnel

import (
	"context"
	"io"
	"net"
	"sync"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/guardian/pkg/asyncutil"
)

const (
	tunnelNetwork = "voltron-tunnel"
)

type Tunnel interface {
	Connect(context.Context) error
	Open() (net.Conn, error)
	Listener() (net.Listener, error)
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
	openConnExecutor    asyncutil.CommandExecutor[any, net.Conn]
	getListenerExecutor asyncutil.CommandExecutor[any, net.Listener]
	acceptConnExecutor  asyncutil.CommandExecutor[any, net.Conn]
	getAddrExecutor     asyncutil.CommandExecutor[any, net.Addr]

	connectOnce sync.Once

	dialing     bool
	dialer      SessionDialer
	session     Session
	sessionChan chan ObjectWithErr[Session]
	cmdErrBuff  asyncutil.AsyncErrorBuffer
	closed      chan struct{}
}

func (t *tunnel) WaitForClose() <-chan struct{} {
	return t.closed
}

func NewTunnel(dialer SessionDialer, opts ...Option) (Tunnel, error) {
	return newTunnel(dialer, opts...)
}

func newTunnel(dialer SessionDialer, opts ...Option) (*tunnel, error) {
	t := &tunnel{
		dialer:      dialer,
		sessionChan: make(chan ObjectWithErr[Session]),
		closed:      make(chan struct{}),
		cmdErrBuff:  asyncutil.NewAsyncErrorBuffer(),
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
	var err error
	t.connectOnce.Do(func() {
		t.session, err = t.dialer.Dial()
		if err != nil {
			logrus.WithError(err).Error("Failed to open initial connection.")
			return
		}
		t.openConnExecutor = asyncutil.NewCommandExecutor(ctx, t.cmdErrBuff, func(ctx context.Context, a any) (net.Conn, error) {
			logrus.Debug("Opening connection to other side of tunnel.")
			return t.session.Open()
		})
		t.getListenerExecutor = asyncutil.NewCommandExecutor(ctx, t.cmdErrBuff, func(ctx context.Context, a any) (net.Listener, error) {
			logrus.Debug("Getting listener for requests from the other side of the tunnel.")
			return newListener(t), nil
		})
		t.acceptConnExecutor = asyncutil.NewCommandExecutor(ctx, t.cmdErrBuff, func(ctx context.Context, a any) (net.Conn, error) {
			logrus.Debug("Accepting connection from the other side of the tunnel.")

			return t.session.Accept()
		})
		t.getAddrExecutor = asyncutil.NewCommandExecutor(ctx, t.cmdErrBuff, func(ctx context.Context, a any) (net.Addr, error) {
			logrus.Debug("Getting tunnel address.")
			return newTunnelAddress(t.session.Addr().String()), nil
		})
		go t.startServiceLoop(ctx)
	})
	return err
}

func (t *tunnel) startServiceLoop(ctx context.Context) {
	defer t.cmdErrBuff.Close()
	defer close(t.sessionChan)

	requestHandlers := asyncutil.CommandDispatcher{
		t.openConnExecutor, t.acceptConnExecutor, t.getListenerExecutor, t.getAddrExecutor,
	}

	defer func() {
		defer close(t.closed)
		if t.session != nil {
			logrus.Info("Closing session.")
			if err := t.session.Close(); err != nil {
				logrus.WithError(err).Error("Failed to close mux.")
			}
		}

		return
	}()

	for {
		logrus.Debug("Waiting for signals.")
		select {
		case err := <-t.cmdErrBuff.Receive():
			// TODO need to handle rapid retries.
			if err != io.EOF {
				logrus.WithError(err).Error("Failed to handle request, closing tunnel permanently.")
				return
			}

			logrus.Info("Session was closed, recreating it...")
			requestHandlers.PauseExecution()
			t.reCreateSession()
		case req := <-t.sessionChan:
			if req.Err != nil {
				logrus.WithError(req.Err).Error("Failed to handle request, closing tunnel permanently.")
				return
			}
			logrus.Info("Session successfully recreated, will handle any outstanding requests.")
			t.session = req.Obj
			t.dialing = false
			requestHandlers.ResumeExecution()
		case <-ctx.Done():
			logrus.Info("Context cancelled, will handle any outstanding requests and shutdown.")
			return
		}

		// If we're dialing to acquire the session then continue since be can't handle any of the outstanding requests.
		if t.dialing {
			logrus.Info("Skipping handling of requests while waiting for session to be established.")
			continue
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

func (t *tunnel) Listener() (net.Listener, error) {
	return (<-t.getListenerExecutor.Send(nil)).Result()
}

func (t *tunnel) accept() (net.Conn, error) {
	result := <-t.acceptConnExecutor.Send(nil)
	logrus.Debug("Brian Markl.")
	return result.Result()
}

// Addr returns the address of this tunnel sides endpoint.
func (t *tunnel) addr() (net.Addr, error) {
	return (<-t.getAddrExecutor.Send(nil)).Result()
}

// Open opens a new net.Conn to the other side of the tunnel. Returns when
func (t *tunnel) Open() (net.Conn, error) {
	r := <-t.openConnExecutor.Send(nil)
	return r.Result()
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
	c, err := l.tunnel.accept()
	return c, err
}

// Close closes the listener. A closed listener cannot be used again
func (l *listener) Close() error {
	return nil
}

func (l *listener) Addr() net.Addr {
	a, err := l.tunnel.addr()
	if err != nil {
		return nil
	}
	return a
}
