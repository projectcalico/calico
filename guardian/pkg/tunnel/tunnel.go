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
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/guardian/pkg/asyncutil"
	"github.com/projectcalico/calico/lib/std/clock"
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

	stopExecutors context.CancelFunc

	connectOnce sync.Once

	dialing     bool
	dialer      SessionDialer
	session     Session
	sessionChan chan ObjectWithErr[Session]
	cmdErrBuff  asyncutil.ErrorBuffer
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
		cmdErrBuff:  asyncutil.NewErrorBuffer(),
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
		// Block until the initial connection can be created. If this fails then return an error.
		// It is up to the dialer to decide whether dialing should be retried, and for how long. An error
		// return signals a fatal error.
		t.session, err = t.dialer.Dial(ctx)
		if err != nil {
			logrus.WithError(err).Error("Failed to open initial connection.")
			return
		}

		coordinatorCtx, stopCoordinator := context.WithCancel(context.Background())
		t.stopExecutors = stopCoordinator

		// We use AsyncCommandExecutors to handle interacting with the session. The executors run the commands in the
		// background and respond over a channel. The executors help to manage the life cycle of these commands and
		// facilitate fail / retry handling, as well as shutdown logic.
		t.openConnExecutor = asyncutil.NewCommandExecutor(coordinatorCtx, t.cmdErrBuff,
			func(ctx context.Context, a any) (net.Conn, error) {
				logrus.Debug("Opening connection to other side of tunnel.")
				return t.session.Open()
			})
		t.getListenerExecutor = asyncutil.NewCommandExecutor(coordinatorCtx, t.cmdErrBuff,
			func(ctx context.Context, a any) (net.Listener, error) {
				logrus.Debug("Getting listener for requests from the other side of the tunnel.")
				return newListener(t), nil
			})
		t.acceptConnExecutor = asyncutil.NewCommandExecutor(coordinatorCtx, t.cmdErrBuff,
			func(ctx context.Context, a any) (net.Conn, error) {
				logrus.Debug("Waiting for connection from other side of tunnel.")

				conn, err := t.session.Accept()
				if err != nil {
					logrus.WithError(err).Error("Failed to accept connection.")
					return nil, err
				}

				logrus.Debug("Finished waiting for connection from other side of tunnel.")

				return conn, err
			})
		t.getAddrExecutor = asyncutil.NewCommandExecutor(coordinatorCtx, t.cmdErrBuff,
			func(ctx context.Context, a any) (net.Addr, error) {
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

	cmdCoordinator := asyncutil.NewCommandCoordinator(t.openConnExecutor, t.acceptConnExecutor, t.getListenerExecutor, t.getAddrExecutor)

	defer func() {
		defer close(t.closed)

		logrus.Info("Shutting down.")
		if t.session != nil {
			logrus.Info("Closing session.")
			if err := t.session.Close(); err != nil {
				logrus.WithError(err).Error("Failed to close mux.")
			}
		}

		t.stopExecutors()
		<-cmdCoordinator.WaitForShutdown()
	}()

	var lastDrainTime time.Time
	var drain <-chan time.Time
	var drainFinished <-chan struct{}
	drainInterval := 2 * time.Second

	for {
		logrus.Debug("Waiting for signals.")
		select {
		case err := <-t.cmdErrBuff.Receive():
			logrus.WithError(err).Debug("Received error from executors.")
			// Receive errors from the command executors. If the error is an EOF then it's a signal that the session returned
			// an EOF error and needs to be recreated.
			//
			// If it's a non EOF error than the tunnel needs to be taken down.
			if err != io.EOF {
				logrus.WithError(err).Error("Failed to handle request, closing tunnel permanently.")
				return
			}

			// Break from this block if we're in the middle of draining (drainAndBacklogFinished channel is not nil)
			// or if the drainTimer hasn't expired yet (
			if drainFinished != nil || drain != nil {
				break
			}

			// Set the drain channel to signal that we executors should be drained. This is an immediate action if the
			// amount of time past since the last drain is greater than the drainInterval (this is to avoid rapid draining
			// on continuous errors).
			duration := clock.Since(lastDrainTime.Add(drainInterval))
			// The negative duration here makes the channel fire immediately if the drain interval has been exceeded.
			drain = clock.NewTimer(-duration).Chan()
		case <-drain:
			drain = nil
			logrus.Info("Starting drain and backlog...")

			// Indicate that we're not ready.
			drainFinished = cmdCoordinator.DrainAndBacklog()
		case <-drainFinished:
			logrus.Info("Finished draining, recreating the tunnel session...")

			lastDrainTime = clock.Now()
			drainFinished = nil

			// Now that we've finished draining and backlogging, kick off the session recreation (which is done asynchronously
			// and puts the session on the sessionChan when done.
			t.reCreateSession(ctx)
		case obj := <-t.sessionChan:
			if obj.Err != nil {
				logrus.WithError(obj.Err).Error("Failed to handle request, closing tunnel permanently.")
				return
			}

			logrus.Info("Session successfully recreated, will handle any outstanding requests.")

			t.session = obj.Obj
			t.dialing = false

			cmdCoordinator.Resume()
		case <-ctx.Done():
			logrus.Info("Context cancelled, will handle any outstanding requests and shutdown.")
			return
		}
	}
}

func (t *tunnel) reCreateSession(ctx context.Context) {
	if !t.dialing {
		t.dialing = true
		go func() {
			mux, err := t.dialer.Dial(ctx)
			t.sessionChan <- newObjectWithErr(mux, err)
		}()
	}
}

func (t *tunnel) Listener() (net.Listener, error) {
	return (<-t.getListenerExecutor.Send(nil)).Result()
}

func (t *tunnel) accept() (net.Conn, error) {
	result := <-t.acceptConnExecutor.Send(nil)
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
	if err != nil {
		logrus.WithError(err).Error("Failed to accept connection.")
	}
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
