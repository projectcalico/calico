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

package tunnel_test

import (
	"context"
	"errors"
	"io"
	"testing"

	. "github.com/onsi/gomega"

	netmocks "github.com/projectcalico/calico/guardian/pkg/thirdpartymocks/net"
	"github.com/projectcalico/calico/guardian/pkg/tunnel"
	tunmocks "github.com/projectcalico/calico/guardian/pkg/tunnel/mocks"
)

func TestTunnelOpenConnection(t *testing.T) {
	setupTest(t)

	tt := []struct {
		description string
		setSession  func(*tunmocks.Session)
		expectedErr error
	}{
		{
			description: "happy path",
			setSession: func(session *tunmocks.Session) {
				session.
					On("Close").Return(nil).Once().
					On("Open").Return(new(netmocks.Conn), nil).Once()
			},
		},
		{
			description: "connection fails then succeeds",
			setSession: func(session *tunmocks.Session) {
				session.
					On("Close").Return(nil).Once().
					On("Open").Return(nil, io.EOF).Once().
					On("Open").Return(new(netmocks.Conn), nil).Once()
			},
		},
		{
			description: "fails",
			setSession: func(session *tunmocks.Session) {
				session.
					On("Close").Return(nil).
					On("Open").Return(nil, errors.New("some error")).Once()
			},
			expectedErr: errors.New("some error"),
		},
	}

	for _, tc := range tt {
		t.Run(tc.description, func(t *testing.T) {
			mockDialer := tunmocks.NewSessionDialer(t)
			mockSession := tunmocks.NewSession(t)

			mockDialer.On("Dial").Return(mockSession, nil)
			tc.setSession(mockSession)

			tun, err := tunnel.NewTunnel(mockDialer)
			Expect(err).NotTo(HaveOccurred())

			ctx, cancel := context.WithCancel(context.Background())
			defer func() {
				cancel()
				<-tun.WaitForClose()
			}()

			Expect(tun.Connect(ctx)).ShouldNot(HaveOccurred())
			con, err := tun.Open(ctx)
			if tc.expectedErr != nil {
				Expect(err).Should(HaveOccurred())
				Expect(con).Should(BeNil())
			} else {
				Expect(err).ShouldNot(HaveOccurred())
				Expect(con).ShouldNot(BeNil())
			}
		})
	}
}

func TestTunnelAcceptConnection(t *testing.T) {
	setupTest(t)

	setupTest(t)

	tt := []struct {
		description string
		setSession  func(*tunmocks.Session)
		expectedErr error
	}{
		{
			description: "happy path",
			setSession: func(session *tunmocks.Session) {
				session.
					On("Close").Return(nil).
					On("Accept").Return(netmocks.NewConn(t), nil)
			}},
	}

	for _, tc := range tt {
		t.Run(tc.description, func(t *testing.T) {
			mockDialer := tunmocks.NewSessionDialer(t)
			mockSession := tunmocks.NewSession(t)

			mockDialer.On("Dial").Return(mockSession, nil)
			tc.setSession(mockSession)

			tun, err := tunnel.NewTunnel(mockDialer)
			Expect(err).NotTo(HaveOccurred())

			ctx, cancel := context.WithCancel(context.Background())
			defer func() {
				cancel()
				<-tun.WaitForClose()
			}()

			Expect(tun.Connect(ctx)).ShouldNot(HaveOccurred())
			listener, err := tun.Listener(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(listener).NotTo(BeNil())

			conn, err := listener.Accept()
			if tc.expectedErr != nil {
				Expect(err).Should(HaveOccurred())
				Expect(conn).Should(BeNil())
			} else {
				Expect(err).ShouldNot(HaveOccurred())
				Expect(conn).ShouldNot(BeNil())
			}
		})
	}
	mockConn := new(netmocks.Conn)
	mockDialer := new(tunmocks.SessionDialer)
	mockSession := new(tunmocks.Session)
	mockDialer.On("Dial").Return(mockSession, nil)
	mockSession.On("Close").Return(nil)
	mockSession.On("Accept").Return(mockConn, nil)

	tun, err := tunnel.NewTunnel(mockDialer)
	Expect(err).NotTo(HaveOccurred())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	Expect(tun.Connect(ctx)).ShouldNot(HaveOccurred())
	listener, err := tun.Listener(ctx)
	Expect(err).NotTo(HaveOccurred())
	Expect(listener).NotTo(BeNil())

	conn, err := listener.Accept()
	Expect(err).NotTo(HaveOccurred())
	Expect(conn).NotTo(BeNil())
}
