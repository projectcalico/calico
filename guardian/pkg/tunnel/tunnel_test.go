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
	"time"

	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"

	netmocks "github.com/projectcalico/calico/guardian/pkg/thirdpartymocks/net"
	mockclock "github.com/projectcalico/calico/guardian/pkg/thirdpartymocks/std/clock"
	"github.com/projectcalico/calico/guardian/pkg/tunnel"
	tunmocks "github.com/projectcalico/calico/guardian/pkg/tunnel/mocks"
	"github.com/projectcalico/calico/lib/std/clock"
)

func TestTunnelOpenConnection(t *testing.T) {
	setupTest(t)

	tt := []struct {
		description string
		setSession  func(*tunmocks.Session)
		expectedErr error
	}{
		{
			description: "session opens immediately",
			setSession: func(session *tunmocks.Session) {
				session.
					On("Close").Return(nil).Once().
					On("Open").Return(netmocks.NewConn(t), nil).Once()
			},
		},
		{
			description: "session fails to open first with EOF then succeeds",
			setSession: func(session *tunmocks.Session) {
				session.
					On("Close").Return(nil).Once().
					On("Open").Return(nil, io.EOF).Once().
					On("Open").Return(netmocks.NewConn(t), nil).Once()
			},
		},
		{
			description: "session to open with non EOF error and returns an error",
			setSession: func(session *tunmocks.Session) {
				session.
					On("Close").Return(nil).Once().
					On("Open").Return(nil, errors.New("some error")).Once()
			},
			expectedErr: errors.New("some error"),
		},
	}

	for _, tc := range tt {
		t.Run(tc.description, func(t *testing.T) {
			mockDialer := new(tunmocks.SessionDialer)
			mockSession := new(tunmocks.Session)

			mockDialer.On("Dial", mock.Anything).Return(mockSession, nil)
			tc.setSession(mockSession)

			tun, err := tunnel.NewTunnel(mockDialer)
			Expect(err).NotTo(HaveOccurred())

			ctx, cancel := context.WithDeadline(context.Background(), clock.Now().Add(time.Second*30))
			defer func() {
				cancel()
				<-tun.WaitForClose()
			}()

			Expect(tun.Connect(ctx)).ShouldNot(HaveOccurred())
			con, err := tun.Open()
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

	tt := []struct {
		description string
		setSession  func(*tunmocks.Session)
		expectedErr error
	}{
		{
			description: "listener accepts connection initially",
			setSession: func(session *tunmocks.Session) {
				session.
					On("Close").Return(nil).Once().
					On("Accept").Return(netmocks.NewConn(t), nil)
			},
		},
		{
			description: "listener fails to accept connection initially with EOF then succeeds",
			setSession: func(session *tunmocks.Session) {
				session.
					On("Close").Return(nil).Once().
					On("Accept").Return(nil, io.EOF).Once().
					On("Accept").Return(netmocks.NewConn(t), nil)
			},
		},
		{
			description: "listener fails to accept connection with non EOF error and returns an error",
			setSession: func(session *tunmocks.Session) {
				session.
					On("Close").Return(nil).Once().
					On("Accept").Return(nil, errors.New("some error")).Once()
			},
			expectedErr: errors.New("some error"),
		},
	}

	for _, tc := range tt {
		t.Run(tc.description, func(t *testing.T) {
			mockDialer := tunmocks.NewSessionDialer(t)
			mockSession := tunmocks.NewSession(t)

			mockDialer.On("Dial", mock.Anything).Return(mockSession, nil)
			tc.setSession(mockSession)

			tun, err := tunnel.NewTunnel(mockDialer)
			Expect(err).NotTo(HaveOccurred())

			ctx, cancel := context.WithCancel(context.Background())
			defer func() {
				cancel()
				<-tun.WaitForClose()
			}()

			Expect(tun.Connect(ctx)).ShouldNot(HaveOccurred())
			listener, err := tun.Listener()
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
}

func TestTunnel_DialRetry(t *testing.T) {
	setupTest(t)

	mockClock := new(mockclock.Clock)

	livenessTickerChan := make(chan time.Time)
	timerChan := make(chan time.Time, 1)
	defer close(livenessTickerChan)
	defer close(timerChan)

	mockTimer := new(mockclock.Timer)

	mockTimer.On("Chan").
		Run(func(mock.Arguments) { timerChan <- time.Now() }).
		Return((<-chan time.Time)(timerChan))

	mockTimer.On("Stop").Return()

	mockClock.On("Now").Return(time.Now())
	mockClock.On("Since", mock.Anything).Return(time.Duration(0))
	mockClock.On("NewTimer", mock.Anything).Return(mockTimer)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	mockDialer := new(tunmocks.SessionDialer)
	mockSession := new(tunmocks.Session)

	mockDialer.On("Dial", mock.Anything).Return(mockSession, nil).Times(5)

	_ = clock.DoWithClock(mockClock, func() error {
		tun, err := tunnel.NewTunnel(mockDialer)
		Expect(err).NotTo(HaveOccurred())

		Expect(tun.Connect(ctx)).ShouldNot(HaveOccurred())
		mockConn := new(netmocks.Conn)
		mockSession.
			On("Close").Return(nil).Once().
			On("Open").Return(nil, io.EOF).Times(4).
			On("Open").Return(mockConn, nil).Once()

		conn, err := tun.Open()
		Expect(err).ShouldNot(HaveOccurred())
		Expect(conn).ShouldNot(BeNil())

		cancel()
		<-tun.WaitForClose()

		return nil
	})

	mockSession.AssertExpectations(t)
	mockClock.AssertExpectations(t)
	mockDialer.AssertExpectations(t)
}
