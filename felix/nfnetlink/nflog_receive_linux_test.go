// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

package nfnetlink

import (
	"errors"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestReceiveNflogs(t *testing.T) {
	data := syscall.NetlinkMessage{Data: []byte("nflog")}
	done := syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: syscall.NLMSG_DONE}}
	nlErr := syscall.NetlinkMessage{
		Header: syscall.NlMsghdr{Type: syscall.NLMSG_ERROR},
		Data:   []byte{0xf3, 0xff, 0xff, 0xff}, // -EACCES
	}
	errShortResponse := errors.New("Got short response from netlink")

	for _, tc := range []struct {
		name     string
		receives []fakeReceive
		// closeDone closes done before receiving, as Stop does before closing the socket.
		closeDone   bool
		wantBatches int
		wantErr     error
	}{
		{
			name: "reads on through overruns and temporary errors",
			receives: []fakeReceive{
				{err: syscall.ENOBUFS},
				{err: syscall.EINTR},
				{err: syscall.EAGAIN},
				{msgs: []syscall.NetlinkMessage{data}},
				{err: syscall.EBADF},
			},
			wantBatches: 1,
			wantErr:     syscall.EBADF,
		},
		{
			name:     "ends on an error that is not an errno",
			receives: []fakeReceive{{err: errShortResponse}},
			wantErr:  errShortResponse,
		},
		{
			name: "sends no empty batches",
			receives: []fakeReceive{
				{msgs: nil},
				{msgs: []syscall.NetlinkMessage{done}},
				{msgs: []syscall.NetlinkMessage{data, nlErr}},
				{err: syscall.EBADF},
			},
			wantErr: syscall.EBADF,
		},
		{
			name:      "ends cleanly when the socket fails because done closed",
			receives:  []fakeReceive{{err: syscall.EBADF}},
			closeDone: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doneC := make(chan struct{})
			if tc.closeDone {
				close(doneC)
			}
			resChan := make(chan [][]byte, len(tc.receives))

			err := receiveNflogs(&fakeNflogSocket{receives: tc.receives}, 1, doneC, resChan)

			if tc.wantErr == nil && err != nil {
				t.Errorf("receiveNflogs returned %v, want nil", err)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Errorf("receiveNflogs returned %v, want an error wrapping %v", err, tc.wantErr)
			}
			if len(resChan) != tc.wantBatches {
				t.Errorf("receiveNflogs sent %d batches, want %d", len(resChan), tc.wantBatches)
			}
			for len(resChan) > 0 {
				if batch := <-resChan; len(batch) == 0 {
					t.Error("receiveNflogs sent an empty batch")
				}
			}
		})
	}
}

type fakeReceive struct {
	msgs []syscall.NetlinkMessage
	err  error
}

// fakeNflogSocket returns its receives in order.  Each test ends with an error, which
// receiveNflogs must return on.
type fakeNflogSocket struct {
	receives []fakeReceive
}

func (s *fakeNflogSocket) Receive() ([]syscall.NetlinkMessage, *unix.SockaddrNetlink, error) {
	if len(s.receives) == 0 {
		panic("receiveNflogs called Receive after the test's final error")
	}
	r := s.receives[0]
	s.receives = s.receives[1:]
	return r.msgs, nil, r.err
}
