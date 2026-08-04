//go:build linux

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

package collector

import (
	"errors"
	"strings"
	"testing"

	"github.com/projectcalico/calico/felix/nfnetlink"
)

// A reader that cannot subscribe produces no rule hits and no policy verdicts for the lifetime of
// the process, so Start must report the failure rather than looking like it succeeded.
func TestNFLogReaderStartReportsSubscribeFailure(t *testing.T) {
	subscribeErr := errors.New("no NFLOG for you")

	for _, tc := range []struct {
		name string
		// failOnGroup is the netlink group whose subscription fails.
		failOnGroup int
		wantInErr   string
	}{
		{"ingress subscription fails", 1, "ingress"},
		{"egress subscription fails", 2, "egress"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withStubbedNflogSubscribe(t, func(gn int, _ int, _ chan map[nfnetlink.NflogPacketTuple]*nfnetlink.NflogPacketAggregate, _ chan struct{}, _ bool) error {
				if gn == tc.failOnGroup {
					return subscribeErr
				}
				return nil
			})

			err := NewNFLogReader(nil, 1, 2, 0, false).Start()
			if err == nil {
				t.Fatal("Start() returned nil after the subscription failed")
			}
			if !errors.Is(err, subscribeErr) {
				t.Errorf("Start() error does not wrap the subscribe error: %v", err)
			}
			if !strings.Contains(err.Error(), tc.wantInErr) {
				t.Errorf("Start() error %q does not say which direction failed (want %q)", err, tc.wantInErr)
			}
		})
	}
}

func TestNFLogReaderStartSucceeds(t *testing.T) {
	withStubbedNflogSubscribe(t, func(int, int, chan map[nfnetlink.NflogPacketTuple]*nfnetlink.NflogPacketAggregate, chan struct{}, bool) error {
		return nil
	})

	r := NewNFLogReader(nil, 1, 2, 0, false)
	if err := r.Start(); err != nil {
		t.Fatalf("Start() failed with a working subscription: %v", err)
	}
	r.Stop()
}

func withStubbedNflogSubscribe(t *testing.T, stub func(int, int, chan map[nfnetlink.NflogPacketTuple]*nfnetlink.NflogPacketAggregate, chan struct{}, bool) error) {
	t.Helper()
	orig := subscribeToNflog
	subscribeToNflog = stub
	t.Cleanup(func() { subscribeToNflog = orig })
}
