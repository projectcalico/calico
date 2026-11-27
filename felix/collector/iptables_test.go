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
	"testing"
	"time"

	"github.com/projectcalico/calico/libcalico-go/lib/health"
)

const (
	ingressGroup = 1
	egressGroup  = 2
)

// A reader that isn't subscribed produces no rule hits or policy verdicts, so it must report not
// ready and keep trying to subscribe, whether the subscribe call fails or a running subscription
// does.
func TestNFLogReaderMaintainsSubscriptions(t *testing.T) {
	ha := health.NewHealthAggregator()
	r, subscribeCalls := newStubbedNFLogReader(ha)
	if err := r.Start(); err != nil {
		t.Fatalf("Start() failed: %v", err)
	}
	t.Cleanup(r.Stop)

	nextSubscribe(t, subscribeCalls[ingressGroup]).succeed()

	nextSubscribe(t, subscribeCalls[egressGroup]).fail(errors.New("no NFLOG for you"))
	expectReady(t, ha, false)

	egress := nextSubscribe(t, subscribeCalls[egressGroup]).succeed()
	eventuallyReady(t, ha)

	egress <- errors.New("socket broke")
	retry := nextSubscribe(t, subscribeCalls[egressGroup])
	// The reader reports the failure before it resubscribes.
	expectReady(t, ha, false)
	retry.succeed()
	eventuallyReady(t, ha)

	r.Stop()
	expectReady(t, ha, false)
}

func TestNFLogReaderStartsOnce(t *testing.T) {
	r, _ := newStubbedNFLogReader(nil)
	if err := r.Start(); err != nil {
		t.Fatalf("Start() failed: %v", err)
	}
	if err := r.Start(); err == nil {
		t.Error("second Start() succeeded")
	}
	r.Stop()
	if err := r.Start(); err == nil {
		t.Error("Start() after Stop() succeeded")
	}
}

// newStubbedNFLogReader returns a reader whose subscribe calls are sent, per group, to the
// returned channels for the test to answer.
func newStubbedNFLogReader(ha *health.HealthAggregator) (*NFLogReader, map[int]chan subscribeCall) {
	calls := map[int]chan subscribeCall{
		ingressGroup: make(chan subscribeCall),
		egressGroup:  make(chan subscribeCall),
	}
	r := NewNFLogReader(nil, ha, ingressGroup, egressGroup, 0, false)
	r.retryInterval = time.Millisecond
	r.subscribe = func(gn int, _ int, _ chan<- nflogAggregates, done <-chan struct{}, _ bool) (<-chan error, error) {
		errStopped := errors.New("stopped")
		call := subscribeCall{reply: make(chan subscribeReply)}
		select {
		case calls[gn] <- call:
		case <-done:
			return nil, errStopped
		}
		var reply subscribeReply
		select {
		case reply = <-call.reply:
		case <-done:
			return nil, errStopped
		}
		if reply.err != nil {
			return nil, reply.err
		}
		// Like NflogSubscribe, report nil once done closes.
		endC := make(chan error, 1)
		go func() {
			select {
			case err := <-reply.failC:
				endC <- err
			case <-done:
				endC <- nil
			}
		}()
		return endC, nil
	}
	return r, calls
}

type subscribeCall struct {
	reply chan subscribeReply
}

type subscribeReply struct {
	err   error
	failC chan error
}

// succeed lets the subscribe call succeed and returns a channel that fails the subscription.
func (c subscribeCall) succeed() chan<- error {
	failC := make(chan error, 1)
	c.reply <- subscribeReply{failC: failC}
	return failC
}

func (c subscribeCall) fail(err error) {
	c.reply <- subscribeReply{err: err}
}

func nextSubscribe(t *testing.T, calls chan subscribeCall) subscribeCall {
	t.Helper()
	select {
	case call := <-calls:
		return call
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the reader to subscribe")
		return subscribeCall{}
	}
}

func expectReady(t *testing.T, ha *health.HealthAggregator, want bool) {
	t.Helper()
	if got := ha.Summary().Ready; got != want {
		t.Fatalf("health aggregator Ready = %v, want %v", got, want)
	}
}

func eventuallyReady(t *testing.T, ha *health.HealthAggregator) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !ha.Summary().Ready {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for the reader to report ready")
		}
		time.Sleep(time.Millisecond)
	}
}
