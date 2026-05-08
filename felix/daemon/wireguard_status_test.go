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

package daemon

import (
	"errors"
	"sync"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/proto"
)

var _ = Describe("handleWireguardStatUpdateFromDataplane", func() {
	var (
		fc      *DataplaneConnector
		fake    *fakeReconciler
		done    chan struct{}
		stopped chan struct{}
	)

	BeforeEach(func() {
		fake = newFakeReconciler()
		fc = &DataplaneConnector{
			wireguardStatUpdateFromDataplane: make(chan *proto.WireguardStatusUpdate, 1),
		}
		done = make(chan struct{})
		stopped = make(chan struct{})
		go func() {
			defer close(stopped)
			fc.handleWireguardStatUpdateFromDataplane(fake.reconcile, done)
		}()
	})

	AfterEach(func() {
		close(done)
		Eventually(stopped, "5s").Should(BeClosed())
	})

	It("retries a failed v6 update even when a v4 update arrives during the failure", func() {
		// Make the first v6 reconcile call fail (simulating an etcd
		// context-deadline-exceeded). Subsequent v6 calls succeed.
		fake.failOnce(proto.IPVersion_IPV6)

		// Send v6 first so it is the in-flight reconcile when v4 arrives.
		fc.wireguardStatUpdateFromDataplane <- &proto.WireguardStatusUpdate{
			PublicKey: "v6-key",
			IpVersion: proto.IPVersion_IPV6,
		}
		// Send v4 while v6 is failing. Without the fix, this displaces the
		// pending v6 retry and the v6 publication is silently lost.
		fc.wireguardStatUpdateFromDataplane <- &proto.WireguardStatusUpdate{
			PublicKey: "v4-key",
			IpVersion: proto.IPVersion_IPV4,
		}

		// v4 should reconcile successfully promptly.
		Eventually(func() string {
			return fake.lastSucceeded(proto.IPVersion_IPV4)
		}, "5s", "50ms").Should(Equal("v4-key"))

		// v6 must also eventually be reconciled — this is the assertion
		// that fails on the unpatched code. The retry loop runs every 2-4s.
		Eventually(func() string {
			return fake.lastSucceeded(proto.IPVersion_IPV6)
		}, "10s", "50ms").Should(Equal("v6-key"))
	})
})

// fakeReconciler is a stub for reconcileWireguardStatUpdate that records calls
// and lets a test inject one-shot failures per IP version.
type fakeReconciler struct {
	mu          sync.Mutex
	failNext    map[proto.IPVersion]bool
	succeededAt map[proto.IPVersion]string
}

func newFakeReconciler() *fakeReconciler {
	return &fakeReconciler{
		failNext:    map[proto.IPVersion]bool{},
		succeededAt: map[proto.IPVersion]string{},
	}
}

func (f *fakeReconciler) failOnce(ipVersion proto.IPVersion) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failNext[ipVersion] = true
}

func (f *fakeReconciler) reconcile(pubKey string, ipVersion proto.IPVersion) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failNext[ipVersion] {
		delete(f.failNext, ipVersion)
		return errors.New("injected failure")
	}
	f.succeededAt[ipVersion] = pubKey
	return nil
}

func (f *fakeReconciler) lastSucceeded(ipVersion proto.IPVersion) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.succeededAt[ipVersion]
}
