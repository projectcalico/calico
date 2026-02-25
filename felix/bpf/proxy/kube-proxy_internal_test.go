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

package proxy

import (
	"net"
	"testing"
	"time"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/proto"
)

// The main suite of tests in kube-proxy_test.go use a real syncer, making it
// hard to check for the start of day race between the CheckXXX methods and the
// initial sync.  These tests hack in a mock syncer so we can test the low
// level logic

func TestConntrackFrontendHasBackendChecksHasSynced(t *testing.T) {
	m := &mockSyncer{}
	kp := KubeProxy{
		syncer: m,
	}

	if !kp.ConntrackFrontendHasBackend(nil, 0, nil, 0, 0) {
		t.Errorf("ConntrackFrontendHasBackend should return true when syncer has not synced")
	}
	m.synced = true
	if kp.ConntrackFrontendHasBackend(nil, 0, nil, 0, 0) {
		t.Errorf("ConntrackFrontendHasBackend should return false when syncer has synced")
	}
}

func TestConntrackDestIsServiceChecksHasSynced(t *testing.T) {
	m := &mockSyncer{}
	kp := KubeProxy{
		syncer: m,
	}

	if kp.ConntrackDestIsService(nil, 0, 0) {
		t.Errorf("ConntrackDestIsService should return false when syncer has not synced")
	}
	m.synced = true
	if !kp.ConntrackDestIsService(nil, 0, 0) {
		t.Errorf("ConntrackDestIsService should return true when syncer has synced")
	}
}

type mockSyncer struct {
	DPSyncer
	synced bool
}

func (s *mockSyncer) HasSynced() bool {
	return s.synced
}

func (s *mockSyncer) ConntrackFrontendHasBackend(ip net.IP, port uint16, backendIP net.IP,
	backendPort uint16, proto uint8) bool {
	return false
}

func (s *mockSyncer) ConntrackDestIsService(ip net.IP, port uint16, proto uint8) bool {
	return true
}

func TestMergeHostMetadataV4V6Updates(t *testing.T) {
	RegisterTestingT(t)
	existing := map[string]*proto.HostMetadataV4V6Update{
		"host1": {Hostname: "host1", Ipv4Addr: "1.1.1.1"},
		"host2": {Hostname: "host2", Ipv4Addr: "2.2.2.2"},
	}
	latest := map[string]any{
		"host1": &proto.HostMetadataV4V6Remove{Hostname: "host1"},
		"host2": &proto.HostMetadataV4V6Update{Hostname: "host2", Ipv4Addr: "5.5.5.5"},
		"host3": &proto.HostMetadataV4V6Update{Hostname: "host3", Ipv4Addr: "3.3.3.3"},
	}
	mergeHostMetadataV4V6Updates(existing, latest)

	Expect(existing).To(HaveLen(2), "Expected host1 to be removed and host3 to be added")
	Expect(existing).NotTo(HaveKey("host1"))
	Expect(existing).To(HaveKey("host2"))
	Expect(existing).To(HaveKey("host3"))

	Expect(existing["host2"].Ipv4Addr).To(Equal("5.5.5.5"))
	Expect(existing["host3"].Ipv4Addr).To(Equal("3.3.3.3"))
}

func TestOnUpdateBatchesHostMetadataUpdates(t *testing.T) {
	RegisterTestingT(t)
	kp := KubeProxy{
		hostMetadataUpdates:        make(chan map[string]any, 1),
		pendingHostMetadataUpdates: make(map[string]any),
	}

	update := &proto.HostMetadataV4V6Update{
		Hostname: "hn1",
		Ipv4Addr: "1.2.3.4",
		Labels:   map[string]string{"label1": "label1val"},
	}
	kp.OnUpdate(update)

	update2 := &proto.HostMetadataV4V6Update{
		Hostname: "hn2",
		Ipv4Addr: "2.2.2.2",
		Labels:   map[string]string{"label2": "label2val"},
	}
	kp.OnUpdate(update2)

	Consistently(kp.pollHostMetadataV4V6UpdatesNonBlocking(), 100*time.Millisecond).Should(BeNil(), "No updates should have been sent before CompleteDeferredWork")

	Expect(kp.CompleteDeferredWork()).To(Succeed(), "CompleteDeferredWork should succeed")
	// Read the queued update from the channel.
	Expect(kp.pollHostMetadataV4V6UpdatesNonBlocking()).To(Equal(map[string]any{
		"hn1": update,
		"hn2": update2,
	}))
}

func TestCompleteDeferredWorkSendsEmptyUpdateOnce(t *testing.T) {
	RegisterTestingT(t)
	kp := KubeProxy{
		hostMetadataUpdates:        make(chan map[string]any, 1),
		pendingHostMetadataUpdates: make(map[string]any),
	}

	// First call with no pending updates should still send an empty map
	// to signal the KP loop to start.
	Expect(kp.CompleteDeferredWork()).To(Succeed())
	msg := kp.pollHostMetadataV4V6UpdatesNonBlocking()
	Expect(msg).NotTo(BeNil(), "First call should send an empty update to unblock the KP loop")
	Expect(msg).To(BeEmpty(), "The update should be an empty map")

	// Second call with no pending updates should be a no-op.
	Expect(kp.CompleteDeferredWork()).To(Succeed())
	Expect(kp.pollHostMetadataV4V6UpdatesNonBlocking()).To(BeNil(),
		"Second call with no pending updates should not send anything")

	// Sending a real update should still work after we're in sync.
	kp.OnUpdate(&proto.HostMetadataV4V6Update{Hostname: "host1", Ipv4Addr: "1.1.1.1"})
	Expect(kp.CompleteDeferredWork()).To(Succeed())
	msg = kp.pollHostMetadataV4V6UpdatesNonBlocking()
	Expect(msg).To(HaveLen(1))
	Expect(msg).To(HaveKey("host1"))

	// And after that, no-op again with no pending updates.
	Expect(kp.CompleteDeferredWork()).To(Succeed())
	Expect(kp.pollHostMetadataV4V6UpdatesNonBlocking()).To(BeNil(),
		"Should not send when in sync and no pending updates")
}

func TestOnUpdateRemoveOverwritesPendingUpdate(t *testing.T) {
	RegisterTestingT(t)
	kp := KubeProxy{
		hostMetadataUpdates:        make(chan map[string]any, 1),
		pendingHostMetadataUpdates: make(map[string]any),
	}

	update1 := &proto.HostMetadataV4V6Update{
		Hostname: "hn1",
		Ipv4Addr: "1.2.3.4",
	}
	update2 := &proto.HostMetadataV4V6Update{
		Hostname: "hn2",
		Ipv4Addr: "1.2.3.4",
	}
	update1Remove := &proto.HostMetadataV4V6Remove{Hostname: "hn1"}

	// Queue an update, then an immediate remove for the same hostname.
	kp.OnUpdate(update1)
	kp.OnUpdate(update2)
	kp.OnUpdate(update1Remove)

	Expect(kp.CompleteDeferredWork()).To(Succeed(), "CompleteDeferredWork should succeed")

	Expect(kp.pollHostMetadataV4V6UpdatesNonBlocking()).To(Equal(map[string]any{
		"hn1": update1Remove,
		"hn2": update2,
	}))
}
