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
	"k8s.io/client-go/kubernetes/fake"

	"github.com/projectcalico/calico/felix/bpf/bpfmap"
	"github.com/projectcalico/calico/felix/bpf/conntrack"
	"github.com/projectcalico/calico/felix/bpf/mock"
	"github.com/projectcalico/calico/felix/bpf/nat"
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

func TestMergeHostMetadataV4V6Updates_AppliesUpdates(t *testing.T) {
	existing := map[string]*proto.HostMetadataV4V6Update{}
	latest := map[string]any{
		"host1": &proto.HostMetadataV4V6Update{Hostname: "host1", Ipv4Addr: "1.1.1.1"},
		"host2": &proto.HostMetadataV4V6Update{Hostname: "host2", Ipv4Addr: "2.2.2.2"},
	}
	mergeHostMetadataV4V6Updates(existing, latest)

	if len(existing) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(existing))
	}
	if existing["host1"].Ipv4Addr != "1.1.1.1" {
		t.Errorf("host1 Ipv4Addr = %q, want %q", existing["host1"].Ipv4Addr, "1.1.1.1")
	}
	if existing["host2"].Ipv4Addr != "2.2.2.2" {
		t.Errorf("host2 Ipv4Addr = %q, want %q", existing["host2"].Ipv4Addr, "2.2.2.2")
	}
}

func TestMergeHostMetadataV4V6Updates_OverridesExisting(t *testing.T) {
	existing := map[string]*proto.HostMetadataV4V6Update{
		"host1": {Hostname: "host1", Ipv4Addr: "1.1.1.1"},
	}
	latest := map[string]any{
		"host1": &proto.HostMetadataV4V6Update{Hostname: "host1", Ipv4Addr: "9.9.9.9"},
	}
	mergeHostMetadataV4V6Updates(existing, latest)

	if existing["host1"].Ipv4Addr != "9.9.9.9" {
		t.Errorf("host1 Ipv4Addr = %q, want %q", existing["host1"].Ipv4Addr, "9.9.9.9")
	}
}

func TestMergeHostMetadataV4V6Updates_RemovesExisting(t *testing.T) {
	existing := map[string]*proto.HostMetadataV4V6Update{
		"host1": {Hostname: "host1", Ipv4Addr: "1.1.1.1"},
		"host2": {Hostname: "host2", Ipv4Addr: "2.2.2.2"},
	}
	latest := map[string]any{
		"host1": &proto.HostMetadataV4V6Remove{Hostname: "host1"},
	}
	mergeHostMetadataV4V6Updates(existing, latest)

	if len(existing) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(existing))
	}
	if _, ok := existing["host1"]; ok {
		t.Error("host1 should have been removed")
	}
	if existing["host2"].Ipv4Addr != "2.2.2.2" {
		t.Errorf("host2 should be unchanged, got %q", existing["host2"].Ipv4Addr)
	}
}

func TestMergeHostMetadataV4V6Updates_MixedUpdatesAndRemoves(t *testing.T) {
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

	if len(existing) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(existing))
	}
	if _, ok := existing["host1"]; ok {
		t.Error("host1 should have been removed")
	}
	if existing["host2"].Ipv4Addr != "5.5.5.5" {
		t.Errorf("host2 Ipv4Addr = %q, want %q", existing["host2"].Ipv4Addr, "5.5.5.5")
	}
	if existing["host3"].Ipv4Addr != "3.3.3.3" {
		t.Errorf("host3 Ipv4Addr = %q, want %q", existing["host3"].Ipv4Addr, "3.3.3.3")
	}
}

func TestOnUpdateQueuesHostMetadataUpdates(t *testing.T) {
	kp := KubeProxy{
		hostMetadataUpdates: make(chan map[string]any, 1),
	}

	update := &proto.HostMetadataV4V6Update{
		Hostname: "hn1",
		Ipv4Addr: "1.2.3.4",
		Labels:   map[string]string{"label1": "label1val"},
	}
	kp.OnUpdate(update)

	// Read the queued update from the channel.
	updates := kp.recvHostMetadataV4V6Updates()
	if updates == nil {
		t.Fatal("expected updates on channel, got nil")
	}
	if len(updates) != 1 {
		t.Fatalf("expected 1 update, got %d", len(updates))
	}
	if _, ok := updates["hn1"].(*proto.HostMetadataV4V6Update); !ok {
		t.Fatalf("expected *proto.HostMetadataV4V6Update, got %T", updates["hn1"])
	}
}

func TestOnUpdateCoalescesRemoveWithPendingUpdate(t *testing.T) {
	kp := KubeProxy{
		hostMetadataUpdates: make(chan map[string]any, 1),
	}

	// Queue an update, then an immediate remove for the same hostname.
	kp.OnUpdate(&proto.HostMetadataV4V6Update{
		Hostname: "hn1",
		Ipv4Addr: "1.2.3.4",
	})
	kp.OnUpdate(&proto.HostMetadataV4V6Remove{Hostname: "hn1"})

	updates := kp.recvHostMetadataV4V6Updates()
	if updates == nil {
		t.Fatal("expected updates on channel, got nil")
	}
	// The remove should have deleted the pending update for "hn1".
	if len(updates) != 0 {
		t.Fatalf("expected 0 entries after remove coalesced pending update, got %d: %+v", len(updates), updates)
	}
}

func TestOnUpdateQueuesRemoveWhenNoPendingUpdate(t *testing.T) {
	kp := KubeProxy{
		hostMetadataUpdates: make(chan map[string]any, 1),
	}

	// Queue a remove without a prior update.
	kp.OnUpdate(&proto.HostMetadataV4V6Remove{Hostname: "hn1"})

	updates := kp.recvHostMetadataV4V6Updates()
	if updates == nil {
		t.Fatal("expected updates on channel, got nil")
	}
	if len(updates) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(updates))
	}
	if _, ok := updates["hn1"].(*proto.HostMetadataV4V6Remove); !ok {
		t.Fatalf("expected *proto.HostMetadataV4V6Remove, got %T", updates["hn1"])
	}
}

// startTestKubeProxy starts a real KubeProxy backed by mock maps and a fake
// k8s client, then sends an initial host IP to unblock the start loop.
// The caller must call kp.Stop() when done.
func startTestKubeProxy(t *testing.T) *KubeProxy {
	t.Helper()

	maps := &bpfmap.IPMaps{
		FrontendMap: mock.NewMockMap(nat.FrontendMapParameters),
		BackendMap:  mock.NewMockMap(nat.BackendMapParameters),
		AffinityMap: mock.NewMockMap(nat.AffinityMapParameters),
		MaglevMap:   mock.NewMockMap(nat.MaglevMapParameters),
		CtMap:       mock.NewMockMap(conntrack.MapParams),
	}

	k8s := fake.NewClientset()
	kp, err := StartKubeProxy(k8s, "test-node", maps, WithImmediateSync())
	if err != nil {
		t.Fatalf("StartKubeProxy failed: %v", err)
	}

	// Unblock the start loop by providing initial host IPs.
	kp.OnHostIPsUpdate([]net.IP{net.IPv4(1, 1, 1, 1)})

	return kp
}

// getProxyHostMetadata reads the proxy's hostMetadataByHostname field
// under the runner lock. Safe to call from Eventually/Consistently.
func getProxyHostMetadata(kp *KubeProxy) func() map[string]*proto.HostMetadataV4V6Update {
	return func() map[string]*proto.HostMetadataV4V6Update {
		p := kp.proxy.(*proxy)
		p.runnerLck.Lock()
		defer p.runnerLck.Unlock()

		result := make(map[string]*proto.HostMetadataV4V6Update, len(p.hostMetadataByHostname))
		for k, v := range p.hostMetadataByHostname {
			result[k] = v
		}
		return result
	}
}

func TestKubeProxyPropagatesHostMetadataUpdate(t *testing.T) {
	RegisterTestingT(t)

	kp := startTestKubeProxy(t)
	defer kp.Stop()

	update := &proto.HostMetadataV4V6Update{
		Hostname: "hn1",
		Ipv4Addr: "1.2.3.4",
		Labels:   map[string]string{"label1": "label1val"},
	}

	kp.OnUpdate(update)

	Eventually(getProxyHostMetadata(kp), 2*time.Second, 10*time.Millisecond).
		Should(HaveKeyWithValue("hn1", update))
}

func TestKubeProxyPropagatesHostMetadataRemove(t *testing.T) {
	RegisterTestingT(t)

	kp := startTestKubeProxy(t)
	defer kp.Stop()

	update := &proto.HostMetadataV4V6Update{
		Hostname: "hn1",
		Ipv4Addr: "1.2.3.4",
		Labels:   map[string]string{"label1": "label1val"},
	}

	// First, apply an update.
	kp.OnUpdate(update)
	Eventually(getProxyHostMetadata(kp), 2*time.Second, 10*time.Millisecond).
		Should(HaveKeyWithValue("hn1", update))

	// Remove hn1 and add hn2.
	kp.OnUpdate(&proto.HostMetadataV4V6Remove{Hostname: "hn1"})
	update2 := &proto.HostMetadataV4V6Update{
		Hostname: "hn2",
		Ipv4Addr: "5.6.7.8",
		Labels:   map[string]string{"label2": "label2val"},
	}
	kp.OnUpdate(update2)

	Eventually(getProxyHostMetadata(kp), 2*time.Second, 10*time.Millisecond).
		Should(And(
			Not(HaveKey("hn1")),
			HaveKeyWithValue("hn2", update2),
		))
}
