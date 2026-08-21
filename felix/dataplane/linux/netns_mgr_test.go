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

package intdataplane

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/containernetworking/plugins/pkg/ns"

	"github.com/projectcalico/calico/felix/proto"
)

// stubBatchResolver returns a batched /proc-scan resolver backed by a
// fixed uid -> path map. UIDs with no entry are omitted, mirroring
// netns.ResolvePodNetnsPaths.
func stubBatchResolver(byUID map[string]string) netnsBatchResolver {
	return func(uids []string) map[string]string {
		out := map[string]string{}
		for _, uid := range uids {
			if p, ok := byUID[uid]; ok {
				out[uid] = p
			}
		}
		return out
	}
}

// stubCookieReader returns a deterministic cookie keyed by netns path.
func stubCookieReader(byPath map[string]uint64) netnsCookieReader {
	return func(path string) (uint64, error) {
		c, ok := byPath[path]
		if !ok {
			return 0, fmt.Errorf("no cookie for path %s", path)
		}
		return c, nil
	}
}

func newNetnsManagerForTest(byPath map[string]uint64, byUID map[string]string) *netnsManager {
	m := newNetnsManager("/proc", nil, nil)
	m.resolveCookieByPath = stubCookieReader(byPath)
	m.resolveCookieDirect = stubCookieReader(byPath)
	m.resolveProcPaths = stubBatchResolver(byUID)
	m.openNetns = func(string) (ns.NetNS, error) {
		return nil, fmt.Errorf("openNetns not stubbed in this test")
	}
	return m
}

func netnsWepUpdate(orch, workload, endpoint, uid, netnsPath string) *proto.WorkloadEndpointUpdate {
	return &proto.WorkloadEndpointUpdate{
		Id: &proto.WorkloadEndpointID{
			OrchestratorId: orch,
			WorkloadId:     workload,
			EndpointId:     endpoint,
		},
		Endpoint: &proto.WorkloadEndpoint{
			Uid:       uid,
			NetnsPath: netnsPath,
		},
	}
}

func TestNetnsMgr_Tier1_CNIPathWins(t *testing.T) {
	// WEP carries a CNI-set netns path; Tier 1 resolves inline in
	// OnUpdate without touching the background tiers.
	const uid = "uid-1"
	const path = "/var/run/netns/cni-X"
	m := newNetnsManagerForTest(
		map[string]uint64{path: 0xabcd},
		map[string]string{uid: "/proc/9999/ns/net"}, // would resolve but shouldn't be reached
	)
	m.resolveProcPaths = func([]string) map[string]string {
		t.Fatal("Tier 3 must not run when Tier 1 hits")
		return nil
	}

	upd := netnsWepUpdate("k8s", "ns/p", "eth0", uid, path)
	m.OnUpdate(upd)

	got, ok := m.CookieForWEP(upd.Id)
	if !ok || got != 0xabcd {
		t.Fatalf("CookieForWEP: got (%#x, %v), want (0xabcd, true)", got, ok)
	}
}

func TestNetnsMgr_Tier2_CRIWhenNoPath(t *testing.T) {
	// No CNI path on the WEP; CRI (Tier 2) resolves it on the background
	// pass. Tier 3 must not run.
	const uid = "uid-2"
	const criPath = "/proc/4321/ns/net"
	m := newNetnsManagerForTest(
		map[string]uint64{criPath: 0xbeef},
		map[string]string{uid: "/proc/9999/ns/net"},
	)
	procScanCalls := 0
	m.resolveProcPaths = func([]string) map[string]string {
		procScanCalls++
		return nil
	}
	m.resolveNetnsViaCRI = func(_ context.Context, podUID string) (string, error) {
		if podUID != uid {
			return "", fmt.Errorf("unexpected uid %q", podUID)
		}
		return criPath, nil
	}

	upd := netnsWepUpdate("k8s", "ns/p", "eth0", uid, "")
	m.OnUpdate(upd)
	// Tier 1 missed → deferred; nothing cached yet.
	if _, ok := m.CookieForWEP(upd.Id); ok {
		t.Fatalf("Tier 2/3 must not resolve inline on OnUpdate")
	}
	// Drive the background resolver synchronously.
	m.resolveDeepBatch()

	got, ok := m.CookieForWEP(upd.Id)
	if !ok || got != 0xbeef {
		t.Fatalf("CookieForWEP got (%#x, %v); want (0xbeef, true)", got, ok)
	}
	if procScanCalls != 0 {
		t.Fatalf("proc scan must not run when CRI succeeded (got %d calls)", procScanCalls)
	}
}

func TestNetnsMgr_Tier3_ProcScanFallback(t *testing.T) {
	// Tier 1 missing, Tier 2 errors, Tier 3 (/proc scan) picks up.
	const uid = "uid-3"
	const t3path = "/proc/1234/ns/net"
	m := newNetnsManagerForTest(
		map[string]uint64{t3path: 0xc0de},
		map[string]string{uid: t3path},
	)
	m.resolveNetnsViaCRI = func(_ context.Context, _ string) (string, error) {
		return "", fmt.Errorf("CRI unreachable")
	}

	upd := netnsWepUpdate("k8s", "ns/p", "eth0", uid, "")
	m.OnUpdate(upd)
	m.resolveDeepBatch()

	got, ok := m.CookieForWEP(upd.Id)
	if !ok || got != 0xc0de {
		t.Fatalf("CookieForWEP got (%#x, %v); want (0xc0de, true)", got, ok)
	}
}

func TestNetnsMgr_Tier3_BatchedSingleScan(t *testing.T) {
	// Multiple WEPs pending Tier-3 resolution are drained with a single
	// batched /proc scan carrying all their UIDs.
	const (
		uidA = "uid-a"
		uidB = "uid-b"
	)
	pathA := "/proc/111/ns/net"
	pathB := "/proc/222/ns/net"
	m := newNetnsManagerForTest(
		map[string]uint64{pathA: 0x1, pathB: 0x2},
		map[string]string{uidA: pathA, uidB: pathB},
	)
	scanCalls := 0
	var lastUIDs []string
	inner := stubBatchResolver(map[string]string{uidA: pathA, uidB: pathB})
	m.resolveProcPaths = func(uids []string) map[string]string {
		scanCalls++
		lastUIDs = uids
		return inner(uids)
	}
	m.resolveNetnsViaCRI = nil // Tier 2 disabled → both fall to Tier 3.

	updA := netnsWepUpdate("k8s", "ns/a", "eth0", uidA, "")
	updB := netnsWepUpdate("k8s", "ns/b", "eth0", uidB, "")
	m.OnUpdate(updA)
	m.OnUpdate(updB)
	m.resolveDeepBatch()

	if scanCalls != 1 {
		t.Fatalf("expected exactly 1 batched /proc scan, got %d", scanCalls)
	}
	if len(lastUIDs) != 2 {
		t.Fatalf("expected both UIDs in one scan, got %v", lastUIDs)
	}
	if c, ok := m.CookieForWEP(updA.Id); !ok || c != 0x1 {
		t.Fatalf("WEP A cookie got (%#x,%v), want (0x1,true)", c, ok)
	}
	if c, ok := m.CookieForWEP(updB.Id); !ok || c != 0x2 {
		t.Fatalf("WEP B cookie got (%#x,%v), want (0x2,true)", c, ok)
	}
}

func TestNetnsMgr_RecreateMidResolve_DropsStale(t *testing.T) {
	// A pod is deleted and recreated with the same name (same wepKey) but
	// a new UID/netns while a background resolve for the old UID is in
	// flight. The resolver must NOT cache the old netns against the
	// recreated pod, and must leave the new UID pending for a later cycle.
	const (
		uidA  = "uid-old"
		uidB  = "uid-new"
		pathA = "/proc/111/ns/net"
		pathB = "/proc/222/ns/net"
	)
	m := newNetnsManagerForTest(
		map[string]uint64{pathA: 0xA, pathB: 0xB},
		map[string]string{uidA: pathA, uidB: pathB},
	)
	m.resolveNetnsViaCRI = nil // Tier 2 disabled → Tier 3 does the work.

	id := &proto.WorkloadEndpointID{OrchestratorId: "k8s", WorkloadId: "ns/p", EndpointId: "eth0"}

	// The Tier-3 scan for uidA simulates the recreate landing mid-resolve:
	// before returning uidA's (now stale) path, a fresh WEP update for the
	// same key arrives carrying uidB with no Tier-1 path.
	recreated := false
	inner := stubBatchResolver(map[string]string{uidA: pathA, uidB: pathB})
	m.resolveProcPaths = func(uids []string) map[string]string {
		out := inner(uids)
		if !recreated {
			recreated = true
			m.onWepUpdate(id, &proto.WorkloadEndpoint{Uid: uidB})
		}
		return out
	}

	// Old pod update → pending{uidA}. Resolve; the recreate fires inside.
	m.onWepUpdate(id, &proto.WorkloadEndpoint{Uid: uidA})
	m.resolveDeepBatch()

	// The stale uidA result must not have been cached.
	if c, ok := m.CookieForWEP(id); ok {
		t.Fatalf("stale resolve cached: CookieForWEP returned (%#x, true); want (_, false)", c)
	}
	// uidB must still be pending (not dropped by the stale store).
	if p, ok := m.pendingDeep[wepKey(id)]; !ok || p.uid != uidB {
		t.Fatalf("expected uidB still pending, got %+v (present=%v)", p, ok)
	}

	// Next cycle resolves the recreated pod cleanly.
	m.resolveDeepBatch()
	if c, ok := m.CookieForWEP(id); !ok || c != 0xB {
		t.Fatalf("after recreate resolve: got (%#x, %v); want (0xB, true)", c, ok)
	}
}

func TestNetnsMgr_ResolverWakesApplyLoop(t *testing.T) {
	const uid = "uid-wake"
	const t3path = "/proc/1234/ns/net"
	m := newNetnsManagerForTest(
		map[string]uint64{t3path: 0xc0de},
		map[string]string{uid: t3path},
	)
	m.resolveNetnsViaCRI = nil
	wakeupC := make(chan struct{}, 1)
	m.wakeupC = wakeupC

	m.OnUpdate(netnsWepUpdate("k8s", "ns/p", "eth0", uid, ""))
	m.resolveDeepBatch()

	select {
	case <-wakeupC:
	default:
		t.Fatal("expected resolver to wake the apply loop after caching a result")
	}
}

func TestNetnsMgr_NoUID_NoResolution(t *testing.T) {
	// Non-k8s WEP (no pod UID) and no path → nothing to resolve.
	m := newNetnsManagerForTest(map[string]uint64{}, map[string]string{})

	upd := netnsWepUpdate("openstack", "vm/inst", "eth0", "", "")
	m.OnUpdate(upd)
	m.resolveDeepBatch()

	if _, ok := m.CookieForWEP(upd.Id); ok {
		t.Fatalf("CookieForWEP should be (_, false) when no UID and no path")
	}
}

func TestNetnsMgr_AllTiersFail_NoCookie(t *testing.T) {
	const uid = "uid-4"
	m := newNetnsManagerForTest(
		map[string]uint64{}, // no cookie resolver match
		map[string]string{}, // no proc-scan match
	)
	m.resolveNetnsViaCRI = func(_ context.Context, _ string) (string, error) {
		return "", fmt.Errorf("CRI unreachable")
	}

	upd := netnsWepUpdate("k8s", "ns/p", "eth0", uid, "")
	m.OnUpdate(upd)
	m.resolveDeepBatch()

	if _, ok := m.CookieForWEP(upd.Id); ok {
		t.Fatalf("CookieForWEP should be (_, false) when all tiers fail")
	}
}

func TestNetnsMgr_Remove_ClearsEntry(t *testing.T) {
	const uid = "uid-5"
	const path = "/var/run/netns/cni-Y"
	m := newNetnsManagerForTest(
		map[string]uint64{path: 0xfeed},
		map[string]string{},
	)
	upd := netnsWepUpdate("k8s", "ns/p", "eth0", uid, path)
	m.OnUpdate(upd)
	if _, ok := m.CookieForWEP(upd.Id); !ok {
		t.Fatalf("expected cookie present after update")
	}

	m.OnUpdate(&proto.WorkloadEndpointRemove{Id: upd.Id})
	if _, ok := m.CookieForWEP(upd.Id); ok {
		t.Fatalf("expected cookie cleared after remove")
	}
}

func TestNetnsMgr_CookieChange_OnPathChange(t *testing.T) {
	// Pod recreated: WEP arrives again with a new netns path; the
	// cookie must be re-resolved against the new path.
	const uid = "uid-6"
	const oldPath = "/var/run/netns/cni-A"
	const newPath = "/var/run/netns/cni-B"
	m := newNetnsManagerForTest(
		map[string]uint64{oldPath: 0xaaa, newPath: 0xbbb},
		map[string]string{},
	)
	upd1 := netnsWepUpdate("k8s", "ns/p", "eth0", uid, oldPath)
	m.OnUpdate(upd1)
	if c, _ := m.CookieForWEP(upd1.Id); c != 0xaaa {
		t.Fatalf("first cookie should be 0xaaa, got %#x", c)
	}

	upd2 := netnsWepUpdate("k8s", "ns/p", "eth0", uid, newPath)
	m.OnUpdate(upd2)
	if c, _ := m.CookieForWEP(upd2.Id); c != 0xbbb {
		t.Fatalf("updated cookie should be 0xbbb, got %#x", c)
	}
}

// fakeNetNS is a no-op ns.NetNS used only to check that
// OpenNetnsForWEP delegates to the configured opener.
type fakeNetNS struct{ path string }

func (f *fakeNetNS) Do(func(ns.NetNS) error) error { return nil }
func (f *fakeNetNS) Set() error                    { return nil }
func (f *fakeNetNS) Path() string                  { return f.path }
func (f *fakeNetNS) Fd() uintptr                   { return 0 }
func (f *fakeNetNS) Close() error                  { return nil }

func TestNetnsMgr_OpenNetnsForWEP(t *testing.T) {
	const uid = "uid-7"
	const path = "/var/run/netns/cni-Z"
	m := newNetnsManagerForTest(
		map[string]uint64{path: 0xdead},
		map[string]string{},
	)
	openedWith := ""
	m.openNetns = func(p string) (ns.NetNS, error) {
		openedWith = p
		return &fakeNetNS{path: p}, nil
	}

	upd := netnsWepUpdate("k8s", "ns/p", "eth0", uid, path)
	m.OnUpdate(upd)

	h, err := m.OpenNetnsForWEP(upd.Id)
	if err != nil {
		t.Fatalf("OpenNetnsForWEP returned error: %v", err)
	}
	defer h.Close()
	if openedWith != path {
		t.Fatalf("opener called with %q, want %q", openedWith, path)
	}
}

func TestNetnsMgr_OpenNetnsForWEP_Unresolved(t *testing.T) {
	// No path resolved for the WEP → ErrNetnsUnresolved (distinct from a
	// real open failure).
	m := newNetnsManagerForTest(map[string]uint64{}, map[string]string{})
	upd := netnsWepUpdate("k8s", "ns/p", "eth0", "uid-x", "")

	_, err := m.OpenNetnsForWEP(upd.Id)
	if !errors.Is(err, ErrNetnsUnresolved) {
		t.Fatalf("expected ErrNetnsUnresolved, got %v", err)
	}
}

func TestNetnsMgr_OpenNetnsForWEP_PathStaleDropsEntry(t *testing.T) {
	// If the cached path no longer opens (pod gone), the manager returns
	// the underlying open error (NOT ErrNetnsUnresolved) and drops the
	// cached cookie/path so the next WEP update re-resolves.
	const uid = "uid-8"
	const path = "/var/run/netns/cni-stale"
	m := newNetnsManagerForTest(
		map[string]uint64{path: 0xbabe},
		map[string]string{},
	)
	openErr := fmt.Errorf("ENOENT")
	m.openNetns = func(string) (ns.NetNS, error) { return nil, openErr }

	upd := netnsWepUpdate("k8s", "ns/p", "eth0", uid, path)
	m.OnUpdate(upd)

	_, err := m.OpenNetnsForWEP(upd.Id)
	if err == nil || errors.Is(err, ErrNetnsUnresolved) {
		t.Fatalf("expected the underlying open error, got %v", err)
	}
	if _, ok := m.CookieForWEP(upd.Id); ok {
		t.Fatalf("cookie should be cleared after a failed open")
	}
}
