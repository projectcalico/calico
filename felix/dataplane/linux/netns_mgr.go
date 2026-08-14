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
	"sync"
	"time"

	"github.com/containernetworking/plugins/pkg/ns"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/netns"
	"github.com/projectcalico/calico/felix/proto"
)

// ErrNetnsUnresolved is returned by OpenNetnsForWEP when the manager
// has not (yet) resolved a netns path for the WEP. It lets callers
// distinguish "not ready, retry later" from a real open failure.
var ErrNetnsUnresolved = errors.New("netns not resolved for WEP")

// criLookupTimeout bounds a single CRI ListPodSandbox/PodSandboxStatus
// round-trip in the background resolver.
const criLookupTimeout = 3 * time.Second

// deepRetryInterval is how often the background resolver re-attempts
// WEPs still pending Tier-2/Tier-3 resolution (e.g. the pause container
// isn't up yet, or the CRI socket is briefly unreachable).
const deepRetryInterval = 10 * time.Second

// netnsCRIResolver returns the host netns path of a pod sandbox
// identified by its UID, via the local container runtime's CRI API.
// May be nil; nil means "CRI tier disabled."
type netnsCRIResolver func(ctx context.Context, podUID string) (netnsPath string, err error)

// netnsBatchResolver resolves netns paths for many pod UIDs in a single
// /proc-cgroup scan, returning uid -> path only for the UIDs that
// matched a live process.
type netnsBatchResolver func(podUIDs []string) map[string]string

// netnsCookieReader opens the given netns path and returns its
// kernel-stable cookie (SO_NETNS_COOKIE).
type netnsCookieReader func(netnsPath string) (uint64, error)

// netnsOpener opens the given (already-host-rooted-as-needed) netns
// path and returns a handle the caller must Close.
type netnsOpener func(netnsPath string) (ns.NetNS, error)

// pendingWEP is a WEP awaiting background (Tier-2/Tier-3) resolution.
type pendingWEP struct {
	id  *proto.WorkloadEndpointID
	uid string
}

// resolvedNetns is a netns path resolved for a specific pod UID. The UID
// is carried so the store step can detect a pod recreate (same wepKey,
// new UID) that landed while this resolve was in flight, and drop the
// now-stale result rather than caching it against the new pod.
type resolvedNetns struct {
	path string
	uid  string
}

// netnsManager is a Felix dataplane Manager that resolves each local
// pod's netns path + cookie and caches them for any consumer. Resolution
// walks a three-tier fallback chain, first hit wins:
//
//  1. CNI-set netns path on the WEP (cni.projectcalico.org/podNetns).
//  2. CRI runtime lookup by pod UID (felix/cri); only if a resolver was
//     provided at construction.
//  3. /proc-cgroup UID scan (felix/netns).
//
// Tier 1 is cheap and runs inline in OnUpdate; Tiers 2/3 are expensive
// and run on a background resolver goroutine that drains all pending
// WEPs per cycle with a single batched /proc walk, then wakes the apply
// loop so consumers pick up the result on a later CompleteDeferredWork.
//
// Consumers read the result by WorkloadEndpointID via CookieForWEP
// (cached SO_NETNS_COOKIE) or OpenNetnsForWEP (opens the cached path).
// See felix/design/netns-resolution.md for the full model.
type netnsManager struct {
	// resolveCookieByPath reads the cookie for the host-absolute annotation
	// path (Tier 1), re-rooting it via /host/proc/1/root.
	resolveCookieByPath netnsCookieReader
	// resolveCookieDirect reads the cookie for a path Felix can already
	// reach: the CRI (Tier 2) and /proc-scan (Tier 3) results, both built
	// under procRoot.
	resolveCookieDirect netnsCookieReader
	resolveProcPaths    netnsBatchResolver
	resolveNetnsViaCRI  netnsCRIResolver
	openNetns           netnsOpener

	// wakeupC wakes the main apply loop after the background resolver
	// caches a new result, so consumer managers' CompleteDeferredWork
	// re-runs. Owned by int_dataplane; may be nil in tests.
	wakeupC chan<- struct{}

	// kickC pokes the background resolver to run a cycle now. Buffered
	// size 1 so a send never blocks and repeated kicks coalesce.
	kickC chan struct{}
	// stopC stops the background resolver goroutine (test/lifecycle).
	stopC chan struct{}

	// mu guards paths, cookies, and pendingDeep, which are read/written
	// from both the main dataplane goroutine and the resolver goroutine.
	mu sync.Mutex
	// paths maps WEP key -> resolved host netns path.
	paths map[string]string
	// cookies maps WEP key -> netns cookie (SO_NETNS_COOKIE), read once
	// at resolve time.
	cookies map[string]uint64
	// pendingDeep holds WEPs whose Tier 1 missed, awaiting Tier-2/Tier-3
	// resolution on the background goroutine.
	pendingDeep map[string]pendingWEP
}

// newNetnsManager builds a netnsManager. procRoot is where the Tier-3
// /proc-cgroup scan reads (FelixConfiguration.ProcRootPath, default
// /proc). criResolver may be nil (Tier 2 disabled). wakeupC (owned by
// int_dataplane, buffered size 1) is used to wake the apply loop when the
// background resolver produces a result; it may be nil in tests. Call
// Start once before use to launch the background resolver goroutine.
func newNetnsManager(procRoot string, criResolver netnsCRIResolver, wakeupC chan<- struct{}) *netnsManager {
	return &netnsManager{
		resolveCookieByPath: func(p string) (uint64, error) {
			return netns.ResolveCookieByPath(procRoot, p)
		},
		resolveCookieDirect: netns.CookieByPath,
		resolveProcPaths: func(uids []string) map[string]string {
			return netns.ResolvePodNetnsPaths(procRoot, uids)
		},
		resolveNetnsViaCRI: criResolver,
		openNetns:          ns.GetNS,
		wakeupC:            wakeupC,
		kickC:              make(chan struct{}, 1),
		stopC:              make(chan struct{}),
		paths:              map[string]string{},
		cookies:            map[string]uint64{},
		pendingDeep:        map[string]pendingWEP{},
	}
}

// Start launches the background resolver goroutine. Safe to call once.
func (m *netnsManager) Start() {
	go m.runResolver()
}

// Stop terminates the background resolver goroutine.
func (m *netnsManager) Stop() {
	close(m.stopC)
}

func (m *netnsManager) OnUpdate(msg any) {
	switch upd := msg.(type) {
	case *proto.WorkloadEndpointUpdate:
		m.onWepUpdate(upd.GetId(), upd.GetEndpoint())
	case *proto.WorkloadEndpointRemove:
		key := wepKey(upd.GetId())
		m.mu.Lock()
		delete(m.paths, key)
		delete(m.cookies, key)
		delete(m.pendingDeep, key)
		m.mu.Unlock()
	}
}

func (m *netnsManager) CompleteDeferredWork() error {
	// netnsManager programs nothing itself; consumers read its cache in
	// their own CompleteDeferredWork. Nothing to do here.
	return nil
}

// onWepUpdate runs Tier 1 inline. On a Tier-1 hit it caches the path and
// cookie immediately. On a Tier-1 miss with a usable pod UID it records
// the WEP for background Tier-2/Tier-3 resolution and kicks the resolver.
func (m *netnsManager) onWepUpdate(id *proto.WorkloadEndpointID, ep *proto.WorkloadEndpoint) {
	if id == nil || ep == nil {
		return
	}
	key := wepKey(id)

	// Tier 1: CNI-set netns path on the WEP. Cheap enough to run inline.
	if path := ep.GetNetnsPath(); path != "" {
		cookie, err := m.resolveCookieByPath(path)
		if err != nil {
			// The annotation named a path we can't read a cookie from
			// (pod already gone, race). Drop any stale entry and wait
			// for the next WEP update to re-resolve cleanly.
			log.WithError(err).WithFields(log.Fields{"workloadID": id.GetWorkloadId(), "path": path}).
				Debug("Tier 1 netns path failed to yield a cookie; dropping entry")
			m.mu.Lock()
			delete(m.paths, key)
			delete(m.cookies, key)
			delete(m.pendingDeep, key)
			m.mu.Unlock()
			return
		}
		m.mu.Lock()
		m.paths[key] = path
		m.cookies[key] = cookie
		delete(m.pendingDeep, key)
		m.mu.Unlock()
		return
	}

	// Tier 1 missed. We need the pod UID to run the deeper tiers.
	uid := ep.GetUid()
	if uid == "" {
		m.mu.Lock()
		delete(m.paths, key)
		delete(m.cookies, key)
		delete(m.pendingDeep, key)
		m.mu.Unlock()
		return
	}

	// Defer Tiers 2/3 to the background resolver — never on the main loop.
	m.mu.Lock()
	m.pendingDeep[key] = pendingWEP{id: id, uid: uid}
	m.mu.Unlock()
	m.kick()
}

// runResolver is the background goroutine that drains pendingDeep. It
// runs a cycle on each kick and periodically retries WEPs still pending
// (transient CRI/pause-container unavailability).
func (m *netnsManager) runResolver() {
	ticker := time.NewTicker(deepRetryInterval)
	defer ticker.Stop()
	for {
		select {
		case <-m.stopC:
			return
		case <-m.kickC:
			m.resolveDeepBatch()
		case <-ticker.C:
			m.resolveDeepBatch()
		}
	}
}

// kick pokes the resolver without blocking; a pending kick coalesces.
func (m *netnsManager) kick() {
	select {
	case m.kickC <- struct{}{}:
	default:
	}
}

// resolveDeepBatch resolves every currently-pending WEP through Tier 2
// (CRI, per WEP) and Tier 3 (a single batched /proc walk for all Tier-2
// misses), caches the results, and wakes the apply loop if anything
// newly resolved. It runs only on the background goroutine (or directly
// from tests).
func (m *netnsManager) resolveDeepBatch() {
	// Snapshot the pending set so we don't hold the lock across CRI
	// round-trips or the /proc walk.
	m.mu.Lock()
	pending := make([]pendingWEP, 0, len(m.pendingDeep))
	for _, p := range m.pendingDeep {
		pending = append(pending, p)
	}
	m.mu.Unlock()
	if len(pending) == 0 {
		return
	}

	// resolved maps WEP key -> {path, uid} from whichever tier succeeded.
	resolved := map[string]resolvedNetns{}

	// Tier 2: CRI runtime query, per pending WEP. Collect the UIDs that
	// CRI couldn't resolve for a single batched Tier-3 scan.
	var tier3 []pendingWEP
	for _, p := range pending {
		if m.resolveNetnsViaCRI == nil {
			tier3 = append(tier3, p)
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), criLookupTimeout)
		path, err := m.resolveNetnsViaCRI(ctx, p.uid)
		cancel()
		if err == nil && path != "" {
			resolved[wepKey(p.id)] = resolvedNetns{path: path, uid: p.uid}
			continue
		}
		log.WithError(err).WithFields(log.Fields{"workloadID": p.id.GetWorkloadId(), "uid": p.uid}).
			Debug("Tier 2 (CRI lookup) failed; falling through to /proc scan")
		tier3 = append(tier3, p)
	}

	// Tier 3: one batched /proc-cgroup scan for all Tier-2 misses.
	if len(tier3) > 0 {
		uids := make([]string, 0, len(tier3))
		for _, p := range tier3 {
			uids = append(uids, p.uid)
		}
		byUID := m.resolveProcPaths(uids)
		for _, p := range tier3 {
			if path, ok := byUID[p.uid]; ok {
				resolved[wepKey(p.id)] = resolvedNetns{path: path, uid: p.uid}
			}
		}
	}

	if len(resolved) == 0 {
		return
	}

	// Read the cookie for each resolved path and cache both, unless the
	// WEP was removed, resolved elsewhere (Tier 1), or recreated with a
	// new UID while we were resolving.
	wokeAny := false
	for key, r := range resolved {
		// Both Tier-2 (CRI) and Tier-3 (/proc scan) paths are built under
		// procRoot and are directly openable.
		cookie, err := m.resolveCookieDirect(r.path)
		if err != nil {
			// Leave it in pendingDeep for the next cycle to retry.
			log.WithError(err).WithField("path", r.path).
				Debug("Resolved netns path failed to yield a cookie; will retry")
			continue
		}
		m.mu.Lock()
		// Only store if the WEP is still pending for the SAME UID. A pod
		// recreate (same wepKey, new UID) or a Tier-1 hit that landed
		// while we were resolving supersedes this result: drop it and
		// leave the newer pending entry for the next cycle to resolve.
		if cur, ok := m.pendingDeep[key]; ok && cur.uid == r.uid {
			m.paths[key] = r.path
			m.cookies[key] = cookie
			delete(m.pendingDeep, key)
			wokeAny = true
		}
		m.mu.Unlock()
	}

	if wokeAny {
		m.wake()
	}
}

// wake nudges the main apply loop (non-blocking) so consumer managers'
// CompleteDeferredWork re-runs and re-reads the freshly-cached results.
func (m *netnsManager) wake() {
	if m.wakeupC == nil {
		return
	}
	select {
	case m.wakeupC <- struct{}{}:
	default:
	}
}

// CookieForWEP returns the netns cookie for the given WEP, or
// (0, false) if the manager hasn't resolved it (yet) or the WEP isn't
// tracked. Suitable for consumers that only need the kernel-stable
// identifier — e.g. installing BPF-map entries keyed by netns cookie —
// without re-opening the netns on every call.
func (m *netnsManager) CookieForWEP(id *proto.WorkloadEndpointID) (uint64, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.cookies[wepKey(id)]
	return c, ok
}

// OpenNetnsForWEP opens the netns of the given WEP and returns a handle
// the caller must Close. Callers that need a raw FD use the returned
// handle's Fd() method.
//
// Returns ErrNetnsUnresolved if no path has been resolved for the WEP
// yet; otherwise returns whatever error the open failed with (the path
// went away, FDs exhausted, permission, etc.) so the caller can
// distinguish "not ready, retry later" from a real failure. On an open
// failure the cached entry is dropped so the next WEP update re-resolves.
//
// Primary entry point for managers that need to act inside a pod's netns
// (sockets, per-netns kernel state, attaching a probe, etc.).
func (m *netnsManager) OpenNetnsForWEP(id *proto.WorkloadEndpointID) (ns.NetNS, error) {
	key := wepKey(id)
	m.mu.Lock()
	path, ok := m.paths[key]
	m.mu.Unlock()
	if !ok {
		return nil, ErrNetnsUnresolved
	}
	handle, err := m.openNetns(path)
	if err != nil {
		log.WithError(err).WithFields(log.Fields{"workloadID": id.GetWorkloadId(), "path": path}).
			Debug("Cached netns path no longer opens; dropping entry")
		m.mu.Lock()
		delete(m.paths, key)
		delete(m.cookies, key)
		m.mu.Unlock()
		return nil, err
	}
	return handle, nil
}

// wepKey is the cache key used by netnsManager (and any consumer that
// mirrors the same WEP-keyed state) for a WorkloadEndpointID.
func wepKey(id *proto.WorkloadEndpointID) string {
	if id == nil {
		return ""
	}
	return id.GetOrchestratorId() + "/" + id.GetWorkloadId() + "/" + id.GetEndpointId()
}
