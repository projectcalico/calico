// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fvtests_test

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/syncersv1/dedupebuffer"
	"github.com/projectcalico/calico/typha/pkg/calc"
	"github.com/projectcalico/calico/typha/pkg/discovery"
	"github.com/projectcalico/calico/typha/pkg/rolemanager"
	"github.com/projectcalico/calico/typha/pkg/slotacquirer"
	"github.com/projectcalico/calico/typha/pkg/snapcache"
	"github.com/projectcalico/calico/typha/pkg/synccheck"
	"github.com/projectcalico/calico/typha/pkg/syncclient"
	"github.com/projectcalico/calico/typha/pkg/syncproto"
	"github.com/projectcalico/calico/typha/pkg/syncserver"
	"github.com/projectcalico/calico/typha/pkg/syncsource"
)

// fakeDatastore models the real datastore for one syncer type as seen by a
// "leader" Typha.  It holds a canonical set of GlobalConfig KVs and, each time a
// datastore source is started against it, replays the current snapshot
// (ResyncInProgress → updates → InSync) into the sink and then forwards
// subsequent mutations.  This mirrors a real datastore syncer delivering a fresh
// snapshot on each (re)connection, which is exactly what the dedupe buffer needs
// to reconcile across a promotion.
type fakeDatastore struct {
	mu    sync.Mutex
	state map[string]string // config name -> value
	sinks map[*datastoreSourceSink]struct{}
}

func newFakeDatastore() *fakeDatastore {
	return &fakeDatastore{
		state: map[string]string{},
		sinks: map[*datastoreSourceSink]struct{}{},
	}
}

// Set adds or updates a config key in the canonical state and pushes the update
// to any currently-attached sink.
func (d *fakeDatastore) Set(name, value string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.state[name] = value
	upd := configUpdate(name, value)
	for s := range d.sinks {
		s.sink.OnUpdates([]api.Update{upd})
	}
}

// Delete removes a config key and pushes the deletion to any attached sink.
func (d *fakeDatastore) Delete(name string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.state, name)
	upd := configDelete(name)
	for s := range d.sinks {
		s.sink.OnUpdates([]api.Update{upd})
	}
}

func (d *fakeDatastore) attach(s *datastoreSourceSink) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.sinks[s] = struct{}{}
	// Replay the current snapshot to this new sink.
	s.sink.OnStatusUpdated(api.ResyncInProgress)
	var ups []api.Update
	for name, value := range d.state {
		ups = append(ups, configUpdate(name, value))
	}
	if len(ups) > 0 {
		s.sink.OnUpdates(ups)
	}
	s.sink.OnStatusUpdated(api.InSync)
}

func (d *fakeDatastore) detach(s *datastoreSourceSink) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.sinks, s)
}

func configUpdate(name, value string) api.Update {
	return api.Update{
		KVPair: model.KVPair{
			Key:      model.GlobalConfigKey{Name: name},
			Value:    value,
			Revision: fmt.Sprintf("ds-%s-%s", name, value),
		},
		UpdateType: api.UpdateTypeKVNew,
	}
}

func configDelete(name string) api.Update {
	return api.Update{
		KVPair:     model.KVPair{Key: model.GlobalConfigKey{Name: name}},
		UpdateType: api.UpdateTypeKVDeleted,
	}
}

// datastoreSourceSink is a SyncerSource that, on Start, attaches to a
// fakeDatastore (snapshot replay) and detaches on Stop.  It satisfies the
// SyncerSource contract: Stop blocks until no more callbacks can fire (we detach
// under the datastore lock so no concurrent push can be in flight afterwards).
type datastoreSourceSink struct {
	ds   *fakeDatastore
	sink api.SyncerCallbacks

	mu      sync.Mutex
	started bool
	stopped bool
	done    chan struct{}
}

func newDatastoreSourceSink(ds *fakeDatastore, sink api.SyncerCallbacks) *datastoreSourceSink {
	return &datastoreSourceSink{ds: ds, sink: sink, done: make(chan struct{})}
}

func (s *datastoreSourceSink) Start(_ context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started || s.stopped {
		return nil
	}
	s.started = true
	s.ds.attach(s)
	return nil
}

func (s *datastoreSourceSink) Stop() {
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return
	}
	s.stopped = true
	started := s.started
	s.mu.Unlock()
	if started {
		// detach takes the datastore lock; Set/Delete also take it, so after
		// detach returns no further callback can be delivered to our sink.
		s.ds.detach(s)
	}
	close(s.done)
}

func (s *datastoreSourceSink) Done() <-chan struct{} { return s.done }

var _ syncsource.SyncerSource = (*datastoreSourceSink)(nil)

// promotableHarness is a follower Typha whose pipeline sources are owned by a
// real rolemanager.Manager driven by a fake elector.  As a FOLLOWER it sources
// from an upstream harness; promoted to LEADER it sources from a fakeDatastore.
// It serves its own snapcache to downstream clients.
type promotableHarness struct {
	st syncproto.SyncerType

	buffer *dedupebuffer.DedupeBuffer
	cache  *snapcache.Cache
	ds     *fakeDatastore
	server *syncserver.Server

	elector *promotionElector
	manager *rolemanager.Manager

	cacheCtx     context.Context
	cacheCancel  context.CancelFunc
	serverCtx    context.Context
	serverCancel context.CancelFunc
	mgrCtx       context.Context
	mgrCancel    context.CancelFunc
}

// promotionElector is a fake role source whose Roles channel the test drives.
// It implements rolemanager.RoleSource (emitting slotacquirer.Role values).
type promotionElector struct {
	ch chan slotacquirer.Role
}

func newPromotionElector() *promotionElector {
	return &promotionElector{ch: make(chan slotacquirer.Role, 16)}
}

func (e *promotionElector) Roles() <-chan slotacquirer.Role { return e.ch }

func (e *promotionElector) promote() { e.ch <- slotacquirer.Leader }
func (e *promotionElector) demote()  { e.ch <- slotacquirer.Tier2 }

// promoteTier1 / demoteToTier2 drive the tier-1 role for two-tier chain tests.
func (e *promotionElector) promoteTier1() { e.ch <- slotacquirer.Tier1 }

func newPromotableHarness(upstreamAddr string, st syncproto.SyncerType) *promotableHarness {
	return newPromotableHarnessOpts(upstreamAddr, st, false)
}

// newPromotableHarnessOpts builds a promotable follower; checksum enables
// snapshot-integrity checking on the upstream (follower) source, exactly as the
// daemon wires it, so a promotion fv-test doubles as the checksum-over-promotion
// proof.
func newPromotableHarnessOpts(upstreamAddr string, st syncproto.SyncerType, checksum bool) *promotableHarness {
	h := &promotableHarness{st: st, ds: newFakeDatastore()}
	h.buffer = dedupebuffer.New()
	h.cache = snapcache.New(snapcache.Config{
		MaxBatchSize:   10,
		WakeUpInterval: 50 * time.Millisecond,
		Name:           "promotable-" + string(st),
	})
	validator := calc.NewValidationFilter(h.cache)
	go h.buffer.SendToSinkForever(validator)

	newUpstream := func() syncsource.SyncerSource {
		src := syncsource.NewUpstreamTyphaSource(
			discovery.New(discovery.WithAddrOverride(upstreamAddr)),
			syncsource.UpstreamConfig{
				MyVersion:  "follower-version",
				MyHostname: "follower-host",
				MyInfo:     "follower",
				SyncerType: st,
				ClientOptions: syncclient.Options{
					ChecksumCheckInterval: 50 * time.Millisecond,
				},
			},
			h.buffer,
		)
		if checksum {
			ups := src.(syncsource.UpstreamTyphaSource)
			verifier := synccheck.NewVerifier(synccheck.VerifierConfig{
				SyncerType:     string(st),
				MismatchAction: synccheck.MismatchActionReconnect,
				Local: synccheck.LocalChecksumFunc(func() synccheck.Checksum {
					return h.cache.CurrentBreadcrumb().Checksum
				}),
				RequestReconnect:     ups.Reconnect,
				PersistChecks:        2,
				ReconnectMinInterval: time.Millisecond,
			})
			ups.SetChecksumVerifier(verifier)
		}
		return src
	}
	newDatastore := func() syncsource.SyncerSource {
		return newDatastoreSourceSink(h.ds, h.buffer)
	}

	newSourceForRole := func(role rolemanager.Role) syncsource.SyncerSource {
		if role == rolemanager.Leader {
			return newDatastore()
		}
		// Tier1 and Tier2 both source from the single configured upstream in this
		// harness (callers that need distinct tier upstreams use the chain harness).
		return newUpstream()
	}

	h.elector = newPromotionElector()
	h.manager = rolemanager.New(
		rolemanager.Config{Debounce: 20 * time.Millisecond},
		h.elector,
		nil, // no labeller in-process
		nil, // no client drainer in-process
		[]*rolemanager.Pipeline{{
			Name:             string(st),
			Buffer:           h.buffer,
			NewSourceForRole: newSourceForRole,
		}},
	)

	cacheProviders := map[syncproto.SyncerType]syncserver.BreadcrumbProvider{st: h.cache}
	h.server = syncserver.New(cacheProviders, syncserver.Config{
		PingInterval: 10 * time.Second,
		Port:         syncserver.PortRandom,
		DropInterval: 50 * time.Millisecond,
	})
	return h
}

func (h *promotableHarness) Start() {
	h.cacheCtx, h.cacheCancel = context.WithCancel(context.Background())
	h.cache.Start(h.cacheCtx)
	h.serverCtx, h.serverCancel = context.WithCancel(context.Background())
	h.server.Start(h.serverCtx)
	h.mgrCtx, h.mgrCancel = context.WithCancel(context.Background())
	go h.manager.Run(h.mgrCtx)
}

func (h *promotableHarness) Stop() {
	h.mgrCancel()
	// Give the manager a moment to tear down sources.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && h.manager.Role() != rolemanager.Sourceless {
		time.Sleep(5 * time.Millisecond)
	}
	h.buffer.Stop()
	h.serverCancel()
	h.server.Finished.Wait()
	h.cacheCancel()
	// Wait for the cache goroutine to exit so it does its shutdown logging
	// before the test returns (avoids "Log after test completed" under -race).
	if h.cache.Done != nil {
		<-h.cache.Done
	}
}

func (h *promotableHarness) Addr() string {
	return fmt.Sprintf("127.0.0.1:%d", h.server.Port())
}
