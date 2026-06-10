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
	"testing"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/syncersv1/dedupebuffer"
	"github.com/projectcalico/calico/typha/pkg/calc"
	"github.com/projectcalico/calico/typha/pkg/discovery"
	"github.com/projectcalico/calico/typha/pkg/snapcache"
	"github.com/projectcalico/calico/typha/pkg/syncproto"
	"github.com/projectcalico/calico/typha/pkg/syncserver"
	"github.com/projectcalico/calico/typha/pkg/syncsource"
)

// upstreamHarness is a minimal Typha "leader": one snapcache per syncer type,
// each fed by a test decoupler, served by a real syncserver.  It is the upstream
// for a followerHarness.  Unlike ServerHarness it supports an arbitrary set of
// syncer types so the chain test can cover all four.
type upstreamHarness struct {
	syncerTypes []syncproto.SyncerType
	decouplers  map[syncproto.SyncerType]*calc.SyncerCallbacksDecoupler
	caches      map[syncproto.SyncerType]*snapcache.Cache
	server      *syncserver.Server

	cacheCtx     context.Context
	cacheCancel  context.CancelFunc
	serverCtx    context.Context
	serverCancel context.CancelFunc

	// port is captured on first Start so that RestartServer can rebind to the
	// same port (the follower's discovery uses a static address override, so
	// the upstream must come back on the same port for reconnection to work).
	port int

	updIdx int
}

func newUpstreamHarness(syncerTypes ...syncproto.SyncerType) *upstreamHarness {
	u := &upstreamHarness{
		syncerTypes: syncerTypes,
		decouplers:  map[syncproto.SyncerType]*calc.SyncerCallbacksDecoupler{},
		caches:      map[syncproto.SyncerType]*snapcache.Cache{},
	}
	cacheProviders := map[syncproto.SyncerType]syncserver.BreadcrumbProvider{}
	for _, st := range syncerTypes {
		dec := calc.NewSyncerCallbacksDecoupler()
		cache := snapcache.New(snapcache.Config{
			MaxBatchSize:   10,
			WakeUpInterval: 50 * time.Millisecond,
			Name:           string(st),
		})
		u.decouplers[st] = dec
		u.caches[st] = cache
		cacheProviders[st] = cache
	}
	u.server = syncserver.New(cacheProviders, syncserver.Config{
		PingInterval: 10 * time.Second,
		Port:         syncserver.PortRandom,
		DropInterval: 50 * time.Millisecond,
	})
	return u
}

func (u *upstreamHarness) Start() {
	u.cacheCtx, u.cacheCancel = context.WithCancel(context.Background())
	for st, dec := range u.decouplers {
		cache := u.caches[st]
		go dec.SendToContext(u.cacheCtx, cache)
		cache.Start(u.cacheCtx)
	}
	u.serverCtx, u.serverCancel = context.WithCancel(context.Background())
	u.server.Start(u.serverCtx)
	u.port = u.server.Port()
}

// StopServerOnly tears down just the server (simulating an upstream outage)
// without losing the cached data, so it can be restarted.
func (u *upstreamHarness) StopServerOnly() {
	u.serverCancel()
	u.server.Finished.Wait()
}

// RestartServer rebuilds and restarts the server in front of the existing
// caches (the caches keep running across the outage).
func (u *upstreamHarness) RestartServer() {
	cacheProviders := map[syncproto.SyncerType]syncserver.BreadcrumbProvider{}
	for st, c := range u.caches {
		cacheProviders[st] = c
	}
	u.server = syncserver.New(cacheProviders, syncserver.Config{
		PingInterval: 10 * time.Second,
		Port:         u.port,
		DropInterval: 50 * time.Millisecond,
	})
	u.serverCtx, u.serverCancel = context.WithCancel(context.Background())
	u.server.Start(u.serverCtx)
}

func (u *upstreamHarness) Stop() {
	u.serverCancel()
	u.server.Finished.Wait()
	u.cacheCancel()
	// Wait for each cache goroutine to exit so its shutdown logging happens
	// before the test returns (avoids "Log after test completed" under -race).
	for _, c := range u.caches {
		if c.Done != nil {
			<-c.Done
		}
	}
}

func (u *upstreamHarness) Addr() string {
	return fmt.Sprintf("127.0.0.1:%d", u.server.Port())
}

func (u *upstreamHarness) SendStatus(st syncproto.SyncerType, s api.SyncStatus) {
	u.decouplers[st].OnStatusUpdated(s)
}

// SendConfigUpdate sends a single GlobalConfig KV to the given syncer type and
// returns the path/update it created so the test can build expectations.
func (u *upstreamHarness) SendConfigUpdate(st syncproto.SyncerType, name, value string) (string, api.Update) {
	update := api.Update{
		KVPair: model.KVPair{
			Key:      model.GlobalConfigKey{Name: name},
			Value:    value,
			Revision: fmt.Sprintf("%d", u.updIdx),
		},
		UpdateType: api.UpdateTypeKVNew,
	}
	u.updIdx++
	path, err := model.KeyToDefaultPath(update.Key)
	if err != nil {
		panic(err)
	}
	u.decouplers[st].OnUpdates([]api.Update{update})
	return path, update
}

// SendDelete sends a deletion for the given config name.
func (u *upstreamHarness) SendDelete(st syncproto.SyncerType, name string) {
	u.decouplers[st].OnUpdates([]api.Update{{
		KVPair:     model.KVPair{Key: model.GlobalConfigKey{Name: name}},
		UpdateType: api.UpdateTypeKVDeleted,
	}})
}

// followerHarness is a chained Typha: for each syncer type it runs a real
// upstreamTyphaSource (connected to the upstream) -> dedupe buffer ->
// validation filter -> snapcache -> its own syncserver.  This is exactly the
// follower pipeline that daemon.go builds in hierarchical mode.
type followerHarness struct {
	syncerTypes []syncproto.SyncerType
	sources     map[syncproto.SyncerType]syncsource.SyncerSource
	buffers     map[syncproto.SyncerType]*dedupebuffer.DedupeBuffer
	caches      map[syncproto.SyncerType]*snapcache.Cache
	server      *syncserver.Server

	cacheCtx     context.Context
	cacheCancel  context.CancelFunc
	srcCtx       context.Context
	srcCancel    context.CancelFunc
	serverCtx    context.Context
	serverCancel context.CancelFunc
}

func newFollowerHarness(upstreamAddr string, syncerTypes ...syncproto.SyncerType) *followerHarness {
	f := &followerHarness{
		syncerTypes: syncerTypes,
		sources:     map[syncproto.SyncerType]syncsource.SyncerSource{},
		buffers:     map[syncproto.SyncerType]*dedupebuffer.DedupeBuffer{},
		caches:      map[syncproto.SyncerType]*snapcache.Cache{},
	}
	f.cacheCtx, f.cacheCancel = context.WithCancel(context.Background())
	cacheProviders := map[syncproto.SyncerType]syncserver.BreadcrumbProvider{}
	for _, st := range syncerTypes {
		buf := dedupebuffer.New()
		cache := snapcache.New(snapcache.Config{
			MaxBatchSize:   10,
			WakeUpInterval: 50 * time.Millisecond,
			Name:           "follower-" + string(st),
		})
		validator := calc.NewValidationFilter(cache)
		go buf.SendToSinkForever(validator)

		source := syncsource.NewUpstreamTyphaSource(
			discovery.New(discovery.WithAddrOverride(upstreamAddr)),
			syncsource.UpstreamConfig{
				MyVersion:  "follower-version",
				MyHostname: "follower-host",
				MyInfo:     "follower",
				SyncerType: st,
			},
			buf,
		)
		f.buffers[st] = buf
		f.caches[st] = cache
		f.sources[st] = source
		cacheProviders[st] = cache
	}
	f.server = syncserver.New(cacheProviders, syncserver.Config{
		PingInterval: 10 * time.Second,
		Port:         syncserver.PortRandom,
		DropInterval: 50 * time.Millisecond,
	})
	return f
}

func (f *followerHarness) Start() {
	for _, c := range f.caches {
		c.Start(f.cacheCtx)
	}
	f.serverCtx, f.serverCancel = context.WithCancel(context.Background())
	f.server.Start(f.serverCtx)
	f.srcCtx, f.srcCancel = context.WithCancel(context.Background())
	for _, s := range f.sources {
		if err := s.Start(f.srcCtx); err != nil {
			panic(err)
		}
	}
}

func (f *followerHarness) Stop() {
	for _, s := range f.sources {
		s.Stop()
	}
	for _, b := range f.buffers {
		b.Stop()
	}
	f.serverCancel()
	f.server.Finished.Wait()
	f.cacheCancel()
	for _, c := range f.caches {
		if c.Done != nil {
			<-c.Done
		}
	}
}

func (f *followerHarness) Addr() string {
	return fmt.Sprintf("127.0.0.1:%d", f.server.Port())
}

// cacheContents reads the follower's snapcache for the given syncer type by
// taking a breadcrumb and walking it.
func breadcrumbContents(t *testing.T, cache *snapcache.Cache) (map[string]string, api.SyncStatus) {
	t.Helper()
	crumb := cache.CurrentBreadcrumb()
	values := map[string]string{}
	crumb.KVs.Ascend(func(item syncproto.SerializedUpdate) bool {
		upd, err := item.ToUpdate()
		if err != nil {
			t.Fatalf("failed to deserialize cache item: %v", err)
		}
		path, err := model.KeyToDefaultPath(upd.Key)
		if err != nil {
			t.Fatalf("failed to compute path: %v", err)
		}
		if s, ok := upd.Value.(string); ok {
			values[path] = s
		}
		return true
	})
	return values, crumb.SyncStatus
}

func init() {
	log.SetLevel(log.InfoLevel)
}
