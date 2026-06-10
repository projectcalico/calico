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
	"sync/atomic"
	"time"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/syncersv1/dedupebuffer"
	"github.com/projectcalico/calico/typha/pkg/calc"
	"github.com/projectcalico/calico/typha/pkg/discovery"
	"github.com/projectcalico/calico/typha/pkg/snapcache"
	"github.com/projectcalico/calico/typha/pkg/synccheck"
	"github.com/projectcalico/calico/typha/pkg/syncclient"
	"github.com/projectcalico/calico/typha/pkg/syncproto"
	"github.com/projectcalico/calico/typha/pkg/syncserver"
	"github.com/projectcalico/calico/typha/pkg/syncsource"
)

// checksumFollowerHarness is a follower Typha with snapshot-integrity checking
// enabled.  It mirrors followerHarness (ws-a) but, for each syncer type, wires a
// synccheck.Verifier into the upstream syncclient and points the verifier at the
// follower's own snapcache.  It also exposes the dedupe buffer so tests can
// inject a fault directly into the follower's pipeline.
//
// It lives in its own file (WS-D) so it does not touch the shared ws-a harness.
type checksumFollowerHarness struct {
	syncerTypes []syncproto.SyncerType
	buffers     map[syncproto.SyncerType]*dedupebuffer.DedupeBuffer
	caches      map[syncproto.SyncerType]*snapcache.Cache
	verifiers   map[syncproto.SyncerType]*synccheck.Verifier
	sources     map[syncproto.SyncerType]syncsource.SyncerSource
	server      *syncserver.Server

	// reconnects counts forced reconnects requested by each verifier, so tests
	// can assert remediation fired.
	reconnects map[syncproto.SyncerType]*atomic.Int64

	cacheCtx     context.Context
	cacheCancel  context.CancelFunc
	srcCtx       context.Context
	srcCancel    context.CancelFunc
	serverCtx    context.Context
	serverCancel context.CancelFunc
}

// newChecksumFollowerHarness builds a follower with checksums enabled.
// mismatchAction selects the verifier remediation; myVersion lets a test force
// version skew (set it different from the upstream's version to exercise
// count-only comparison).
func newChecksumFollowerHarness(
	upstreamAddr string,
	myVersion string,
	mismatchAction synccheck.MismatchAction,
	syncerTypes ...syncproto.SyncerType,
) *checksumFollowerHarness {
	f := &checksumFollowerHarness{
		syncerTypes: syncerTypes,
		buffers:     map[syncproto.SyncerType]*dedupebuffer.DedupeBuffer{},
		caches:      map[syncproto.SyncerType]*snapcache.Cache{},
		verifiers:   map[syncproto.SyncerType]*synccheck.Verifier{},
		sources:     map[syncproto.SyncerType]syncsource.SyncerSource{},
		reconnects:  map[syncproto.SyncerType]*atomic.Int64{},
	}
	f.cacheCtx, f.cacheCancel = context.WithCancel(context.Background())
	cacheProviders := map[syncproto.SyncerType]syncserver.BreadcrumbProvider{}
	for _, st := range syncerTypes {
		buf := dedupebuffer.New()
		cache := snapcache.New(snapcache.Config{
			MaxBatchSize:   10,
			WakeUpInterval: 50 * time.Millisecond,
			Name:           "cksum-follower-" + string(st),
		})
		validator := calc.NewValidationFilter(cache)
		go buf.SendToSinkForever(validator)

		reconnectCount := &atomic.Int64{}
		// The verifier reads the follower's own snapcache: the current
		// breadcrumb's checksum is the follower's reconstruction of the upstream
		// snapshot.
		cacheForClosure := cache
		verifier := synccheck.NewVerifier(synccheck.VerifierConfig{
			SyncerType:     string(st),
			MismatchAction: mismatchAction,
			Local: synccheck.LocalChecksumFunc(func() synccheck.Checksum {
				return cacheForClosure.CurrentBreadcrumb().Checksum
			}),
			RequestReconnect: func() {
				reconnectCount.Add(1)
			},
			// Fast, deterministic for the FV: confirm a mismatch after a couple of
			// checks and don't rate-limit within a test.
			PersistChecks:        2,
			ReconnectMinInterval: time.Millisecond,
		})

		source := syncsource.NewUpstreamTyphaSource(
			discovery.New(discovery.WithAddrOverride(upstreamAddr)),
			syncsource.UpstreamConfig{
				MyVersion:  myVersion,
				MyHostname: "cksum-follower-host",
				MyInfo:     "cksum-follower",
				SyncerType: st,
				ClientOptions: syncclient.Options{
					ChecksumVerifier:      verifier,
					ChecksumCheckInterval: 50 * time.Millisecond,
				},
			},
			buf,
		)

		f.buffers[st] = buf
		f.caches[st] = cache
		f.verifiers[st] = verifier
		f.sources[st] = source
		f.reconnects[st] = reconnectCount
		cacheProviders[st] = cache
	}
	f.server = syncserver.New(cacheProviders, syncserver.Config{
		PingInterval: 10 * time.Second,
		Port:         syncserver.PortRandom,
		DropInterval: 50 * time.Millisecond,
	})
	return f
}

func (f *checksumFollowerHarness) Start() {
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

func (f *checksumFollowerHarness) Stop() {
	for _, s := range f.sources {
		s.Stop()
	}
	for _, b := range f.buffers {
		b.Stop()
	}
	f.serverCancel()
	f.server.Finished.Wait()
	f.cacheCancel()
}

func (f *checksumFollowerHarness) Addr() string {
	return fmt.Sprintf("127.0.0.1:%d", f.server.Port())
}

// injectPhantomKey pushes an extra key/value into the follower's pipeline that
// the upstream never sent.  This corrupts the follower's reconstruction so that
// its checksum diverges from the upstream's, simulating a hop that duplicated or
// fabricated data.  It goes straight into the dedupe buffer (the head of the
// follower's pipeline), so it flows through exactly like a real update.
func (f *checksumFollowerHarness) injectPhantomKey(st syncproto.SyncerType, name, value string) {
	f.buffers[st].OnUpdates([]api.Update{{
		KVPair: model.KVPair{
			Key:      model.GlobalConfigKey{Name: name},
			Value:    value,
			Revision: "phantom",
		},
		UpdateType: api.UpdateTypeKVNew,
	}})
}
