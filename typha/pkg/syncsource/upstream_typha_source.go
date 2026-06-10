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

package syncsource

import (
	"context"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/typha/pkg/discovery"
	"github.com/projectcalico/calico/typha/pkg/syncclient"
	"github.com/projectcalico/calico/typha/pkg/syncproto"
)

const (
	initialReconnectBackoff = 1 * time.Second
	maxReconnectBackoff     = 30 * time.Second
)

// UpstreamConfig holds the parameters for connecting to an upstream Typha.
type UpstreamConfig struct {
	// MyVersion, MyHostname, MyInfo identify this Typha to the upstream (used
	// in the client hello, surfaced in the upstream's logs/metrics).
	MyVersion  string
	MyHostname string
	MyInfo     string

	// SyncerType is the pipeline this source feeds; one upstream connection per
	// syncer type, mirroring how Felix connects.
	SyncerType syncproto.SyncerType

	// ClientOptions carries the per-connection options (TLS, timeouts) passed
	// straight through to syncclient.  SyncerType is overwritten from the field
	// above so callers don't have to set it twice.
	ClientOptions syncclient.Options
}

// upstreamTyphaSource is a SyncerSource backed by a syncclient.SyncerClient
// connected to an upstream Typha.  Because the sink is a restart-aware dedupe
// buffer, the underlying syncclient transparently reconnects and reconciles on
// connection loss.  This source additionally wraps the *initial* connection in
// a retry-with-backoff loop so that startup tolerates the upstream not being
// ready yet (WS-C replaces this loop with the role state machine).
type upstreamTyphaSource struct {
	discoverer *discovery.Discoverer
	cfg        UpstreamConfig
	callbacks  api.SyncerCallbacks

	lock    sync.Mutex
	client  *syncclient.SyncerClient
	stopped bool

	// stopSignal is closed by Stop() to interrupt the backoff sleep promptly.
	stopSignal chan struct{}
	done       chan struct{}
}

// NewUpstreamTyphaSource returns a SyncerSource that connects to an upstream
// Typha discovered via the supplied discoverer.  callbacks must be
// restart-aware (a dedupebuffer.DedupeBuffer) so that the syncclient can
// reconnect on its own.
func NewUpstreamTyphaSource(
	discoverer *discovery.Discoverer,
	cfg UpstreamConfig,
	callbacks api.SyncerCallbacks,
) SyncerSource {
	cfg.ClientOptions.SyncerType = cfg.SyncerType
	return &upstreamTyphaSource{
		discoverer: discoverer,
		cfg:        cfg,
		callbacks:  callbacks,
		stopSignal: make(chan struct{}),
		done:       make(chan struct{}),
	}
}

func (s *upstreamTyphaSource) Start(ctx context.Context) error {
	go s.loop(ctx)
	return nil
}

// loop owns the lifecycle of the underlying syncclient.  It retries the initial
// connection forever (with backoff) until it succeeds or the source is stopped.
// Once connected, the syncclient handles its own reconnections via the
// restart-aware callbacks, so loop just waits for it to finish (which only
// happens on a fatal error or on Stop) and, if it wasn't a deliberate stop,
// retries.
func (s *upstreamTyphaSource) loop(ctx context.Context) {
	defer close(s.done)

	logCxt := log.WithField("syncerType", s.cfg.SyncerType)
	backoff := initialReconnectBackoff
	for {
		if s.isStopped() || ctx.Err() != nil {
			return
		}

		client := syncclient.New(
			s.discoverer,
			s.cfg.MyVersion, s.cfg.MyHostname, s.cfg.MyInfo,
			s.callbacks,
			&s.cfg.ClientOptions,
		)
		// Record the client so Stop() can shut it down.  Bail out if we were
		// stopped concurrently.
		s.lock.Lock()
		if s.stopped {
			s.lock.Unlock()
			return
		}
		s.client = client
		s.lock.Unlock()

		err := client.Start(ctx)
		if err != nil {
			logCxt.WithError(err).Warnf("Failed to connect to upstream Typha; will retry in %v.", backoff)
			// Make sure the (failed) client is fully torn down before retrying.
			client.Stop()
			if !s.sleepWithBackoff(ctx, &backoff) {
				return
			}
			continue
		}

		logCxt.Info("Connected to upstream Typha.")
		backoff = initialReconnectBackoff

		// The syncclient reconnects internally for as long as its callbacks are
		// restart-aware.  Finished only completes on a fatal error or on Stop().
		client.Finished.Wait()

		if s.isStopped() || ctx.Err() != nil {
			logCxt.Info("Upstream Typha source stopped.")
			return
		}
		logCxt.Warn("Upstream Typha connection exited unexpectedly; will reconnect.")
		if !s.sleepWithBackoff(ctx, &backoff) {
			return
		}
	}
}

// sleepWithBackoff sleeps for the current backoff (doubling it up to the max)
// and returns false if the source was stopped or the context cancelled while
// sleeping.
func (s *upstreamTyphaSource) sleepWithBackoff(ctx context.Context, backoff *time.Duration) bool {
	timer := time.NewTimer(*backoff)
	defer timer.Stop()
	*backoff = min(*backoff*2, maxReconnectBackoff)
	select {
	case <-timer.C:
		return !s.isStopped() && ctx.Err() == nil
	case <-ctx.Done():
		return false
	case <-s.stopSignal:
		return false
	}
}

func (s *upstreamTyphaSource) Stop() {
	s.lock.Lock()
	if s.stopped {
		s.lock.Unlock()
		return
	}
	s.stopped = true
	close(s.stopSignal)
	client := s.client
	s.lock.Unlock()

	if client != nil {
		// syncclient.Stop() blocks until its main loop has exited, so no more
		// callbacks will fire after this returns.
		client.Stop()
	}
	// Wait for loop() to exit so that Done() is closed and we honour the
	// "no more callbacks after Stop" contract even if Start hadn't connected
	// yet.
	<-s.done
}

func (s *upstreamTyphaSource) Done() <-chan struct{} {
	return s.done
}

func (s *upstreamTyphaSource) isStopped() bool {
	s.lock.Lock()
	defer s.lock.Unlock()
	return s.stopped
}

var _ SyncerSource = (*upstreamTyphaSource)(nil)
