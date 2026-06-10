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

	log "github.com/sirupsen/logrus"

	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
)

// datastoreSource is a SyncerSource backed by a real datastore bapi.Syncer.
//
// bapi.Syncer.Stop() already provides the "block until no more callbacks" and
// "delete events emitted for everything" semantics we need: watcherSyncer.Stop()
// cancels the watcher caches and blocks on its run loop (the only goroutine
// that calls the callbacks) before returning.
type datastoreSource struct {
	syncer bapi.Syncer

	lock    sync.Mutex
	done    chan struct{}
	started bool
	stopped bool
}

// NewDatastoreSource returns a SyncerSource that wraps a datastore syncer
// (constructed via newSyncer) feeding the supplied callbacks.  newSyncer is
// typically one of the DatastoreClient.*SyncerByIface methods.  The syncer is
// constructed eagerly (matching the historical behaviour where the syncer was
// created during server setup) but only started when Start() is called.
func NewDatastoreSource(
	newSyncer func(callbacks bapi.SyncerCallbacks) bapi.Syncer,
	callbacks bapi.SyncerCallbacks,
) SyncerSource {
	return &datastoreSource{
		syncer: newSyncer(callbacks),
		done:   make(chan struct{}),
	}
}

func (s *datastoreSource) Start(_ context.Context) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	if s.stopped || s.started {
		return nil
	}
	s.started = true
	log.WithField("syncer", s.syncer).Debug("Starting datastore syncer source.")
	s.syncer.Start()
	return nil
}

func (s *datastoreSource) Stop() {
	s.lock.Lock()
	alreadyStopped := s.stopped
	started := s.started
	s.stopped = true
	s.lock.Unlock()

	if alreadyStopped {
		return
	}
	if started {
		// Syncer.Stop() blocks until the syncer's run loop has exited, so no
		// more callbacks will fire after this returns.  Only call it if we
		// actually started the syncer (calling Stop on an unstarted syncer can
		// panic in some implementations).
		s.syncer.Stop()
	}
	close(s.done)
}

func (s *datastoreSource) Done() <-chan struct{} {
	return s.done
}

var _ SyncerSource = (*datastoreSource)(nil)
