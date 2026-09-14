// Copyright (c) 2018-2025 Tigera, Inc. All rights reserved.

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

package policystore

import (
	"maps"
	"sync"

	log "github.com/sirupsen/logrus"

	apptypes "github.com/projectcalico/calico/app-policy/types"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/types"
)

// PolicyStore is a data store that holds Calico policy information.
type PolicyStore struct {
	// route looker upper
	IPToIndexes apptypes.IPToEndpointsIndex

	// The RWMutex protects the entire contents of the PolicyStore. No one should read from or write to the PolicyStore
	// without acquiring the corresponding lock.
	// Helper methods Write() and Read() encapsulate the correct locking logic.
	RWMutex sync.RWMutex

	PolicyByID         map[types.PolicyID]*proto.Policy
	ProfileByID        map[types.ProfileID]*proto.Profile
	IPSetByID          map[string]IPSet
	Endpoint           *proto.WorkloadEndpoint
	Endpoints          map[types.WorkloadEndpointID]*proto.WorkloadEndpoint
	ServiceAccountByID map[types.ServiceAccountID]*proto.ServiceAccountUpdate
	NamespaceByID      map[types.NamespaceID]*proto.NamespaceUpdate

	// Generation counts the updates ProcessUpdate has applied to the store. State derived from the
	// store's contents (the verdict cache) records the generation it was derived at and is discarded
	// when the generation moves on. Code that mutates the store other than through ProcessUpdate
	// must increment it.
	Generation uint64
	// Verdicts caches evaluation results for this store's contents; nil when caching is off. Set
	// through WithVerdictCache on the manager that creates the store, so that a cache never outlives
	// the store it was filled from.
	Verdicts *VerdictCache
}

func NewPolicyStore() *PolicyStore {
	return &PolicyStore{
		IPToIndexes:        apptypes.NewIPToEndpointsIndex(),
		Endpoints:          make(map[types.WorkloadEndpointID]*proto.WorkloadEndpoint),
		RWMutex:            sync.RWMutex{},
		IPSetByID:          make(map[string]IPSet),
		ProfileByID:        make(map[types.ProfileID]*proto.Profile),
		PolicyByID:         make(map[types.PolicyID]*proto.Policy),
		ServiceAccountByID: make(map[types.ServiceAccountID]*proto.ServiceAccountUpdate),
		NamespaceByID:      make(map[types.NamespaceID]*proto.NamespaceUpdate),
	}
}

type policyStoreManager struct {
	current, pending *PolicyStore
	mu               sync.RWMutex
	toActive         bool
	// newStore creates the stores the manager hands out: at construction and on every reconnect.
	newStore func() *PolicyStore
}

type PolicyStoreManager interface {
	// PolicyStoreManager reads from a current or pending policy store if
	// syncher has an established and in-sync connection; or not, respectively.
	DoWithReadLock(func(*PolicyStore))
	// PolicyStoreManager writes to a current or pending policy store if
	// syncher has an established and in-sync connection; or not, respectively.
	DoWithLock(func(*PolicyStore))

	// tells PSM of syncher state 'connection lost; reestablishing until inSync encountered'
	OnReconnecting()
	// tells PSM of syncher state 'connection (re-)established and in-sync'
	OnInSync()

	GetCurrentEndpoints() map[types.WorkloadEndpointID]*proto.WorkloadEndpoint
}

type PolicyStoreManagerOption func(*policyStoreManager)

func NewPolicyStoreManager() PolicyStoreManager {
	return NewPolicyStoreManagerWithOpts()
}

func NewPolicyStoreManagerWithOpts(opts ...PolicyStoreManagerOption) *policyStoreManager {
	psm := &policyStoreManager{newStore: NewPolicyStore}
	for _, o := range opts {
		o(psm)
	}
	psm.current = psm.newStore()
	psm.pending = psm.newStore()
	return psm
}

// WithVerdictCache gives every store the manager creates a verdict cache of the given capacity,
// reporting into the shared counters. See VerdictCache for what it caches and when it is emptied.
func WithVerdictCache(capacity int, stats *VerdictCacheStats) PolicyStoreManagerOption {
	return func(m *policyStoreManager) {
		m.newStore = func() *PolicyStore {
			s := NewPolicyStore()
			s.Verdicts = NewVerdictCache(capacity, stats)
			return s
		}
	}
}

func (m *policyStoreManager) DoWithReadLock(cb func(*PolicyStore)) {
	log.Tracef("StoreManager acquiring read lock")
	m.mu.RLock()
	defer m.mu.RUnlock()

	log.Debugf("StoreManager calling callback on current store: %p", m.current)

	cb(m.current)
	log.Tracef("StoreManager callback done, going to release read lock")
}

// DoWithLock acquires a lock and calls the callback with the current or pending store
// depending on the state of the connection.
func (m *policyStoreManager) DoWithLock(cb func(*PolicyStore)) {
	log.Tracef("StoreManager acquiring lock")
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.toActive {
		log.Debugf("StoreManager calling callback on current store: %p", m.current)
		cb(m.current)
		return
	}

	log.Debugf("StoreManager calling callback on pending store: %p", m.pending)
	cb(m.pending)
	log.Tracef("StoreManager callback done, releasing lock")
}

func (m *policyStoreManager) GetCurrentEndpoints() map[types.WorkloadEndpointID]*proto.WorkloadEndpoint {
	m.mu.RLock()
	defer m.mu.RUnlock()

	copy := make(map[types.WorkloadEndpointID]*proto.WorkloadEndpoint, len(m.current.Endpoints))
	maps.Copy(copy, m.current.Endpoints)
	return copy
}

// OnReconnecting - PSM creates a pending store and starts writing to it
func (m *policyStoreManager) OnReconnecting() {
	log.Trace("storeManager OnReconnecting(). acquiring write lock")
	m.mu.Lock()
	defer m.mu.Unlock()

	// create store
	m.pending = m.newStore()
	log.Tracef("storeManager OnReconnecting() created new pending store %p", m.pending)

	// route next writes to pending
	m.toActive = false
}

func (m *policyStoreManager) OnInSync() {
	log.Tracef("storeManager OnInSync() acquiring write lock")
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.toActive {
		// we're already in-sync..
		// exit this routine so we don't cause a swap in case
		// insync is called more than once
		return
	}
	// swap pending to active
	m.current = m.pending
	m.pending = nil
	// route next writes to active
	m.toActive = true
}
