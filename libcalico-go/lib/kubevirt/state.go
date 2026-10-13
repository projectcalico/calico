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

package kubevirt

import (
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/tools/cache"
)

type kvIndexers struct {
	vm  cache.Indexer
	vmi cache.Indexer
}

type kvInformers struct {
	vm  cache.SharedIndexInformer
	vmi cache.SharedIndexInformer
}

// EventHandlers are attached to the KubeVirt informers once they exist.
type EventHandlers struct {
	// VM and VMI may each be nil.
	VM, VMI cache.ResourceEventHandler
	// Synced is called once, after the indexers are published and the handlers
	// are attached. It is never called while DeferredInformers holds a lock.
	// It can run before client-go delivers the replayed add events to the
	// handlers, so read the indexers instead of counting on handler delivery.
	Synced func()
}

// GetIndexInformerFunc creates KubeVirt VM and VMI informers.
// Returns (nil, nil, nil) when KubeVirt is not installed.
type GetIndexInformerFunc func() (cache.SharedIndexInformer, cache.SharedIndexInformer, error)

// DeferredInformers provides thread-safe access to KubeVirt cache indexers
// that may be populated lazily if KubeVirt is installed after startup.
// It is safe for concurrent reads and a single writer (the init goroutine).
type DeferredInformers struct {
	indexers atomic.Pointer[kvIndexers]

	mu        sync.Mutex
	informers *kvInformers
	pending   []EventHandlers
}

// NewDeferredInformers creates a DeferredInformers and starts a background
// goroutine that polls for KubeVirt, creates informers, and publishes their
// indexers once synced. If KubeVirt is already installed, the informers are
// created immediately.
func NewDeferredInformers(createInformers GetIndexInformerFunc, pollInterval time.Duration, stop <-chan struct{}) *DeferredInformers {
	d := &DeferredInformers{}
	go d.initInformers(createInformers, pollInterval, stop)
	return d
}

// VMIndexer returns the VM cache indexer, or nil if KubeVirt has not been
// detected yet.
func (d *DeferredInformers) VMIndexer() cache.Indexer {
	idx := d.indexers.Load()
	if idx == nil {
		return nil
	}
	return idx.vm
}

// VMInstanceIndexer returns the VMI cache indexer, or nil if KubeVirt has not
// been detected yet.
func (d *DeferredInformers) VMInstanceIndexer() cache.Indexer {
	idx := d.indexers.Load()
	if idx == nil {
		return nil
	}
	return idx.vmi
}

// AddEventHandlers registers handlers for the VM and VMI informers. If the
// informers already run, the handlers attach at once and client-go replays the
// existing objects as adds. Otherwise they attach when the informers sync.
func (d *DeferredInformers) AddEventHandlers(h EventHandlers) {
	d.mu.Lock()
	inf := d.informers
	if inf == nil {
		d.pending = append(d.pending, h)
	}
	d.mu.Unlock()
	if inf != nil {
		attach(inf, h)
		if h.Synced != nil {
			h.Synced()
		}
	}
}

func attach(inf *kvInformers, h EventHandlers) {
	for _, p := range []struct {
		i cache.SharedIndexInformer
		h cache.ResourceEventHandler
	}{{inf.vm, h.VM}, {inf.vmi, h.VMI}} {
		if p.h == nil {
			continue
		}
		if _, err := p.i.AddEventHandler(p.h); err != nil {
			log.WithError(err).Error("Failed to add a KubeVirt event handler")
		}
	}
}

// NewDeferredInformersWithIndexers creates a DeferredInformers pre-populated
// with the given indexers. Intended for use in tests.
func NewDeferredInformersWithIndexers(vm, vmi cache.Indexer) *DeferredInformers {
	d := &DeferredInformers{}
	d.setIndexers(vm, vmi)
	return d
}

// setIndexers atomically publishes the VM and VMI indexers.
func (d *DeferredInformers) setIndexers(vm, vmi cache.Indexer) {
	d.indexers.Store(&kvIndexers{vm: vm, vmi: vmi})
}

// initInformers detects KubeVirt, creates VM/VMI informers, and publishes
// their indexers. If KubeVirt is not installed at call time it polls every
// pollInterval until it appears or stop is closed.
func (d *DeferredInformers) initInformers(createInformers GetIndexInformerFunc, pollInterval time.Duration, stop <-chan struct{}) {
	// Try immediately first.
	vmInf, vmiInf, err := createInformers()
	if err != nil {
		log.WithError(err).Warn("Failed to create KubeVirt informers, will keep polling")
	}

	if vmInf == nil || vmiInf == nil {
		// KubeVirt not found — poll until it appears.
		ticker := time.NewTicker(pollInterval)
		defer ticker.Stop()
		for vmInf == nil || vmiInf == nil {
			select {
			case <-stop:
				return
			case <-ticker.C:
				vmInf, vmiInf, err = createInformers()
				if err != nil {
					log.WithError(err).Debug("KubeVirt detection check failed, will retry")
				}
			}
		}
	}

	// Start the informers and wait for initial sync.
	go vmInf.Run(stop)
	go vmiInf.Run(stop)
	if !cache.WaitForCacheSync(stop, vmInf.HasSynced, vmiInf.HasSynced) {
		log.Warn("Failed to sync KubeVirt informers")
		return
	}
	d.setIndexers(vmInf.GetIndexer(), vmiInf.GetIndexer())
	log.Info("KubeVirt informers synced, VM-aware IPAM GC enabled")

	inf := &kvInformers{vm: vmInf, vmi: vmiInf}
	d.mu.Lock()
	d.informers = inf
	pending := d.pending
	d.pending = nil
	d.mu.Unlock()
	for _, h := range pending {
		attach(inf, h)
		if h.Synced != nil {
			h.Synced()
		}
	}
}
