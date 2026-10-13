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
	vm   cache.Indexer
	vmi  cache.Indexer
	vmim cache.Indexer
}

type kvInformers struct {
	vm   cache.SharedIndexInformer
	vmi  cache.SharedIndexInformer
	vmim cache.SharedIndexInformer
}

// EventHandlers are attached to the KubeVirt informers once they exist.
type EventHandlers struct {
	// VM, VMI and VMIM may each be nil. VMIM is attached only when there is a
	// VMIM informer, as from NewDeferredInformersWithMigrations.
	VM, VMI, VMIM cache.ResourceEventHandler
	// Synced is called once, after the indexers are published and the handlers
	// are attached. It is never called while DeferredInformers holds a lock.
	// It can run before client-go delivers the replayed add events to the
	// handlers, so read the indexers instead of counting on handler delivery.
	Synced func()
	// MigrationsSynced is called once, after the VMIM indexer is published,
	// which can be after Synced. It is never called when there is no VMIM
	// informer or it never syncs.
	MigrationsSynced func()
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
	// createMigrations is nil unless built by NewDeferredInformersWithMigrations.
	createMigrations GetMigrationInformerFunc
	// migrationsSynced is set once the VMIM indexer is published. Until then,
	// migrationWaiters holds the MigrationsSynced callbacks registered so far.
	migrationsSynced bool
	migrationWaiters []func()
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

// MigrationIndexer returns the VMIM cache indexer, indexed by
// MigrationsByVMIIndex, or nil until its informer has synced. It stays nil
// when there is no VMIM informer, or when it cannot list VMIMs.
func (d *DeferredInformers) MigrationIndexer() cache.Indexer {
	idx := d.indexers.Load()
	if idx == nil {
		return nil
	}
	return idx.vmim
}

// AddEventHandlers registers handlers for the KubeVirt informers. If the
// informers already run, the handlers attach at once and client-go replays the
// existing objects as adds. Otherwise they attach when the informers sync.
func (d *DeferredInformers) AddEventHandlers(h EventHandlers) {
	d.mu.Lock()
	inf := d.informers
	if inf == nil {
		d.pending = append(d.pending, h)
	}
	migrationsSynced := d.migrationsSynced
	if !migrationsSynced && h.MigrationsSynced != nil {
		d.migrationWaiters = append(d.migrationWaiters, h.MigrationsSynced)
	}
	d.mu.Unlock()
	if inf != nil {
		attach(inf, h)
		if h.Synced != nil {
			h.Synced()
		}
	}
	if migrationsSynced && h.MigrationsSynced != nil {
		h.MigrationsSynced()
	}
}

func attach(inf *kvInformers, h EventHandlers) {
	for _, p := range []struct {
		i cache.SharedIndexInformer
		h cache.ResourceEventHandler
	}{{inf.vm, h.VM}, {inf.vmi, h.VMI}, {inf.vmim, h.VMIM}} {
		if p.i == nil || p.h == nil {
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
	return NewDeferredInformersWithMigrationIndexer(vm, vmi, nil)
}

// NewDeferredInformersWithMigrationIndexer is NewDeferredInformersWithIndexers
// with a VMIM indexer too. Intended for use in tests.
func NewDeferredInformersWithMigrationIndexer(vm, vmi, vmim cache.Indexer) *DeferredInformers {
	d := &DeferredInformers{}
	d.setIndexers(vm, vmi, vmim)
	return d
}

// setIndexers atomically publishes the indexers.
func (d *DeferredInformers) setIndexers(vm, vmi, vmim cache.Indexer) {
	d.indexers.Store(&kvIndexers{vm: vm, vmi: vmi, vmim: vmim})
}

// initInformers detects KubeVirt, creates its informers, and publishes their
// indexers: VM and VMI once both sync, then VMIM, when createMigrations is set,
// once it syncs on its own. That last wait lasts until stop when the VMIM list
// keeps failing, as when the caller may not list VMIMs. If KubeVirt is not
// installed at call time it polls every pollInterval until it appears or stop
// is closed.
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

	var vmimInf cache.SharedIndexInformer
	if d.createMigrations != nil {
		if vmimInf, err = d.createMigrations(); err != nil {
			log.WithError(err).Warn("Failed to create the KubeVirt VMIM informer")
			vmimInf = nil
		}
	}

	// Start the informers and wait for initial sync.
	go vmInf.Run(stop)
	go vmiInf.Run(stop)
	if vmimInf != nil {
		go vmimInf.Run(stop)
	}
	if !cache.WaitForCacheSync(stop, vmInf.HasSynced, vmiInf.HasSynced) {
		log.Warn("Failed to sync KubeVirt informers")
		return
	}
	d.setIndexers(vmInf.GetIndexer(), vmiInf.GetIndexer(), nil)
	log.Info("KubeVirt informers synced, VM-aware IPAM GC enabled")

	inf := &kvInformers{vm: vmInf, vmi: vmiInf, vmim: vmimInf}
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

	// The VMIM informer syncs on its own, so a caller without RBAC for VMIMs,
	// whose informer never syncs, still has VMs and VMIs.
	if vmimInf == nil {
		return
	}
	if !cache.WaitForCacheSync(stop, vmimInf.HasSynced) {
		return
	}
	d.setIndexers(vmInf.GetIndexer(), vmiInf.GetIndexer(), vmimInf.GetIndexer())
	log.Info("KubeVirt VMIM informer synced")
	d.mu.Lock()
	d.migrationsSynced = true
	waiters := d.migrationWaiters
	d.migrationWaiters = nil
	d.mu.Unlock()
	for _, f := range waiters {
		f()
	}
}
