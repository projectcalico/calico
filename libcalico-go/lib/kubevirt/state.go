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
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/tools/cache"
)

type kvIndexers struct {
	vm  cache.Indexer
	vmi cache.Indexer
}

// GetIndexerFunc creates KubeVirt VM and VMI informers.
// Returns (nil, nil, nil) when KubeVirt is not installed.
type GetIndexerFunc func() (cache.SharedIndexInformer, cache.SharedIndexInformer, error)

// DeferredInformers provides thread-safe access to KubeVirt cache indexers
// that may be populated lazily if KubeVirt is installed after startup.
// It is safe for concurrent reads and a single writer (the init goroutine).
type DeferredInformers struct {
	indexers atomic.Pointer[kvIndexers]
}

// NewDeferredInformers creates a DeferredInformers and starts a background
// goroutine that polls for KubeVirt, creates informers, and publishes their
// indexers once synced. If KubeVirt is already installed, the informers are
// created immediately.
func NewDeferredInformers(createInformers GetIndexerFunc, pollInterval time.Duration, stop <-chan struct{}) *DeferredInformers {
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
func (d *DeferredInformers) initInformers(createInformers GetIndexerFunc, pollInterval time.Duration, stop <-chan struct{}) {
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
}
