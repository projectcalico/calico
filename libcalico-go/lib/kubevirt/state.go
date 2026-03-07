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

// kubeVirtIndexers holds the VM and VMI cache indexers.
type kubeVirtIndexers struct {
	VM  cache.Indexer
	VMI cache.Indexer
}

// KubeVirtState provides thread-safe access to KubeVirt cache indexers.
// It is safe for concurrent reads and a single writer (the lazy init goroutine).
type KubeVirtState struct {
	indexers atomic.Pointer[kubeVirtIndexers]
}

// Get returns the VM and VMI indexers, or (nil, nil) if KubeVirt has not been
// detected yet.
func (s *KubeVirtState) Get() (vm cache.Indexer, vmi cache.Indexer) {
	idx := s.indexers.Load()
	if idx == nil {
		return nil, nil
	}
	return idx.VM, idx.VMI
}

// Set atomically publishes the VM and VMI indexers.
func (s *KubeVirtState) Set(vm, vmi cache.Indexer) {
	s.indexers.Store(&kubeVirtIndexers{VM: vm, VMI: vmi})
}

// InformerFactory creates KubeVirt VM and VMI informers.
// Returns (nil, nil, nil) when KubeVirt is not installed.
type InformerFactory func() (cache.SharedIndexInformer, cache.SharedIndexInformer, error)

// InitInformers detects KubeVirt, creates VM/VMI informers, and publishes
// their indexers to kubevirtState. If KubeVirt is not installed at call time it
// polls every pollInterval until it appears or stop is closed.
func InitInformers(createInformers InformerFactory, pollInterval time.Duration, stop <-chan struct{}, kubevirtState *KubeVirtState) {
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
	kubevirtState.Set(vmInf.GetIndexer(), vmiInf.GetIndexer())
	log.Info("KubeVirt informers synced, VM-aware IPAM GC enabled")
}
