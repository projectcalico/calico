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

package conntrack

import (
	"sync"

	log "github.com/sirupsen/logrus"
)

type IfindexRepointer interface {
	RepointIfindex(oldIfindex, newIfindex int) (int, error)
}

type IfindexReplacement struct {
	OldIfindex, NewIfindex int
}

// TunnelIfaceRepointer moves BPF conntrack legs off a replaced tunnel device. Otherwise
// established flows keep egressing to the deleted device.
type TunnelIfaceRepointer struct {
	lock     sync.Mutex
	families map[int]IfindexRepointer
	// replaced is replayed to families registered later.
	replaced []IfindexReplacement
}

func NewTunnelIfaceRepointer() *TunnelIfaceRepointer {
	return &TunnelIfaceRepointer{
		families: map[int]IfindexRepointer{},
	}
}

// OnTunnelReplaced is called from the tunnel device goroutine.
func (r *TunnelIfaceRepointer) OnTunnelReplaced(oldIfindex, newIfindex int) {
	r.lock.Lock()
	defer r.lock.Unlock()

	rp := IfindexReplacement{OldIfindex: oldIfindex, NewIfindex: newIfindex}
	r.replaced = append(r.replaced, rp)
	for ipVersion, c := range r.families {
		repoint(ipVersion, c, rp)
	}
}

// RegisterFamily adds the per-family program runner; Felix creates them only after the tunnel goroutine starts.
func (r *TunnelIfaceRepointer) RegisterFamily(ipVersion int, c IfindexRepointer) {
	r.lock.Lock()
	defer r.lock.Unlock()

	r.families[ipVersion] = c
	for _, rp := range r.replaced {
		repoint(ipVersion, c, rp)
	}
}

func repoint(ipVersion int, c IfindexRepointer, rp IfindexReplacement) {
	logCtx := log.WithFields(log.Fields{
		"ipVersion":  ipVersion,
		"oldIfindex": rp.OldIfindex,
		"newIfindex": rp.NewIfindex,
	})
	n, err := c.RepointIfindex(rp.OldIfindex, rp.NewIfindex)
	if err != nil {
		logCtx.WithError(err).Error("Failed to repoint conntrack entries to the replaced tunnel device.")
		return
	}
	logCtx.WithField("legs", n).Info("Repointed conntrack entries to the replaced tunnel device.")
}
