// Copyright (c) 2020 Tigera, Inc. All rights reserved.
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

package proxy

import (
	"context"
	"sync"

	"github.com/projectcalico/calico/felix/bpf/routes"
	"github.com/projectcalico/calico/felix/ip"
)

// Routes is an interface to query routes
type Routes interface {
	Lookup(ip.Addr) (routes.ValueInterface, bool)
	WaitAfter(ctx context.Context, fn func(lookup func(addr ip.Addr) (routes.ValueInterface, bool)) bool)
}

// RTCache is a lookup data structure that allow inserting and deleting routes
// and to do a LPM prefix match for IP addresses
type RTCache struct {
	cond4 *sync.Cond
	rts   *routes.LPM
}

// NewRTCache creates an empty routing cache
func NewRTCache() *RTCache {
	rt := &RTCache{
		rts: routes.NewLPM(),
	}

	rt.cond4 = sync.NewCond(rt.rts.RLocker())

	return rt
}

// Update either creates an entry or updates an existing one
func (rt *RTCache) Update(k routes.KeyInterface, v routes.ValueInterface) {
	rt.rts.Lock()
	defer rt.rts.Unlock()
	defer rt.cond4.Broadcast()
	rt.rts.Update(k, v)
}

// Delete deletes and entry if it exists, does not return error if not
func (rt *RTCache) Delete(k routes.KeyInterface) {
	rt.rts.Lock()
	defer rt.rts.Unlock()
	// no need to broadcast, lookup will not succeed
	rt.rts.Delete(k)
}

// Lookup looks LPM match for an address and returns the associated data.
func (rt *RTCache) Lookup(addr ip.Addr) (routes.ValueInterface, bool) {
	rt.rts.RLock()
	defer rt.rts.RUnlock()

	v, ok := rt.rts.Lookup(addr)
	return v, ok
}

func (rt *RTCache) lookupUnlocked(addr ip.Addr) (routes.ValueInterface, bool) {
	return rt.rts.Lookup(addr)
}

// WaitAfter executes a function and if it returns false, it blocks until
// another update or until the provided context is canceled. The function can do
// only lookups as the state of the cache is read-locked. It must use the
// provided lookup function.
func (rt *RTCache) WaitAfter(ctx context.Context,
	fn func(lookup func(addr ip.Addr) (routes.ValueInterface, bool)) bool) {

	ctx, cancel := context.WithCancel(ctx)

	exit := false

	go func() {
		// Wait until the ctx is either canceled from outside or by fn completing
		<-ctx.Done()
		// Take the lock to sync with fn deciding to Wait
		rt.rts.Lock()
		exit = true
		rt.rts.Unlock()
		rt.cond4.Broadcast()
	}()

	rt.rts.RLock()
	if !fn(rt.lookupUnlocked) && !exit {
		rt.cond4.Wait()
	}
	rt.rts.RUnlock()
	cancel()
}
