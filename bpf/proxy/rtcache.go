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

	"github.com/pkg/errors"

	"github.com/projectcalico/felix/bpf/routes"
	"github.com/projectcalico/felix/ip"
)

// Routes is an interface to query routes
type Routes interface {
	Lookup(context.Context, ip.Addr) (routes.Value, bool)
}

// RTCache is a lookup data structure that allow inserting and deleting routes
// and to do a LPM prefix match for IP addresses
type RTCache struct {
	cond4 *sync.Cond
	v4    *routes.LPMv4
}

// NewRTCache creates an empty routing cache
func NewRTCache() *RTCache {
	rt := &RTCache{
		v4: routes.NewLPMv4(),
	}

	rt.cond4 = sync.NewCond(rt.v4.RLocker())

	return rt
}

// UpdateV4 makes an update with V4 CIDR or errors
func (rt *RTCache) UpdateV4(k routes.Key, v routes.Value) error {
	rt.v4.Lock()
	defer rt.v4.Unlock()
	defer rt.cond4.Broadcast()
	return rt.v4.Update(k, v)
}

// Update either creates an entry or updates an existing one
func (rt *RTCache) Update(k routes.Key, v routes.Value) error {
	switch k.Dest().(type) {
	case ip.V4CIDR:
		return rt.UpdateV4(k, v)
	default:
		return errors.Errorf("unsupported CIDR type %T", k.Dest())
	}
}

// DeleteV4 deletes an entry and errors if the key is not V4
func (rt *RTCache) DeleteV4(k routes.Key) error {
	rt.v4.Lock()
	defer rt.v4.Unlock()
	// no need to broadcast, lookup will not succeed
	return rt.v4.Delete(k)
}

// Delete deletes and entry if it exists, does not return error if not
func (rt *RTCache) Delete(k routes.Key) error {
	switch k.Dest().(type) {
	case ip.V4CIDR:
		return rt.DeleteV4(k)
	default:
		return errors.Errorf("unsupported CIDR type %T", k.Dest())
	}
}

// LookupV4 is the same as Lookup for V4 only
func (rt *RTCache) LookupV4(ctx context.Context, addr ip.V4Addr) (routes.Value, bool) {
	rt.v4.RLock()
	defer rt.v4.RUnlock()

	if v, ok := rt.v4.Lookup(addr); ok || ctx.Err() != nil {
		return v, ok
	}

	go func() {
		<-ctx.Done()
		rt.cond4.Broadcast()
	}()

	for {
		rt.cond4.Wait()
		if v, ok := rt.v4.Lookup(addr); ok || ctx.Err() != nil {
			return v, ok
		}
	}
}

// Lookup looks LPM match for an address and returns the associated data. If
// there is a cache miss, the operation waits for the route to appear until the
// context is done.
func (rt *RTCache) Lookup(ctx context.Context, addr ip.Addr) (routes.Value, bool) {
	switch a := addr.(type) {
	case ip.V4Addr:
		return rt.LookupV4(ctx, a)
	default:
		return routes.Value{}, false
	}
}
