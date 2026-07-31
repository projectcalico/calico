// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package node

import (
	"context"
	"fmt"
	"sync"

	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
)

// fakeBackend is a minimal in-memory bapi.Client used by tests that exercise
// the IPAM handle reconciler. Only IPAMHandle operations are implemented;
// every other method panics.
//
// Concurrency: a single mutex protects all state. CAS via Revision is
// emulated by a monotonically increasing counter.
type fakeBackend struct {
	mu        sync.Mutex
	handles   map[string]*model.KVPair
	revisions int

	// Per-handle error injection. Each entry is consumed on first use, so
	// tests can stage a single CAS conflict / transient failure without
	// permanently breaking the fake.
	createErrs map[string]error
	updateErrs map[string]error
	deleteErrs map[string]error
	listErr    error
}

func newFakeBackend() *fakeBackend {
	return &fakeBackend{handles: map[string]*model.KVPair{}}
}

func (b *fakeBackend) seedHandle(id string, blocks map[string]int, deleted bool) *model.KVPair {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.revisions++
	cp := make(map[string]int, len(blocks))
	for k, v := range blocks {
		cp[k] = v
	}
	kvp := &model.KVPair{
		Key: model.IPAMHandleKey{HandleID: id},
		Value: &model.IPAMHandle{
			HandleID: id,
			Block:    cp,
			Deleted:  deleted,
		},
		Revision: fmt.Sprintf("%d", b.revisions),
	}
	b.handles[id] = kvp
	return copyHandleKVP(kvp)
}

func (b *fakeBackend) getHandle(id string) *model.IPAMHandle {
	b.mu.Lock()
	defer b.mu.Unlock()
	kvp, ok := b.handles[id]
	if !ok {
		return nil
	}
	return copyHandleKVP(kvp).Value.(*model.IPAMHandle)
}

func (b *fakeBackend) handleKVP(id string) *model.KVPair {
	b.mu.Lock()
	defer b.mu.Unlock()
	kvp, ok := b.handles[id]
	if !ok {
		return nil
	}
	return copyHandleKVP(kvp)
}

// SetCreateErr / SetUpdateErr / SetDeleteErr stage a single error to be
// returned by the next operation against the given handle. Useful for
// driving CAS-conflict and transient-failure paths.
func (b *fakeBackend) SetCreateErr(id string, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.createErrs == nil {
		b.createErrs = map[string]error{}
	}
	b.createErrs[id] = err
}

func (b *fakeBackend) SetUpdateErr(id string, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.updateErrs == nil {
		b.updateErrs = map[string]error{}
	}
	b.updateErrs[id] = err
}

func (b *fakeBackend) SetDeleteErr(id string, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.deleteErrs == nil {
		b.deleteErrs = map[string]error{}
	}
	b.deleteErrs[id] = err
}

func copyHandleKVP(kvp *model.KVPair) *model.KVPair {
	src := kvp.Value.(*model.IPAMHandle)
	cp := make(map[string]int, len(src.Block))
	for k, v := range src.Block {
		cp[k] = v
	}
	return &model.KVPair{
		Key: kvp.Key,
		Value: &model.IPAMHandle{
			HandleID: src.HandleID,
			Block:    cp,
			Deleted:  src.Deleted,
		},
		Revision: kvp.Revision,
	}
}

// --- bapi.Client surface; only IPAMHandle operations are implemented. ---

func (b *fakeBackend) Create(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	hk, ok := kvp.Key.(model.IPAMHandleKey)
	if !ok {
		panic(fmt.Sprintf("fakeBackend.Create: unsupported key type %T", kvp.Key))
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if err, ok := b.createErrs[hk.HandleID]; ok {
		delete(b.createErrs, hk.HandleID)
		return nil, err
	}
	if _, exists := b.handles[hk.HandleID]; exists {
		return nil, cerrors.ErrorResourceAlreadyExists{Identifier: kvp.Key}
	}
	b.revisions++
	src := kvp.Value.(*model.IPAMHandle)
	cp := make(map[string]int, len(src.Block))
	for k, v := range src.Block {
		cp[k] = v
	}
	stored := &model.KVPair{
		Key: kvp.Key,
		Value: &model.IPAMHandle{
			HandleID: src.HandleID,
			Block:    cp,
			Deleted:  src.Deleted,
		},
		Revision: fmt.Sprintf("%d", b.revisions),
	}
	b.handles[hk.HandleID] = stored
	return copyHandleKVP(stored), nil
}

func (b *fakeBackend) Update(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	hk, ok := kvp.Key.(model.IPAMHandleKey)
	if !ok {
		panic(fmt.Sprintf("fakeBackend.Update: unsupported key type %T", kvp.Key))
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if err, ok := b.updateErrs[hk.HandleID]; ok {
		delete(b.updateErrs, hk.HandleID)
		return nil, err
	}
	cur, exists := b.handles[hk.HandleID]
	if !exists {
		return nil, cerrors.ErrorResourceDoesNotExist{Identifier: kvp.Key}
	}
	if cur.Revision != kvp.Revision {
		return nil, cerrors.ErrorResourceUpdateConflict{Identifier: kvp.Key}
	}
	b.revisions++
	src := kvp.Value.(*model.IPAMHandle)
	cp := make(map[string]int, len(src.Block))
	for k, v := range src.Block {
		cp[k] = v
	}
	stored := &model.KVPair{
		Key: kvp.Key,
		Value: &model.IPAMHandle{
			HandleID: src.HandleID,
			Block:    cp,
			Deleted:  src.Deleted,
		},
		Revision: fmt.Sprintf("%d", b.revisions),
	}
	b.handles[hk.HandleID] = stored
	return copyHandleKVP(stored), nil
}

func (b *fakeBackend) DeleteKVP(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	hk, ok := kvp.Key.(model.IPAMHandleKey)
	if !ok {
		panic(fmt.Sprintf("fakeBackend.DeleteKVP: unsupported key type %T", kvp.Key))
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if err, ok := b.deleteErrs[hk.HandleID]; ok {
		delete(b.deleteErrs, hk.HandleID)
		return nil, err
	}
	cur, exists := b.handles[hk.HandleID]
	if !exists {
		return nil, cerrors.ErrorResourceDoesNotExist{Identifier: kvp.Key}
	}
	if cur.Revision != kvp.Revision {
		return nil, cerrors.ErrorResourceUpdateConflict{Identifier: kvp.Key}
	}
	delete(b.handles, hk.HandleID)
	return copyHandleKVP(cur), nil
}

func (b *fakeBackend) List(ctx context.Context, list model.ListInterface, _ string) (*model.KVPairList, error) {
	if _, ok := list.(model.IPAMHandleListOptions); !ok {
		panic(fmt.Sprintf("fakeBackend.List: unsupported list type %T", list))
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.listErr != nil {
		return nil, b.listErr
	}
	out := make([]*model.KVPair, 0, len(b.handles))
	for _, kvp := range b.handles {
		out = append(out, copyHandleKVP(kvp))
	}
	return &model.KVPairList{KVPairs: out}, nil
}

// Unused bapi.Client methods. They panic so accidental use is loud.

func (b *fakeBackend) Apply(ctx context.Context, _ *model.KVPair) (*model.KVPair, error) {
	panic("fakeBackend.Apply: not implemented")
}

func (b *fakeBackend) Delete(ctx context.Context, _ model.Key, _ string) (*model.KVPair, error) {
	panic("fakeBackend.Delete: not implemented (use DeleteKVP)")
}

func (b *fakeBackend) Get(ctx context.Context, _ model.Key, _ string) (*model.KVPair, error) {
	panic("fakeBackend.Get: not implemented")
}

func (b *fakeBackend) Watch(ctx context.Context, _ model.ListInterface, _ bapi.WatchOptions) (bapi.WatchInterface, error) {
	panic("fakeBackend.Watch: not implemented")
}

func (b *fakeBackend) EnsureInitialized() error { return nil }
func (b *fakeBackend) Clean() error             { return nil }
func (b *fakeBackend) Close() error             { return nil }
