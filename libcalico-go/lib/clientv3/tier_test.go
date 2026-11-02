// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package clientv3

import (
	"context"
	"errors"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/names"
)

var _ = Describe("ensureTierExists", func() {
	var be *fakeTierBackend
	var c client

	ensureDefaultTier := func() error {
		return c.ensureTierExists(context.Background(), names.DefaultTierName, v3.Deny, v3.DefaultTierOrder)
	}

	BeforeEach(func() {
		be = &fakeTierBackend{tiers: map[string]*v3.Tier{}}
		var ok bool
		c, ok = NewFromBackend(apiconfig.CalicoAPIConfig{}, be).(client)
		Expect(ok).To(BeTrue())
	})

	It("should create the tier when it does not exist", func() {
		Expect(ensureDefaultTier()).NotTo(HaveOccurred())
		Expect(be.creates).To(Equal(1))
		Expect(be.tiers).To(HaveKey(names.DefaultTierName))
	})

	It("should not write to the datastore when the tier already exists", func() {
		Expect(ensureDefaultTier()).NotTo(HaveOccurred())
		be.creates = 0

		Expect(ensureDefaultTier()).NotTo(HaveOccurred())
		Expect(be.creates).To(BeZero())
	})

	It("should tolerate a tier created by another client after the get", func() {
		be.createErr = cerrors.ErrorResourceAlreadyExists{Identifier: names.DefaultTierName}
		Expect(ensureDefaultTier()).NotTo(HaveOccurred())
	})

	It("should return an error when the get fails", func() {
		be.getErr = errors.New("datastore unavailable")
		Expect(ensureDefaultTier()).To(MatchError(be.getErr))
		Expect(be.creates).To(BeZero())
	})

	It("should ignore a tier it is not authorized to read", func() {
		be.getErr = cerrors.ErrorConnectionUnauthorized{Err: errors.New("forbidden")}
		Expect(ensureDefaultTier()).NotTo(HaveOccurred())
		Expect(be.creates).To(BeZero())
	})
})

// fakeTierBackend serves tiers from memory and counts the writes made against it.
type fakeTierBackend struct {
	tiers map[string]*v3.Tier

	// Errors to return instead of serving the request.
	getErr    error
	createErr error

	creates int
}

var (
	_ bapi.Client = &fakeTierBackend{}

	errFakeUnsupported = errors.New("operation not supported by fakeTierBackend")
)

func (f *fakeTierBackend) Get(ctx context.Context, key model.Key, revision string) (*model.KVPair, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	rk, ok := key.(model.ResourceKey)
	if !ok {
		return nil, errFakeUnsupported
	}
	tier, ok := f.tiers[rk.Name]
	if !ok {
		return nil, cerrors.ErrorResourceDoesNotExist{Identifier: key}
	}
	return &model.KVPair{Key: key, Value: tier, Revision: "1"}, nil
}

func (f *fakeTierBackend) Create(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	f.creates++
	if f.createErr != nil {
		return nil, f.createErr
	}
	rk, ok := kvp.Key.(model.ResourceKey)
	if !ok {
		return nil, errFakeUnsupported
	}
	if _, ok := f.tiers[rk.Name]; ok {
		return nil, cerrors.ErrorResourceAlreadyExists{Identifier: kvp.Key}
	}
	tier, ok := kvp.Value.(*v3.Tier)
	if !ok {
		return nil, errFakeUnsupported
	}
	f.tiers[rk.Name] = tier
	return &model.KVPair{Key: kvp.Key, Value: tier, Revision: "1"}, nil
}

func (f *fakeTierBackend) Update(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	return nil, errFakeUnsupported
}

func (f *fakeTierBackend) Apply(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	return nil, errFakeUnsupported
}

func (f *fakeTierBackend) Delete(ctx context.Context, key model.Key, revision string) (*model.KVPair, error) {
	return nil, errFakeUnsupported
}

func (f *fakeTierBackend) DeleteKVP(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	return nil, errFakeUnsupported
}

func (f *fakeTierBackend) List(ctx context.Context, list model.ListInterface, revision string) (*model.KVPairList, error) {
	return nil, errFakeUnsupported
}

func (f *fakeTierBackend) Watch(ctx context.Context, list model.ListInterface, options bapi.WatchOptions) (bapi.WatchInterface, error) {
	return nil, errFakeUnsupported
}

func (f *fakeTierBackend) EnsureInitialized() error {
	return nil
}

func (f *fakeTierBackend) Clean() error {
	return nil
}

func (f *fakeTierBackend) Close() error {
	return nil
}
