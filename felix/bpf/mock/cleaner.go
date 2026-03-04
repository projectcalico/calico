//go:build !windows

// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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

package mock

import (
	"github.com/projectcalico/calico/felix/bpf/conntrack"
	"github.com/projectcalico/calico/felix/bpf/maps"
)

type mockBPFCleaner struct {
	ctMap        *Map
	ctCleanupMap *Map
}

func NewMockBPFCleaner(ctMap, ctCleanupMap *Map) *mockBPFCleaner {
	return &mockBPFCleaner{ctMap: ctMap, ctCleanupMap: ctCleanupMap}
}

func (m *mockBPFCleaner) Run(opts ...conntrack.RunOpt) (*conntrack.CleanupContext, error) {
	err := m.ctCleanupMap.Iter(func(k, v []byte) maps.IteratorAction {
		revKey := conntrack.CleanupValueFromBytes(v).OtherNATKey()
		if revKey.Proto() != 0 {
			if err := m.ctMap.Delete(revKey.AsBytes()); err != nil {
				return maps.IterNone
			}
		}
		if err := m.ctMap.Delete(k); err != nil {
			return maps.IterNone
		}
		return maps.IterDelete
	})
	return &conntrack.CleanupContext{}, err
}

func (m *mockBPFCleaner) Close() error {
	return nil
}
