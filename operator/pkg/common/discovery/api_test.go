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

package discovery

import (
	"testing"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// fakeAPIMapper returns the registered versions for the given GroupKind. Other RESTMapper methods
// are not implemented because APIDiscovery only uses RESTMappings.
type fakeAPIMapper struct {
	meta.RESTMapper
	served map[schema.GroupKind][]string
	calls  int
}

func (f *fakeAPIMapper) RESTMappings(gk schema.GroupKind, _ ...string) ([]*meta.RESTMapping, error) {
	f.calls++
	versions, ok := f.served[gk]
	if !ok {
		return nil, &meta.NoKindMatchError{GroupKind: gk}
	}
	out := make([]*meta.RESTMapping, 0, len(versions))
	for _, v := range versions {
		out = append(out, &meta.RESTMapping{GroupVersionKind: gk.WithVersion(v)})
	}
	return out, nil
}

func TestAPIDiscoveryRecordsPreferredVersion(t *testing.T) {
	served := map[schema.GroupKind][]string{}
	for _, gk := range trackedGroupKinds {
		served[gk] = []string{"v1", "v1beta1"}
	}
	mapper := &fakeAPIMapper{served: served}

	d := DiscoverAPIs(mapper)

	for _, gk := range trackedGroupKinds {
		if got := d.ServedVersion(gk.Group, gk.Kind); got != "v1" {
			t.Errorf("%s: got %q, want v1", gk, got)
		}
	}
	if got := d.ServedVersion("never.registered.com", "Other"); got != "" {
		t.Errorf("untracked GroupKind: got %q, want empty", got)
	}
}

func TestAPIDiscoveryUnservedGroupKind(t *testing.T) {
	mapper := &fakeAPIMapper{served: map[schema.GroupKind][]string{}}
	d := DiscoverAPIs(mapper)
	for _, gk := range trackedGroupKinds {
		if got := d.ServedVersion(gk.Group, gk.Kind); got != "" {
			t.Errorf("%s served unexpectedly: %q", gk, got)
		}
	}
}

func TestAPIDiscoveryNoCallsAfterConstruction(t *testing.T) {
	served := map[schema.GroupKind][]string{}
	for _, gk := range trackedGroupKinds {
		served[gk] = []string{"v1"}
	}
	mapper := &fakeAPIMapper{served: served}
	d := DiscoverAPIs(mapper)
	calls := mapper.calls

	for i := 0; i < 100; i++ {
		for _, gk := range trackedGroupKinds {
			_ = d.ServedVersion(gk.Group, gk.Kind)
		}
		_ = d.ServedVersion("nope", "Other")
	}
	if mapper.calls != calls {
		t.Errorf("expected zero additional mapper calls after construction, got %d (was %d)", mapper.calls, calls)
	}
}

func TestNilAPIDiscoverySafe(t *testing.T) {
	var d *APIDiscovery
	if got := d.ServedVersion("g", "K"); got != "" {
		t.Errorf("nil APIDiscovery: got %q, want empty", got)
	}
}
