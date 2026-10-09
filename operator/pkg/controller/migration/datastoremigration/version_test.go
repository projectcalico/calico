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

package datastoremigration

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/kubernetes/fake"
)

// discoveryServing returns a discovery client serving datastoremigrations at each given version.
func discoveryServing(versions ...schema.GroupVersion) discovery.DiscoveryInterface {
	c := fake.NewClientset()
	for _, gv := range versions {
		c.Resources = append(c.Resources, &metav1.APIResourceList{
			GroupVersion: gv.String(),
			APIResources: []metav1.APIResource{{Name: Resource, Kind: Kind}},
		})
	}
	return c.Discovery()
}

// failingDiscovery fails the first failures lookups, then behaves like the wrapped client.
type failingDiscovery struct {
	discovery.DiscoveryInterface

	remaining atomic.Int32
	attempts  atomic.Int32
}

func (d *failingDiscovery) ServerResourcesForGroupVersion(gv string) (*metav1.APIResourceList, error) {
	d.attempts.Add(1)
	if d.remaining.Add(-1) >= 0 {
		return nil, errors.New("connection refused")
	}
	return d.DiscoveryInterface.ServerResourcesForGroupVersion(gv)
}

func TestServedGroupVersion(t *testing.T) {
	cases := []struct {
		name   string
		disco  discovery.DiscoveryInterface
		want   schema.GroupVersion
		wantOK bool
	}{
		{"v1 only", discoveryServing(GroupVersionV1), GroupVersionV1, true},
		{"v1beta1 only", discoveryServing(GroupVersionV1beta1), GroupVersionV1beta1, true},
		{"both served prefers v1", discoveryServing(GroupVersionV1beta1, GroupVersionV1), GroupVersionV1, true},
		{"neither served", discoveryServing(), schema.GroupVersion{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok, err := ServedGroupVersion(tc.disco)
			if err != nil {
				t.Fatalf("ServedGroupVersion() error = %v, want nil", err)
			}
			if ok != tc.wantOK {
				t.Fatalf("ServedGroupVersion() ok = %t, want %t", ok, tc.wantOK)
			}
			if got != tc.want {
				t.Errorf("ServedGroupVersion() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestServedGroupVersionIgnoresGroupWithoutResource(t *testing.T) {
	c := fake.NewClientset()
	c.Resources = []*metav1.APIResourceList{{GroupVersion: GroupVersionV1.String()}}

	_, ok, err := ServedGroupVersion(c.Discovery())
	if err != nil {
		t.Fatalf("ServedGroupVersion() error = %v, want nil", err)
	}
	if ok {
		t.Error("ServedGroupVersion() = true, want false when the group serves no datastoremigrations")
	}
}

// A lookup failure must not read as an absent CRD, or we'd pin the wrong version.
func TestServedGroupVersionReportsLookupFailure(t *testing.T) {
	disco := &failingDiscovery{DiscoveryInterface: discoveryServing(GroupVersionV1beta1)}
	disco.remaining.Store(1)

	if _, ok, err := ServedGroupVersion(disco); err == nil {
		t.Errorf("ServedGroupVersion() ok = %t, err = nil, want an error", ok)
	}
}

func TestWaitForServedVersion(t *testing.T) {
	cases := []struct {
		name  string
		disco discovery.DiscoveryInterface
		want  schema.GroupVersion
	}{
		{"picks up the legacy version", discoveryServing(GroupVersionV1beta1), GroupVersionV1beta1},
		{"picks up v1", discoveryServing(GroupVersionV1), GroupVersionV1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer restoreServedVersion(t)()

			WaitForServedVersion(context.Background(), tc.disco)
			if got := ServedVersion(); got != tc.want {
				t.Fatalf("ServedVersion() = %v, want %v", got, tc.want)
			}
			if got := WatchObject().GetObjectKind().GroupVersionKind().GroupVersion(); got != tc.want {
				t.Errorf("WatchObject() group version = %v, want %v", got, tc.want)
			}
		})
	}
}

// The CRD is normally installed long after startup, so a missing one can't resolve to v1.
func TestWaitForServedVersionWaitsForTheCRD(t *testing.T) {
	defer restoreServedVersion(t)()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		WaitForServedVersion(ctx, discoveryServing())
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("WaitForServedVersion() did not return when the context was cancelled")
	}
	if got := ServedVersion(); got != GroupVersionV1 {
		t.Errorf("ServedVersion() = %v, want the %v default", got, GroupVersionV1)
	}
}

func TestWaitForServedVersionRetriesLookupFailures(t *testing.T) {
	defer restoreServedVersion(t)()

	disco := &failingDiscovery{DiscoveryInterface: discoveryServing(GroupVersionV1beta1)}
	disco.remaining.Store(2)

	WaitForServedVersion(context.Background(), disco)
	if got := ServedVersion(); got != GroupVersionV1beta1 {
		t.Fatalf("ServedVersion() = %v, want %v", got, GroupVersionV1beta1)
	}
	if got := disco.attempts.Load(); got < 3 {
		t.Errorf("discovery attempts = %d, want at least 3", got)
	}
}

func restoreServedVersion(t *testing.T) func() {
	t.Helper()
	original := ServedVersion()
	return func() {
		servedMutex.Lock()
		defer servedMutex.Unlock()
		servedVersion = original
	}
}
