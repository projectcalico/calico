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

package migration

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8sdiscovery "k8s.io/client-go/discovery"
	discoveryfake "k8s.io/client-go/discovery/fake"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	rtclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	migrationv1 "github.com/projectcalico/calico/kube-controllers/pkg/apis/migration/v1"
)

// TestResolveServedVersion covers the versions a cluster can be on. v3.32
// installs a v1beta1-only CRD and may never re-apply it.
func TestResolveServedVersion(t *testing.T) {
	for _, tc := range []struct {
		name     string
		served   []string
		expected string
		wantErr  bool
	}{
		{
			name:     "v1 only",
			served:   []string{"v1"},
			expected: "v1",
		},
		{
			name:     "v1beta1 only",
			served:   []string{"v1beta1"},
			expected: "v1beta1",
		},
		{
			name:     "both served prefers v1",
			served:   []string{"v1beta1", "v1"},
			expected: "v1",
		},
		{
			name:    "neither served",
			served:  nil,
			wantErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			version, err := resolveServedVersion(fakeDiscovery(t, tc.served...))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got version %q", version)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolve served version: %v", err)
			}
			if version != tc.expected {
				t.Errorf("got version %q, want %q", version, tc.expected)
			}
		})
	}
}

// TestResolveServedVersionIgnoresOtherResources checks that a group version
// carrying some other resource doesn't count as serving DatastoreMigration.
func TestResolveServedVersionIgnoresOtherResources(t *testing.T) {
	disco, ok := k8sfake.NewSimpleClientset().Discovery().(*discoveryfake.FakeDiscovery)
	if !ok {
		t.Fatal("fake clientset did not return a fake discovery client")
	}
	disco.Resources = []*metav1.APIResourceList{{
		GroupVersion: migrationv1.Group + "/v1",
		APIResources: []metav1.APIResource{{Name: "somethingelse", Kind: "SomethingElse"}},
	}}

	if version, err := resolveServedVersion(disco); err == nil {
		t.Fatalf("expected an error, got version %q", version)
	}
}

// A cluster still on the v3.32 CRD must not be allowed to start a new migration.
func TestRefusePreGAVersion(t *testing.T) {
	m := &migrationController{
		servedVersion: "v1beta1",
		k8sClient:     fakeClientsetServing(t, "v1beta1"),
	}

	err := m.refusePreGAVersion()
	if err == nil {
		t.Fatal("refusePreGAVersion() = nil, want a terminal error")
	}
	if !isTerminal(err) {
		t.Errorf("refusePreGAVersion() = %v, want a terminal error", err)
	}
}

// Applying the v1 CRD over a running controller must clear the guard without a restart.
func TestRefusePreGAVersionRechecksAfterCRDUpgrade(t *testing.T) {
	m := &migrationController{
		servedVersion: "v1beta1",
		k8sClient:     fakeClientsetServing(t, migrationv1.Version, "v1beta1"),
	}

	if err := m.refusePreGAVersion(); err != nil {
		t.Errorf("refusePreGAVersion() = %v, want nil", err)
	}
	if m.servedVersion != migrationv1.Version {
		t.Errorf("servedVersion = %q, want %q", m.servedVersion, migrationv1.Version)
	}
}

// An unresolved version means no guard, so the FV clients are left alone.
func TestRefusePreGAVersionUnresolved(t *testing.T) {
	m := &migrationController{}

	if err := m.refusePreGAVersion(); err != nil {
		t.Errorf("refusePreGAVersion() = %v, want nil", err)
	}
}

// Nothing re-triggers RunWithContext once it returns, so a failed client build
// has to be retried in place.
func TestWaitForServedAPIRetriesClientBuild(t *testing.T) {
	want := fake.NewClientBuilder().Build()
	attempts := 0
	m := &migrationController{
		k8sClient: fakeClientsetServing(t, "v1beta1"),
		rtClientForVersion: func(version string) (rtclient.WithWatch, error) {
			attempts++
			if attempts == 1 {
				return nil, fmt.Errorf("discovery blip")
			}
			return want, nil
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	version, client, err := m.waitForServedAPI(ctx)
	if err != nil {
		t.Fatalf("waitForServedAPI() = %v, want nil", err)
	}
	if version != "v1beta1" {
		t.Errorf("version = %q, want %q", version, "v1beta1")
	}
	if client != want {
		t.Errorf("client = %v, want the client from the successful retry", client)
	}
	if attempts != 2 {
		t.Errorf("rtClientForVersion called %d times, want 2", attempts)
	}
}

// Discovery lags the CRD becoming established, so an unresolved version is retried too.
func TestWaitForServedAPIRetriesDiscovery(t *testing.T) {
	// Two failures covers one full pass over both candidate versions.
	disco := &flakyDiscovery{
		DiscoveryInterfaces: fakeDiscovery(t, migrationv1.Version),
		failures:            2,
	}
	m := &migrationController{
		k8sClient: clientsetWithDiscovery{Interface: k8sfake.NewSimpleClientset(), disco: disco},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	version, _, err := m.waitForServedAPI(ctx)
	if err != nil {
		t.Fatalf("waitForServedAPI() = %v, want nil", err)
	}
	if version != migrationv1.Version {
		t.Errorf("version = %q, want %q", version, migrationv1.Version)
	}
	if disco.failures != 0 {
		t.Errorf("%d discovery failures left unspent, want 0", disco.failures)
	}
}

// The v1 path leaves the pre-built client alone.
func TestWaitForServedAPIKeepsClientForV1(t *testing.T) {
	want := fake.NewClientBuilder().Build()
	m := &migrationController{
		k8sClient: fakeClientsetServing(t, migrationv1.Version),
		rtClient:  want,
		rtClientForVersion: func(version string) (rtclient.WithWatch, error) {
			t.Errorf("rtClientForVersion called for %q, want no call", version)
			return nil, nil
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	version, client, err := m.waitForServedAPI(ctx)
	if err != nil {
		t.Fatalf("waitForServedAPI() = %v, want nil", err)
	}
	if version != migrationv1.Version {
		t.Errorf("version = %q, want %q", version, migrationv1.Version)
	}
	if client != want {
		t.Errorf("client = %v, want the pre-built client", client)
	}
}

// fakeDiscovery returns a discovery client serving DatastoreMigration on each of
// the given versions of the migration group.
func fakeDiscovery(t *testing.T, versions ...string) k8sdiscovery.DiscoveryInterfaces {
	t.Helper()

	return fakeClientsetServing(t, versions...).Discovery()
}

// fakeClientsetServing returns a clientset whose discovery serves DatastoreMigration
// on each of the given versions of the migration group.
func fakeClientsetServing(t *testing.T, versions ...string) kubernetes.Interface {
	t.Helper()

	cs := k8sfake.NewSimpleClientset()
	disco, ok := cs.Discovery().(*discoveryfake.FakeDiscovery)
	if !ok {
		t.Fatal("fake clientset did not return a fake discovery client")
	}
	for _, version := range versions {
		disco.Resources = append(disco.Resources, &metav1.APIResourceList{
			GroupVersion: migrationv1.Group + "/" + version,
			APIResources: []metav1.APIResource{{
				Name: migrationv1.DatastoreMigrationGVR.Resource,
				Kind: "DatastoreMigration",
			}},
		})
	}
	return cs
}

// clientsetWithDiscovery swaps in a discovery client the fake clientset can't produce.
type clientsetWithDiscovery struct {
	kubernetes.Interface

	disco k8sdiscovery.DiscoveryInterfaces
}

func (c clientsetWithDiscovery) Discovery() k8sdiscovery.DiscoveryInterfaces {
	return c.disco
}

// flakyDiscovery reports the group version as absent for the first few lookups.
type flakyDiscovery struct {
	k8sdiscovery.DiscoveryInterfaces

	failures int
}

func (f *flakyDiscovery) ServerResourcesForGroupVersion(groupVersion string) (*metav1.APIResourceList, error) {
	if f.failures > 0 {
		f.failures--
		return nil, kerrors.NewNotFound(schema.GroupResource{Resource: groupVersion}, "")
	}
	return f.DiscoveryInterfaces.ServerResourcesForGroupVersion(groupVersion)
}

// installationGVR is the Installation resource isOperatorManaged looks for.
var installationGVR = schema.GroupVersionResource{Group: "operator.tigera.io", Version: "v1", Resource: "installations"}

// k8sfakeWithDiscovery returns a clientset whose discovery serves the operator
// API group, so isOperatorManaged gets past the discovery check.
func k8sfakeWithDiscovery(t *testing.T) kubernetes.Interface {
	t.Helper()

	cs := k8sfake.NewSimpleClientset()
	disco, ok := cs.Discovery().(*discoveryfake.FakeDiscovery)
	if !ok {
		t.Fatal("fake clientset did not return a fake discovery client")
	}
	disco.Resources = append(disco.Resources, &metav1.APIResourceList{
		GroupVersion: "operator.tigera.io/v1",
		APIResources: []metav1.APIResource{{Name: "installations", Kind: "Installation"}},
	})
	return cs
}

// installationDynamicClient returns a dynamic client holding the given Installations.
func installationDynamicClient(objs ...runtime.Object) *dynamicfake.FakeDynamicClient {
	return dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
		runtime.NewScheme(),
		map[schema.GroupVersionResource]string{installationGVR: "InstallationList"},
		objs...,
	)
}

// installationObj is a minimal Installation CR.
func installationObj() *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "operator.tigera.io/v1",
		"kind":       "Installation",
		"metadata":   map[string]any{"name": "default"},
	}}
}

// The operator only grants the RBAC to read Installations once a migration starts,
// so a negative answer has to be retried rather than cached for the process.
func TestIsOperatorManagedRetriesUntilVisible(t *testing.T) {
	dyn := installationDynamicClient()
	dyn.PrependReactor("list", "installations", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, kerrors.NewForbidden(installationGVR.GroupResource(), "", errors.New("no RBAC yet"))
	})

	m := &migrationController{
		ctx:           context.Background(),
		k8sClient:     k8sfakeWithDiscovery(t),
		dynamicClient: dyn,
	}
	if m.isOperatorManaged() {
		t.Fatal("isOperatorManaged() = true while the list is forbidden, want false")
	}

	// RBAC lands and the Installation becomes readable.
	m.dynamicClient = installationDynamicClient(installationObj())
	if !m.isOperatorManaged() {
		t.Error("isOperatorManaged() = false after the Installation became readable, want true")
	}
}

// Once seen, the answer sticks even if a later read fails.
func TestIsOperatorManagedCachesTrue(t *testing.T) {
	m := &migrationController{
		ctx:           context.Background(),
		k8sClient:     k8sfakeWithDiscovery(t),
		dynamicClient: installationDynamicClient(installationObj()),
	}
	if !m.isOperatorManaged() {
		t.Fatal("isOperatorManaged() = false with an Installation present, want true")
	}

	m.dynamicClient = installationDynamicClient()
	if !m.isOperatorManaged() {
		t.Error("isOperatorManaged() = false on a later failed read, want the cached true")
	}
}
