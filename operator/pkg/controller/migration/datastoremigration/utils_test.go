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
	"testing"

	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func newFakeClient(t *testing.T, gv schema.GroupVersion, objects ...*unstructured.Unstructured) client.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	for _, v := range []schema.GroupVersion{GroupVersionV1, GroupVersionV1beta1} {
		scheme.AddKnownTypeWithName(v.WithKind(Kind), &unstructured.Unstructured{})
		scheme.AddKnownTypeWithName(v.WithKind(ListKind), &unstructured.UnstructuredList{})
		metav1.AddToGroupVersion(scheme, v)
	}

	b := fake.NewClientBuilder().WithScheme(scheme)
	for _, obj := range objects {
		b = b.WithObjects(obj)
	}
	return b.Build()
}

func migrationCR(gv schema.GroupVersion, name, phase string) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(gv.WithKind(Kind))
	obj.SetName(name)
	if phase != "" {
		if err := unstructured.SetNestedField(obj.Object, phase, "status", "phase"); err != nil {
			panic(err)
		}
	}
	return obj
}

func TestGetPhaseAndExists(t *testing.T) {
	tests := []struct {
		name      string
		phase     string
		noCR      bool
		nilClient bool
		wantPhase string
		wantExist bool
	}{
		{
			name:      "nil client",
			nilClient: true,
			wantPhase: "",
			wantExist: false,
		},
		{
			name:      "no CRs",
			noCR:      true,
			wantPhase: "",
			wantExist: false,
		},
		{
			name:      "CR with no status",
			wantPhase: "",
			wantExist: true,
		},
		{
			name:      "CR in Migrating phase",
			phase:     PhaseMigrating,
			wantPhase: PhaseMigrating,
			wantExist: true,
		},
		{
			name:      "CR in Converged phase",
			phase:     PhaseConverged,
			wantPhase: PhaseConverged,
			wantExist: true,
		},
		{
			name:      "CR in Complete phase",
			phase:     PhaseComplete,
			wantPhase: PhaseComplete,
			wantExist: true,
		},
	}

	// Both served versions are read through the same unstructured path, so run each case twice.
	for _, gv := range []schema.GroupVersion{GroupVersionV1, GroupVersionV1beta1} {
		for _, tt := range tests {
			t.Run(gv.Version+"/"+tt.name, func(t *testing.T) {
				g := NewWithT(t)
				defer withServedVersion(t, gv)()

				if tt.nilClient {
					g.Expect(GetPhase(nil)).To(Equal(tt.wantPhase))
					g.Expect(Exists(nil)).To(Equal(tt.wantExist))
					return
				}

				var objects []*unstructured.Unstructured
				if !tt.noCR {
					objects = append(objects, migrationCR(gv, "default", tt.phase))
				}

				c := newFakeClient(t, gv, objects...)
				g.Expect(GetPhase(c)).To(Equal(tt.wantPhase))
				g.Expect(Exists(c)).To(Equal(tt.wantExist))
			})
		}
	}
}

// A CR written at the version the cluster doesn't serve must not be read as present.
func TestGetPhaseUsesTheServedVersion(t *testing.T) {
	g := NewWithT(t)
	defer withServedVersion(t, GroupVersionV1)()

	c := newFakeClient(t, GroupVersionV1beta1, migrationCR(GroupVersionV1beta1, "default", PhaseMigrating))
	g.Expect(GetPhase(c)).To(BeEmpty())

	defer withServedVersion(t, GroupVersionV1beta1)()
	g.Expect(GetPhase(c)).To(Equal(PhaseMigrating))
}

func withServedVersion(t *testing.T, gv schema.GroupVersion) func() {
	t.Helper()
	restore := restoreServedVersion(t)
	servedMutex.Lock()
	servedVersion = gv
	servedMutex.Unlock()
	return restore
}
