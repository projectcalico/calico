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
	"fmt"
	"testing"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	rtclient "sigs.k8s.io/controller-runtime/pkg/client"
)

func TestRemapOwnerReferences_RemapsCalicoRefs(t *testing.T) {
	oldUID := types.UID("old-tier-uid")
	newUID := types.UID("new-tier-uid")

	gnp := &apiv3.GlobalNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-gnp",
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: "projectcalico.org/v3",
					Kind:       "Tier",
					Name:       "default",
					UID:        oldUID,
				},
			},
		},
	}

	var updated []rtclient.Object
	update := func(_ context.Context, obj rtclient.Object, _ ...rtclient.UpdateOption) error {
		updated = append(updated, obj)
		return nil
	}

	err := RemapOwnerReferences(context.Background(), map[types.UID]types.UID{oldUID: newUID}, []rtclient.Object{gnp}, update)
	if err != nil {
		t.Fatalf("RemapOwnerReferences: %v", err)
	}
	if len(updated) != 1 {
		t.Fatalf("expected 1 update, got %d", len(updated))
	}
	if gnp.OwnerReferences[0].UID != newUID {
		t.Errorf("OwnerRef UID should be remapped to %q, got %q", newUID, gnp.OwnerReferences[0].UID)
	}
}

func TestRemapOwnerReferences_PreservesNonCalicoRefs(t *testing.T) {
	calicoOld := types.UID("old-calico-uid")
	calicoNew := types.UID("new-calico-uid")
	k8sUID := types.UID("namespace-uid")

	gnp := &apiv3.GlobalNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-gnp",
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: "projectcalico.org/v3",
					Kind:       "Tier",
					Name:       "default",
					UID:        calicoOld,
				},
				{
					APIVersion: "v1",
					Kind:       "Namespace",
					Name:       "production",
					UID:        k8sUID,
				},
			},
		},
	}

	update := func(_ context.Context, _ rtclient.Object, _ ...rtclient.UpdateOption) error { return nil }

	err := RemapOwnerReferences(context.Background(), map[types.UID]types.UID{calicoOld: calicoNew}, []rtclient.Object{gnp}, update)
	if err != nil {
		t.Fatalf("RemapOwnerReferences: %v", err)
	}
	if gnp.OwnerReferences[0].UID != calicoNew {
		t.Errorf("Calico OwnerRef should be remapped, got %q", gnp.OwnerReferences[0].UID)
	}
	if gnp.OwnerReferences[1].UID != k8sUID {
		t.Errorf("non-Calico OwnerRef should be untouched, got %q want %q", gnp.OwnerReferences[1].UID, k8sUID)
	}
}

func TestRemapOwnerReferences_SkipsWhenNoMappingExists(t *testing.T) {
	unmappedUID := types.UID("not-in-the-map")

	gnp := &apiv3.GlobalNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-gnp",
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: "projectcalico.org/v3",
					Kind:       "Tier",
					Name:       "default",
					UID:        unmappedUID,
				},
			},
		},
	}

	updateCalled := false
	update := func(_ context.Context, _ rtclient.Object, _ ...rtclient.UpdateOption) error {
		updateCalled = true
		return nil
	}

	err := RemapOwnerReferences(context.Background(), map[types.UID]types.UID{}, []rtclient.Object{gnp}, update)
	if err != nil {
		t.Fatalf("RemapOwnerReferences: %v", err)
	}
	if updateCalled {
		t.Error("update should not be called when no UIDs need remapping")
	}
	if gnp.OwnerReferences[0].UID != unmappedUID {
		t.Errorf("UID should be unchanged, got %q", gnp.OwnerReferences[0].UID)
	}
}

func TestRemapOwnerReferences_PropagatesUpdateError(t *testing.T) {
	oldUID := types.UID("old-uid")
	newUID := types.UID("new-uid")

	gnp := &apiv3.GlobalNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-gnp",
			OwnerReferences: []metav1.OwnerReference{
				{APIVersion: "projectcalico.org/v3", Kind: "Tier", UID: oldUID},
			},
		},
	}

	update := func(_ context.Context, _ rtclient.Object, _ ...rtclient.UpdateOption) error {
		return fmt.Errorf("simulated update failure")
	}

	err := RemapOwnerReferences(context.Background(), map[types.UID]types.UID{oldUID: newUID}, []rtclient.Object{gnp}, update)
	if err == nil {
		t.Fatal("expected error to be propagated")
	}
}

func TestRemapOwnerReferences_EmptyInputs(t *testing.T) {
	update := func(_ context.Context, _ rtclient.Object, _ ...rtclient.UpdateOption) error {
		t.Fatal("update should not be called")
		return nil
	}

	// Empty UID map.
	if err := RemapOwnerReferences(context.Background(), nil, []rtclient.Object{&apiv3.Tier{}}, update); err != nil {
		t.Fatalf("empty uidMap: %v", err)
	}

	// Empty objects.
	if err := RemapOwnerReferences(context.Background(), map[types.UID]types.UID{"a": "b"}, nil, update); err != nil {
		t.Fatalf("empty objects: %v", err)
	}
}

func TestIsCalicoAPIGroup(t *testing.T) {
	tests := []struct {
		group string
		want  bool
	}{
		{"projectcalico.org", true},
		{"projectcalico.org/v3", true},
		{"crd.projectcalico.org", true},
		{"crd.projectcalico.org/v1", true},
		{"v1", false},
		{"apps/v1", false},
		{"", false},
		{"notprojectcalico.org", false},
	}
	for _, tt := range tests {
		t.Run(tt.group, func(t *testing.T) {
			if got := isCalicoAPIGroup(tt.group); got != tt.want {
				t.Errorf("isCalicoAPIGroup(%q) = %v, want %v", tt.group, got, tt.want)
			}
		})
	}
}
