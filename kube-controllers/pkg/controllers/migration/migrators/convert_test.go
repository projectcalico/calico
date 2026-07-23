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

package migrators

import (
	"testing"
	"time"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

func TestDefaultConvert_ClearsServerMetadata(t *testing.T) {
	kvp := &model.KVPair{
		Value: &apiv3.Tier{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "test-tier",
				ResourceVersion:   "12345",
				Generation:        3,
				CreationTimestamp: metav1.Time{Time: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)},
				ManagedFields: []metav1.ManagedFieldsEntry{
					{Manager: "kubectl"},
				},
			},
		},
	}

	result, err := defaultConvert[apiv3.Tier](kvp)
	if err != nil {
		t.Fatalf("defaultConvert: %v", err)
	}
	if result.ResourceVersion != "" {
		t.Errorf("ResourceVersion should be cleared, got %q", result.ResourceVersion)
	}
	if result.Generation != 0 {
		t.Errorf("Generation should be 0, got %d", result.Generation)
	}
	if !result.CreationTimestamp.IsZero() {
		t.Errorf("CreationTimestamp should be zero, got %v", result.CreationTimestamp)
	}
	if result.ManagedFields != nil {
		t.Errorf("ManagedFields should be nil, got %v", result.ManagedFields)
	}
}

func TestDefaultConvert_PreservesUIDAndOwnerRefs(t *testing.T) {
	uid := types.UID("test-uid-12345")
	ownerRefs := []metav1.OwnerReference{
		{
			APIVersion: "projectcalico.org/v3",
			Kind:       "Tier",
			Name:       "default",
			UID:        types.UID("owner-uid"),
		},
	}

	kvp := &model.KVPair{
		Value: &apiv3.GlobalNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "test-gnp",
				UID:             uid,
				OwnerReferences: ownerRefs,
			},
		},
	}

	result, err := defaultConvert[apiv3.GlobalNetworkPolicy](kvp)
	if err != nil {
		t.Fatalf("defaultConvert: %v", err)
	}
	if result.UID != uid {
		t.Errorf("UID should be preserved, got %q want %q", result.UID, uid)
	}
	if len(result.OwnerReferences) != 1 {
		t.Fatalf("OwnerReferences should be preserved, got %d", len(result.OwnerReferences))
	}
	if result.OwnerReferences[0].UID != ownerRefs[0].UID {
		t.Errorf("OwnerRef UID should be preserved, got %q want %q", result.OwnerReferences[0].UID, ownerRefs[0].UID)
	}
}

func TestDefaultConvert_FiltersInternalAnnotation(t *testing.T) {
	kvp := &model.KVPair{
		Value: &apiv3.Tier{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-tier",
				Annotations: map[string]string{
					"projectcalico.org/metadata": `{"uid":"ignored"}`,
					"custom-annotation":          "keep-me",
				},
			},
		},
	}

	result, err := defaultConvert[apiv3.Tier](kvp)
	if err != nil {
		t.Fatalf("defaultConvert: %v", err)
	}
	if _, ok := result.Annotations["projectcalico.org/metadata"]; ok {
		t.Error("internal metadata annotation should be filtered")
	}
	if result.Annotations["custom-annotation"] != "keep-me" {
		t.Error("custom annotations should be preserved")
	}
}

func TestDefaultConvert_NilsAnnotationsWhenOnlyInternal(t *testing.T) {
	kvp := &model.KVPair{
		Value: &apiv3.Tier{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-tier",
				Annotations: map[string]string{
					"projectcalico.org/metadata": `{"uid":"ignored"}`,
				},
			},
		},
	}

	result, err := defaultConvert[apiv3.Tier](kvp)
	if err != nil {
		t.Fatalf("defaultConvert: %v", err)
	}
	if result.Annotations != nil {
		t.Errorf("annotations should be nil when only internal annotation present, got %v", result.Annotations)
	}
}

func TestDefaultConvert_DeepCopiesSpec(t *testing.T) {
	order := float64(100)
	original := &apiv3.Tier{
		ObjectMeta: metav1.ObjectMeta{Name: "test-tier"},
		Spec:       apiv3.TierSpec{Order: &order},
	}
	kvp := &model.KVPair{Value: original}

	result, err := defaultConvert[apiv3.Tier](kvp)
	if err != nil {
		t.Fatalf("defaultConvert: %v", err)
	}

	// Mutating the result should not affect the original.
	*result.Spec.Order = 999
	if *original.Spec.Order != 100 {
		t.Error("defaultConvert should deep copy — mutating result affected original")
	}
}

func TestDefaultConvert_WrongType(t *testing.T) {
	kvp := &model.KVPair{Value: "not a tier"}
	_, err := defaultConvert[apiv3.Tier](kvp)
	if err == nil {
		t.Fatal("expected error for wrong type")
	}
}
