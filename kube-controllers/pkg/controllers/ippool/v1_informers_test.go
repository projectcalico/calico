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

package ippool

import (
	"testing"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/client/clientset_generated/clientset/fake"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/resources"
)

func TestTransformV1Pool_RestoresAnnotationMetadata(t *testing.T) {
	deleting := metav1.Unix(1000, 0)
	pool := testPool("pool-1", "192.168.0.0/24")
	pool.Finalizers = []string{IPPoolFinalizer}
	pool.DeletionTimestamp = &deleting

	// Build the v1 form the same way libcalico writes it, with metadata folded into an annotation.
	stored, err := resources.ConvertCalicoResourceToK8sResource(pool)
	if err != nil {
		t.Fatalf("convert to v1: %v", err)
	}
	if len(stored.GetObjectMeta().GetFinalizers()) != 0 {
		t.Fatal("expected v1 form to carry finalizers only in the metadata annotation")
	}
	obj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(stored)
	if err != nil {
		t.Fatalf("convert to unstructured: %v", err)
	}

	out, err := transformV1Pool(&unstructured.Unstructured{Object: obj})
	if err != nil {
		t.Fatalf("transform: %v", err)
	}
	got, ok := out.(*v3.IPPool)
	if !ok {
		t.Fatalf("expected *v3.IPPool, got %T", out)
	}
	if got.Name != "pool-1" || got.Spec.CIDR != "192.168.0.0/24" {
		t.Fatalf("unexpected pool %s/%s", got.Name, got.Spec.CIDR)
	}
	if !hasFinalizer(got) {
		t.Fatalf("expected finalizer restored from annotation, got %v", got.Finalizers)
	}
	if got.DeletionTimestamp == nil || !got.DeletionTimestamp.Equal(&deleting) {
		t.Fatalf("expected deletion timestamp restored from annotation, got %v", got.DeletionTimestamp)
	}
}

func TestTransformV1Block(t *testing.T) {
	obj := map[string]any{
		"apiVersion": "crd.projectcalico.org/v1",
		"kind":       "IPAMBlock",
		"metadata":   map[string]any{"name": "10-0-0-0-26"},
		"spec": map[string]any{
			"cidr":        "10.0.0.0/26",
			"allocations": []any{int64(0), nil},
			"unallocated": []any{int64(1)},
			"attributes": []any{
				map[string]any{
					"handle_id":  "handle-1",
					"releasedAt": "2026-09-28T00:00:00Z",
				},
			},
		},
	}

	out, err := transformV1Block(&unstructured.Unstructured{Object: obj})
	if err != nil {
		t.Fatalf("transform: %v", err)
	}
	block, ok := out.(*v3.IPAMBlock)
	if !ok {
		t.Fatalf("expected *v3.IPAMBlock, got %T", out)
	}
	if block.Spec.CIDR != "10.0.0.0/26" {
		t.Fatalf("unexpected CIDR %q", block.Spec.CIDR)
	}
	if len(block.Spec.Allocations) != 2 || block.Spec.Allocations[0] == nil || *block.Spec.Allocations[0] != 0 || block.Spec.Allocations[1] != nil {
		t.Fatalf("unexpected allocations %v", block.Spec.Allocations)
	}
	if len(block.Spec.Attributes) != 1 || block.Spec.Attributes[0].ReleasedAt == nil {
		t.Fatalf("expected releasedAt to survive conversion, got %+v", block.Spec.Attributes)
	}
}

func TestTransformPassesThroughNonUnstructured(t *testing.T) {
	tombstone := "not-an-object"
	for name, transform := range map[string]func(any) (any, error){
		"pool":  transformV1Pool,
		"block": transformV1Block,
	} {
		out, err := transform(tombstone)
		if err != nil || out != tombstone {
			t.Fatalf("%s: expected passthrough, got %v, %v", name, out, err)
		}
	}
}

func TestReconcile_FinalizersOnlyWhenManaged(t *testing.T) {
	for _, manage := range []bool{true, false} {
		pool := testPool("pool-1", "192.168.0.0/24")
		cli := fake.NewClientset(pool)
		c, _ := newTestController(cli, pool)
		c.manageFinalizers = manage

		if err := c.reconcile(); err != nil {
			t.Fatalf("manage=%v: reconcile: %v", manage, err)
		}

		got, err := cli.ProjectcalicoV3().IPPools().Get(c.ctx, pool.Name, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("manage=%v: get: %v", manage, err)
		}
		if hasFinalizer(got) != manage {
			t.Fatalf("manage=%v: finalizers %v", manage, got.Finalizers)
		}
		if !hasCondition(got, v3.IPPoolConditionAllocatable, metav1.ConditionTrue) {
			t.Fatalf("manage=%v: expected Allocatable=True, got %+v", manage, got.Status)
		}
	}
}
