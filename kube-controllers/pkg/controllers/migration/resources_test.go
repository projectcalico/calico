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
	"testing"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

func TestConvertIPAMBlock(t *testing.T) {
	cidr := cnet.MustParseCIDR("10.0.0.0/30")
	handle1 := "k8s-pod-network.abc123"
	handle2 := "k8s-pod-network.def456"
	uid := types.UID("block-uid-1")

	kvp := &model.KVPair{
		Value: &model.AllocationBlock{
			CIDR:     cidr,
			Affinity: ptr.To("host:node-1"),
			Allocations: []*int{
				ptr.To(0),
				ptr.To(1),
				nil,
				nil,
			},
			Unallocated: []int{2, 3},
			Attributes: []model.AllocationAttribute{
				{
					HandleID:         &handle1,
					ActiveOwnerAttrs: map[string]string{"namespace": "default", "pod": "nginx-abc123", "node": "node-1"},
				},
				{
					HandleID:         &handle2,
					ActiveOwnerAttrs: map[string]string{"namespace": "kube-system", "pod": "coredns-def456", "node": "node-1"},
				},
			},
			SequenceNumber:              5,
			SequenceNumberForAllocation: map[string]uint64{"0": 4, "1": 5},
			Deleted:                     false,
		},
		UID: &uid,
	}

	block, err := convertIPAMBlock(kvp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if block.Name != "10-0-0-0-30" {
		t.Errorf("expected name 10-0-0-0-30, got %s", block.Name)
	}
	if block.UID != uid {
		t.Errorf("expected UID %s, got %s", uid, block.UID)
	}
	if block.Spec.CIDR != "10.0.0.0/30" {
		t.Errorf("expected CIDR 10.0.0.0/30, got %s", block.Spec.CIDR)
	}
	if *block.Spec.Affinity != "host:node-1" {
		t.Errorf("expected affinity host:node-1, got %s", *block.Spec.Affinity)
	}
	if len(block.Spec.Allocations) != 4 {
		t.Fatalf("expected 4 allocations, got %d", len(block.Spec.Allocations))
	}
	if len(block.Spec.Unallocated) != 2 {
		t.Errorf("expected 2 unallocated, got %d", len(block.Spec.Unallocated))
	}
	if len(block.Spec.Attributes) != 2 {
		t.Fatalf("expected 2 attributes, got %d", len(block.Spec.Attributes))
	}
	if *block.Spec.Attributes[0].HandleID != handle1 {
		t.Errorf("expected handle ID %s, got %s", handle1, *block.Spec.Attributes[0].HandleID)
	}
	if block.Spec.Attributes[0].ActiveOwnerAttrs["pod"] != "nginx-abc123" {
		t.Error("expected ActiveOwnerAttrs to contain pod=nginx-abc123")
	}
	if block.Spec.SequenceNumber != 5 {
		t.Errorf("expected sequence number 5, got %d", block.Spec.SequenceNumber)
	}
	if block.Spec.SequenceNumberForAllocation["1"] != 5 {
		t.Errorf("expected seqno-for-alloc[1]=5, got %d", block.Spec.SequenceNumberForAllocation["1"])
	}
	if block.Spec.Deleted {
		t.Error("expected Deleted=false")
	}
}

func TestConvertIPAMBlock_NilUID(t *testing.T) {
	cidr := cnet.MustParseCIDR("10.0.1.0/30")
	kvp := &model.KVPair{
		Value: &model.AllocationBlock{
			CIDR:        cidr,
			Allocations: []*int{nil, nil, nil, nil},
			Unallocated: []int{0, 1, 2, 3},
		},
	}

	block, err := convertIPAMBlock(kvp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if block.UID != "" {
		t.Errorf("expected empty UID when KVPair.UID is nil, got %s", block.UID)
	}
}

func TestConvertIPAMBlock_WrongType(t *testing.T) {
	kvp := &model.KVPair{
		Value: &apiv3.Tier{},
	}
	_, err := convertIPAMBlock(kvp)
	if err == nil {
		t.Fatal("expected error for wrong type")
	}
}

func TestConvertIPAMHandle(t *testing.T) {
	uid := types.UID("handle-uid-1")
	kvp := &model.KVPair{
		Key: model.IPAMHandleKey{HandleID: "k8s-pod-network.abc123"},
		Value: &model.IPAMHandle{
			HandleID: "k8s-pod-network.abc123",
			Block:    map[string]int{"10.0.0.0/26": 3, "10.0.1.0/26": 1},
			Deleted:  false,
		},
		UID: &uid,
	}

	handle, err := convertIPAMHandle(kvp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if handle.Name != "k8s-pod-network.abc123" {
		t.Errorf("expected name k8s-pod-network.abc123, got %s", handle.Name)
	}
	if handle.UID != uid {
		t.Errorf("expected UID %s, got %s", uid, handle.UID)
	}
	if handle.Spec.HandleID != "k8s-pod-network.abc123" {
		t.Errorf("expected HandleID k8s-pod-network.abc123, got %s", handle.Spec.HandleID)
	}
	if len(handle.Spec.Block) != 2 || handle.Spec.Block["10.0.0.0/26"] != 3 {
		t.Errorf("unexpected Block: %v", handle.Spec.Block)
	}
	if handle.Spec.Deleted {
		t.Error("expected Deleted=false")
	}
}

func TestConvertIPAMHandle_NilUID(t *testing.T) {
	kvp := &model.KVPair{
		Key:   model.IPAMHandleKey{HandleID: "no-uid"},
		Value: &model.IPAMHandle{HandleID: "no-uid"},
	}

	handle, err := convertIPAMHandle(kvp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if handle.UID != "" {
		t.Errorf("expected empty UID when KVPair.UID is nil, got %s", handle.UID)
	}
}

func TestConvertIPAMHandle_WrongValueType(t *testing.T) {
	kvp := &model.KVPair{
		Key:   model.IPAMHandleKey{HandleID: "x"},
		Value: &apiv3.Tier{},
	}
	_, err := convertIPAMHandle(kvp)
	if err == nil {
		t.Fatal("expected error for wrong value type")
	}
}

func TestConvertIPAMHandle_WrongKeyType(t *testing.T) {
	kvp := &model.KVPair{
		Key:   model.ResourceKey{Kind: "IPAMHandle", Name: "x"},
		Value: &model.IPAMHandle{HandleID: "x"},
	}
	_, err := convertIPAMHandle(kvp)
	if err == nil {
		t.Fatal("expected error for wrong key type")
	}
}
