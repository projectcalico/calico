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
	"net"
	"sync"
	"testing"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

func TestMigratedPolicyName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		tier     string
		expected string
	}{
		{"default tier with prefix", "default.my-policy", "default", "my-policy"},
		{"default tier without prefix", "my-policy", "default", "my-policy"},
		{"empty tier with prefix", "default.my-policy", "", "my-policy"},
		{"non-default tier with prefix", "default.my-policy", "security", "default.my-policy"},
		{"non-default tier", "my-policy", "security", "my-policy"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := migratedPolicyName(tt.input, tt.tier)
			if result != tt.expected {
				t.Errorf("migratedPolicyName(%q, %q) = %q, want %q", tt.input, tt.tier, result, tt.expected)
			}
		})
	}
}

func TestCopyLabelsAndAnnotations(t *testing.T) {
	src := &apiv3.GlobalNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{
				"app": "test",
				"env": "prod",
			},
			Annotations: map[string]string{
				"projectcalico.org/metadata": "should-be-skipped",
				"custom-annotation":          "keep-this",
			},
		},
	}

	dst := &apiv3.GlobalNetworkPolicy{}
	copyLabelsAndAnnotations(src, dst)

	if len(dst.Labels) != 2 {
		t.Errorf("expected 2 labels, got %d", len(dst.Labels))
	}
	if dst.Labels["app"] != "test" {
		t.Errorf("expected label app=test, got %s", dst.Labels["app"])
	}

	if len(dst.Annotations) != 1 {
		t.Errorf("expected 1 annotation (metadata filtered), got %d: %v", len(dst.Annotations), dst.Annotations)
	}
	if _, ok := dst.Annotations["projectcalico.org/metadata"]; ok {
		t.Error("projectcalico.org/metadata annotation should have been filtered out")
	}
	if dst.Annotations["custom-annotation"] != "keep-this" {
		t.Errorf("expected custom-annotation=keep-this, got %s", dst.Annotations["custom-annotation"])
	}
}

// mockBackendClient is a simple mock of the api.Client interface for testing.
type mockBackendClient struct {
	api.Client
	resources   map[string][]*model.KVPair
	ipamBlocks  []*model.KVPair
	ipamHandles []*model.KVPair
}

func (m *mockBackendClient) List(ctx context.Context, list model.ListInterface, revision string) (*model.KVPairList, error) {
	switch list.(type) {
	case model.BlockListOptions:
		return &model.KVPairList{KVPairs: m.ipamBlocks}, nil
	case model.IPAMHandleListOptions:
		return &model.KVPairList{KVPairs: m.ipamHandles}, nil
	default:
		rlo := list.(model.ResourceListOptions)
		kvps := m.resources[rlo.Kind]
		return &model.KVPairList{KVPairs: kvps}, nil
	}
}

func TestMigrateResourceType_NewResources(t *testing.T) {
	ctx := context.Background()

	bc := &mockBackendClient{
		resources: map[string][]*model.KVPair{
			apiv3.KindTier: {
				{
					Key:   model.ResourceKey{Kind: apiv3.KindTier, Name: "default"},
					Value: &apiv3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Spec: apiv3.TierSpec{Order: floatPtr(100)}},
				},
				{
					Key:   model.ResourceKey{Kind: apiv3.KindTier, Name: "security"},
					Value: &apiv3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "security"}, Spec: apiv3.TierSpec{Order: floatPtr(200)}},
				},
			},
		},
	}

	var (
		created []string
		mu      sync.Mutex
	)
	migrator := ResourceMigrator{
		Kind:  apiv3.KindTier,
		Order: OrderTiers,
		ListV1: func(ctx context.Context, c api.Client) (*model.KVPairList, error) {
			return listV1Resources(ctx, c, apiv3.KindTier)
		},
		Convert: func(kvp *model.KVPair) (metav1.Object, error) {
			v1 := kvp.Value.(*apiv3.Tier)
			return &apiv3.Tier{
				ObjectMeta: metav1.ObjectMeta{Name: v1.Name},
				Spec:       *v1.Spec.DeepCopy(),
			}, nil
		},
		CreateV3: func(ctx context.Context, obj metav1.Object) error {
			mu.Lock()
			created = append(created, obj.GetName())
			mu.Unlock()
			return nil
		},
		GetV3: func(ctx context.Context, name, namespace string) (metav1.Object, error) {
			return nil, nil // doesn't exist
		},
		SpecsEqual: func(a, b metav1.Object) bool {
			return false
		},
	}

	result, err := MigrateResourceType(ctx, bc, migrator)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Migrated != 2 {
		t.Errorf("expected 2 migrated, got %d", result.Migrated)
	}
	if result.Skipped != 0 {
		t.Errorf("expected 0 skipped, got %d", result.Skipped)
	}
	if len(result.Conflicts) != 0 {
		t.Errorf("expected 0 conflicts, got %d", len(result.Conflicts))
	}
	if len(created) != 2 {
		t.Errorf("expected 2 creates, got %d", len(created))
	}
}

func TestMigrateResourceType_SkipExisting(t *testing.T) {
	ctx := context.Background()

	bc := &mockBackendClient{
		resources: map[string][]*model.KVPair{
			apiv3.KindTier: {
				{
					Key:   model.ResourceKey{Kind: apiv3.KindTier, Name: "default"},
					Value: &apiv3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Spec: apiv3.TierSpec{Order: floatPtr(100)}},
				},
			},
		},
	}

	existingTier := &apiv3.Tier{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec:       apiv3.TierSpec{Order: floatPtr(100)},
	}

	migrator := ResourceMigrator{
		Kind:  apiv3.KindTier,
		Order: OrderTiers,
		ListV1: func(ctx context.Context, c api.Client) (*model.KVPairList, error) {
			return listV1Resources(ctx, c, apiv3.KindTier)
		},
		Convert: func(kvp *model.KVPair) (metav1.Object, error) {
			v1 := kvp.Value.(*apiv3.Tier)
			return &apiv3.Tier{
				ObjectMeta: metav1.ObjectMeta{Name: v1.Name},
				Spec:       *v1.Spec.DeepCopy(),
			}, nil
		},
		CreateV3: func(ctx context.Context, obj metav1.Object) error {
			t.Fatal("CreateV3 should not be called for existing matching resource")
			return nil
		},
		GetV3: func(ctx context.Context, name, namespace string) (metav1.Object, error) {
			return existingTier, nil
		},
		SpecsEqual: func(a, b metav1.Object) bool {
			aSpec := a.(*apiv3.Tier).Spec
			bSpec := b.(*apiv3.Tier).Spec
			return *aSpec.Order == *bSpec.Order
		},
	}

	result, err := MigrateResourceType(ctx, bc, migrator)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Migrated != 0 {
		t.Errorf("expected 0 migrated, got %d", result.Migrated)
	}
	if result.Skipped != 1 {
		t.Errorf("expected 1 skipped, got %d", result.Skipped)
	}
}

func TestMigrateResourceType_Conflict(t *testing.T) {
	ctx := context.Background()

	bc := &mockBackendClient{
		resources: map[string][]*model.KVPair{
			apiv3.KindTier: {
				{
					Key:   model.ResourceKey{Kind: apiv3.KindTier, Name: "default"},
					Value: &apiv3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Spec: apiv3.TierSpec{Order: floatPtr(100)}},
				},
			},
		},
	}

	existingTier := &apiv3.Tier{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec:       apiv3.TierSpec{Order: floatPtr(999)}, // different
	}

	migrator := ResourceMigrator{
		Kind:  apiv3.KindTier,
		Order: OrderTiers,
		ListV1: func(ctx context.Context, c api.Client) (*model.KVPairList, error) {
			return listV1Resources(ctx, c, apiv3.KindTier)
		},
		Convert: func(kvp *model.KVPair) (metav1.Object, error) {
			v1 := kvp.Value.(*apiv3.Tier)
			return &apiv3.Tier{
				ObjectMeta: metav1.ObjectMeta{Name: v1.Name},
				Spec:       *v1.Spec.DeepCopy(),
			}, nil
		},
		CreateV3: func(ctx context.Context, obj metav1.Object) error {
			t.Fatal("CreateV3 should not be called when there's a conflict")
			return nil
		},
		GetV3: func(ctx context.Context, name, namespace string) (metav1.Object, error) {
			return existingTier, nil
		},
		SpecsEqual: func(a, b metav1.Object) bool {
			aSpec := a.(*apiv3.Tier).Spec
			bSpec := b.(*apiv3.Tier).Spec
			return *aSpec.Order == *bSpec.Order
		},
	}

	result, err := MigrateResourceType(ctx, bc, migrator)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Migrated != 0 {
		t.Errorf("expected 0 migrated, got %d", result.Migrated)
	}
	if len(result.Conflicts) != 1 {
		t.Errorf("expected 1 conflict, got %d", len(result.Conflicts))
	}
}

func TestListV1IPAMBlocks(t *testing.T) {
	_, cidr, _ := net.ParseCIDR("10.0.0.0/26")
	cnetCIDR := cnet.IPNet{IPNet: *cidr}
	blockUID := types.UID("block-uid-1")

	bc := &mockBackendClient{
		ipamBlocks: []*model.KVPair{
			{
				Key: model.BlockKey{CIDR: cnetCIDR},
				Value: &model.AllocationBlock{
					CIDR:        cnetCIDR,
					Affinity:    strPtr("host:node-1"),
					Allocations: []*int{intPtr(0), nil, nil},
					Unallocated: []int{1, 2},
					Attributes: []model.AllocationAttribute{
						{HandleID: strPtr("handle-1"), ActiveOwnerAttrs: map[string]string{"pod": "test-pod"}},
					},
					SequenceNumber:              5,
					SequenceNumberForAllocation: map[string]uint64{"0": 3},
					Deleted:                     false,
				},
				Revision: "12345",
				UID:      &blockUID,
			},
		},
	}

	ctx := context.Background()
	result, err := listV1IPAMBlocks(ctx, bc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.KVPairs) != 1 {
		t.Fatalf("expected 1 KVPair, got %d", len(result.KVPairs))
	}

	kvp := result.KVPairs[0]

	// Verify the key is a ResourceKey with the CIDR-derived name.
	rk, ok := kvp.Key.(model.ResourceKey)
	if !ok {
		t.Fatalf("expected ResourceKey, got %T", kvp.Key)
	}
	if rk.Kind != KindIPAMBlock {
		t.Errorf("expected kind %s, got %s", KindIPAMBlock, rk.Kind)
	}
	if rk.Name != "10-0-0-0-26" {
		t.Errorf("expected name 10-0-0-0-26, got %s", rk.Name)
	}

	// Verify the value is a v3 IPAMBlock with the right spec.
	block, ok := kvp.Value.(*apiv3.IPAMBlock)
	if !ok {
		t.Fatalf("expected *apiv3.IPAMBlock, got %T", kvp.Value)
	}
	if block.Name != "10-0-0-0-26" {
		t.Errorf("expected name 10-0-0-0-26, got %s", block.Name)
	}
	if block.UID != blockUID {
		t.Errorf("expected UID %s, got %s", blockUID, block.UID)
	}
	if block.Spec.CIDR != "10.0.0.0/26" {
		t.Errorf("expected CIDR 10.0.0.0/26, got %s", block.Spec.CIDR)
	}
	if block.Spec.Affinity == nil || *block.Spec.Affinity != "host:node-1" {
		t.Errorf("expected affinity host:node-1, got %v", block.Spec.Affinity)
	}
	if len(block.Spec.Attributes) != 1 {
		t.Errorf("expected 1 attribute, got %d", len(block.Spec.Attributes))
	}
	if block.Spec.SequenceNumber != 5 {
		t.Errorf("expected sequence number 5, got %d", block.Spec.SequenceNumber)
	}
}

func TestListV1IPAMHandles(t *testing.T) {
	handleUID := types.UID("handle-uid-1")

	bc := &mockBackendClient{
		ipamHandles: []*model.KVPair{
			{
				Key: model.IPAMHandleKey{HandleID: "k8s-pod-network.abc123"},
				Value: &model.IPAMHandle{
					HandleID: "k8s-pod-network.abc123",
					Block:    map[string]int{"10.0.0.0/26": 3},
					Deleted:  false,
				},
				Revision: "67890",
				UID:      &handleUID,
			},
		},
	}

	ctx := context.Background()
	result, err := listV1IPAMHandles(ctx, bc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.KVPairs) != 1 {
		t.Fatalf("expected 1 KVPair, got %d", len(result.KVPairs))
	}

	kvp := result.KVPairs[0]

	// Verify the key is a ResourceKey.
	rk, ok := kvp.Key.(model.ResourceKey)
	if !ok {
		t.Fatalf("expected ResourceKey, got %T", kvp.Key)
	}
	if rk.Kind != KindIPAMHandle {
		t.Errorf("expected kind %s, got %s", KindIPAMHandle, rk.Kind)
	}
	if rk.Name != "k8s-pod-network.abc123" {
		t.Errorf("expected name k8s-pod-network.abc123, got %s", rk.Name)
	}

	// Verify the value is a v3 IPAMHandle with the right spec.
	handle, ok := kvp.Value.(*apiv3.IPAMHandle)
	if !ok {
		t.Fatalf("expected *apiv3.IPAMHandle, got %T", kvp.Value)
	}
	if handle.Name != "k8s-pod-network.abc123" {
		t.Errorf("expected name k8s-pod-network.abc123, got %s", handle.Name)
	}
	if handle.UID != handleUID {
		t.Errorf("expected UID %s, got %s", handleUID, handle.UID)
	}
	if handle.Spec.HandleID != "k8s-pod-network.abc123" {
		t.Errorf("expected HandleID k8s-pod-network.abc123, got %s", handle.Spec.HandleID)
	}
	if handle.Spec.Block["10.0.0.0/26"] != 3 {
		t.Errorf("expected block count 3 for 10.0.0.0/26, got %d", handle.Spec.Block["10.0.0.0/26"])
	}
}

func floatPtr(f float64) *float64 {
	return &f
}

func strPtr(s string) *string {
	return &s
}

func intPtr(i int) *int {
	return &i
}
