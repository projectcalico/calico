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
	"reflect"
	"testing"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/types"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/utils/ptr"
	rtclient "sigs.k8s.io/controller-runtime/pkg/client"
	fakertclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/migration/migrators"
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
		{"non-default tier keeps own prefix", "security.my-policy", "security", "security.my-policy"},
		{"name is just the prefix", "default.", "default", ""},
		{"multiple dots in name", "default.my.dotted.policy", "default", "my.dotted.policy"},
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

func TestFilterInternalAnnotations(t *testing.T) {
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

	filterInternalAnnotations(src)

	// Labels are not touched by filterInternalAnnotations.
	if len(src.Labels) != 2 {
		t.Errorf("expected 2 labels, got %d", len(src.Labels))
	}
	if src.Labels["app"] != "test" {
		t.Errorf("expected label app=test, got %s", src.Labels["app"])
	}

	if len(src.Annotations) != 1 {
		t.Errorf("expected 1 annotation (metadata filtered), got %d: %v", len(src.Annotations), src.Annotations)
	}
	if _, ok := src.Annotations["projectcalico.org/metadata"]; ok {
		t.Error("projectcalico.org/metadata annotation should have been filtered out")
	}
	if src.Annotations["custom-annotation"] != "keep-this" {
		t.Errorf("expected custom-annotation=keep-this, got %s", src.Annotations["custom-annotation"])
	}
}

func newTestRTClient(t *testing.T) rtclient.Client {
	t.Helper()
	s := runtime.NewScheme()
	if err := apiv3.AddToScheme(s); err != nil {
		t.Fatalf("failed to add scheme: %v", err)
	}
	// Use a simple object tracker to avoid structured merge diff panics on
	// types with []*int fields (e.g., IPAMBlock.Spec.Allocations).
	codecs := serializer.NewCodecFactory(s)
	tracker := k8stesting.NewObjectTracker(s, codecs.UniversalDecoder())
	return fakertclient.NewClientBuilder().WithScheme(s).WithObjectTracker(tracker).Build()
}

func TestMigrateResourceType_NewResources(t *testing.T) {
	ctx := context.Background()

	bc := &mockBackendClient{
		resources: map[string][]*model.KVPair{
			apiv3.KindTier: {
				{
					Key:   model.ResourceKey{Kind: apiv3.KindTier, Name: "default"},
					Value: &apiv3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Spec: apiv3.TierSpec{Order: ptr.To[float64](100)}},
				},
				{
					Key:   model.ResourceKey{Kind: apiv3.KindTier, Name: "security"},
					Value: &apiv3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "security"}, Spec: apiv3.TierSpec{Order: ptr.To[float64](200)}},
				},
			},
		},
	}

	fakeRT := newTestRTClient(t)
	migrator := testTierMigrator(bc, fakeRT)

	result, err := MigrateResourceType(ctx, migrator)
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
}

func TestMigrateResourceType_SkipExisting(t *testing.T) {
	ctx := context.Background()

	bc := &mockBackendClient{
		resources: map[string][]*model.KVPair{
			apiv3.KindTier: {
				{
					Key:   model.ResourceKey{Kind: apiv3.KindTier, Name: "default"},
					Value: &apiv3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Spec: apiv3.TierSpec{Order: ptr.To[float64](100)}},
				},
			},
		},
	}

	fakeRT := newTestRTClient(t)
	// Pre-create a matching tier so migration skips it.
	if err := fakeRT.Create(ctx, &apiv3.Tier{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec:       apiv3.TierSpec{Order: ptr.To[float64](100)},
	}); err != nil {
		t.Fatalf("creating existing tier: %v", err)
	}

	migrator := testTierMigrator(bc, fakeRT)

	result, err := MigrateResourceType(ctx, migrator)
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
					Value: &apiv3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Spec: apiv3.TierSpec{Order: ptr.To[float64](100)}},
				},
			},
		},
	}

	fakeRT := newTestRTClient(t)
	// Pre-create a conflicting tier with a different spec.
	if err := fakeRT.Create(ctx, &apiv3.Tier{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Spec:       apiv3.TierSpec{Order: ptr.To[float64](999)},
	}); err != nil {
		t.Fatalf("creating conflicting tier: %v", err)
	}

	migrator := testTierMigrator(bc, fakeRT)

	result, err := MigrateResourceType(ctx, migrator)
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

func TestConvertIPAMBlock(t *testing.T) {
	_, cidr, _ := net.ParseCIDR("10.0.0.0/26")
	cnetCIDR := cnet.IPNet{IPNet: *cidr}
	blockUID := types.UID("block-uid-1")

	kvp := &model.KVPair{
		Key: model.BlockKey{CIDR: cnetCIDR},
		Value: &model.AllocationBlock{
			CIDR:        cnetCIDR,
			Affinity:    ptr.To("host:node-1"),
			Allocations: []*int{ptr.To(0), nil, nil},
			Unallocated: []int{1, 2},
			Attributes: []model.AllocationAttribute{
				{HandleID: ptr.To("handle-1"), ActiveOwnerAttrs: map[string]string{"pod": "test-pod"}},
			},
			SequenceNumber:              5,
			SequenceNumberForAllocation: map[string]uint64{"0": 3},
			Deleted:                     false,
		},
		Revision: "12345",
		UID:      &blockUID,
	}

	block, err := convertIPAMBlock(kvp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
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

func TestConvertIPAMHandle(t *testing.T) {
	handleUID := types.UID("handle-uid-1")

	kvp := &model.KVPair{
		Key: model.IPAMHandleKey{HandleID: "k8s-pod-network.abc123"},
		Value: &model.IPAMHandle{
			HandleID: "k8s-pod-network.abc123",
			Block:    map[string]int{"10.0.0.0/26": 3},
			Deleted:  false,
		},
		Revision: "67890",
		UID:      &handleUID,
	}

	handle, err := convertIPAMHandle(kvp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
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

func TestMigrateIPAMBlock_Full(t *testing.T) {
	_, cidr, _ := net.ParseCIDR("192.168.1.0/26")
	cnetCIDR := cnet.IPNet{IPNet: *cidr}
	blockUID := types.UID("v1-block-uid")

	// 1. Setup v1 backend with a diverse set of IPAM allocations.
	v1Block := &model.AllocationBlock{
		CIDR:     cnetCIDR,
		Affinity: ptr.To("host:node-1"),
		// Allocations point to indices in the Attributes array.
		// 0: Pod, 1: Unallocated, 2: LoadBalancer, 3: KubeVirt VM, 4: Leaked, 5: Incomplete
		Allocations: []*int{ptr.To(0), nil, ptr.To(1), ptr.To(2), ptr.To(3), ptr.To(4)},
		Unallocated: []int{1, 6, 7},
		Attributes: []model.AllocationAttribute{
			{
				// Standard Pod allocation
				HandleID:         ptr.To("k8s-pod-network.abc-123"),
				ActiveOwnerAttrs: map[string]string{"pod": "test-pod", "namespace": "default"},
			},
			{
				// LoadBalancer IP allocation
				HandleID:         ptr.To("lb-handle-555"),
				ActiveOwnerAttrs: map[string]string{"service": "my-lb-service", "namespace": "kube-system"},
			},
			{
				// KubeVirt VM allocation
				HandleID:         ptr.To("kubevirt-vm-handle-99"),
				ActiveOwnerAttrs: map[string]string{"vm": "my-virtual-machine", "namespace": "vms"},
			},
			{
				// Leaked allocation: has handle but no owner attributes
				HandleID:         ptr.To("leaked-handle-404"),
				ActiveOwnerAttrs: map[string]string{},
			},
			{
				// Incomplete allocation: has attributes but nil handle (rare but possible in v1)
				HandleID:            nil,
				ActiveOwnerAttrs:    map[string]string{"unknown": "source"},
				AlternateOwnerAttrs: map[string]string{"fallback": "info"},
			},
		},
		SequenceNumber: 42,
		SequenceNumberForAllocation: map[string]uint64{
			"0": 10,
			"1": 20,
			"2": 30,
		},
	}

	// Verify the conversion function works correctly on this block.
	kvp := &model.KVPair{
		Key:      model.BlockKey{CIDR: cnetCIDR},
		Value:    v1Block,
		UID:      &blockUID,
		Revision: "rv-1",
	}
	v3Block, err := convertIPAMBlock(kvp)
	if err != nil {
		t.Fatalf("conversion failed: %v", err)
	}

	if v3Block.Name != "192-168-1-0-26" {
		t.Errorf("expected name 192-168-1-0-26, got %s", v3Block.Name)
	}
	if v3Block.UID != blockUID {
		t.Errorf("expected UID %s, got %s", blockUID, v3Block.UID)
	}

	// Verify all critical fields are preserved.
	if v3Block.Spec.CIDR != "192.168.1.0/26" {
		t.Errorf("wrong CIDR: %s", v3Block.Spec.CIDR)
	}
	if !reflect.DeepEqual(v3Block.Spec.Allocations, v1Block.Allocations) {
		t.Errorf("allocations mismatch")
	}
	if len(v3Block.Spec.Attributes) != 5 {
		t.Errorf("expected 5 attributes, got %d", len(v3Block.Spec.Attributes))
	}

	// Spot check specific allocation types in v3.
	attrPod := v3Block.Spec.Attributes[0]
	if *attrPod.HandleID != "k8s-pod-network.abc-123" || attrPod.ActiveOwnerAttrs["pod"] != "test-pod" {
		t.Errorf("Pod attribute mismatch: %v", attrPod)
	}

	attrLB := v3Block.Spec.Attributes[1]
	if *attrLB.HandleID != "lb-handle-555" || attrLB.ActiveOwnerAttrs["service"] != "my-lb-service" {
		t.Errorf("LoadBalancer attribute mismatch: %v", attrLB)
	}

	attrVM := v3Block.Spec.Attributes[2]
	if *attrVM.HandleID != "kubevirt-vm-handle-99" || attrVM.ActiveOwnerAttrs["vm"] != "my-virtual-machine" {
		t.Errorf("KubeVirt VM attribute mismatch: %v", attrVM)
	}

	attrLeaked := v3Block.Spec.Attributes[3]
	if *attrLeaked.HandleID != "leaked-handle-404" || len(attrLeaked.ActiveOwnerAttrs) != 0 {
		t.Errorf("Leaked attribute mismatch: %v", attrLeaked)
	}

	attrIncomplete := v3Block.Spec.Attributes[4]
	if attrIncomplete.HandleID != nil || attrIncomplete.ActiveOwnerAttrs["unknown"] != "source" || attrIncomplete.AlternateOwnerAttrs["fallback"] != "info" {
		t.Errorf("Incomplete attribute mismatch: %v", attrIncomplete)
	}

	if v3Block.Spec.SequenceNumber != 42 {
		t.Errorf("wrong sequence number: %d", v3Block.Spec.SequenceNumber)
	}
}

func TestMigrateIPAMHandle_Full(t *testing.T) {
	handleUID := types.UID("v1-handle-uid")

	v1Handle := &model.IPAMHandle{
		HandleID: "k8s-pod-network.abc-123",
		Block:    map[string]int{"10.0.0.0/26": 5, "10.0.0.64/26": 2},
		Deleted:  false,
	}

	v3Handle, err := convertIPAMHandle(&model.KVPair{
		Key:      model.IPAMHandleKey{HandleID: v1Handle.HandleID},
		Value:    v1Handle,
		UID:      &handleUID,
		Revision: "rv-2",
	})
	if err != nil {
		t.Fatalf("conversion failed: %v", err)
	}

	if v3Handle.Name != "k8s-pod-network.abc-123" {
		t.Errorf("expected name k8s-pod-network.abc-123, got %s", v3Handle.Name)
	}
	if v3Handle.UID != handleUID {
		t.Errorf("expected UID %s, got %s", handleUID, v3Handle.UID)
	}
	if v3Handle.Spec.HandleID != v1Handle.HandleID {
		t.Errorf("wrong HandleID: %s", v3Handle.Spec.HandleID)
	}
	if v3Handle.Spec.Block["10.0.0.0/26"] != 5 {
		t.Errorf("wrong block count: %v", v3Handle.Spec.Block)
	}
	if v3Handle.Spec.Block["10.0.0.64/26"] != 2 {
		t.Errorf("wrong block count: %v", v3Handle.Spec.Block)
	}
}

// resetMetricVec resets a CounterVec by collecting all metrics and deleting their
// label combinations. This isolates test cases that inspect metric values.
func resetMetricVec(cv *prometheus.CounterVec) {
	ch := make(chan prometheus.Metric, 100)
	cv.Collect(ch)
	close(ch)
	for range ch {
	}
	cv.Reset()
}

func TestMigrateResourceType_Metrics(t *testing.T) {
	t.Run("migrated counter", func(t *testing.T) {
		resetMetricVec(migrationResourcesTotal)
		resetMetricVec(migrationRetries)

		ctx := context.Background()
		bc := &mockBackendClient{
			resources: map[string][]*model.KVPair{
				apiv3.KindTier: {
					{
						Key:   model.ResourceKey{Kind: apiv3.KindTier, Name: "t1"},
						Value: &apiv3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "t1"}, Spec: apiv3.TierSpec{Order: ptr.To[float64](10)}},
					},
					{
						Key:   model.ResourceKey{Kind: apiv3.KindTier, Name: "t2"},
						Value: &apiv3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "t2"}, Spec: apiv3.TierSpec{Order: ptr.To[float64](20)}},
					},
				},
			},
		}
		fakeRT := newTestRTClient(t)
		migrator := testTierMigrator(bc, fakeRT)

		result, err := MigrateResourceType(ctx, migrator)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Migrated != 2 {
			t.Fatalf("expected 2 migrated, got %d", result.Migrated)
		}

		// The handleMigrating method in the controller calls
		// migrationResourcesTotal.Add() after MigrateResourceType returns.
		// Simulate that here to verify the metric pipeline works.
		migrationResourcesTotal.WithLabelValues(apiv3.KindTier, "migrated").Add(float64(result.Migrated))
		val := testutil.ToFloat64(migrationResourcesTotal.WithLabelValues(apiv3.KindTier, "migrated"))
		if val != 2 {
			t.Errorf("expected migrated counter == 2, got %f", val)
		}
	})

	t.Run("skipped counter", func(t *testing.T) {
		resetMetricVec(migrationResourcesTotal)

		ctx := context.Background()
		bc := &mockBackendClient{
			resources: map[string][]*model.KVPair{
				apiv3.KindTier: {
					{
						Key:   model.ResourceKey{Kind: apiv3.KindTier, Name: "default"},
						Value: &apiv3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Spec: apiv3.TierSpec{Order: ptr.To[float64](100)}},
					},
				},
			},
		}
		fakeRT := newTestRTClient(t)
		if err := fakeRT.Create(ctx, &apiv3.Tier{
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
			Spec:       apiv3.TierSpec{Order: ptr.To[float64](100)},
		}); err != nil {
			t.Fatalf("creating existing tier: %v", err)
		}

		result, err := MigrateResourceType(ctx, testTierMigrator(bc, fakeRT))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		migrationResourcesTotal.WithLabelValues(apiv3.KindTier, "skipped").Add(float64(result.Skipped))
		val := testutil.ToFloat64(migrationResourcesTotal.WithLabelValues(apiv3.KindTier, "skipped"))
		if val != 1 {
			t.Errorf("expected skipped counter == 1, got %f", val)
		}
	})

	t.Run("conflict counter", func(t *testing.T) {
		resetMetricVec(migrationResourcesTotal)

		ctx := context.Background()
		bc := &mockBackendClient{
			resources: map[string][]*model.KVPair{
				apiv3.KindTier: {
					{
						Key:   model.ResourceKey{Kind: apiv3.KindTier, Name: "default"},
						Value: &apiv3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "default"}, Spec: apiv3.TierSpec{Order: ptr.To[float64](100)}},
					},
				},
			},
		}
		fakeRT := newTestRTClient(t)
		if err := fakeRT.Create(ctx, &apiv3.Tier{
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
			Spec:       apiv3.TierSpec{Order: ptr.To[float64](999)},
		}); err != nil {
			t.Fatalf("creating conflicting tier: %v", err)
		}

		result, err := MigrateResourceType(ctx, testTierMigrator(bc, fakeRT))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		migrationResourcesTotal.WithLabelValues(apiv3.KindTier, "conflict").Add(float64(len(result.Conflicts)))
		val := testutil.ToFloat64(migrationResourcesTotal.WithLabelValues(apiv3.KindTier, "conflict"))
		if val != 1 {
			t.Errorf("expected conflict counter == 1, got %f", val)
		}
	})

	t.Run("retry counter on transient error", func(t *testing.T) {
		resetMetricVec(migrationRetries)

		ctx := context.Background()
		bc := &mockBackendClient{
			resources: map[string][]*model.KVPair{
				apiv3.KindTier: {
					{
						Key:   model.ResourceKey{Kind: apiv3.KindTier, Name: "retry-tier"},
						Value: &apiv3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "retry-tier"}, Spec: apiv3.TierSpec{Order: ptr.To[float64](50)}},
					},
				},
			},
		}

		rtScheme := runtime.NewScheme()
		if err := apiv3.AddToScheme(rtScheme); err != nil {
			t.Fatalf("failed to add scheme: %v", err)
		}
		calls := 0
		inner := fakertclient.NewClientBuilder().WithScheme(rtScheme).WithObjectTracker(k8stesting.NewObjectTracker(rtScheme, serializer.NewCodecFactory(rtScheme).UniversalDecoder())).Build()
		wrapper := &retryTestClient{Client: inner, createCalls: &calls}

		migrator := testTierMigrator(bc, wrapper)
		_, err := MigrateResourceType(ctx, migrator)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// The retryTestClient fails the first Create, triggering a retry.
		// The retry path increments migrationRetries.
		retryVal := testutil.ToFloat64(migrationRetries.WithLabelValues(apiv3.KindTier, "create"))
		if retryVal < 1 {
			t.Errorf("expected retry counter >= 1, got %f", retryVal)
		}
	})
}

func TestMigrateResourceType_ContentVerification(t *testing.T) {
	ctx := context.Background()

	action := apiv3.Action("Allow")
	v1Spec := apiv3.TierSpec{Order: ptr.To[float64](77), DefaultAction: &action}
	v1Labels := map[string]string{"team": "networking", "env": "staging"}
	v1Annotations := map[string]string{
		"projectcalico.org/metadata": "filtered-out",
		"custom.io/reason":           "test-annotation",
		"another.io/data":            "extra-value",
	}

	bc := &mockBackendClient{
		resources: map[string][]*model.KVPair{
			apiv3.KindTier: {
				{
					Key: model.ResourceKey{Kind: apiv3.KindTier, Name: "content-tier"},
					Value: &apiv3.Tier{
						ObjectMeta: metav1.ObjectMeta{
							Name:        "content-tier",
							Labels:      v1Labels,
							Annotations: v1Annotations,
						},
						Spec: v1Spec,
					},
				},
			},
		},
	}

	fakeRT := newTestRTClient(t)

	// Use a migrator with a convert function that filters internal annotations
	// and copies labels, matching the real production Convert functions.
	migrator := newTestMigrator(
		apiv3.KindTier, OrderTiers, bc, fakeRT,
		func() rtclient.Object { return &apiv3.Tier{} },
		func() rtclient.ObjectList { return &apiv3.TierList{} },
		func(obj rtclient.Object) any { return obj.(*apiv3.Tier).Spec },
		func(kvp *model.KVPair) (rtclient.Object, error) {
			v1 := kvp.Value.(*apiv3.Tier)
			v3 := &apiv3.Tier{
				ObjectMeta: metav1.ObjectMeta{
					Name:        v1.Name,
					Labels:      v1.Labels,
					Annotations: v1.Annotations,
				},
				Spec: *v1.Spec.DeepCopy(),
			}
			filterInternalAnnotations(v3)
			return v3, nil
		},
	)

	result, err := MigrateResourceType(ctx, migrator)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Migrated != 1 {
		t.Fatalf("expected 1 migrated, got %d", result.Migrated)
	}

	tier := &apiv3.Tier{}
	if err := fakeRT.Get(ctx, types.NamespacedName{Name: "content-tier"}, tier); err != nil {
		t.Fatalf("failed to get tier: %v", err)
	}

	// Verify name.
	if tier.Name != "content-tier" {
		t.Errorf("expected name content-tier, got %s", tier.Name)
	}

	// Verify spec fields match exactly.
	if tier.Spec.Order == nil || *tier.Spec.Order != 77 {
		t.Errorf("expected Order 77, got %v", tier.Spec.Order)
	}
	if tier.Spec.DefaultAction == nil || *tier.Spec.DefaultAction != apiv3.Action("Allow") {
		t.Errorf("expected DefaultAction Allow, got %v", tier.Spec.DefaultAction)
	}

	// Verify labels were copied verbatim.
	if len(tier.Labels) != 2 {
		t.Errorf("expected 2 labels, got %d: %v", len(tier.Labels), tier.Labels)
	}
	if tier.Labels["team"] != "networking" {
		t.Errorf("expected label team=networking, got %s", tier.Labels["team"])
	}
	if tier.Labels["env"] != "staging" {
		t.Errorf("expected label env=staging, got %s", tier.Labels["env"])
	}

	// Verify annotations: projectcalico.org/metadata filtered, others preserved,
	// plus the migration annotation added by MigrateResourceType.
	if tier.Annotations["custom.io/reason"] != "test-annotation" {
		t.Errorf("expected annotation custom.io/reason=test-annotation, got %s", tier.Annotations["custom.io/reason"])
	}
	if tier.Annotations["another.io/data"] != "extra-value" {
		t.Errorf("expected annotation another.io/data=extra-value, got %s", tier.Annotations["another.io/data"])
	}
	if _, ok := tier.Annotations["projectcalico.org/metadata"]; ok {
		t.Error("projectcalico.org/metadata annotation should have been filtered out")
	}
	if tier.Annotations[migratedByAnnotation] != "v1-to-v3" {
		t.Errorf("expected migration annotation, got %v", tier.Annotations[migratedByAnnotation])
	}
}

func TestRemapOwnerReferences(t *testing.T) {
	ctx := context.Background()

	// Build a fake RT client and create v3 resources as if migration already ran.
	fakeRT := newTestRTClient(t)
	bc := &mockBackendClient{}

	// Tier "security" was migrated: v1 UID was "v1-tier-uid", v3 UID is "v3-tier-uid".
	if err := fakeRT.Create(ctx, &apiv3.Tier{
		ObjectMeta: metav1.ObjectMeta{Name: "security", UID: "v3-tier-uid"},
		Spec:       apiv3.TierSpec{Order: ptr.To[float64](200)},
	}); err != nil {
		t.Fatalf("creating tier: %v", err)
	}

	// GNP "test-deny" was migrated and has an OwnerRef pointing to the OLD v1 tier UID.
	if err := fakeRT.Create(ctx, &apiv3.GlobalNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-deny",
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: "projectcalico.org/v3",
					Kind:       "Tier",
					Name:       "security",
					UID:        "v1-tier-uid",
				},
			},
		},
		Spec: apiv3.GlobalNetworkPolicySpec{Tier: "default"},
	}); err != nil {
		t.Fatalf("creating GNP: %v", err)
	}

	// GNP "native-owner" has an OwnerRef to a Namespace (non-Calico), should stay unchanged.
	if err := fakeRT.Create(ctx, &apiv3.GlobalNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "native-owner",
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: "v1",
					Kind:       "Namespace",
					Name:       "kube-system",
					UID:        "ns-uid-unchanged",
				},
			},
		},
		Spec: apiv3.GlobalNetworkPolicySpec{Tier: "default"},
	}); err != nil {
		t.Fatalf("creating GNP: %v", err)
	}

	uidMap := map[types.UID]types.UID{
		"v1-tier-uid": "v3-tier-uid",
	}

	ms := []migrators.ResourceMigrator{
		newTestMigrator(
			apiv3.KindTier, OrderTiers, bc, fakeRT,
			func() rtclient.Object { return &apiv3.Tier{} },
			func() rtclient.ObjectList { return &apiv3.TierList{} },
			func(obj rtclient.Object) any { return obj.(*apiv3.Tier).Spec },
			nil,
		),
		newTestMigrator(
			apiv3.KindGlobalNetworkPolicy, OrderPolicy, bc, fakeRT,
			func() rtclient.Object { return &apiv3.GlobalNetworkPolicy{} },
			func() rtclient.ObjectList { return &apiv3.GlobalNetworkPolicyList{} },
			func(obj rtclient.Object) any { return obj.(*apiv3.GlobalNetworkPolicy).Spec },
			nil,
		),
	}

	if err := RemapOwnerReferences(ctx, uidMap, ms); err != nil {
		t.Fatalf("RemapOwnerReferences failed: %v", err)
	}

	// Verify the GNP's OwnerRef was remapped to the v3 tier UID.
	gnp := &apiv3.GlobalNetworkPolicy{}
	if err := fakeRT.Get(ctx, types.NamespacedName{Name: "test-deny"}, gnp); err != nil {
		t.Fatalf("getting GNP: %v", err)
	}
	if len(gnp.OwnerReferences) != 1 {
		t.Fatalf("expected 1 ownerRef, got %d", len(gnp.OwnerReferences))
	}
	if gnp.OwnerReferences[0].UID != "v3-tier-uid" {
		t.Errorf("expected ownerRef UID to be remapped to v3-tier-uid, got %s", gnp.OwnerReferences[0].UID)
	}

	// Verify the native-owner GNP's OwnerRef was NOT remapped.
	gnpNative := &apiv3.GlobalNetworkPolicy{}
	if err := fakeRT.Get(ctx, types.NamespacedName{Name: "native-owner"}, gnpNative); err != nil {
		t.Fatalf("getting native-owner GNP: %v", err)
	}
	if len(gnpNative.OwnerReferences) != 1 {
		t.Fatalf("expected 1 ownerRef, got %d", len(gnpNative.OwnerReferences))
	}
	if gnpNative.OwnerReferences[0].UID != "ns-uid-unchanged" {
		t.Errorf("expected native ownerRef UID to be preserved (ns-uid-unchanged), got %s", gnpNative.OwnerReferences[0].UID)
	}
}

func TestRemapOwnerReferences_EmptyMap(t *testing.T) {
	ctx := context.Background()

	// Should be a no-op with an empty UID map.
	if err := RemapOwnerReferences(ctx, nil, nil); err != nil {
		t.Fatalf("expected no error with empty map, got: %v", err)
	}
}

func TestDetectConflicts(t *testing.T) {
	ctx := context.Background()

	bc := &mockBackendClient{
		resources: map[string][]*model.KVPair{
			apiv3.KindTier: {
				{
					Key:   model.ResourceKey{Kind: apiv3.KindTier, Name: "matching"},
					Value: &apiv3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "matching"}, Spec: apiv3.TierSpec{Order: ptr.To[float64](100)}},
				},
				{
					Key:   model.ResourceKey{Kind: apiv3.KindTier, Name: "conflicting"},
					Value: &apiv3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "conflicting"}, Spec: apiv3.TierSpec{Order: ptr.To[float64](200)}},
				},
				{
					Key:   model.ResourceKey{Kind: apiv3.KindTier, Name: "missing"},
					Value: &apiv3.Tier{ObjectMeta: metav1.ObjectMeta{Name: "missing"}, Spec: apiv3.TierSpec{Order: ptr.To[float64](300)}},
				},
			},
		},
	}

	fakeRT := newTestRTClient(t)
	// Pre-create matching and conflicting tiers in v3.
	if err := fakeRT.Create(ctx, &apiv3.Tier{
		ObjectMeta: metav1.ObjectMeta{Name: "matching"},
		Spec:       apiv3.TierSpec{Order: ptr.To[float64](100)},
	}); err != nil {
		t.Fatalf("creating matching tier: %v", err)
	}
	if err := fakeRT.Create(ctx, &apiv3.Tier{
		ObjectMeta: metav1.ObjectMeta{Name: "conflicting"},
		Spec:       apiv3.TierSpec{Order: ptr.To[float64](999)},
	}); err != nil {
		t.Fatalf("creating conflicting tier: %v", err)
	}

	conflicts, err := DetectConflicts(ctx, []migrators.ResourceMigrator{testTierMigrator(bc, fakeRT)})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Only "conflicting" should be reported; "matching" has same spec, "missing" doesn't exist.
	if len(conflicts) != 1 {
		t.Fatalf("expected 1 conflict, got %d: %v", len(conflicts), conflicts)
	}
	if conflicts[0].Name != "conflicting" {
		t.Errorf("expected conflict on 'conflicting', got %s", conflicts[0].Name)
	}
}
