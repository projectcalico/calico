// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package v3

import (
	"context"
	"runtime"
	"sync"
	"testing"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestCRDValidatorsMemory verifies that compiling all CRD validators stays
// within a reasonable memory budget. CEL compilation cost scales with
// maxItems/maxLength annotations on CRD schemas — if those bounds grow
// too large the compilation can consume hundreds of megabytes.
func TestCRDValidatorsMemory(t *testing.T) {
	// Reset state so we can measure a fresh initialization.
	resetCRDValidationState()
	SetCRDValidationEnabled(true)

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	// Force compilation of the most expensive Kinds by validating a
	// representative object for each.
	gnp := &apiv3.GlobalNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "mem-test"},
		Spec:       apiv3.GlobalNetworkPolicySpec{},
	}
	defaultAndValidateCRD(context.Background(), gnp, nil)

	np := &apiv3.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "mem-test", Namespace: "default"},
		Spec:       apiv3.NetworkPolicySpec{},
	}
	defaultAndValidateCRD(context.Background(), np, nil)

	sgnp := &apiv3.StagedGlobalNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "mem-test"},
		Spec:       apiv3.StagedGlobalNetworkPolicySpec{},
	}
	defaultAndValidateCRD(context.Background(), sgnp, nil)

	snp := &apiv3.StagedNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "mem-test", Namespace: "default"},
		Spec:       apiv3.StagedNetworkPolicySpec{},
	}
	defaultAndValidateCRD(context.Background(), snp, nil)

	pool := &apiv3.IPPool{
		ObjectMeta: metav1.ObjectMeta{Name: "mem-test"},
		Spec:       apiv3.IPPoolSpec{CIDR: "10.0.0.0/16"},
	}
	defaultAndValidateCRD(context.Background(), pool, nil)

	fc := &apiv3.FelixConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "mem-test"},
		Spec:       apiv3.FelixConfigurationSpec{},
	}
	defaultAndValidateCRD(context.Background(), fc, nil)

	bgp := &apiv3.BGPConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "mem-test"},
		Spec:       apiv3.BGPConfigurationSpec{},
	}
	defaultAndValidateCRD(context.Background(), bgp, nil)

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	allocMB := float64(after.TotalAlloc-before.TotalAlloc) / (1024 * 1024)
	t.Logf("CRD validator compilation allocated %.1f MB", allocMB)

	// Budget: 100 MB. If a CRD change pushes compilation past this
	// threshold, investigate the CEL cost of newly added
	// maxItems/maxLength annotations.
	const budgetMB = 100.0
	if allocMB > budgetMB {
		t.Errorf("CRD validator compilation allocated %.1f MB, exceeding %.0f MB budget; CEL compilation is too expensive", allocMB, budgetMB)
	}
}

// resetCRDValidationState resets all CRD validation state so tests can
// measure fresh initialization.
func resetCRDValidationState() {
	crdValidationEnabled = false
	rawSchemas = nil
	schemasOnce = syncOnceZero
	schemasErr = nil
	celValidators = nil
	schemaValidators = nil
	schemas = nil
	kindCompiled = nil
}

// syncOnceZero is a zero-value sync.Once used to reset schemasOnce.
var syncOnceZero sync.Once
