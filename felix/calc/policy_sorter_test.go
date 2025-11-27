// Copyright (c) 2016-2025 Tigera, Inc. All rights reserved.
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

package calc

import (
	"reflect"
	"testing"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

func floatPtr(f float64) *float64 {
	return &f
}

func TestPolKV_String(t *testing.T) {
	type kvTestType struct {
		name     string
		kv       PolKV
		expected string
	}

	nilOrder := ExtractPolicyMetadata(&model.Policy{})

	tests := []kvTestType{
		{
			name:     "zero",
			kv:       PolKV{},
			expected: "(nil policy)",
		},
		{
			name:     "nil policy",
			kv:       PolKV{Key: model.PolicyKey{Name: "name", Namespace: "ns", Kind: "kind"}},
			expected: "kind/ns/name(nil policy)",
		},
		{
			name:     "nil order",
			kv:       PolKV{Key: model.PolicyKey{Name: "name", Kind: "kind"}, Value: &nilOrder},
			expected: "kind/name(default)",
		},
		{
			name:     "order set",
			kv:       PolKV{Key: model.PolicyKey{Name: "name", Kind: "kind"}, Value: &policyMetadata{Order: 10.5, Tier: "default"}},
			expected: "kind/name(10.5)",
		},
	}

	for _, tc := range tests {
		got := tc.kv.String()
		if got != tc.expected {
			t.Errorf("%v - expected: %v, got: %v", tc.name, tc.expected, got)
		}
	}
}

func TestPolicySorter_HasPolicy(t *testing.T) {
	poc := NewPolicySorter()
	polKey := model.PolicyKey{
		Name: "test-policy",
		Kind: v3.KindGlobalNetworkPolicy,
	}
	found := poc.HasPolicy(polKey)
	if found {
		t.Error("Unexpectedly found policy when it should not be present")
	}

	pol := policyMetadata{Tier: "default"}
	_ = poc.UpdatePolicy(polKey, &pol)

	found = poc.HasPolicy(polKey)
	if !found {
		t.Error("Policy that should be present was not found")
	}
}

func TestPolicySorter_UpdatePolicy(t *testing.T) {
	poc := NewPolicySorter()

	polKey := model.PolicyKey{
		Name: "test-policy",
		Kind: v3.KindGlobalNetworkPolicy,
	}

	pol := policyMetadata{Tier: "default"}

	dirty := poc.UpdatePolicy(polKey, &pol)
	if tierName, tierInfo := poc.tierForPolicy(polKey, &pol); tierName == "" {
		t.Error("Adding new policy to tier that does not yet exist - expected tier to be created but it is not found")
	} else {
		if !dirty {
			t.Error("Adding new policy - expected dirty to be true but it was false")
		}
		if _, found := tierInfo.Policies[polKey]; !found {
			t.Error("Adding new policy - expected policy to be in Policies but it is not")
		}
	}

	newPol := policyMetadata{
		Tier:  "default",
		Order: 7,
	}

	dirty = poc.UpdatePolicy(polKey, &newPol)
	if !dirty {
		t.Error("Updating existing policy Order field - expected dirty to be true but it was false")
	}

	pol.Flags |= policyMetaDoNotTrack

	dirty = poc.UpdatePolicy(polKey, &pol)
	if !dirty {
		t.Error("Updating existing policy DoNotTrack field - expected dirty to be true but it was false")
	}

	pol.Flags |= policyMetaPreDNAT

	dirty = poc.UpdatePolicy(polKey, &newPol)
	if !dirty {
		t.Error("Updating existing policy PreDNAT field - expected dirty to be true but it was false")
	}

	pol.Flags |= policyMetaApplyOnForward

	dirty = poc.UpdatePolicy(polKey, &pol)
	if !dirty {
		t.Error("Updating existing policy ApplyOnForward field - expected dirty to be true but it was false")
	}

	newPol.Flags |= policyMetaIngress

	dirty = poc.UpdatePolicy(polKey, &newPol)
	if !dirty {
		t.Error("Updating existing policy types - expected dirty to be true but it was false")
	}

	dirty = poc.UpdatePolicy(polKey, &newPol)
	if dirty {
		t.Error("Updating existing policy with identical policy - expected dirty to be false but it was true")
	}

	dirty = poc.UpdatePolicy(polKey, nil)
	if !dirty {
		t.Error("Deleting existing policy - expected dirty to be true but it was false")
	}

	if tierName, tierInfo := poc.tierForPolicy(polKey, nil); tierName != "" {
		if _, found := tierInfo.Policies[polKey]; found {
			t.Error("Deleting existing policy - expected policy not to be in Policies but it is")
		}
	}

	dirty = poc.UpdatePolicy(polKey, nil)
	if dirty {
		t.Error("Deleting nonexistent policy - expected dirty to be false but it was true")
	}
}

func TestPolicySorter_OnUpdate_Basic(t *testing.T) {
	poc := NewPolicySorter()

	policy := model.Policy{Tier: "default"}
	kvp := model.KVPair{
		Key: model.PolicyKey{
			Name: "test-policy",
			Kind: v3.KindGlobalNetworkPolicy,
		},
		Value: &policy,
	}
	update := api.Update{}
	update.Key = kvp.Key
	update.Value = kvp.Value

	dirty := poc.OnUpdate(update)
	if !dirty {
		t.Error("Update containing new policy - expected dirty to be true but it was false")
	}

	update.Value = nil

	dirty = poc.OnUpdate(update)
	if !dirty {
		t.Error("Update containing empty value for existing policy - expected dirty to be true but it was false")
	}

	update.Value = kvp.Value
	update.Key = model.HostEndpointKey{}

	dirty = poc.OnUpdate(update)
	if dirty {
		t.Error("Update containing key type other than PolicyKey - expected dirty to be false but it was true")
	}
}

func TestPolicySorter_OnUpdate_RemoveFromNonExistent(t *testing.T) {
	ps := NewPolicySorter()
	key := model.PolicyKey{Name: "foo", Kind: v3.KindGlobalNetworkPolicy}
	pol := &model.Policy{
		Tier: "default",
	}
	ps.OnUpdate(api.Update{
		KVPair: model.KVPair{
			Key:   key,
			Value: pol,
		},
	})

	if ps.tiers["default"].Valid {
		t.Error("Expected default tier not to be valid but it is")
	}

	expectedPolicies := map[model.PolicyKey]policyMetadata{
		key: {
			Tier:  "default",
			Order: polMetaDefaultOrder,
			Flags: policyMetaIngress | policyMetaEgress,
		},
	}

	if !reflect.DeepEqual(ps.tiers["default"].Policies, expectedPolicies) {
		t.Errorf("Expected %v \n to equal \n %v", ps.tiers["default"].Policies, expectedPolicies)
	}

	ps.OnUpdate(api.Update{
		KVPair: model.KVPair{
			Key:   key,
			Value: nil, // deletion
		},
	})

	if _, found := ps.tiers["default"]; found {
		t.Error("Expected default tier not to exist but it does")
	}
}

func TestPolicySorter_OnUpdate_Remove(t *testing.T) {
	ps := NewPolicySorter()
	key := model.TierKey{Name: "default"}
	tier := &model.Tier{}
	ps.OnUpdate(api.Update{
		KVPair: model.KVPair{
			Key:   key,
			Value: tier,
		},
	})

	if !ps.tiers["default"].Valid {
		t.Error("Expected default tier to be valid but it is not")
	}

	if len(ps.tiers["default"].Policies) > 0 {
		t.Error("Expected default tier to be empty but it is not")
	}

	ps.OnUpdate(api.Update{
		KVPair: model.KVPair{
			Key:   key,
			Value: nil, // deletion
		},
	})

	if _, found := ps.tiers["default"]; found {
		t.Error("Expected default tier not to exist but it does")
	}
}

func TestPolicySorter_Sorting(t *testing.T) {
	type sortingTestType struct {
		name     string
		input    []*TierInfo
		expected []*TierInfo
	}

	tests := []sortingTestType{
		{
			name:     "nil",
			input:    []*TierInfo(nil),
			expected: []*TierInfo(nil),
		},
		{
			name:     "empty",
			input:    []*TierInfo{},
			expected: []*TierInfo(nil),
		},
		{
			name: "valid sorts ahead of invalid",
			input: []*TierInfo{
				{
					Name:  "bar",
					Valid: false,
					Order: floatPtr(1),
				},
				{
					Name:  "foo",
					Valid: true,
					Order: floatPtr(10),
				},
			},
			expected: []*TierInfo{
				{
					Name:  "foo",
					Valid: true,
					Order: floatPtr(10),
				},
				{
					Name:  "bar",
					Valid: false,
					Order: floatPtr(1),
				},
			},
		},
		{
			name: "both invalid, both nil order rely on name",
			input: []*TierInfo{
				{
					Name:  "foo",
					Valid: false,
				},
				{
					Name:  "bar",
					Valid: false,
				},
			},
			expected: []*TierInfo{
				{
					Name:  "bar",
					Valid: false,
				},
				{
					Name:  "foo",
					Valid: false,
				},
			},
		},
		{
			name: "both valid, both nil order rely on name",
			input: []*TierInfo{
				{
					Name:  "foo",
					Valid: true,
				},
				{
					Name:  "bar",
					Valid: true,
				},
			},
			expected: []*TierInfo{
				{
					Name:  "bar",
					Valid: true,
				},
				{
					Name:  "foo",
					Valid: true,
				},
			},
		},
		{
			name: "both valid, rely on order",
			input: []*TierInfo{
				{
					Name:  "bar",
					Order: floatPtr(10),
					Valid: true,
				},
				{
					Name:  "foo",
					Order: floatPtr(1),
					Valid: true,
				},
			},
			expected: []*TierInfo{
				{
					Name:  "foo",
					Order: floatPtr(1),
					Valid: true,
				},
				{
					Name:  "bar",
					Order: floatPtr(10),
					Valid: true,
				},
			},
		},
		{
			name: "all valid, non-nil orders sort ahead of nil",
			input: []*TierInfo{
				{
					Name:  "bar",
					Valid: true,
				},
				{
					Name:  "baz",
					Order: floatPtr(10),
					Valid: true,
				},
				{
					Name:  "foo",
					Order: floatPtr(1),
					Valid: true,
				},
			},
			expected: []*TierInfo{
				{
					Name:  "foo",
					Order: floatPtr(1),
					Valid: true,
				},
				{
					Name:  "baz",
					Order: floatPtr(10),
					Valid: true,
				},
				{
					Name:  "bar",
					Valid: true,
				},
			},
		},
		{
			name: "all valid, equal order relies on name",
			input: []*TierInfo{
				{
					Name:  "baz",
					Order: floatPtr(10),
					Valid: true,
				},
				{
					Name:  "foo",
					Order: floatPtr(10),
					Valid: true,
				},
			},
			expected: []*TierInfo{
				{
					Name:  "baz",
					Order: floatPtr(10),
					Valid: true,
				},
				{
					Name:  "foo",
					Order: floatPtr(10),
					Valid: true,
				},
			},
		},
	}

	insertTierInfos := func(ps *PolicySorter, ti []*TierInfo) {
		for _, tierInfo := range ti {
			if tierInfo != nil {
				tiKey := tierInfoKey{
					Name:  tierInfo.Name,
					Order: tierInfo.Order,
					Valid: tierInfo.Valid,
				}
				ps.tiers[tierInfo.Name] = tierInfo
				ps.sortedTiers.ReplaceOrInsert(tiKey)
			}
		}
	}

	for _, tc := range tests {
		ps := NewPolicySorter()

		insertTierInfos(ps, tc.input)
		got := ps.Sorted()

		if !reflect.DeepEqual(got, tc.expected) {
			t.Errorf("%v: Inserting in input order expected \n %v \n but got \n %v", tc.name, tc.expected, got)
		}

		ps = NewPolicySorter()
		var reversedInput []*TierInfo
		if tc.input != nil {
			reversedInput = make([]*TierInfo, len(tc.input))
			for i, v := range tc.input {
				reversedInput[len(tc.input)-1-i] = v
			}
		}
		insertTierInfos(ps, reversedInput)

		got = ps.Sorted()

		if !reflect.DeepEqual(got, tc.expected) {
			t.Errorf("%v: Inserting in reverse order expected \n %v \n but got \n %v", tc.name, tc.expected, got)
		}
	}
}
