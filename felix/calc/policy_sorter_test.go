// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.
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

package calc_test

import (
	"testing"

	. "github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

var (
	tenPointFive = 10.5
)

func TestPolKV_String(t *testing.T) {
	type kvTestType struct {
		name     string
		kv       PolKV
		expected string
	}

	tests := []kvTestType{
		{
			name:     "zero",
			kv:       PolKV{},
			expected: "(nil policy)",
		},
		{
			name:     "nil policy",
			kv:       PolKV{Key: model.PolicyKey{Name: "name"}},
			expected: "name(nil policy)"},
		{
			name:     "nil order",
			kv:       PolKV{Key: model.PolicyKey{Name: "name"}, Value: &model.Policy{}},
			expected: "name(default)",
		},
		{
			name:     "order set",
			kv:       PolKV{Key: model.PolicyKey{Name: "name"}, Value: &model.Policy{Order: &tenPointFive}},
			expected: "name(10.5)",
		},
	}

	for _, tc := range tests {
		got := tc.kv.String()
		if got != tc.expected {
			t.Errorf("%v - expected: %v, got: %v", tc.name, tc.expected, got)
		}
	}
}

func TestPolicySorter_OnUpdate(t *testing.T) {
	poc := NewPolicySorter()

	policy := model.Policy{}
	kvp := model.KVPair{
		Key: model.PolicyKey{
			Name: "test-policy",
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

func TestPolicySorter_UpdatePolicy(t *testing.T) {
	poc := NewPolicySorter()

	polKey := model.PolicyKey{
		Name: "test-policy",
	}

	pol := model.Policy{}

	dirty := poc.UpdatePolicy(polKey, &pol)
	if !dirty {
		t.Error("Adding new policy - expected dirty to be true but it was false")
	}
	if _, found := poc.Tier.Policies[polKey]; !found {
		t.Error("Adding new policy - expected policy to be in Policies but it is not")
	}

	newOrder := float64(7)
	newPol := model.Policy{}
	newPol.Order = &newOrder

	dirty = poc.UpdatePolicy(polKey, &newPol)
	if !dirty {
		t.Error("Updating existing policy Order field - expected dirty to be true but it was false")
	}

	pol.DoNotTrack = true

	dirty = poc.UpdatePolicy(polKey, &pol)
	if !dirty {
		t.Error("Updating existing policy DoNotTrack field - expected dirty to be true but it was false")
	}

	newPol.PreDNAT = true

	dirty = poc.UpdatePolicy(polKey, &newPol)
	if !dirty {
		t.Error("Updating existing policy PreDNAT field - expected dirty to be true but it was false")
	}

	pol.ApplyOnForward = true

	dirty = poc.UpdatePolicy(polKey, &pol)
	if !dirty {
		t.Error("Updating existing policy ApplyOnForward field - expected dirty to be true but it was false")
	}

	newPol.Types = []string{"don't care"}

	dirty = poc.UpdatePolicy(polKey, &newPol)
	if !dirty {
		t.Error("Updating existing policy Types field - expected dirty to be true but it was false")
	}

	dirty = poc.UpdatePolicy(polKey, &newPol)
	if dirty {
		t.Error("Updating existing policy with identical policy - expected dirty to be false but it was true")
	}

	dirty = poc.UpdatePolicy(polKey, nil)
	if !dirty {
		t.Error("Deleting existing policy - expected dirty to be true but it was false")
	}
	if _, found := poc.Tier.Policies[polKey]; found {
		t.Error("Deleting existing policy - expected policy not to be in Policies but it is")
	}

	dirty = poc.UpdatePolicy(polKey, nil)
	if dirty {
		t.Error("Deleting nonexistent policy - expected dirty to be false but it was true")
	}
}

func TestPolicySorter_HasPolicy(t *testing.T) {
	poc := NewPolicySorter()
	polKey := model.PolicyKey{
		Name: "test-policy",
	}
	found := poc.HasPolicy(polKey)
	if found {
		t.Error("Unexpectedly found policy when it should not be present")
	}

	pol := model.Policy{}
	_ = poc.UpdatePolicy(polKey, &pol)

	found = poc.HasPolicy(polKey)
	if !found {
		t.Error("Policy that should be present was not found")
	}
}
