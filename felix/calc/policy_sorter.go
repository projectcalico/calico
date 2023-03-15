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

package calc

import (
	"fmt"
	"strings"

	"github.com/google/btree"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

type PolicySorter struct {
	Tier *TierInfo
}

func NewPolicySorter() *PolicySorter {
	return &PolicySorter{
		Tier: &TierInfo{
			Name:           "default",
			Policies:       make(map[model.PolicyKey]*model.Policy),
			SortedPolicies: btree.NewG[PolKV](2, PolKVLess),
		},
	}
}

func policyTypesEqual(pol1, pol2 *model.Policy) bool {
	if pol1.Types == nil {
		return pol2.Types == nil
	}
	if pol2.Types == nil {
		return false
	}
	types1 := set.FromArray(pol1.Types)
	types2 := set.FromArray(pol2.Types)
	return types1.Equals(types2)
}

func (poc *PolicySorter) Sorted() *TierInfo {
	poc.Tier.OrderedPolicies = make([]PolKV, 0, len(poc.Tier.Policies))
	poc.Tier.SortedPolicies.Ascend(func(kv PolKV) bool {
		poc.Tier.OrderedPolicies = append(poc.Tier.OrderedPolicies, kv)
		return true
	})
	return poc.Tier
}

func (poc *PolicySorter) OnUpdate(update api.Update) (dirty bool) {
	switch key := update.Key.(type) {
	case model.PolicyKey:
		var newPolicy *model.Policy
		if update.Value != nil {
			newPolicy = update.Value.(*model.Policy)
		} else {
			newPolicy = nil
		}
		dirty = poc.UpdatePolicy(key, newPolicy)
	}
	return
}

func (poc *PolicySorter) HasPolicy(key model.PolicyKey) (found bool) {
	_, found = poc.Tier.Policies[key]
	return found
}

func (poc *PolicySorter) UpdatePolicy(key model.PolicyKey, newPolicy *model.Policy) (dirty bool) {
	oldPolicy := poc.Tier.Policies[key]
	if newPolicy != nil {
		if oldPolicy == nil ||
			oldPolicy.Order != newPolicy.Order ||
			oldPolicy.DoNotTrack != newPolicy.DoNotTrack ||
			oldPolicy.PreDNAT != newPolicy.PreDNAT ||
			oldPolicy.ApplyOnForward != newPolicy.ApplyOnForward ||
			!policyTypesEqual(oldPolicy, newPolicy) {
			dirty = true
		}
		if oldPolicy != nil {
			// Need to do delete prior to ReplaceOrInsert because we don't insert strictly based on key but rather a
			// combination of key + value so if for instance we add PolKV{k1, v1} then add PolKV{k1, v2} we'll simply have
			// both KVs in the tree instead of only {k1, v2} like we want. By deleting first we guarantee that only the
			// newest value remains in the tree.
			poc.Tier.SortedPolicies.Delete(PolKV{Key: key, Value: oldPolicy})
		}
		poc.Tier.SortedPolicies.ReplaceOrInsert(PolKV{Key: key, Value: newPolicy})
		poc.Tier.Policies[key] = newPolicy
	} else {
		if oldPolicy != nil {
			poc.Tier.SortedPolicies.Delete(PolKV{Key: key, Value: oldPolicy})
			delete(poc.Tier.Policies, key)
			dirty = true
		}
	}

	return
}

// PolKV is really internal to the calc package.  It is named with an initial capital so that
// the test package calc_test can also use it.
type PolKV struct {
	Key   model.PolicyKey
	Value *model.Policy

	// Caches for whether the policy governs ingress and/or egress traffic.
	ingress *bool
	egress  *bool
}

func (p PolKV) String() string {
	orderStr := "nil policy"
	if p.Value != nil {
		if p.Value.Order != nil {
			orderStr = fmt.Sprintf("%v", *p.Value.Order)
		} else {
			orderStr = "default"
		}
	}
	return fmt.Sprintf("%s(%s)", p.Key.Name, orderStr)
}

func (p PolKV) governsType(wanted string) bool {
	// Back-compatibility: no Types means Ingress and Egress.
	if len(p.Value.Types) == 0 {
		return true
	}
	for _, t := range p.Value.Types {
		if strings.EqualFold(t, wanted) {
			return true
		}
	}
	return false
}

func (p PolKV) GovernsIngress() bool {
	if p.ingress == nil {
		governsIngress := p.governsType("ingress")
		p.ingress = &governsIngress
	}
	return *p.ingress
}

func (p PolKV) GovernsEgress() bool {
	if p.egress == nil {
		governsEgress := p.governsType("egress")
		p.egress = &governsEgress
	}
	return *p.egress
}

func PolKVLess(i, j PolKV) bool {
	bothNil := i.Value.Order == nil && j.Value.Order == nil
	bothSet := i.Value.Order != nil && j.Value.Order != nil
	ordersEqual := bothNil || bothSet && (*i.Value.Order == *j.Value.Order)

	if ordersEqual {
		// Use name as tie-break.
		result := i.Key.Name < j.Key.Name
		return result
	}

	// nil order maps to "infinity"
	if i.Value.Order == nil {
		return false
	} else if j.Value.Order == nil {
		return true
	}

	// Otherwise, use numeric comparison.
	return *i.Value.Order < *j.Value.Order
}

type TierInfo struct {
	Name            string
	Valid           bool
	Order           *float64
	Policies        map[model.PolicyKey]*model.Policy
	SortedPolicies  *btree.BTreeG[PolKV]
	OrderedPolicies []PolKV
}

func NewTierInfo(name string) *TierInfo {
	return &TierInfo{
		Name:     name,
		Policies: make(map[model.PolicyKey]*model.Policy),
	}
}

func (t TierInfo) String() string {
	policies := make([]string, len(t.OrderedPolicies))
	for ii, pol := range t.OrderedPolicies {
		polType := "t"
		if pol.Value != nil {
			if pol.Value.DoNotTrack {
				polType = "u"
			} else if pol.Value.PreDNAT {
				polType = "p"
			}

			//Append ApplyOnForward flag.
			if pol.Value.ApplyOnForward {
				polType = polType + "f"
			}
		}
		policies[ii] = fmt.Sprintf("%v(%v)", pol.Key.Name, polType)
	}
	return fmt.Sprintf("%v -> %v", t.Name, policies)
}
