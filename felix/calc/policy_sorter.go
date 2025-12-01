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
	"fmt"
	"math"
	"strings"

	"github.com/google/btree"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/names"
)

type PolicySorter struct {
	tiers       map[string]*TierInfo
	sortedTiers *btree.BTreeG[tierInfoKey]
}

func NewPolicySorter() *PolicySorter {
	return &PolicySorter{
		tiers:       make(map[string]*TierInfo),
		sortedTiers: btree.NewG(2, TierLess),
	}
}

func (poc *PolicySorter) Sorted() []*TierInfo {
	var tiers []*TierInfo
	if poc.sortedTiers.Len() > 0 {
		tiers = make([]*TierInfo, 0, len(poc.tiers))
		poc.sortedTiers.Ascend(func(t tierInfoKey) bool {
			if ti := poc.tiers[t.Name]; ti != nil {
				if ti.SortedPolicies != nil {
					ti.OrderedPolicies = make([]PolKV, 0, len(ti.Policies))
					ti.SortedPolicies.Ascend(func(kv PolKV) bool {
						ti.OrderedPolicies = append(ti.OrderedPolicies, kv)
						return true
					})
				}
				tiers = append(tiers, ti)
				return true
			} else {
				// A key for a tier that isn't found in the map is highly unexpected so panic
				logrus.WithField("name", t.Name).Panic("Bug: tier present in map but not the sorted tree.")
				return false
			}
		})
	}
	return tiers
}

func (poc *PolicySorter) OnUpdate(update api.Update) (dirty bool) {
	switch key := update.Key.(type) {
	case model.TierKey:
		tierName := key.Name
		logCxt := logrus.WithField("tierName", tierName)
		tierInfo := poc.tiers[tierName]
		if update.Value != nil {
			newTier := update.Value.(*model.Tier)
			logCxt.WithFields(logrus.Fields{
				"order":         newTier.Order,
				"defaultAction": newTier.DefaultAction,
			}).Debug("Tier update")
			if tierInfo == nil {
				tierInfo = NewTierInfo(key.Name)
				poc.tiers[tierName] = tierInfo
				dirty = true
			} else {
				oldKey := tierInfoKey{
					Name:  tierInfo.Name,
					Order: tierInfo.Order,
					Valid: tierInfo.Valid,
				}
				poc.sortedTiers.Delete(oldKey)
			}
			if tierInfo.Order != newTier.Order {
				tierInfo.Order = newTier.Order
				dirty = true
			}
			if tierInfo.DefaultAction != newTier.DefaultAction {
				tierInfo.DefaultAction = newTier.DefaultAction
				dirty = true
			}
			tierInfo.Valid = true
			newKey := tierInfoKey{
				Name:  tierInfo.Name,
				Order: tierInfo.Order,
				Valid: tierInfo.Valid,
			}
			poc.sortedTiers.ReplaceOrInsert(newKey)
		} else {
			// Deletion.
			if tierInfo != nil {
				oldKey := tierInfoKey{
					Name:  tierInfo.Name,
					Order: tierInfo.Order,
					Valid: tierInfo.Valid,
				}
				poc.sortedTiers.Delete(oldKey)
				tierInfo.Valid = false
				tierInfo.Order = nil
				if len(tierInfo.Policies) == 0 {
					delete(poc.tiers, tierName)
				} else {
					// Add back so that sort order is maintained correctly after manipulating Valid and
					// Order fields above
					newKey := tierInfoKey{
						Name:  tierInfo.Name,
						Order: tierInfo.Order,
						Valid: tierInfo.Valid,
					}
					poc.sortedTiers.ReplaceOrInsert(newKey)
				}
				dirty = true
			}
		}
	case model.PolicyKey:
		var newPolicy *model.Policy
		if update.Value != nil {
			newPolicy = update.Value.(*model.Policy)
			metadata := ExtractPolicyMetadata(newPolicy)
			dirty = poc.UpdatePolicy(key, &metadata)
		} else {
			dirty = poc.UpdatePolicy(key, nil)
		}
	}
	return
}

func TierLess(i, j tierInfoKey) bool {
	if !i.Valid && j.Valid {
		return false
	} else if i.Valid && !j.Valid {
		return true
	}
	if i.Order == nil && j.Order != nil {
		return false
	} else if i.Order != nil && j.Order == nil {
		return true
	}
	if i.Order == j.Order || *i.Order == *j.Order {
		return i.Name < j.Name
	}
	return *i.Order < *j.Order
}

func (poc *PolicySorter) HasPolicy(key model.PolicyKey) bool {
	for _, tierInfo := range poc.tiers {
		if _, ok := tierInfo.Policies[key]; ok {
			return true
		}
	}
	return false
}

var polMetaDefaultOrder = math.Inf(1)

func ExtractPolicyMetadata(policy *model.Policy) policyMetadata {
	m := policyMetadata{Tier: policy.Tier}

	if policy.Tier == "" {
		// This shouldn't happen - all policies should have a tier assigned by now.
		// Log a warning and assign to default tier to be safe.
		logrus.WithField("policy", policy).Warn("Policy has no tier assigned")
		m.Tier = names.DefaultTierName
	}
	if policy.Order == nil {
		m.Order = polMetaDefaultOrder
	} else {
		m.Order = *policy.Order
	}
	if policy.DoNotTrack {
		m.Flags |= policyMetaDoNotTrack
	}
	if policy.PreDNAT {
		m.Flags |= policyMetaPreDNAT
	}
	if policy.ApplyOnForward {
		m.Flags |= policyMetaApplyOnForward
	}
	if len(policy.Types) == 0 {
		// Back compatibility: no Types means Ingress and Egress.
		m.Flags |= policyMetaIngress | policyMetaEgress
	}
	for _, t := range policy.Types {
		if strings.EqualFold(t, "ingress") {
			m.Flags |= policyMetaIngress
		} else if strings.EqualFold(t, "egress") {
			m.Flags |= policyMetaEgress
		}
	}
	return m
}

type policyMetadata struct {
	Order float64 // Set to +Inf for default order.
	Flags policyMetadataFlags
	Tier  string
}

type policyMetadataFlags uint8

const (
	policyMetaDoNotTrack policyMetadataFlags = 1 << iota
	policyMetaPreDNAT
	policyMetaApplyOnForward
	policyMetaIngress
	policyMetaEgress
)

func (m *policyMetadata) Equals(other *policyMetadata) bool {
	if m != nil && other != nil {
		return *m == *other
	}
	return m == other
}

func (m *policyMetadata) DoNotTrack() bool {
	return m != nil && m.Flags&policyMetaDoNotTrack != 0
}

func (m *policyMetadata) PreDNAT() bool {
	return m != nil && m.Flags&policyMetaPreDNAT != 0
}

func (m *policyMetadata) ApplyOnForward() bool {
	return m != nil && m.Flags&policyMetaApplyOnForward != 0
}

func (poc *PolicySorter) tierForPolicy(key model.PolicyKey, meta *policyMetadata) (string, *TierInfo) {
	if meta != nil {
		return meta.Tier, poc.tiers[meta.Tier]
	}
	for tierName, tierInfo := range poc.tiers {
		if _, ok := tierInfo.Policies[key]; ok {
			return tierName, tierInfo
		}
	}
	return "", nil
}

func (poc *PolicySorter) UpdatePolicy(key model.PolicyKey, newPolicy *policyMetadata) (dirty bool) {
	// Find the old tier info if it exists. If it does, and doesn't match the new tier info, we'll need to
	// remove it from the old tier.
	_, oldTierInfo := poc.tierForPolicy(key, nil)

	tierName, tierInfo := poc.tierForPolicy(key, newPolicy)

	if tierName == "" {
		// Failed to find a tier name for this policy. This should not happen.
		logrus.WithFields(logrus.Fields{
			"policyKey": key,
			"newPolicy": newPolicy,
		}).Warn("Failed to find tier for policy during policy sorter update.")
	}

	// If the tier has changed, remove from old tier first.
	if oldTierInfo != nil && oldTierInfo != tierInfo {
		if logrus.IsLevelEnabled(logrus.DebugLevel) {
			logrus.WithFields(logrus.Fields{
				"policyKey":   key,
				"oldTierName": oldTierInfo.Name,
				"newTierName": tierName,
			}).Debug("Policy tier changed, removing from old tier")
		}

		oldPolicy := oldTierInfo.Policies[key]
		oldTiKey := tierInfoKey{
			Name:  oldTierInfo.Name,
			Order: oldTierInfo.Order,
			Valid: oldTierInfo.Valid,
		}
		oldTierInfo.SortedPolicies.Delete(PolKV{Key: key, Value: &oldPolicy})
		delete(oldTierInfo.Policies, key)
		if len(oldTierInfo.Policies) == 0 && !oldTierInfo.Valid {
			poc.sortedTiers.Delete(oldTiKey)
			delete(poc.tiers, oldTierInfo.Name)
		}
		dirty = true
	}

	// Now add to new tier.
	var tiKey tierInfoKey
	var oldPolicy *policyMetadata
	if tierInfo != nil {
		if op, ok := tierInfo.Policies[key]; ok {
			oldPolicy = &op
		}
		tiKey.Name = tierInfo.Name
		tiKey.Order = tierInfo.Order
		tiKey.Valid = tierInfo.Valid
	}
	if newPolicy != nil {
		if tierInfo == nil {
			tierInfo = NewTierInfo(tierName)
			tiKey.Name = tierInfo.Name
			tiKey.Valid = tierInfo.Valid
			tiKey.Order = tierInfo.Order
			poc.tiers[tierName] = tierInfo
			poc.sortedTiers.ReplaceOrInsert(tiKey)
		}
		if oldPolicy == nil || !oldPolicy.Equals(newPolicy) {
			dirty = true
		}
		if oldPolicy != nil {
			// Need to do delete prior to ReplaceOrInsert because we don't insert strictly based on key but rather a
			// combination of key + value so if for instance we add PolKV{k1, v1} then add PolKV{k1, v2} we'll simply have
			// both KVs in the tree instead of only {k1, v2} like we want. By deleting first we guarantee that only the
			// newest value remains in the tree.
			tierInfo.SortedPolicies.Delete(PolKV{Key: key, Value: oldPolicy})
		}
		tierInfo.SortedPolicies.ReplaceOrInsert(PolKV{Key: key, Value: newPolicy})
		tierInfo.Policies[key] = *newPolicy
	} else {
		if tierInfo != nil && oldPolicy != nil {
			tierInfo.SortedPolicies.Delete(PolKV{Key: key, Value: oldPolicy})
			delete(tierInfo.Policies, key)
			if len(tierInfo.Policies) == 0 && !tierInfo.Valid {
				poc.sortedTiers.Delete(tiKey)
				delete(poc.tiers, tierName)
			}
			dirty = true
		}
	}
	return
}

// PolKV is really internal to the calc package.  It is named with an initial capital so that
// the test package calc_test can also use it.
type PolKV struct {
	Key   model.PolicyKey
	Value *policyMetadata
}

func (p *PolKV) String() string {
	orderStr := "nil policy"
	if p.Value != nil {
		if math.IsInf(p.Value.Order, 1) {
			orderStr = "default"
		} else {
			orderStr = fmt.Sprint(p.Value.Order)
		}
	}

	var parts []string
	if p.Key.Kind != "" {
		parts = append(parts, p.Key.Kind)
	}
	if p.Key.Namespace != "" {
		parts = append(parts, p.Key.Namespace)
	}
	if p.Key.Name != "" {
		parts = append(parts, p.Key.Name)
	}
	return fmt.Sprintf("%s(%s)", strings.Join(parts, "/"), orderStr)
}

func (p *PolKV) GovernsIngress() bool {
	if p.Value == nil {
		return false
	}
	return p.Value.Flags&policyMetaIngress != 0
}

func (p *PolKV) GovernsEgress() bool {
	if p.Value == nil {
		return false
	}
	return p.Value.Flags&policyMetaEgress != 0
}

func PolKVLess(i, j PolKV) bool {
	// We map the default order to +Inf, which compares equal to itself so,
	// this "just works".
	if i.Value.Order == j.Value.Order {
		// Order is equal, use namespace/name/kind to break ties.
		// We start with the most specific (name) to least specific (kind), as
		// it's more intuitive to have policies sorted that way.
		iStr := fmt.Sprintf("%s/%s/%s", i.Key.Name, i.Key.Namespace, i.Key.Kind)
		jStr := fmt.Sprintf("%s/%s/%s", j.Key.Name, j.Key.Namespace, j.Key.Kind)
		return iStr < jStr
	}
	return i.Value.Order < j.Value.Order
}

type TierInfo struct {
	Name            string
	Valid           bool
	Order           *float64
	DefaultAction   v3.Action
	Policies        map[model.PolicyKey]policyMetadata
	SortedPolicies  *btree.BTreeG[PolKV]
	OrderedPolicies []PolKV
}

type tierInfoKey struct {
	Name  string
	Valid bool
	Order *float64
}

func NewTierInfo(name string) *TierInfo {
	return &TierInfo{
		Name:           name,
		Policies:       make(map[model.PolicyKey]policyMetadata),
		SortedPolicies: btree.NewG[PolKV](2, PolKVLess),
	}
}

func (t TierInfo) String() string {
	policies := make([]string, len(t.OrderedPolicies))
	for ii, pol := range t.OrderedPolicies {
		polType := "t"
		if pol.Value != nil {
			if pol.Value.DoNotTrack() {
				polType = "u"
			} else if pol.Value.PreDNAT() {
				polType = "p"
			}

			// Append ApplyOnForward flag.
			if pol.Value.ApplyOnForward() {
				polType = polType + "f"
			}
		}
		policies[ii] = fmt.Sprintf("%v(%v)", pol.Key.Name, polType)
	}
	return fmt.Sprintf("%v -> %v", t.Name, policies)
}
