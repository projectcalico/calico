// Copyright (c) 2016-2024 Tigera, Inc. All rights reserved.
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
			metadata := extractPolicyMetadata(newPolicy)
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
	var tierInfo *TierInfo
	var found bool
	if tierInfo, found = poc.tiers[key.Tier]; found {
		_, found = tierInfo.Policies[key]
	}
	return found
}

var polMetaDefaultOrder = math.Inf(1)

func extractPolicyMetadata(policy *model.Policy) policyMetadata {
	m := policyMetadata{}
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

func (poc *PolicySorter) UpdatePolicy(key model.PolicyKey, newPolicy *policyMetadata) (dirty bool) {
	tierInfo := poc.tiers[key.Tier]
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
			tierInfo = NewTierInfo(key.Tier)
			tiKey.Name = tierInfo.Name
			tiKey.Valid = tierInfo.Valid
			tiKey.Order = tierInfo.Order
			poc.tiers[key.Tier] = tierInfo
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
				delete(poc.tiers, key.Tier)
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
	return fmt.Sprintf("%s(%s)", p.Key.Name, orderStr)
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
		// Order is equal, use name as tie-break.
		return i.Key.Name < j.Key.Name
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

			//Append ApplyOnForward flag.
			if pol.Value.ApplyOnForward() {
				polType = polType + "f"
			}
		}
		policies[ii] = fmt.Sprintf("%v(%v)", pol.Key.Name, polType)
	}
	return fmt.Sprintf("%v -> %v", t.Name, policies)
}
