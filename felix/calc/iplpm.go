// Copyright (c) 2019-2025 Tigera, Inc. All rights reserved.
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
	"slices"
	"strings"
	"unique"

	"github.com/tchap/go-patricia/v2/patricia"

	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

// Node is represented by cidr as KEY and stores all keys for that CIDR.
type IPTrieNode struct {
	cidr ip.CIDR
	keys []unique.Handle[model.Key]
}

type IpTrie struct {
	lpmCache      *patricia.Trie
	existingCidrs set.Set[ip.CIDR]
}

func NewIpTrie() *IpTrie {
	return &IpTrie{
		lpmCache:      patricia.NewTrie(),
		existingCidrs: set.New[ip.CIDR](),
	}
}

// getLowestSortingKey returns the key with the lexicographically smallest name from a slice of
// keys. This provides deterministic tie-breaking for network sets with the same prefix length.
func getLowestSortingKey(keys []unique.Handle[model.Key]) model.Key {
	if len(keys) == 0 {
		return nil
	}
	if len(keys) == 1 {
		return keys[0].Value()
	}

	// Linear scan to find the lexicographically lowest key
	lowestHandle := keys[0]
	lowestKeyStr := lowestHandle.Value().String()

	for i := 1; i < len(keys); i++ {
		keyStr := keys[i].Value().String()
		if keyStr < lowestKeyStr {
			lowestHandle = keys[i]
			lowestKeyStr = keyStr
		}
	}

	return lowestHandle.Value()
}

func newIPTrieNode(cidr ip.CIDR, key model.Key) *IPTrieNode {
	return &IPTrieNode{
		cidr: cidr,
		keys: []unique.Handle[model.Key]{unique.Make(key)},
	}
}

// GetLongestPrefixCidr finds the longest prefix match CIDR for the given IP and if successful returns the
// lexicographically lowest key associated with that CIDR.
func (trie *IpTrie) GetLongestPrefixCidr(ipAddr ip.Addr) (model.Key, bool) {
	var longestPrefix patricia.Prefix
	var longestItem patricia.Item
	ptrie := trie.lpmCache

	err := ptrie.VisitPrefixes(patricia.Prefix(ipAddr.AsBinary()),
		func(prefix patricia.Prefix, item patricia.Item) error {
			if len(prefix) > len(longestPrefix) {
				longestPrefix = prefix
				longestItem = item
			}
			return nil
		})

	if err != nil || longestItem == nil {
		return nil, false
	}

	node := longestItem.(*IPTrieNode)
	return getLowestSortingKey(node.keys), true
}

// GetLongestPrefixCidrWithNamespaceIsolation finds the best prefix match with namespace isolation.
// Priority order:
// 1) preferred namespace match
// 2) global match
// 3) any other namespace match
func (trie *IpTrie) GetLongestPrefixCidrWithNamespaceIsolation(ipAddr ip.Addr, preferredNamespace string) (model.Key, bool) {
	ptrie := trie.lpmCache
	searchPrefix := patricia.Prefix(ipAddr.AsBinary())

	type bestMatch struct {
		keys   []unique.Handle[model.Key]
		prefix patricia.Prefix
	}

	var (
		bestPreferred bestMatch
		bestGlobal    bestMatch
		bestOther     bestMatch
	)

	updateBest := func(b *bestMatch, prefix patricia.Prefix, keyHandle unique.Handle[model.Key]) {
		switch {
		case len(prefix) > len(b.prefix):
			b.keys = append(b.keys[:0], keyHandle)
			b.prefix = prefix
		case len(prefix) == len(b.prefix):
			b.keys = append(b.keys, keyHandle)
		}
	}

	if err := ptrie.VisitPrefixes(searchPrefix, func(prefix patricia.Prefix, item patricia.Item) error {
		node := item.(*IPTrieNode)
		for _, keyHandle := range node.keys {
			key := keyHandle.Value()
			nsKey, ok := key.(model.NetworkSetKey)
			if !ok {
				continue
			}
			ns := nsKey.GetNamespace()

			switch {
			case preferredNamespace != "" && ns == preferredNamespace:
				updateBest(&bestPreferred, prefix, keyHandle)
			case ns == "":
				updateBest(&bestGlobal, prefix, keyHandle)
			default:
				updateBest(&bestOther, prefix, keyHandle)
			}
		}
		return nil
	}); err != nil {
		return nil, false
	}

	switch {
	case len(bestPreferred.keys) > 0:
		return getLowestSortingKey(bestPreferred.keys), true
	case len(bestGlobal.keys) > 0:
		return getLowestSortingKey(bestGlobal.keys), true
	case len(bestOther.keys) > 0:
		return getLowestSortingKey(bestOther.keys), true
	default:
		return nil, false
	}
}

// GetKeys return list of keys for the Given CIDR
func (t *IpTrie) GetKeys(cidr ip.CIDR) ([]model.Key, bool) {
	ptrie := t.lpmCache
	cidrb := cidr.AsBinary()
	val := ptrie.Get(patricia.Prefix(cidrb))

	if val != nil {
		node := val.(*IPTrieNode)
		// Convert handles back to keys
		keys := make([]model.Key, len(node.keys))
		for i, h := range node.keys {
			keys[i] = h.Value()
		}
		return keys, true
	}

	return nil, false
}

// DeleteKey walks through the trie, finds the key CIDR and delete corresponding key.
func (t *IpTrie) DeleteKey(cidr ip.CIDR, key model.Key) {
	ptrie := t.lpmCache
	cidrb := cidr.AsBinary()

	val := ptrie.Get(patricia.Prefix(cidrb))

	if val == nil {
		return
	}
	node := val.(*IPTrieNode)
	if len(node.keys) == 1 {
		t.existingCidrs.Discard(cidr)
		ptrie.Delete(patricia.Prefix(cidrb))
	} else {
		node.keys = slices.DeleteFunc(node.keys, func(h unique.Handle[model.Key]) bool {
			return h.Value() == key
		})
	}
}

// InsertKey inserts the given CIDR in Trie and stores the key in List.
// - Check if this CIDR already has a corresponding networkset.
//   - if it has one, then append the key to it.
//   - else, create a new CIDR to key.
func (t *IpTrie) InsertKey(cidr ip.CIDR, key model.Key) {
	ptrie := t.lpmCache
	cidrb := cidr.AsBinary()

	t.existingCidrs.Add(cidr)
	val := ptrie.Get(patricia.Prefix(cidrb))
	if val == nil {
		newNode := newIPTrieNode(cidr, key)
		ptrie.Insert(patricia.Prefix(cidrb), newNode)
	} else {
		node := val.(*IPTrieNode)
		keyHandle := unique.Make(key)
		isExistingNetset := false
		for i, existingHandle := range node.keys {
			if key == existingHandle.Value() {
				node.keys[i] = keyHandle
				isExistingNetset = true
				break
			}
		}
		if !isExistingNetset {
			node.keys = append(node.keys, keyHandle)
		}
	}
}

// DumpCIDRKeys returns slices of string with Cidr and corresponding key strings.
func (t *IpTrie) DumpCIDRKeys() []string {
	ec := t.existingCidrs
	lines := []string{}
	for cidr := range ec.All() {
		keyStrings := []string{}
		keys, _ := t.GetKeys(cidr)
		for _, key := range keys {
			keyStrings = append(keyStrings, key.String())
		}
		lines = append(lines, cidr.String()+": "+strings.Join(keyStrings, ","))
	}

	return lines
}
