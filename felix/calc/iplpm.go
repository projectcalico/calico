// Copyright (c) 2019-2021 Tigera, Inc. All rights reserved.
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
	"strings"

	"github.com/tchap/go-patricia/v2/patricia"

	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

// Node is represented by cidr as KEY and v1 key data stored in keys.
type IPTrieNode struct {
	cidr ip.CIDR
	keys []model.Key
}

// Root of IpTree
type IpTrie struct {
	lpmCache      *patricia.Trie
	existingCidrs set.Set[ip.CIDR]
}

// NewIpTrie creates new Patricia trie and Initializes
func NewIpTrie() *IpTrie {
	return &IpTrie{
		lpmCache:      patricia.NewTrie(),
		existingCidrs: set.New[ip.CIDR](),
	}
}

// newIPTrieNode Function creates new empty node containing the CIDR and single key.
func newIPTrieNode(cidr ip.CIDR, key model.Key) *IPTrieNode {
	return &IPTrieNode{cidr: cidr, keys: []model.Key{key}}
}

// GetLongestPrefixCidr finds longest prefix match CIDR for the Given IP and if successful return the last key
// recorded.
func (t *IpTrie) GetLongestPrefixCidr(ipAddr ip.Addr) (model.Key, bool) {
	var longestPrefix patricia.Prefix
	var longestItem patricia.Item
	ptrie := t.lpmCache

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
	return node.keys[len(node.keys)-1], true
}

// GetKeys return list of keys for the Given CIDR
func (t *IpTrie) GetKeys(cidr ip.CIDR) ([]model.Key, bool) {
	ptrie := t.lpmCache
	cidrb := cidr.AsBinary()
	val := ptrie.Get(patricia.Prefix(cidrb))

	if val != nil {
		node := val.(*IPTrieNode)
		return node.keys, true
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
		ii := 0
		for _, val := range node.keys {
			if val != key {
				node.keys[ii] = val
				ii++
			}
		}
		node.keys = node.keys[:ii]
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
		isExistingNetset := false
		for i, val := range node.keys {
			if key == val {
				node.keys[i] = key
				isExistingNetset = true
				break
			}
		}
		if !isExistingNetset {
			node.keys = append(node.keys, key)
		}
	}
}

// DumpCIDRKeys returns slices of string with Cidr and corresponding key strings.
func (t *IpTrie) DumpCIDRKeys() []string {
	ec := t.existingCidrs
	lines := []string{}
	ec.Iter(func(cidr ip.CIDR) error {
		keyStrings := []string{}
		keys, _ := t.GetKeys(cidr)
		for _, key := range keys {
			keyStrings = append(keyStrings, key.String())
		}
		lines = append(lines, cidr.String()+": "+strings.Join(keyStrings, ","))

		return nil
	})

	return lines
}
