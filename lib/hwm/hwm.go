// Copyright (c) 2016 Tigera, Inc. All rights reserved.
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

// The hwm package contains the HighWatermarkTracker;
package hwm

import (
	log "github.com/Sirupsen/logrus"
	"gopkg.in/tchap/go-patricia.v2/patricia"
)

// HighWatermarkTracker: map that tracks the highest value seen for each key.
// Supports temporary tracking of deletions in order to resolve concurrent updates.
type HighWatermarkTracker struct {
	hwms         *patricia.Trie
	deletionHwms *patricia.Trie
	deletionHwm  uint64
}

func NewHighWatermarkTracker() *HighWatermarkTracker {
	trie := new(HighWatermarkTracker)
	trie.hwms = patricia.NewTrie()
	trie.deletionHwms = nil // No deletion tracking in progress
	return trie
}

func (trie *HighWatermarkTracker) StartTrackingDeletions() {
	trie.deletionHwms = patricia.NewTrie()
	trie.deletionHwm = 0
}

func (trie *HighWatermarkTracker) StopTrackingDeletions() {
	trie.deletionHwms = nil
	trie.deletionHwm = 0
}

func (trie *HighWatermarkTracker) StoreUpdate(key string, newModIdx uint64) uint64 {
	prefix := keyToPrefix(key)
	if trie.deletionHwms != nil {
		// Optimization: only check if this key is in the deletion
		// trie if we've seen at least one deletion since...
		if newModIdx < trie.deletionHwm {
			_, delHwm := findLongestPrefix(trie.deletionHwms, prefix)
			if delHwm != nil {
				if newModIdx < delHwm.(uint64) {
					return delHwm.(uint64)
				}
			}
		}
	}

	// Get the old value
	oldHwmOrNil := trie.hwms.Get(prefix)
	if oldHwmOrNil != nil {
		oldHwm := oldHwmOrNil.(uint64)
		if oldHwm < newModIdx {
			trie.hwms.Set(prefix, newModIdx)
		}
	} else {
		trie.hwms.Set(prefix, newModIdx)
	}
	if oldHwmOrNil != nil {
		return oldHwmOrNil.(uint64)
	} else {
		return 0
	}
}

func (trie *HighWatermarkTracker) StoreDeletion(key string, newModIdx uint64) []string {
	if newModIdx > trie.deletionHwm {
		trie.deletionHwm = newModIdx
	}
	prefix := keyToPrefix(key)
	if trie.deletionHwms != nil {
		trie.deletionHwms.Set(prefix, newModIdx)
	}
	deletedKeys := make([]string, 0, 1)
	trie.hwms.VisitSubtree(prefix, func(prefix patricia.Prefix, item patricia.Item) error {
		childKey := prefixToKey(prefix)
		deletedKeys = append(deletedKeys, childKey)
		return nil
	})
	return deletedKeys
}

func (trie *HighWatermarkTracker) DeleteOldKeys(hwmLimit uint64) []string {
	if trie.deletionHwms != nil {
		panic("Deletion tracking not compatible with DeleteOldKeys")
	}
	deletedPrefixes := make([]patricia.Prefix, 0)
	deletedKeys := make([]string, 0)
	trie.hwms.Visit(func(prefix patricia.Prefix, item patricia.Item) error {
		log.Debugf("Deleted prefix: %v", prefix)
		if prefix == nil {
			panic("nil prefix passed to visitor")
		}
		if item.(uint64) < hwmLimit {
			prefixCopy := make(patricia.Prefix, len(prefix))
			copy(prefixCopy, prefix)
			deletedPrefixes = append(deletedPrefixes, prefixCopy)
			deletedKeys = append(deletedKeys, prefixToKey(prefixCopy))
		}
		return nil
	})
	for ii, childPrefix := range deletedPrefixes {
		log.Debugf("Key deleted, updating trie: %v", deletedKeys[ii])
		trie.hwms.Delete(childPrefix)
	}
	return deletedKeys
}

func findLongestPrefix(trie *patricia.Trie, prefix patricia.Prefix) (patricia.Prefix, patricia.Item) {
	var longestPrefix patricia.Prefix
	var longestItem patricia.Item

	trie.VisitPrefixes(prefix,
		func(prefix patricia.Prefix, item patricia.Item) error {
			if len(prefix) > len(longestPrefix) {
				longestPrefix = prefix
				longestItem = item
			}
			return nil
		})
	return longestPrefix, longestItem
}

// keyToPrefix converts a datastore key to a patricia.Prefix ending in a "/".
// It's essential that our prefixes end with a "/" so that we can do deletion
// processing.  Without a terminator, deleting "/foo" from the trie would
// also delete "/foobar", which we don't want.
func keyToPrefix(key string) patricia.Prefix {
	if key[len(key)-1] != '/' {
		key = key + "/"
	}
	return patricia.Prefix(key)
}

// prefixToKey converts a patricia.Prefix back into a datastore key.
// Removed the trailing "/" added by encodeKey.
func prefixToKey(prefix patricia.Prefix) string {
	// Strip off the trailing "/"
	return string(prefix)[:len(prefix)-1]
}
